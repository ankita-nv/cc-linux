// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2025 ARM Ltd.
 */

#include <uapi/linux/psci.h>
#include <linux/kvm_host.h>
#include <linux/overflow.h>
#include <linux/sort.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/rmi_cmds.h>
#include <asm/virt.h>

#define RMM_RTT_MAX_LEVEL	KVM_PGTABLE_LAST_LEVEL

static inline unsigned long rmi_rtt_level_mapsize(int level)
{
	if (WARN_ON(level > KVM_PGTABLE_LAST_LEVEL))
		return PAGE_SIZE;

	return (1UL << ARM64_HW_PGTABLE_LEVEL_SHIFT(level));
}

static inline unsigned long rmi_rtt_next_addr(unsigned long addr,
					      unsigned long end, int level)
{
	return min(ALIGN(addr + 1, rmi_rtt_level_mapsize(level)), end);
}

static bool rmi_has_feature0(unsigned long feature)
{
	return !!u64_get_bits(rmm_feat_reg0, feature);
}

static bool rmi_has_feature1(unsigned long feature)
{
	return !!u64_get_bits(rmm_feat_reg1, feature);
}

bool kvm_rmi_supports_sve(void)
{
	return rmi_has_feature0(RMI_FEATURE_REGISTER_0_SVE);
}

u32 kvm_realm_ipa_limit(void)
{
	return u64_get_bits(rmm_feat_reg0, RMI_FEATURE_REGISTER_0_S2SZ);
}

unsigned int kvm_realm_sve_max_vl(void)
{
	return sve_vl_from_vq(u64_get_bits(rmm_feat_reg0,
					   RMI_FEATURE_REGISTER_0_SVE_VL) + 1);
}

u64 kvm_realm_reset_id_aa64dfr0_el1(const struct kvm_vcpu *vcpu, u64 val)
{
	u32 bps = u64_get_bits(rmm_feat_reg0, RMI_FEATURE_REGISTER_0_NUM_BPS);
	u32 wps = u64_get_bits(rmm_feat_reg0, RMI_FEATURE_REGISTER_0_NUM_WPS);
	u32 ctx_cmps;

	/* Ensure CTX_CMPs is still valid */
	ctx_cmps = FIELD_GET(ID_AA64DFR0_EL1_CTX_CMPs, val);
	ctx_cmps = min(bps, ctx_cmps);

	val &= ~(ID_AA64DFR0_EL1_BRPs_MASK | ID_AA64DFR0_EL1_WRPs_MASK |
		 ID_AA64DFR0_EL1_CTX_CMPs);
	val |= FIELD_PREP(ID_AA64DFR0_EL1_BRPs_MASK, bps) |
	       FIELD_PREP(ID_AA64DFR0_EL1_WRPs_MASK, wps) |
	       FIELD_PREP(ID_AA64DFR0_EL1_CTX_CMPs, ctx_cmps);

	return val;
}

static int get_start_level(struct realm *realm)
{
	return 4 - stage2_pgtable_levels(realm->ia_bits);
}

static int find_map_level(struct realm *realm,
			  unsigned long start,
			  unsigned long end)
{
	int level = KVM_PGTABLE_LAST_LEVEL;

	while (level > get_start_level(realm)) {
		unsigned long map_size = rmi_rtt_level_mapsize(level - 1);

		if (!IS_ALIGNED(start, map_size) ||
		    (start + map_size) > end)
			break;

		level--;
	}

	return level;
}

static int rmi_addr_range_desc_decode(unsigned long desc,
				      unsigned long expected_state,
				      phys_addr_t *addr, unsigned long *size)
{
	unsigned long block_size;
	unsigned long count = RMI_ADDR_RANGE_COUNT(desc);
	phys_addr_t base = RMI_ADDR_RANGE_ADDR(desc);
	phys_addr_t end;

	if (!count) {
		if (desc)
			return -EPROTO;
		*addr = 0;
		*size = 0;
		return 0;
	}

	block_size = RMI_ADDR_BSIZE_BYTES(RMI_ADDR_RANGE_SIZE(desc));
	if ((desc & RMI_ADDR_RANGE_RESERVED_MASK) ||
	    RMI_ADDR_RANGE_STATE(desc) != expected_state ||
	    !IS_ALIGNED(base, block_size) ||
	    check_mul_overflow(block_size, count, size) ||
	    check_add_overflow(base, *size, &end))
		return -EPROTO;

	*addr = base;
	return 0;
}

static int find_aligned_map_level(struct realm *realm,
				  unsigned long ipa,
				  phys_addr_t phys,
				  unsigned long end)
{
	int level = KVM_PGTABLE_LAST_LEVEL;

	while (level > get_start_level(realm)) {
		unsigned long map_size = rmi_rtt_level_mapsize(level - 1);

		if (!IS_ALIGNED(ipa | phys, map_size) ||
		    (ipa + map_size) > end)
			break;

		level--;
	}

	return level;
}

static void realm_free_sro(struct realm *realm)
{
	if (realm->sro) {
		rmi_sro_free(realm->sro);
		kfree(realm->sro);
		realm->sro = NULL;
	}
}

static int realm_alloc_sro(struct realm *realm)
{
	if (WARN_ON(realm->sro))
		return -EEXIST;

	realm->sro = kzalloc_obj(*realm->sro, GFP_KERNEL_ACCOUNT);
	if (!realm->sro)
		return -ENOMEM;

	return 0;
}

/*
 * Delegate a PA range using caller-owned SRO state.
 *
 * RMI_GRANULE_RANGE_DELEGATE may make forward progress on only a prefix of
 * the requested range. Return that delegated prefix to the caller so it can
 * either consume the granules or undelegate exactly the granules that changed
 * ownership.
 */
static int realm_delegate_range(phys_addr_t phys,
				unsigned long size,
				unsigned long *delegated_size)
{
	return rmi_delegate_range(phys, size, delegated_size);
}

static int realm_undelegate_range(phys_addr_t phys,
				  unsigned long size,
				  unsigned long *undelegated_size)
{
	return rmi_undelegate_range(phys, size, undelegated_size);
}

static int realm_undelegate_map_range(phys_addr_t phys,
				      unsigned long size)
{
	phys_addr_t addr;
	phys_addr_t end = phys + size;
	unsigned long undelegated_size = 0;
	int ret;

	if (!size)
		return 0;

	ret = realm_undelegate_range(phys, size, &undelegated_size);
	if (WARN_ON(ret != RMI_SUCCESS)) {
		/* Pages can't be returned to NS world so are lost */
		for (addr = phys + undelegated_size; addr < end;
		     addr += PAGE_SIZE)
			get_page(phys_to_page(addr));
		return -ENXIO;
	}

	return 0;
}

static int undelegate_range_desc(unsigned long desc)
{
	unsigned long size;
	phys_addr_t addr;
	int ret;

	ret = rmi_addr_range_desc_decode(desc, RMI_OP_MEM_DELEGATED,
					 &addr, &size);
	if (ret)
		return ret;
	if (!size)
		return 0;

	return realm_undelegate_range(addr, size, NULL);
}

static int rmi_addr_range_desc_cmp(const void *a, const void *b)
{
	unsigned long addr_a = RMI_ADDR_RANGE_ADDR(*(const unsigned long *)a);
	unsigned long addr_b = RMI_ADDR_RANGE_ADDR(*(const unsigned long *)b);

	if (addr_a < addr_b)
		return -1;
	if (addr_a > addr_b)
		return 1;
	return 0;
}

static int undelegate_range_descs(unsigned long *descs, unsigned long count)
{
	unsigned long run_start = 0, run_end = 0;
	bool have_run = false;
	unsigned long i;
	int ret;

	if (!count)
		return 0;

	sort(descs, count, sizeof(*descs), rmi_addr_range_desc_cmp, NULL);

	for (i = 0; i < count; i++) {
		unsigned long size;
		phys_addr_t addr;

		ret = rmi_addr_range_desc_decode(descs[i],
						 RMI_OP_MEM_DELEGATED,
						 &addr, &size);
		if (ret)
			return ret;
		if (!size)
			return -EPROTO;

		if (have_run && addr == run_end) {
			run_end += size;
			continue;
		}

		if (have_run) {
			ret = realm_undelegate_range(run_start,
						     run_end - run_start, NULL);
			if (ret)
				return ret;
		}

		run_start = addr;
		run_end = addr + size;
		have_run = true;
	}

	if (!have_run)
		return 0;

	return realm_undelegate_range(run_start, run_end - run_start, NULL);
}

static void realm_alloc_unmap_desc_buf(struct realm *realm)
{
	unsigned long *buf;

	if (WARN_ON(realm->unmap_desc_buf))
		return;

	buf = (unsigned long *)__get_free_page(GFP_KERNEL_ACCOUNT);
	if (!buf)
		return;

	realm->unmap_desc_buf = buf;
	realm->unmap_desc_pa = virt_to_phys(buf);
	realm->unmap_desc_cap = min_t(unsigned long,
				      PAGE_SIZE / sizeof(*buf),
				      FIELD_MAX(RMI_RTT_UNMAP_FLAGS_LIST_COUNT_MASK));
}

static void realm_free_unmap_desc_buf(struct realm *realm)
{
	if (!realm->unmap_desc_buf)
		return;

	free_page((unsigned long)realm->unmap_desc_buf);
	realm->unmap_desc_buf = NULL;
	realm->unmap_desc_pa = 0;
	realm->unmap_desc_cap = 0;
}

static phys_addr_t alloc_delegated_granule(struct kvm_mmu_memory_cache *mc)
{
	phys_addr_t phys;
	void *virt;

	if (mc) {
		virt = kvm_mmu_memory_cache_alloc(mc);
	} else {
		virt = (void *)__get_free_page(GFP_ATOMIC | __GFP_ZERO |
					       __GFP_ACCOUNT);
	}

	if (!virt)
		return PHYS_ADDR_MAX;

	phys = virt_to_phys(virt);
	if (realm_delegate_range(phys, PAGE_SIZE, NULL)) {
		free_page((unsigned long)virt);
		return PHYS_ADDR_MAX;
	}

	return phys;
}

static int realm_free_delegated_page(phys_addr_t phys)
{
	if (WARN_ON(realm_undelegate_range(phys, PAGE_SIZE, NULL))) {
		/* Undelegate failed: leak the page */
		return -EBUSY;
	}

	free_page((unsigned long)phys_to_virt(phys));
	return 0;
}

static phys_addr_t alloc_rtt(struct kvm_mmu_memory_cache *mc)
{
	phys_addr_t phys = alloc_delegated_granule(mc);

	if (phys != PHYS_ADDR_MAX)
		kvm_account_pgtable_pages(phys_to_virt(phys), 1);

	return phys;
}

static void free_rtt(phys_addr_t phys)
{
	if (realm_free_delegated_page(phys))
		return;

	kvm_account_pgtable_pages(phys_to_virt(phys), -1);
}

unsigned long realm_psci_complete(struct kvm_vcpu *vcpu, unsigned long status)
{
	return rmi_psci_complete(virt_to_phys(vcpu->arch.rec.rec_page), status);
}

static int kvm_mpidr_to_rmi_rec_mpidr(unsigned long mpidr,
				      unsigned long *rec_mpidr)
{
	unsigned long aff0 = MPIDR_AFFINITY_LEVEL(mpidr, 0);

	if (aff0 & ~0xfUL)
		return -EINVAL;

	*rec_mpidr = aff0 |
		     (MPIDR_AFFINITY_LEVEL(mpidr, 1) << 8) |
		     (MPIDR_AFFINITY_LEVEL(mpidr, 2) << 16) |
		     (MPIDR_AFFINITY_LEVEL(mpidr, 3) << 24);

	return 0;
}

static int realm_rtt_create(struct realm *realm,
			    unsigned long addr,
			    int level,
			    phys_addr_t phys)
{
	addr = ALIGN_DOWN(addr, rmi_rtt_level_mapsize(level - 1));
	return rmi_rtt_create(virt_to_phys(realm->rd), phys, addr, level);
}

static int realm_rtt_fold(struct realm *realm,
			  unsigned long addr,
			  int level,
			  phys_addr_t *rtt_granule)
{
	unsigned long out_rtt = 0;
	int ret;

	addr = ALIGN_DOWN(addr, rmi_rtt_level_mapsize(level - 1));
	ret = rmi_rtt_fold(virt_to_phys(realm->rd), addr, level, &out_rtt);

	if (ret == RMI_SUCCESS && rtt_granule)
		*rtt_granule = out_rtt;

	return ret;
}

/*
 * realm_rtt_destroy - Destroy an RTT at @level for @addr.
 *
 * Returns - Result of the RMI_RTT_DESTROY call, and:
 * @rtt_granule:	RTT granule, if the RTT was destroyed.
 * @next_addr:		IPA corresponding to the next possible valid entry we
 *			can target
 */
static int realm_rtt_destroy(struct realm *realm, unsigned long addr,
			     int level, phys_addr_t *rtt_granule,
			     unsigned long *next_addr)
{
	unsigned long out_rtt;
	int ret;

	ret = rmi_rtt_destroy(virt_to_phys(realm->rd), addr, level,
			      &out_rtt, next_addr);

	if (ret == RMI_SUCCESS)
		*rtt_granule = out_rtt;

	return ret;
}

static int realm_create_rtt_levels(struct realm *realm,
				   unsigned long ipa,
				   int level,
				   int max_level,
				   struct kvm_mmu_memory_cache *mc)
{
	while (level++ < max_level) {
		phys_addr_t rtt = alloc_rtt(mc);
		int ret;

		if (rtt == PHYS_ADDR_MAX)
			return -ENOMEM;

		ret = realm_rtt_create(realm, ipa, level, rtt);
		if ((ret >= 0) &&
		    (RMI_RETURN_STATUS(ret) == RMI_BLOCKED)) {
			free_rtt(rtt);
			return -EAGAIN;
		}

		if ((ret >= 0) &&
		    (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) &&
		    RMI_RETURN_INDEX(ret) == level - 1) {
			/* The RTT already exists, continue */
			free_rtt(rtt);
			continue;
		}

		if (ret) {
			WARN(1, "Failed to create RTT at level %d: %d\n",
			     level, ret);
			free_rtt(rtt);
			return -ENXIO;
		}
	}

	return 0;
}

static int realm_tear_down_rtt_level(struct realm *realm, int level,
				     unsigned long start, unsigned long end)
{
	ssize_t map_size;
	unsigned long addr, next_addr;

	if (WARN_ON(level > KVM_PGTABLE_LAST_LEVEL))
		return -EINVAL;

	map_size = rmi_rtt_level_mapsize(level - 1);

	for (addr = start; addr < end; addr = next_addr) {
		phys_addr_t rtt_granule;
		int ret;
		unsigned long align_addr = ALIGN(addr, map_size);

		next_addr = ALIGN(addr + 1, map_size);

		if (next_addr > end || align_addr != addr) {
			/*
			 * The target range is smaller than what this level
			 * covers, recurse deeper.
			 */
			ret = realm_tear_down_rtt_level(realm,
							level + 1,
							addr,
							min(next_addr, end));
			if (ret)
				return ret;
			continue;
		}

		ret = realm_rtt_destroy(realm, addr, level,
					&rtt_granule, &next_addr);

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			free_rtt(rtt_granule);
			break;
		case RMI_ERROR_RTT:
			if (next_addr > addr) {
				/* Missing RTT, skip */
				break;
			}
			/*
			 * We tear down the RTT range for the full IPA
			 * space, after everything is unmapped. Also we
			 * descend down only if we cannot tear down a
			 * top level RTT. Thus RMM must be able to walk
			 * to the requested level. e.g., a block mapping
			 * exists at L1 or L2.
			 */
			if (WARN_ON(RMI_RETURN_INDEX(ret) != level))
				return -EBUSY;
			if (WARN_ON(level == KVM_PGTABLE_LAST_LEVEL))
				return -EBUSY;

			/*
			 * The table has active entries in it, recurse deeper
			 * and tear down the RTTs.
			 */
			next_addr = ALIGN(addr + 1, map_size);
			ret = realm_tear_down_rtt_level(realm,
							level + 1,
							addr,
							next_addr);
			if (ret)
				return ret;
			/*
			 * Now that the child RTTs are destroyed,
			 * retry at this level.
			 */
			next_addr = addr;
			break;
		default:
			WARN_ON(1);
			return -ENXIO;
		}
	}

	return 0;
}

static int realm_tear_down_rtt_range(struct realm *realm,
				     unsigned long start, unsigned long end)
{
	/*
	 * Root level RTTs can only be destroyed after the RD is destroyed. So
	 * tear down everything below the root level
	 */
	return realm_tear_down_rtt_level(realm, get_start_level(realm) + 1,
					 start, end);
}

/*
 * DEN0137 v2.0-bet3 defines RMI_RTT_FOLD as a one-entry operation; there is no
 * counted or LIST form to fold a range. The unmap output descriptors report
 * PA ranges, not the level of the removed RTTE, so probe L3 after any command
 * that removed a mapping. A successful fold makes the enclosing RTT a
 * candidate. On RMI_ERROR_RTT, an error at the target level means the target
 * RTT is non-homogeneous and stops the upward probe. A lower error level leaves
 * the enclosing RTT as a possible candidate, so continue upward.
 */
static bool realm_fold_rtt_level(struct kvm *kvm, int level,
				 unsigned long start, unsigned long end)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long map_size;
	unsigned long addr;
	bool probe_parent = false;

	/*
	 * Final teardown does not need homogeneous RTTs. RMI_RTT_DESTROY can
	 * reclaim any non-live RTT and its @top output skips RTTs which do not
	 * exist. Avoid speculative bottom-up folds while the complete stage-2 is
	 * being removed: a 1 GiB block mapping has no L3 RTT, but probing from L3
	 * would still issue 512 failing RMI_RTT_FOLD calls before reaching L2.
	 *
	 * Keep folding for partial unmaps of a live Realm, where reclaiming an
	 * empty RTT allows a larger block mapping to be installed later.
	 */
	if (kvm_realm_state(kvm) == REALM_STATE_DYING)
		return false;

	if (WARN_ON(level > RMM_RTT_MAX_LEVEL))
		return false;
	if (start >= end || level <= get_start_level(realm))
		return false;

	map_size = rmi_rtt_level_mapsize(level - 1);
	start = ALIGN_DOWN(start, map_size);
	end = ALIGN(end, map_size);

	if (start >= end)
		return false;

	for (addr = start; addr < end; addr += map_size) {
		phys_addr_t rtt_granule;
		int ret;

		ret = realm_rtt_fold(realm, addr, level, &rtt_granule);

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			free_rtt(rtt_granule);
			probe_parent = true;
			break;
		case RMI_ERROR_RTT:
			if (RMI_RETURN_INDEX(ret) < level)
				probe_parent = true;
			break;
		default:
			WARN_ON(1);
			return false;
		}
	}

	/* RMI_RTT_FOLD cannot target the Realm's starting-level root RTT. */
	if (probe_parent && level > (get_start_level(realm) + 1))
		realm_fold_rtt_level(kvm, level - 1, start, end);

	return probe_parent;
}

void kvm_realm_destroy_rtts(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned int ia_bits = realm->ia_bits;

	realm_tear_down_rtt_range(realm, 0, (1UL << ia_bits));
}

static void realm_unmap_shared_range(struct kvm *kvm,
				     unsigned long start,
				     unsigned long end,
				     bool may_block)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long rd = virt_to_phys(realm->rd);
	unsigned long next_addr, addr;
	unsigned long shared_bit = BIT(realm->ia_bits - 1);

	lockdep_assert_held_write(&kvm->mmu_lock);

	if (start >= end)
		return;

	/*
	 * Convert the private IPA interval to its shared alias. Use addition
	 * rather than setting the shared bit so a full private range ending at
	 * @shared_bit maps to the open end of the shared half, not to an empty
	 * range.
	 */
	start += shared_bit;
	end += shared_bit;

	for (addr = start; addr < end; addr = next_addr) {
		unsigned long out_range = 0;
		int ret;

retry:
		ret = rmi_rtt_unprot_unmap(rd, addr, end,
					   RMI_ADDR_TYPE_SINGLE, 0,
					   &next_addr, &out_range, NULL);
		if (WARN_ON(ret < 0))
			return;
		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS: {
			unsigned long count = RMI_ADDR_RANGE_COUNT(out_range);

			/*
			 * @next_addr is RMM's out_top: the IPA up to which the
			 * architecture unmapped (page or block, picked by RMM
			 * transparently per DEN0137 v2.0-bet3 §B4.5.70).
			 */
			if (WARN_ON(next_addr <= addr || next_addr > end))
				return;
			if (count)
				realm_fold_rtt_level(kvm, RMM_RTT_MAX_LEVEL,
						     addr, next_addr);
			break;
		}
		case RMI_ERROR_RTT: {
			unsigned long map_size;
			int err_level = RMI_RETURN_INDEX(ret);

			if (WARN_ON(err_level > KVM_PGTABLE_LAST_LEVEL))
				return;

			map_size = rmi_rtt_level_mapsize(err_level);
			if (err_level == KVM_PGTABLE_LAST_LEVEL ||
			    (IS_ALIGNED(addr, map_size) &&
			     addr + map_size <= end)) {
				next_addr = rmi_rtt_next_addr(addr, end,
							     err_level);
				break;
			}

			ret = realm_create_rtt_levels(realm,
						      addr, err_level,
						      err_level + 1, NULL);
			if (ret)
				return;
			goto retry;
		}
		default:
			WARN_ON(1);
			return;
		}

		if (may_block)
			cond_resched_rwlock_write(&kvm->mmu_lock);
	}
}

static int realm_init_sve_param(struct kvm *kvm, struct realm_params *params)
{
	unsigned long i;
	struct kvm_vcpu *vcpu;
	int vl, last_vl = -1;

	if (!kvm_has_sve(kvm))
		return 0;

	/*
	 * Get the preferred SVE configuration, set by userspace with the
	 * KVM_ARM_VCPU_SVE feature and KVM_REG_ARM64_SVE_VLS pseudo-register.
	 */
	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (!kvm_arm_vcpu_sve_finalized(vcpu))
			return -EINVAL;

		vl = vcpu->arch.sve_max_vl;

		/* We need all vCPUs to have the same SVE config */
		if (last_vl >= 0 && last_vl != vl)
			return -EINVAL;

		last_vl = vl;
	}

	if (last_vl > 0) {
		params->sve_vl = sve_vq_from_vl(last_vl) - 1;
		params->flags0 |= RMI_REALM_PARAM_FLAG_SVE;
	}
	return 0;
}

static int realm_create_rd(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	struct realm_params *params __free(free_page) = NULL;
	void *rd = NULL;
	phys_addr_t rd_phys, params_phys;
	size_t pgd_size = kvm_pgtable_stage2_pgd_size(kvm->arch.mmu.vtcr);
	unsigned long pgd_delegated_size = 0;
	u64 dfr0 = kvm_read_vm_id_reg(kvm, SYS_ID_AA64DFR0_EL1);
	long rmi_ret;
	int r;

	realm->ia_bits = VTCR_EL2_IPA(kvm->arch.mmu.vtcr);

	if (WARN_ON(realm->rd))
		return -EEXIST;

	params = (void *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
	if (!params)
		return -ENOMEM;

	rd = (void *)__get_free_page(GFP_KERNEL_ACCOUNT);
	if (!rd)
		return -ENOMEM;

	rd_phys = virt_to_phys(rd);
	if (realm_delegate_range(rd_phys, PAGE_SIZE, NULL)) {
		r = -ENXIO;
		goto free_rd;
	}

	if (realm_delegate_range(kvm->arch.mmu.pgd_phys,
				 pgd_size, &pgd_delegated_size)) {
		r = -ENXIO;
		goto out_undelegate_tables;
	}

	params->s2sz = VTCR_EL2_IPA(kvm->arch.mmu.vtcr);
	params->rtt_level_start = get_start_level(realm);
	params->rtt_num_start = pgd_size / PAGE_SIZE;
	params->rtt_base = kvm->arch.mmu.pgd_phys;
	params->num_bps = SYS_FIELD_GET(ID_AA64DFR0_EL1, BRPs, dfr0);
	params->num_wps = SYS_FIELD_GET(ID_AA64DFR0_EL1, WRPs, dfr0);
	params->hash_algo = RMI_HASH_SHA_256;

	if (kvm->arch.arm_pmu) {
		params->pmu_num_ctrs = kvm->arch.nr_pmu_counters;
		params->flags0 |= RMI_REALM_PARAM_FLAG_PMU;
	}

	r = realm_init_sve_param(kvm, params);
	if (r)
		goto out_undelegate_tables;

	params_phys = virt_to_phys(params);

	rmi_ret = rmi_realm_create(rd_phys, params_phys, realm->sro);
	if (rmi_ret) {
		r = rmi_ret < 0 ? rmi_ret : -ENXIO;
		goto out_undelegate_tables;
	}

	realm->rd = rd;
	realm_alloc_unmap_desc_buf(realm);
	kvm_set_realm_state(kvm, REALM_STATE_NEW);

	return 0;

out_undelegate_tables:
	if (pgd_delegated_size &&
	    WARN_ON(realm_undelegate_range(kvm->arch.mmu.pgd_phys,
					   pgd_delegated_size, NULL))) {
		/* Leak the pages if they cannot be returned */
		kvm->arch.mmu.pgt = NULL;
	}
	if (WARN_ON(realm_undelegate_range(rd_phys, PAGE_SIZE, NULL))) {
		/* Leak the page if it isn't returned */
		return r;
	}
free_rd:
	free_page((unsigned long)rd);
	return r;
}

static void realm_unmap_private_range_single(struct kvm *kvm,
					     unsigned long start,
					     unsigned long end,
					     bool may_block)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long rd = virt_to_phys(realm->rd);
	unsigned long next_addr, addr;
	int ret;

	lockdep_assert_held_write(&kvm->mmu_lock);

	for (addr = start; addr < end; addr = next_addr) {
		unsigned long out_range = 0;
		unsigned long flags = RMI_ADDR_TYPE_SINGLE;

retry:
		ret = rmi_rtt_data_unmap(rd, addr, end, flags, 0,
					 &next_addr, &out_range, NULL);
		if (WARN_ON(ret < 0))
			return;

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			if (WARN_ON(next_addr <= addr || next_addr > end))
				return;
			if (RMI_ADDR_RANGE_COUNT(out_range))
				realm_fold_rtt_level(kvm, RMM_RTT_MAX_LEVEL,
						     addr, next_addr);
			break;
		case RMI_ERROR_RTT: {
			unsigned long map_size;
			int err_level = RMI_RETURN_INDEX(ret);

			if (WARN_ON(err_level > KVM_PGTABLE_LAST_LEVEL))
				return;

			map_size = rmi_rtt_level_mapsize(err_level);
			if (err_level == KVM_PGTABLE_LAST_LEVEL ||
			    (IS_ALIGNED(addr, map_size) &&
			     addr + map_size <= end)) {
				next_addr = rmi_rtt_next_addr(addr, end,
							     err_level);
				break;
			}

			ret = realm_create_rtt_levels(realm,
						      addr, err_level,
						      err_level + 1, NULL);
			if (ret)
				return;
			goto retry;
		}
		default:
			WARN_ON(1);
			return;
		}
		ret = undelegate_range_desc(out_range);
		if (WARN_ON(ret))
			break;

		if (may_block)
			cond_resched_rwlock_write(&kvm->mmu_lock);
	}
}

static void realm_unmap_private_range(struct kvm *kvm,
				      unsigned long start,
				      unsigned long end,
				      bool may_block)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long rd = virt_to_phys(realm->rd);
	unsigned long next_addr, addr;
	unsigned long flags;
	int ret;

	/*
	 * Protected unmaps need the PA output set for undelegation. Use a
	 * Realm-wide LIST buffer to batch the RMM output; mmu_lock serializes
	 * users of the buffer.
	 */
	if (!realm->unmap_desc_buf) {
		realm_unmap_private_range_single(kvm, start, end, may_block);
		return;
	}

	lockdep_assert_held_write(&kvm->mmu_lock);

	flags = RMI_ADDR_TYPE_LIST |
		FIELD_PREP(RMI_RTT_UNMAP_FLAGS_LIST_COUNT_MASK,
			   realm->unmap_desc_cap);

	for (addr = start; addr < end; addr = next_addr) {
		unsigned long out_count = 0;

retry:
		ret = rmi_rtt_data_unmap(rd, addr, end, flags,
					 realm->unmap_desc_pa, &next_addr,
					 NULL, &out_count);

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			if (WARN_ON(next_addr <= addr || next_addr > end))
				return;
			if (WARN_ON(out_count > realm->unmap_desc_cap))
				return;
			if (out_count)
				realm_fold_rtt_level(kvm, RMM_RTT_MAX_LEVEL,
						     addr, next_addr);
			break;
		case RMI_ERROR_RTT: {
			unsigned long map_size;
			int err_level = RMI_RETURN_INDEX(ret);

			if (WARN_ON(err_level > KVM_PGTABLE_LAST_LEVEL))
				return;

			map_size = rmi_rtt_level_mapsize(err_level);
			if (err_level == KVM_PGTABLE_LAST_LEVEL ||
			    (IS_ALIGNED(addr, map_size) &&
			     addr + map_size <= end)) {
				next_addr = rmi_rtt_next_addr(addr, end,
							     err_level);
				break;
			}

			ret = realm_create_rtt_levels(realm,
						      addr, err_level,
						      err_level + 1, NULL);
			if (ret)
				return;
			goto retry;
		}
		default:
			WARN_ON(1);
			return;
		}

		ret = undelegate_range_descs(realm->unmap_desc_buf, out_count);
		if (WARN_ONCE(ret,
			      "RMI: descriptor list undelegate failed: %d\n",
			      ret))
			break;

		if (may_block)
			cond_resched_rwlock_write(&kvm->mmu_lock);
	}
}

void kvm_realm_unmap_range(struct kvm *kvm, unsigned long start,
			   unsigned long size, bool unmap_private,
			   bool may_block)
{
	unsigned long end = start + size;
	struct realm *realm = &kvm->arch.realm;

	if (!kvm_realm_is_created(kvm))
		return;

	end = min(BIT(realm->ia_bits - 1), end);

	realm_unmap_shared_range(kvm, start, end, may_block);
	if (unmap_private)
		realm_unmap_private_range(kvm, start, end, may_block);
}

static int realm_data_map_init(struct kvm *kvm, unsigned long ipa,
			       kvm_pfn_t dst_pfn, kvm_pfn_t src_pfn,
			       unsigned long flags)
{
	struct realm *realm = &kvm->arch.realm;
	phys_addr_t rd = virt_to_phys(realm->rd);
	phys_addr_t dst_phys, src_phys;
	int ret;

	lockdep_assert_held(&kvm->slots_lock);
	lockdep_assert_held(&kvm->arch.config_lock);

	dst_phys = __pfn_to_phys(dst_pfn);
	src_phys = __pfn_to_phys(src_pfn);

	ret = rmi_rtt_data_map_init(rd, dst_phys, ipa, src_phys, flags);
	if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
		/* Create missing RTTs and retry */
		int level = RMI_RETURN_INDEX(ret);

		KVM_BUG_ON(level == KVM_PGTABLE_LAST_LEVEL, kvm);

		ret = realm_create_rtt_levels(realm, ipa, level,
					      KVM_PGTABLE_LAST_LEVEL, NULL);
		if (ret)
			return ret;

		ret = rmi_rtt_data_map_init(rd, dst_phys, ipa, src_phys,
					    flags);
	}

	if (ret)
		return -ENXIO;

	return 0;
}

static unsigned long addr_range_size(int level)
{
	switch (level) {
	case 0:
		return RMI_ADDR_RANGE_SIZE_P4D;
	case 1:
		return RMI_ADDR_RANGE_SIZE_PUD;
	case 2:
		return RMI_ADDR_RANGE_SIZE_PMD;
	case 3:
		return RMI_ADDR_RANGE_SIZE_PAGE;
	}

	WARN_ON_ONCE(1);
	return RMI_ADDR_RANGE_SIZE_PAGE;
}

static unsigned long desc_range_size(unsigned long size,
				     unsigned long remaining)
{
	remaining = min(remaining, size * FIELD_MAX(RMI_ADDR_RANGE_COUNT_MASK));

	return ALIGN_DOWN(remaining, size);
}

static unsigned long addr_range_desc(unsigned long phys, int level,
				     unsigned long range_size,
				     unsigned long state)
{
	unsigned long size = rmi_rtt_level_mapsize(level);
	unsigned long count = range_size / size;

	if (WARN_ON(!count || count > FIELD_MAX(RMI_ADDR_RANGE_COUNT_MASK) ||
		    !IS_ALIGNED(phys | range_size, size)))
		count = 1;

	WARN_ON(phys & (size - 1));

	return RMI_ADDR_RANGE_DESC(phys, addr_range_size(level), count, state);
}

/*
 * Read and classify the primary RTTE covering @ipa.
 *
 * Return 0 for an assigned or unassigned entry, -EAGAIN if a table exists at
 * @map_level and the caller must descend, -EBUSY if the RMM reports
 * RMI_BLOCKED, or -ENXIO if the RTTE cannot be read or has an unsupported
 * state. For assigned and unassigned entries, @next_ipa is set to the
 * exclusive end of the entry.
 */
static int realm_read_rtte(unsigned long rd, unsigned long ipa, int map_level,
			   unsigned long ipa_top, struct rtt_entry *rtte,
			   unsigned long *next_ipa)
{
	unsigned long map_size;
	unsigned long read_ipa;
	int ret;

	read_ipa = ALIGN_DOWN(ipa, rmi_rtt_level_mapsize(map_level));
	ret = rmi_rtt_read_entry(rd, read_ipa, map_level, rtte);

	if (RMI_RETURN_STATUS(ret) == RMI_BLOCKED)
		return -EBUSY;

	if (ret != RMI_SUCCESS)
		return -ENXIO;

	if (WARN_ONCE(rtte->walk_level > map_level ||
		      rtte->walk_level > KVM_PGTABLE_LAST_LEVEL,
		      "RMI: invalid RTT walk level %lu/%d: %d\n",
		      rtte->walk_level, map_level, -ENXIO))
		return -ENXIO;

	map_size = rmi_rtt_level_mapsize(rtte->walk_level);
	*next_ipa = min(ALIGN_DOWN(ipa, map_size) + map_size, ipa_top);

	switch (rtte->state) {
	case RMI_UNASSIGNED:
	case RMI_ASSIGNED:
		break;
	case RMI_TABLE:
		return (rtte->walk_level == map_level) ? -EAGAIN : -ENXIO;
	default:
		return -ENXIO;
	}

	return 0;
}

/*
 * Select the largest block order supported by the existing RTT hierarchy at
 * @ipa. A single walk to L2 distinguishes an L1 block from an L2 block and an
 * L2 table. Keep @max_order if the hierarchy cannot be classified so the map
 * path retains its existing retry and recovery behaviour.
 */
int realm_rtt_map_order(struct kvm *kvm, unsigned long ipa, int max_order)
{
	struct realm *realm = &kvm->arch.realm;
	const int map_level = KVM_PGTABLE_LAST_LEVEL - 1;
	unsigned long next_ipa;
	struct rtt_entry rtte;
	int ret;

	lockdep_assert_held(&kvm->mmu_lock);

	ret = realm_read_rtte(virt_to_phys(realm->rd), ipa, map_level,
			      ALIGN_DOWN(ipa, PMD_SIZE) + PMD_SIZE,
			      &rtte, &next_ipa);
	if (ret == -EAGAIN)
		return 0;
	if (ret || rtte.walk_level < map_level)
		return max_order;

	return min(max_order, PMD_ORDER);
}

/*
 * Check the protected mapping covering @ipa.
 *
 * Return 1 if an assigned RAM entry maps @ipa to @phys. Return 0 for an
 * unassigned entry, -EAGAIN if the caller must descend through an RTT table,
 * -EBUSY if the RMM reports RMI_BLOCKED, -EFAULT for a conflicting mapping,
 * or -ENXIO if the RTTE cannot be read or has an unsupported state. For
 * matching and unassigned entries, @next_ipa is set to the exclusive end of
 * the entry.
 */
static int realm_check_protected_mapping(unsigned long rd, unsigned long ipa,
					 phys_addr_t phys, int map_level,
					 unsigned long ipa_top,
					 unsigned long *next_ipa)
{
	struct rtt_entry rtte;
	unsigned long map_size;
	phys_addr_t rtte_phys;
	int ret;

	ret = realm_read_rtte(rd, ipa, map_level, ipa_top, &rtte, next_ipa);
	if (ret)
		return ret;

	if (rtte.state == RMI_UNASSIGNED)
		return 0;

	map_size = rmi_rtt_level_mapsize(rtte.walk_level);
	rtte_phys = kvm_pte_to_phys(rtte.desc) + (ipa & (map_size - 1));

	if ((rtte.ripas != RMI_RAM) || (rtte_phys != phys))
		return -EFAULT;

	return 1;
}

struct realm_map_run {
	unsigned long ipa;
	unsigned long top;
	phys_addr_t phys;
};

/*
 * Check whether an Unprotected IPA already has the requested mapping.
 * RMI_RTT_READ_ENTRY returns the architectural stage-2 descriptor, so compare
 * the PA, MemAttr and direct permissions before accepting an existing entry.
 * Unprotected mappings must also be execute-never per DEN0137 §A5.6.11.3.
 */
static int realm_check_unprotected_mapping(unsigned long rd,
					   unsigned long ipa,
					   phys_addr_t phys, int map_level,
					   unsigned long ipa_top,
					   unsigned long attr,
					   unsigned long *next_ipa)
{
	enum kvm_pgtable_prot prot;
	struct rtt_entry rtte;
	unsigned long map_size;
	phys_addr_t rtte_phys;
	int ret;

	ret = realm_read_rtte(rd, ipa, map_level, ipa_top, &rtte, next_ipa);
	if (ret)
		return ret;

	if (rtte.state == RMI_UNASSIGNED)
		return 0;

	map_size = rmi_rtt_level_mapsize(rtte.walk_level);
	rtte_phys = kvm_pte_to_phys(rtte.desc) + (ipa & (map_size - 1));
	prot = kvm_pgtable_stage2_pte_prot(rtte.desc);

	if (rtte.ripas != RMI_EMPTY || rtte_phys != phys ||
	    FIELD_GET(KVM_PTE_LEAF_ATTR_LO_S2_MEMATTR, rtte.desc) != attr ||
	    (prot & KVM_PGTABLE_PROT_RWX) != KVM_PGTABLE_PROT_RW)
		return -EFAULT;

	return 1;
}

/*
 * Delegate the next contiguous run of backing memory that still needs a
 * protected mapping.
 *
 * Range delegation can skip granules already in the delegated state, including
 * granules delegated by another fault. If delegation makes no progress, inspect
 * the RTT and either skip a matching mapping or retry the delegation bounded to
 * the unmapped span the walk found. The backing PA is the caller's @phys offset
 * by (run->ipa - @ipa), since the IPA->PA mapping is linear.
 *
 * Returns 0 with run->top == run->ipa == ipa_top when nothing remains to map
 * (the rest of the range is already mapped), 0 with a non-empty run to map, or
 * -E2BIG when a coarse zero-progress request should be retried around the
 * fault, or another negative errno.
 */
static int realm_prepare_protected_map(struct realm *realm, unsigned long ipa,
				       phys_addr_t phys, unsigned long ipa_top,
				       bool allow_fault_fallback,
				       struct realm_map_run *run)
{
	phys_addr_t rd = virt_to_phys(realm->rd);
	unsigned long next_ipa;
	int map_level;
	int ret;

	while (ipa < ipa_top) {
		unsigned long request_size = ipa_top - ipa;
		unsigned long delegated_size;
		bool skipped = false;
		int delegate_status;

retry_delegate:
		delegated_size = 0;
		ret = realm_delegate_range(phys, request_size,
					   &delegated_size);
		if (delegated_size) {
			/*
			 * Hand back the delegated prefix as the run to map. It may
			 * include granules already delegated by another fault, but
			 * RMI_RTT_DATA_MAP treats an exact existing mapping as
			 * success.
			 */
			run->ipa = ipa;
			run->top = ipa + delegated_size;
			run->phys = phys;
			return 0;
		}

		if (ret < 0)
			return ret;
		if (RMI_RETURN_STATUS(ret) == RMI_BUSY ||
		    RMI_RETURN_STATUS(ret) == RMI_BLOCKED)
			return -EAGAIN;

		/* The RTT walk below reuses @ret, so keep the delegate status. */
		delegate_status = RMI_RETURN_STATUS(ret);

		/*
		 * A failed range made no state change. Let the fault handler retry
		 * only the fault-containing subrange.
		 */
		if (allow_fault_fallback && (request_size > PAGE_SIZE) &&
		    (delegate_status == RMI_ERROR_INPUT))
			return -E2BIG;

		/*
		 * Delegation made no progress. This can be a Granule-state conflict
		 * or a tracking-region constraint. If @ipa is already mapped to the
		 * expected PA, skip it and continue; otherwise propagate the
		 * conflict through the mapping recovery path.
		 */
		map_level = find_aligned_map_level(realm, ipa, phys,
						   ipa + request_size);
retry_check:
		ret = realm_check_protected_mapping(rd, ipa, phys, map_level,
						    ipa_top, &next_ipa);
		if (ret > 0) {
			if (WARN_ON_ONCE(next_ipa <= ipa))
				return -ENXIO;

			phys += next_ipa - ipa;
			ipa = next_ipa;
			if (ipa >= ipa_top)
				break;

			/*
			 * Walk the rest of an already-mapped span with
			 * RTT_READ_ENTRY alone. Re-entering the loop would issue
			 * a whole-range delegate per mapped entry, and that
			 * delegate cannot succeed until the walk reaches an entry
			 * which is not already mapped.
			 */
			skipped = true;
			map_level = find_aligned_map_level(realm, ipa, phys,
							   ipa_top);
			goto retry_check;
		}

		if (ret == -EBUSY)
			return -EAGAIN;

		if (ret == -EAGAIN) {
			/*
			 * A child RTT exists at this level; inspect one level
			 * down to find the mapped target that blocked
			 * delegation.
			 */
			if (map_level >= KVM_PGTABLE_LAST_LEVEL)
				return -ENXIO;
			map_level++;
			goto retry_check;
		}

		if (ret == 0) {
			/* Reissue delegation from the first entry not already mapped. */
			if (skipped)
				continue;

			/*
			 * DEN0137 §B4.5.10 leaves out_top UNKNOWN unless the
			 * result is RMI_SUCCESS, and permits the RMM to refuse
			 * the whole request with RMI_ERROR_INPUT when the range
			 * spans a Granule which is unpopulated or whose state is
			 * neither GRAN_UNDELEGATED nor GRAN_DELEGATED. An RMM
			 * which instead stops short of that Granule reports the
			 * delegated prefix, which is handled above. Such a
			 * failure carries no usable progress, so bound the
			 * request to [ipa, next_ipa), which no RTTE maps.
			 */
			if ((delegate_status == RMI_ERROR_INPUT) &&
			    ((next_ipa - ipa) < request_size)) {
				request_size = next_ipa - ipa;
				goto retry_delegate;
			}
		}

		return ret < 0 ? ret : -ENXIO;
	}

	/* The whole range is already mapped; nothing left to delegate or map. */
	run->ipa = ipa_top;
	run->top = ipa_top;
	run->phys = phys;
	return 0;
}

/*
 * Install protected RTT entries for memory that has already been delegated.
 *
 * Matching mappings installed by another fault are treated as progress.
 */
static int realm_map_delegated_range(struct realm *realm,
				     const struct realm_map_run *run,
				     struct kvm_mmu_memory_cache *memcache)
{
	phys_addr_t rd = virt_to_phys(realm->rd);
	phys_addr_t phys = run->phys;
	unsigned long ipa = run->ipa;
	unsigned long ipa_top = run->top;
	int map_level;
	int ret = 0;

	while (ipa < ipa_top) {
		unsigned long block_size;
		unsigned long chunk_size;
		unsigned long range_desc;
		unsigned long flags;
		unsigned long out_top;

		map_level = find_aligned_map_level(realm, ipa, phys, ipa_top);

retry_lower_level:
		block_size = rmi_rtt_level_mapsize(map_level);
		chunk_size = desc_range_size(block_size, ipa_top - ipa);

retry_chunk:
		flags = RMI_ADDR_TYPE_SINGLE;
		range_desc = addr_range_desc(phys, map_level, chunk_size,
					    RMI_OP_MEM_DELEGATED);

		ret = rmi_rtt_data_map(rd, ipa, ipa + chunk_size, flags,
				       range_desc, &out_top);
		if ((ret >= 0) && (RMI_RETURN_STATUS(ret) == RMI_BLOCKED))
			return -EAGAIN;

		if ((ret >= 0) && (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT)) {
			unsigned long next_ipa;
			int level = RMI_RETURN_INDEX(ret);
			int state;

			if (WARN_ONCE(level > KVM_PGTABLE_LAST_LEVEL,
				      "RMI: DATA_MAP invalid RTT level %d: %d\n",
				      level, -ENXIO))
				return -ENXIO;

			/*
			 * RMI_ERROR_RTT also reports incompatible or concurrently
			 * modified entries. Read the walk result before assuming that
			 * an RTT is missing.
			 */
			state = realm_check_protected_mapping(rd, ipa, phys, level,
								ipa_top, &next_ipa);
			if (state > 0) {
				phys += next_ipa - ipa;
				ipa = next_ipa;
				continue;
			}

			/* Retry the fault after a blocked RTTE read. */
			if (state == -EBUSY)
				return -EAGAIN;

			if (state == -EAGAIN) {
				/*
				 * A table appeared at the level reported by the failed
				 * command. Retry if the target is below it; otherwise
				 * descend into it.
				 */
				if (level < map_level)
					goto retry_chunk;
				if (map_level < KVM_PGTABLE_LAST_LEVEL) {
					map_level++;
					goto retry_lower_level;
				}
				return -ENXIO;
			}

			/* Propagate a conflicting or malformed RTTE. */
			if (state < 0)
				return state;

			if (level < map_level) {
				/* The walk stopped above the target; create its RTTs. */
				ret = realm_create_rtt_levels(realm, ipa,
							      level, map_level,
							      memcache);
				if (ret)
					return ret;
				continue;
			}

			if (level == map_level &&
			    map_level < KVM_PGTABLE_LAST_LEVEL) {
				/* Retry an unassigned target at a finer level. */
				map_level++;
				goto retry_lower_level;
			}

			if (chunk_size > block_size) {
				/* Retry the first entry of the failing counted range. */
				chunk_size = block_size;
				goto retry_chunk;
			}

			if (WARN_ON_ONCE(1))
				return -ENXIO;
		}

		/* Let the caller classify concurrent mapping failures. */
		if (ret)
			return ret;

		if (WARN_ON(out_top <= ipa || out_top > ipa + chunk_size ||
			    !IS_ALIGNED(out_top - ipa, block_size)))
			return -ENXIO;

		phys += out_top - ipa;
		ipa = out_top;
	}

	return 0;
}

static int __realm_map_protected(struct kvm *kvm, unsigned long ipa,
				 kvm_pfn_t pfn, unsigned long map_size,
				 struct kvm_mmu_memory_cache *memcache,
				 bool allow_fault_fallback)
{
	struct realm *realm = &kvm->arch.realm;
	phys_addr_t phys = __pfn_to_phys(pfn);
	unsigned long ipa_top = ipa + map_size;
	unsigned long cur_ipa = ipa;
	int ret;

	lockdep_assert_held(&kvm->mmu_lock);

	if (WARN_ON(!IS_ALIGNED(map_size | ipa, PAGE_SIZE)))
		return -EINVAL;

	/*
	 * Delegate and map one contiguous run at a time. A run can include
	 * granules already delegated by another fault. The IPA->PA mapping is
	 * linear, so each run's backing PA is @phys offset by (run.ipa - @ipa).
	 */
	while (cur_ipa < ipa_top) {
		struct realm_map_run run;

		ret = realm_prepare_protected_map(realm, cur_ipa,
						  phys + (cur_ipa - ipa),
						  ipa_top,
						  allow_fault_fallback, &run);
		if (ret)
			return ret;

		/* No more memory needs mapping (remainder already mapped). */
		if (run.top <= run.ipa)
			break;

		ret = realm_map_delegated_range(realm, &run, memcache);
		if (ret)
			return ret;

		cur_ipa = run.top;
	}

	return 0;
}

int realm_map_protected(struct kvm *kvm, unsigned long ipa, kvm_pfn_t pfn,
			unsigned long map_size,
			struct kvm_mmu_memory_cache *memcache)
{
	bool allow_fault_fallback;

	allow_fault_fallback = (map_size == PUD_SIZE ||
				map_size == PMD_SIZE) &&
			       IS_ALIGNED(ipa | __pfn_to_phys(pfn), map_size);

	return __realm_map_protected(kvm, ipa, pfn, map_size, memcache,
				     allow_fault_fallback);
}

enum realm_map_recovery {
	REALM_MAP_RECOVER_RETRY,
	REALM_MAP_RECOVER_FAIL,
	REALM_MAP_RECOVER_REFAULT,
};

struct realm_map_request {
	struct kvm *kvm;
	unsigned long ipa;
	kvm_pfn_t pfn;
	unsigned long size;
	struct kvm_mmu_memory_cache *memcache;
};

static int realm_recover_protected_map(const struct realm_map_request *req,
				       int map_ret, enum realm_map_recovery recovery)
{
	struct kvm *kvm = req->kvm;
	struct realm *realm = &kvm->arch.realm;
	phys_addr_t start_phys = __pfn_to_phys(req->pfn);
	phys_addr_t phys = start_phys;
	phys_addr_t rd = virt_to_phys(realm->rd);
	unsigned long start_ipa = req->ipa;
	unsigned long end_ipa = start_ipa + req->size;
	unsigned long ipa = start_ipa;
	bool has_unmapped = false;
	int ret;

	lockdep_assert_held_write(&kvm->mmu_lock);

	while (ipa < end_ipa) {
		unsigned long next_ipa;
		int map_level;
		int entry_state;

		map_level = find_aligned_map_level(realm, ipa, phys, end_ipa);
retry:
		entry_state = realm_check_protected_mapping(rd, ipa, phys,
							    map_level, end_ipa,
							    &next_ipa);
		if (entry_state > 0) {
			phys += next_ipa - ipa;
			ipa = next_ipa;
			continue;
		}

		if (entry_state == -EBUSY)
			return -EAGAIN;

		if (entry_state == -EAGAIN) {
			if (map_level >= KVM_PGTABLE_LAST_LEVEL)
				return -ENXIO;
			map_level++;
			goto retry;
		}

		if (entry_state < 0) {
			pr_warn_ratelimited("RMI: DATA_MAP recovery failed ret=%d status=%ld err=%d\n",
					    map_ret,
					    map_ret >= 0 ?
					    (long)RMI_RETURN_STATUS(map_ret) : -1L,
					    entry_state);
			return entry_state;
		}

		/* No RTTE maps this part of the failed range. */
		if (recovery != REALM_MAP_RECOVER_RETRY) {
			ret = realm_undelegate_map_range(phys, next_ipa - ipa);
			if (ret) {
				pr_warn_ratelimited("RMI: DATA_MAP cleanup failed ret=%d status=%ld err=%d\n",
						    map_ret,
						    map_ret >= 0 ?
						    (long)RMI_RETURN_STATUS(map_ret) : -1L,
						    ret);
				return ret;
			}
		}

		has_unmapped = true;
		phys += next_ipa - ipa;
		ipa = next_ipa;
	}

	if (!has_unmapped)
		return 0;

	/*
	 * Another fault can complete part of the range between delegation and
	 * DATA_MAP. Linux may also have converted the resulting RMI failure to
	 * -ENXIO before reaching this recovery path. Retry the complete
	 * delegate+map sequence once while the write lock excludes all other fault
	 * handlers. Leave delegated, unassigned granules in place for the retry;
	 * clean them up only if the serialized attempt also fails.
	 */
	if ((recovery == REALM_MAP_RECOVER_RETRY) &&
	    ((map_ret == -ENXIO) || (map_ret == -EAGAIN) ||
	     ((map_ret >= 0) &&
	      (RMI_RETURN_STATUS(map_ret) == RMI_ERROR_INPUT)))) {
		ret = __realm_map_protected(kvm, start_ipa, req->pfn, req->size,
					    req->memcache, false);
		if (!ret)
			return 0;

		return realm_recover_protected_map(req, ret,
						   REALM_MAP_RECOVER_FAIL);
	}

	/* Clean up an unassigned tail before propagating a terminal failure. */
	if (recovery == REALM_MAP_RECOVER_RETRY)
		return realm_recover_protected_map(req, map_ret,
						   REALM_MAP_RECOVER_FAIL);

	if (recovery == REALM_MAP_RECOVER_REFAULT)
		return 0;

	if (map_ret >= 0) {
		pr_warn_ratelimited("RMI: DATA_MAP failed ipa=%#lx phys=%pa size=%#lx ret=%#x status=%u\n",
				    start_ipa, &start_phys, req->size,
				    (unsigned int)map_ret,
				    (unsigned int)RMI_RETURN_STATUS(map_ret));
		return -ENXIO;
	}

	pr_warn_ratelimited("RMI: DATA_MAP failed ipa=%#lx phys=%pa size=%#lx err=%d\n",
			    start_ipa, &start_phys, req->size, map_ret);
	return map_ret;
}

int realm_recover_protected(struct kvm *kvm, unsigned long ipa,
			    kvm_pfn_t pfn, unsigned long map_size,
			    int map_ret,
			    struct kvm_mmu_memory_cache *memcache,
			    bool mmu_invalidated)
{
	const struct realm_map_request req = {
		.kvm = kvm,
		.ipa = ipa,
		.pfn = pfn,
		.size = map_size,
		.memcache = memcache,
	};
	enum realm_map_recovery recovery;

	recovery = mmu_invalidated ? REALM_MAP_RECOVER_REFAULT :
					   REALM_MAP_RECOVER_RETRY;

	return realm_recover_protected_map(&req, map_ret, recovery);
}

int realm_map_non_secure(struct kvm *kvm,
			 unsigned long ipa,
			 kvm_pfn_t pfn,
			 unsigned long size,
			 enum kvm_pgtable_prot prot,
			 struct kvm_mmu_memory_cache *memcache)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long attr, flags = 0;
	phys_addr_t rd = virt_to_phys(realm->rd);
	phys_addr_t phys = __pfn_to_phys(pfn);
	unsigned long ipa_top = ipa + size;
	unsigned long block_size;
	unsigned long chunk_size;
	unsigned long range_desc;
	unsigned long out_top;
	int map_level;
	int ret;

	lockdep_assert_held(&kvm->mmu_lock);

	if (WARN_ON(!IS_ALIGNED(size | ipa, PAGE_SIZE)))
		return -EINVAL;

	switch (prot & (KVM_PGTABLE_PROT_DEVICE | KVM_PGTABLE_PROT_NORMAL_NC)) {
	case KVM_PGTABLE_PROT_DEVICE | KVM_PGTABLE_PROT_NORMAL_NC:
		return -EINVAL;
	case KVM_PGTABLE_PROT_DEVICE:
		attr = MT_S2_FWB_DEVICE_nGnRE;
		break;
	case KVM_PGTABLE_PROT_NORMAL_NC:
		attr = MT_S2_FWB_NORMAL_NC;
		break;
	default:
		attr = MT_S2_FWB_NORMAL;
	}

	flags |= FIELD_PREP(RMI_RTT_UNPROT_MAP_FLAGS_MEMATTR_MASK, attr);
	if ((prot & (KVM_PGTABLE_PROT_R | KVM_PGTABLE_PROT_W)) ==
	    (KVM_PGTABLE_PROT_R | KVM_PGTABLE_PROT_W))
		flags |= FIELD_PREP(RMI_RTT_UNPROT_MAP_FLAGS_S2AP_MASK,
				    RMI_S2AP_RW);
	else if (prot & KVM_PGTABLE_PROT_R)
		flags |= FIELD_PREP(RMI_RTT_UNPROT_MAP_FLAGS_S2AP_MASK,
				    RMI_S2AP_RO);
	else if (prot & KVM_PGTABLE_PROT_W)
		flags |= FIELD_PREP(RMI_RTT_UNPROT_MAP_FLAGS_S2AP_MASK,
				    RMI_S2AP_WO);

	flags |= RMI_ADDR_TYPE_SINGLE;

	while (ipa < ipa_top) {
		map_level = find_aligned_map_level(realm, ipa, phys, ipa_top);

retry_lower_level:
		block_size = rmi_rtt_level_mapsize(map_level);
		chunk_size = desc_range_size(block_size, ipa_top - ipa);

retry_chunk:
		range_desc = addr_range_desc(phys, map_level, chunk_size,
					    RMI_OP_MEM_UNDELEGATED);

		ret = rmi_rtt_unprot_map(rd, ipa, ipa + chunk_size,
					 flags, range_desc,
					 &out_top);
		if ((ret >= 0) &&
		    (RMI_RETURN_STATUS(ret) == RMI_BLOCKED))
			return -EAGAIN;

		if ((ret >= 0) &&
		    (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT)) {
			unsigned long next_ipa;
			int level = RMI_RETURN_INDEX(ret);
			int state;

			if (WARN_ON(level > KVM_PGTABLE_LAST_LEVEL))
				return -ENXIO;

			/*
			 * RMI_ERROR_RTT also reports an incompatible mapping. Read
			 * the entry before assuming that an RTT is missing.
			 */
			state = realm_check_unprotected_mapping(rd, ipa, phys, level,
								      ipa_top, attr,
								      &next_ipa);
			if (state > 0) {
				phys += next_ipa - ipa;
				ipa = next_ipa;
				continue;
			}

			/* Retry the fault after a blocked RTTE read. */
			if (state == -EBUSY)
				return -EAGAIN;

			if (state == -EAGAIN) {
				/*
				 * A table appeared at the level reported by the failed
				 * command. Retry if the target is below it; otherwise
				 * descend into it.
				 */
				if (level < map_level)
					goto retry_chunk;
				if (map_level < KVM_PGTABLE_LAST_LEVEL) {
					map_level++;
					goto retry_lower_level;
				}
				return -ENXIO;
			}

			/* Propagate a conflicting or malformed RTTE. */
			if (state < 0)
				return state;

			if (level < map_level) {
				/* The walk stopped above the target; create its RTTs. */
				ret = realm_create_rtt_levels(realm, ipa,
							      level, map_level,
							      memcache);
				if (ret)
					return ret;
				continue;
			}

			if (level == map_level &&
			    map_level < KVM_PGTABLE_LAST_LEVEL) {
				/* Retry an unassigned target at a finer level. */
				map_level++;
				goto retry_lower_level;
			}

			if (chunk_size > block_size) {
				/* Retry the first entry of the failing counted range. */
				chunk_size = block_size;
				goto retry_chunk;
			}

			if (WARN_ON_ONCE(1))
				return -ENXIO;
		}

		if (WARN_ON(ret))
			return ret < 0 ? ret : -ENXIO;

		if (WARN_ON(out_top <= ipa || out_top > ipa + chunk_size ||
			    !IS_ALIGNED(out_top - ipa, block_size)))
			return -ENXIO;

		phys += out_top - ipa;
		ipa = out_top;
	}

	return 0;
}

static int populate_region_cb(struct kvm *kvm, gfn_t gfn, kvm_pfn_t pfn,
			      struct page *src_page, void *opaque)
{
	unsigned long *data_flags = opaque;
	unsigned long delegated_size = 0;
	phys_addr_t phys = __pfn_to_phys(pfn);
	phys_addr_t ipa = gfn_to_gpa(gfn);
	int ret;

	if (!src_page)
		return -EOPNOTSUPP;

	/*
	 * kvm_gmem_populate() protects only the folio containing this page for
	 * the duration of this callback. Do not leave later folio pages
	 * delegated across callbacks, as a concurrent hole punch may remove
	 * those pages before their DATA_INIT mappings are installed.
	 */
	ret = realm_delegate_range(phys, PAGE_SIZE, &delegated_size);
	if (ret) {
		if (delegated_size)
			realm_undelegate_map_range(phys, delegated_size);
		return ret > 0 ? -ENXIO : ret;
	}

	if (WARN_ON(delegated_size != PAGE_SIZE)) {
		realm_undelegate_map_range(phys, delegated_size);
		return -ENXIO;
	}

	ret = realm_data_map_init(kvm, ipa, pfn, page_to_pfn(src_page),
				  *data_flags);
	if (ret)
		realm_undelegate_map_range(phys, PAGE_SIZE);

	return ret;
}

static long populate_region(struct kvm *kvm,
			    gfn_t base_gfn,
			    unsigned long pages,
			    u64 uaddr,
			    unsigned long data_flags)
{
	long ret = 0;

	lockdep_assert_held(&kvm->slots_lock);
	lockdep_assert_held(&kvm->arch.config_lock);

	if (!pages)
		return -EINVAL;

	ret = kvm_gmem_populate(kvm, base_gfn, u64_to_user_ptr(uaddr),
				pages, false, populate_region_cb, &data_flags);

	return ret;
}

enum ripas_action {
	RIPAS_INIT,
	RIPAS_SET,
};

static int ripas_change(struct kvm *kvm,
			struct kvm_vcpu *vcpu,
			unsigned long ipa,
			unsigned long end,
			enum ripas_action action,
			unsigned long *top_ipa)
{
	struct realm *realm = &kvm->arch.realm;
	phys_addr_t rd_phys = virt_to_phys(realm->rd);
	phys_addr_t rec_phys;
	struct kvm_mmu_memory_cache *memcache = NULL;
	int ret = 0;

	if (vcpu) {
		rec_phys = virt_to_phys(vcpu->arch.rec.rec_page);
		memcache = &vcpu->arch.mmu_page_cache;

		WARN_ON(action != RIPAS_SET);
	} else {
		WARN_ON(action != RIPAS_INIT);
	}

	while (ipa < end) {
		unsigned long next = ~0;

		switch (action) {
		case RIPAS_INIT:
			ret = rmi_rtt_init_ripas(rd_phys, ipa, end, &next);
			break;
		case RIPAS_SET:
			ret = rmi_rtt_set_ripas(rd_phys, rec_phys, ipa, end,
						&next);
			break;
		}

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			if (WARN_ON((next <= ipa) || (next > end))) {
				if (top_ipa)
					*top_ipa = ipa;
				return -ENXIO;
			}
			ipa = next;
			break;
		case RMI_ERROR_RTT: {
			int err_level = RMI_RETURN_INDEX(ret);
			int level = find_map_level(realm, ipa, end);

			/*
			 * DEN0137 v2.0-bet3 reports terminal RIPAS failures, such as
			 * no_progress, as RMI_ERROR_RTT at the current walk level. If
			 * the walk did not stop above @level, no RTT can be created
			 * and retrying would issue the same command forever.
			 */
			if (err_level >= level) {
				if (top_ipa)
					*top_ipa = ipa;
				return -ENXIO;
			}

			ret = realm_create_rtt_levels(realm, ipa, err_level,
						      level, memcache);
			if (ret) {
				/*
				 * Report progress so the caller retries from
				 * @ipa and any EMPTY-RIPAS unmap is bounded to
				 * the range actually changed, rather than
				 * reading an uninitialised top_ipa.
				 */
				if (top_ipa)
					*top_ipa = ipa;
				return ret;
			}
			/* Retry with the RTT levels in place */
			break;
		}
		default:
			WARN_ON(1);
			if (top_ipa)
				*top_ipa = ipa;
			return -ENXIO;
		}
	}

	if (top_ipa)
		*top_ipa = ipa;

	return 0;
}

static int realm_set_ipa_state(struct kvm_vcpu *vcpu,
			       unsigned long start,
			       unsigned long end,
			       unsigned long ripas,
			       unsigned long *top_ipa)
{
	struct kvm *kvm = vcpu->kvm;
	int ret = ripas_change(kvm, vcpu, start, end, RIPAS_SET, top_ipa);

	if (ripas == RMI_EMPTY && *top_ipa != start)
		realm_unmap_private_range(kvm, start, *top_ipa, false);

	return ret;
}

static int realm_init_ipa_state(struct kvm *kvm,
				unsigned long gfn,
				unsigned long pages)
{
	return ripas_change(kvm, NULL, gfn_to_gpa(gfn), gfn_to_gpa(gfn + pages),
			    RIPAS_INIT, NULL);
}

static int realm_ensure_created(struct kvm *kvm)
{
	int ret;

	lockdep_assert_held(&kvm->arch.config_lock);

	switch (kvm_realm_state(kvm)) {
	case REALM_STATE_NONE:
		break;
	case REALM_STATE_NEW:
		return 0;
	case REALM_STATE_DEAD:
		return -ENXIO;
	default:
		return -EBUSY;
	}

	ret = realm_create_rd(kvm);
	return ret;
}

static int set_ripas_of_protected_regions(struct kvm *kvm)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	int idx, bkt;
	int ret = 0;

	lockdep_assert_held(&kvm->arch.config_lock);

	idx = srcu_read_lock(&kvm->srcu);

	slots = kvm_memslots(kvm);
	kvm_for_each_memslot(memslot, bkt, slots) {
		if (!kvm_slot_has_gmem(memslot))
			continue;

		ret = realm_init_ipa_state(kvm, memslot->base_gfn,
					   memslot->npages);
		if (ret)
			break;
	}
	srcu_read_unlock(&kvm->srcu, idx);

	return ret;
}

int kvm_arm_rmi_populate(struct kvm *kvm,
			 struct kvm_arm_rmi_populate *args)
{
	unsigned long data_flags = 0;
	unsigned long ipa_start = args->base;
	unsigned long ipa_end = ipa_start + args->size;
	long pages_populated;
	int ret;

	if (args->reserved ||
	    (args->flags & ~KVM_ARM_RMI_POPULATE_FLAGS_MEASURE) ||
	    !IS_ALIGNED(ipa_start, PAGE_SIZE) ||
	    !IS_ALIGNED(ipa_end, PAGE_SIZE) ||
	    !IS_ALIGNED(args->source_uaddr, PAGE_SIZE))
		return -EINVAL;

	if (args->flags & KVM_ARM_RMI_POPULATE_FLAGS_MEASURE)
		data_flags |= RMI_MEASURE_CONTENT;

	mutex_lock(&kvm->slots_lock);
	mutex_lock(&kvm->arch.config_lock);

	ret = realm_ensure_created(kvm);
	if (ret)
		goto out_unlock;

	pages_populated = populate_region(kvm, gpa_to_gfn(ipa_start),
					  args->size >> PAGE_SHIFT,
					  args->source_uaddr, data_flags);

	if (pages_populated < 0) {
		ret = pages_populated;
		goto out_unlock;
	}

	args->size -= pages_populated << PAGE_SHIFT;
	args->source_uaddr += pages_populated << PAGE_SHIFT;
	args->base += pages_populated << PAGE_SHIFT;

out_unlock:
	mutex_unlock(&kvm->arch.config_lock);
	mutex_unlock(&kvm->slots_lock);
	return ret;
}

static int kvm_complete_ripas_change(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct realm_rec *rec = &vcpu->arch.rec;
	unsigned long base = rec->run->exit.ripas_base;
	unsigned long top = rec->run->exit.ripas_top;
	unsigned long ripas = rec->run->exit.ripas_value;
	unsigned long top_ipa = base;
	int ret;

	do {
		kvm_mmu_topup_memory_cache(&vcpu->arch.mmu_page_cache,
					   kvm_mmu_cache_min_pages(vcpu->arch.hw_mmu));
		write_lock(&kvm->mmu_lock);
		ret = realm_set_ipa_state(vcpu, base, top, ripas, &top_ipa);
		write_unlock(&kvm->mmu_lock);

		if (ret) {
			if (ret != -ENOMEM) {
				WARN_RATELIMIT(1,
					       "Unable to satisfy RIPAS_CHANGE for %#lx - "
					       "%#lx, ripas: %#lx\n",
					       base, top, ripas);
				break;
			}
			/*
			 * Retry -ENOMEM only while the previous attempt made
			 * progress; otherwise leave the pending range for the
			 * next REC_ENTER instead of spinning here.
			 */
			if (top_ipa == base)
				break;
		}

		base = top_ipa;
	} while (base < top);

	/*
	 * If this function is called again before the REC_ENTER call then
	 * avoid calling realm_set_ipa_state() again by changing to the value
	 * of ripas_base for the part that has already been covered. The RMM
	 * ignores the contains of the rec_exit structure so this doesn't
	 * affect the RMM.
	 */
	rec->run->exit.ripas_base = base;

	return 1;
}

static int kvm_rec_complete_psci(struct kvm_vcpu *vcpu)
{
	struct rec_run *run = vcpu->arch.rec.run;
	struct kvm_vcpu *target = NULL;
	unsigned long status;
	unsigned long psci_ret = vcpu_get_reg(vcpu, 0);
	unsigned long rmi_ret;
	bool owner = false;

	switch (run->exit.gprs[0]) {
	/*
	 * DEN0137 v2.0-bet3 only requires RMI_PSCI_COMPLETE after
	 * PSCI_CPU_ON. Other PSCI exits are notifications or RMM-handled
	 * commands; rec_exit_psci() only flags psci_complete_pending for
	 * CPU_ON so this switch can never see anything else.
	 */
	case PSCI_0_2_FN_CPU_ON:
	case PSCI_0_2_FN64_CPU_ON:
		target = kvm_mpidr_to_vcpu(vcpu->kvm, run->exit.gprs[1]);
		status = (psci_ret == PSCI_RET_SUCCESS ||
			  psci_ret == PSCI_RET_ALREADY_ON) ?
				 PSCI_RET_SUCCESS : PSCI_RET_DENIED;
		break;
	default:
		return 0;
	}

	/*
	 * Concurrent CPU_ON requests to the same target all take a PSCI exit
	 * and reach this path, but only the source recorded in psci_on_source
	 * actually reserved the target. A source whose CPU_ON was denied must
	 * not clear the winner's reservation, otherwise a third caller could
	 * overwrite the target's reset state before the winner completes.
	 *
	 * DEN0137 v2.0-bet3 also forbids a DENIED completion once the target
	 * REC is runnable, so a denied source that raced the winner reports
	 * SUCCESS (PSCI ALREADY_ON) instead of DENIED.
	 */
	if (target) {
		spin_lock(&target->arch.mp_state_lock);
		owner = target->arch.rec.psci_on_source == vcpu;
		if (!owner)
			status = kvm_arm_vcpu_stopped(target) ?
					 PSCI_RET_DENIED : PSCI_RET_SUCCESS;
		spin_unlock(&target->arch.mp_state_lock);
	}

	rmi_ret = realm_psci_complete(vcpu, status);
	if (rmi_ret) {
		WARN_RATELIMIT(1,
			       "RMI_PSCI_COMPLETE: vcpu=%u psci=%#lx rmi=%#lx\n",
			       vcpu->vcpu_id, status, rmi_ret);
		/*
		 * KVM_REQ_RMI was already consumed by the caller. Re-arm it so
		 * a later KVM_RUN retries the completion instead of re-entering
		 * the REC with the PSCI request still outstanding.
		 */
		kvm_make_request(KVM_REQ_RMI, vcpu);
		return -EINVAL;
	}

	vcpu->arch.rec.psci_complete_pending = false;

	if (owner) {
		if (status == PSCI_RET_SUCCESS)
			kvm_psci_vcpu_on_complete(target);
		else
			kvm_psci_vcpu_on_abort(target);
	}

	return 0;
}

int kvm_rec_handle_request(struct kvm_vcpu *vcpu)
{
	struct realm_rec *rec = &vcpu->arch.rec;
	u64 esr;

	/*
	 * REC exit state may still describe the previous PSCI exit after a
	 * retryable REC_ENTER failure. Drive RMI_PSCI_COMPLETE from KVM-owned
	 * state so the host completes each PSCI request exactly once.
	 */
	if (rec->psci_complete_pending)
		return kvm_rec_complete_psci(vcpu) ?: 1;

	switch (rec->run->exit.exit_reason) {
	case RMI_EXIT_SYNC:
		esr = rec->run->exit.esr;
		if (ESR_ELx_EC(esr) == ESR_ELx_EC_SYS64 &&
		    (esr & ESR_ELx_SYS64_ISS_DIR_MASK) ==
				ESR_ELx_SYS64_ISS_DIR_READ) {
			int rt = ESR_ELx_SYS64_ISS_RT(esr);

			if (rt < REC_RUN_GPRS)
				rec->run->enter.gprs[rt] =
					vcpu_get_reg(vcpu, rt);
		}
		break;
	case RMI_EXIT_PSCI:
		break;
	case RMI_EXIT_HOST_CALL:
		for (int i = 0; i < REC_RUN_GPRS; i++)
			rec->run->enter.gprs[i] = vcpu_get_reg(vcpu, i);
		break;
	case RMI_EXIT_RIPAS_CHANGE:
		return kvm_complete_ripas_change(vcpu);
	default:
		KVM_BUG(1, vcpu->kvm, "Unhandled realm exit_reason");
		return -ENXIO;
	}

	return 1;
}

int noinstr kvm_rec_enter(struct kvm_vcpu *vcpu)
{
	struct realm_rec *rec = &vcpu->arch.rec;

	return rmi_rec_enter(rec->rec_phys, rec->run_phys);
}

static int kvm_create_rec(struct kvm_vcpu *vcpu)
{
	struct user_pt_regs *vcpu_regs = vcpu_gp_regs(vcpu);
	unsigned long mpidr = kvm_vcpu_get_mpidr_aff(vcpu);
	unsigned long rec_mpidr;
	struct realm *realm = &vcpu->kvm->arch.realm;
	struct realm_rec *rec = &vcpu->arch.rec;
	unsigned long rec_page_phys;
	struct rec_params *params;
	int r, i;

	if (rec->run)
		return -EBUSY;

	/*
	 * The RMM will report PSCI v1.0 to Realms and the KVM_ARM_VCPU_PSCI_0_2
	 * flag covers v0.2 and onwards.
	 */
	if (!vcpu_has_feature(vcpu, KVM_ARM_VCPU_PSCI_0_2))
		return -EINVAL;

	r = kvm_mpidr_to_rmi_rec_mpidr(mpidr, &rec_mpidr);
	if (r)
		return r;

	BUILD_BUG_ON(sizeof(*params) > PAGE_SIZE);
	BUILD_BUG_ON(sizeof(*rec->run) > PAGE_SIZE);

	params = (struct rec_params *)get_zeroed_page(GFP_KERNEL);
	rec->rec_page = (void *)__get_free_page(GFP_KERNEL);
	rec->run = (void *)get_zeroed_page(GFP_KERNEL);
	rec->sro = kmalloc_obj(*rec->sro);
	if (!params || !rec->rec_page || !rec->run || !rec->sro) {
		r = -ENOMEM;
		goto out_free_pages;
	}
	rec->run_phys = virt_to_phys(rec->run);

	for (i = 0; i < ARRAY_SIZE(params->gprs); i++)
		params->gprs[i] = vcpu_regs->regs[i];

	params->pc = vcpu_regs->pc;

	if (vcpu->vcpu_id == 0)
		params->flags |= REC_PARAMS_FLAG_RUNNABLE;

	rec_page_phys = virt_to_phys(rec->rec_page);
	rec->rec_phys = rec_page_phys;

	if (realm_delegate_range(rec_page_phys, PAGE_SIZE, NULL)) {
		r = -ENXIO;
		goto out_free_pages;
	}

	params->mpidr = rec_mpidr;

	if (rmi_rec_create(virt_to_phys(realm->rd), rec_page_phys,
			   virt_to_phys(params), rec->sro)) {
		r = -ENXIO;
		goto out_undelegate_rmm_rec;
	}

	rec->mpidr = mpidr;

	free_page((unsigned long)params);
	return 0;

out_undelegate_rmm_rec:
	if (WARN_ON(realm_undelegate_range(rec_page_phys, PAGE_SIZE, NULL)))
		rec->rec_page = NULL;
out_free_pages:
	free_page((unsigned long)rec->run);
	free_page((unsigned long)rec->rec_page);
	free_page((unsigned long)params);
	kfree(rec->sro);
	rec->run = NULL;
	rec->run_phys = 0;
	rec->rec_page = NULL;
	rec->rec_phys = 0;
	rec->sro = NULL;
	return r;
}

void kvm_destroy_rec(struct kvm_vcpu *vcpu)
{
	struct realm_rec *rec = &vcpu->arch.rec;
	unsigned long rec_page_phys;

	if (!vcpu_is_rec(vcpu))
		return;

	if (!rec->run) {
		/* Nothing to do if the VCPU hasn't been finalized */
		return;
	}

	/*
	 * If a CPU_ON completion was pending on this REC, release the target's
	 * psci_on_pending flag so it isn't wedged in DENIED-for-future-CPU_ON
	 * state after we destroy the source. The RMM has no spec hook to be
	 * told the source died; KVM-owned state is the only thing to unwind.
	 * Must run before rec->run is freed below, since the saved CPU_ON
	 * arguments live in rec->run->exit.gprs[].
	 */
	if (rec->psci_complete_pending) {
		unsigned long fn = rec->run->exit.gprs[0];

		if (fn == PSCI_0_2_FN_CPU_ON || fn == PSCI_0_2_FN64_CPU_ON) {
			struct kvm_vcpu *target =
				kvm_mpidr_to_vcpu(vcpu->kvm,
						  rec->run->exit.gprs[1]);

			if (target)
				kvm_psci_vcpu_on_abort(target);
		}
		rec->psci_complete_pending = false;
	}

	rec_page_phys = virt_to_phys(rec->rec_page);

	if (WARN_ON(rmi_rec_destroy(rec_page_phys, rec->sro)))
		return;

	free_page((unsigned long)rec->run);
	rec->run = NULL;
	rec->run_phys = 0;

	realm_free_delegated_page(rec_page_phys);
	rec->rec_page = NULL;
	rec->rec_phys = 0;

	kfree(rec->sro);
	rec->sro = NULL;
}

int kvm_activate_realm(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	struct kvm_vcpu *vcpu;
	unsigned long i;
	int ret;

	if (kvm_realm_state(kvm) >= REALM_STATE_ACTIVE)
		return 0;

	if (!irqchip_in_kernel(kvm)) {
		/* Userspace irqchip not yet supported with realms */
		return -EOPNOTSUPP;
	}

	guard(mutex)(&kvm->arch.config_lock);
	/* Check again with the lock held */
	if (kvm_realm_state(kvm) >= REALM_STATE_ACTIVE)
		return 0;

	ret = realm_ensure_created(kvm);
	if (ret)
		return ret;

	/* Mark state as dead in case we fail */
	kvm_set_realm_state(kvm, REALM_STATE_DEAD);

	kvm_for_each_vcpu(i, vcpu, kvm) {
		ret = kvm_create_rec(vcpu);
		if (ret)
			return ret;
	}

	ret = set_ripas_of_protected_regions(kvm);
	if (ret)
		return ret;

	ret = rmi_realm_activate(virt_to_phys(realm->rd));
	if (ret)
		return -ENXIO;

	kvm_set_realm_state(kvm, REALM_STATE_ACTIVE);
	return 0;
}

void kvm_destroy_realm(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	size_t pgd_size = kvm_pgtable_stage2_pgd_size(kvm->arch.mmu.vtcr);

	if (!kvm_realm_is_created(kvm)) {
		realm_free_unmap_desc_buf(realm);
		realm_free_sro(realm);
		return;
	}

	kvm_set_realm_state(kvm, REALM_STATE_DYING);

	write_lock(&kvm->mmu_lock);
	kvm_stage2_unmap_range(&kvm->arch.mmu, 0,
			       BIT(realm->ia_bits - 1), true);
	write_unlock(&kvm->mmu_lock);

	if (realm->rd) {
		phys_addr_t rd_phys = virt_to_phys(realm->rd);

		if (WARN_ON(rmi_realm_terminate(rd_phys)))
			return;

		kvm_realm_destroy_rtts(kvm);

		if (WARN_ON(rmi_realm_destroy(rd_phys, realm->sro)))
			return;
		realm_free_delegated_page(rd_phys);
		realm->rd = NULL;
	}

	if (WARN_ON(realm_undelegate_range(kvm->arch.mmu.pgd_phys,
					   pgd_size, NULL)))
		return;

	kvm_set_realm_state(kvm, REALM_STATE_DEAD);

	/* Now that the Realm is destroyed, free the entry level RTTs */
	kvm_free_stage2_pgd(&kvm->arch.mmu);
	realm_free_unmap_desc_buf(realm);
	realm_free_sro(realm);
}

int kvm_init_realm(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	int ret;

	ret = realm_alloc_sro(realm);
	if (ret) {
		realm_free_sro(realm);
		return ret;
	}

	return 0;
}

static int rmm_check_features(void)
{
	if (kvm_lpa2_is_enabled() &&
	    !rmi_has_feature0(RMI_FEATURE_REGISTER_0_LPA2)) {
		kvm_err("RMM doesn't support LPA2");
		return -ENXIO;
	}

	if (!rmi_has_feature1(RMI_FEATURE_REGISTER_1_HASH_SHA_256)) {
		kvm_err("RMM doesn't support SHA-256 realms");
		return -ENXIO;
	}

	return 0;
}

void kvm_init_rmi(void)
{
	/*
	 * TODO: Support Realm guests in nVHE mode, this will require adding
	 * EL2 stub(s) for REC entry and possibly other things.
	 */
	if (!is_kernel_in_hyp_mode())
		return;

	if (!rmi_is_available())
		return;

	if (rmm_check_features())
		return;

	kvm_info("Realm guests supported");
	static_branch_enable(&kvm_rmi_is_available);
}
