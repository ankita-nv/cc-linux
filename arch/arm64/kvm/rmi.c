// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2025 ARM Ltd.
 */

#include <uapi/linux/psci.h>
#include <linux/kvm_host.h>
#include <linux/overflow.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/rmi_cmds.h>
#include <asm/virt.h>

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

	return rmi_undelegate_range(addr, size, NULL);
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
	if (rmi_delegate_page(phys)) {
		free_page((unsigned long)virt);
		return PHYS_ADDR_MAX;
	}

	return phys;
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
	if (free_delegated_page(phys))
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
		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT &&
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
 * Returns 0 on successful fold, a negative value on error, a positive value if
 * we were not able to fold all tables at this level.
 */
static int realm_fold_rtt_level(struct realm *realm, int level,
				unsigned long start, unsigned long end)
{
	int not_folded = 0;
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

		ret = realm_rtt_fold(realm, align_addr, level, &rtt_granule);

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			free_rtt(rtt_granule);
			break;
		case RMI_ERROR_RTT:
			if (level == KVM_PGTABLE_LAST_LEVEL ||
			    RMI_RETURN_INDEX(ret) < level) {
				not_folded++;
				break;
			}
			/* Recurse a level deeper */
			ret = realm_fold_rtt_level(realm,
						   level + 1,
						   addr,
						   next_addr);
			if (ret < 0) {
				return ret;
			} else if (ret == 0) {
				/* Try again at this level */
				next_addr = addr;
			}
			break;
		default:
			WARN_ON(1);
			return -ENXIO;
		}
	}

	return not_folded;
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

	start |= shared_bit;
	end |= shared_bit;

	for (addr = start; addr < end; addr = next_addr) {
		int ret;

retry:
		ret = rmi_rtt_unprot_unmap(rd, addr, end,
					   RMI_ADDR_TYPE_SINGLE, 0,
					   &next_addr, NULL, NULL);
		if (WARN_ON(ret < 0))
			return;
		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			/*
			 * @next_addr is RMM's out_top: the IPA up to
			 * which the architecture unmapped (page or
			 * block, picked by RMM transparently per
			 * DEN0137 v2.0-bet3 §B4.5.70). Advance and
			 * continue.
			 */
			if (WARN_ON(next_addr <= addr || next_addr > end))
				return;
			break;
		case RMI_ERROR_RTT: {
			unsigned long map_size;
			int err_level = RMI_RETURN_INDEX(ret);

			/*
			 * RMM walked [addr, end) and did not find a
			 * MAPPED_NS entry, or found a live block larger
			 * than the requested range. Skip a fully covered
			 * missing entry, otherwise split the block and retry.
			 */
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

			ret = realm_create_rtt_levels(realm, addr, err_level,
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

	realm_fold_rtt_level(realm, get_start_level(realm) + 1,
			     start, end);
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
	phys_addr_t rd_phys, params_phys, top_delegated;
	size_t pgd_size = kvm_pgtable_stage2_pgd_size(kvm->arch.mmu.vtcr);
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
	if (rmi_delegate_page(rd_phys)) {
		r = -ENXIO;
		goto free_rd;
	}

	if (rmi_delegate_range(kvm->arch.mmu.pgd_phys, pgd_size,
			       &top_delegated)) {
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
	kvm_set_realm_state(kvm, REALM_STATE_NEW);

	return 0;

out_undelegate_tables:
	if (WARN_ON(rmi_undelegate_range(kvm->arch.mmu.pgd_phys,
					 top_delegated - kvm->arch.mmu.pgd_phys,
					 NULL))) {
		/* Leak the pages if they cannot be returned */
		kvm->arch.mmu.pgt = NULL;
	}
	if (WARN_ON(rmi_undelegate_page(rd_phys))) {
		/* Leak the page if it isn't returned */
		return r;
	}
free_rd:
	free_page((unsigned long)rd);
	return r;
}

static void realm_unmap_private_range(struct kvm *kvm,
				      unsigned long start,
				      unsigned long end,
				      bool may_block)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long rd = virt_to_phys(realm->rd);
	unsigned long next_addr, addr;
	int ret;

	for (addr = start; addr < end; addr = next_addr) {
		unsigned long out_range = 0;
		unsigned long flags = RMI_ADDR_TYPE_SINGLE;
		/* TODO: Optimise using RMI_ADDR_TYPE_LIST */

retry:
		ret = rmi_rtt_data_unmap(rd, addr, end, flags, 0,
					 &next_addr, &out_range, NULL);
		if (WARN_ON(ret < 0))
			return;

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			if (WARN_ON(next_addr <= addr || next_addr > end))
				return;
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

			ret = realm_create_rtt_levels(realm, addr, err_level,
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

	realm_fold_rtt_level(realm, get_start_level(realm) + 1,
			     start, end);
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

	dst_phys = __pfn_to_phys(dst_pfn);
	src_phys = __pfn_to_phys(src_pfn);

	if (rmi_delegate_page(dst_phys))
		return -ENXIO;

	ret = rmi_rtt_data_map_init(rd, dst_phys, ipa, src_phys, flags);
	if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
		/* Create missing RTTs and retry */
		int level = RMI_RETURN_INDEX(ret);

		KVM_BUG_ON(level == KVM_PGTABLE_LAST_LEVEL, kvm);

		ret = realm_create_rtt_levels(realm, ipa, level,
					      KVM_PGTABLE_LAST_LEVEL, NULL);
		if (!ret) {
			ret = rmi_rtt_data_map_init(rd, dst_phys, ipa, src_phys,
						    flags);
		}
	}

	if (ret) {
		if (WARN_ON(rmi_undelegate_page(dst_phys))) {
			/* Undelegate failed, so we leak the page */
			get_page(pfn_to_page(dst_pfn));
		}
	}

	return ret;
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
				  unsigned long size)
{
	return rmi_undelegate_range(phys, size, NULL);
}

static int realm_undelegate_map_range(phys_addr_t phys,
				      unsigned long size)
{
	phys_addr_t addr;
	phys_addr_t end = phys + size;

	if (!size)
		return 0;

	if (WARN_ON(realm_undelegate_range(phys, size))) {
		/* Pages can't be returned to NS world so are lost */
		for (addr = phys; addr < end; addr += PAGE_SIZE)
			get_page(phys_to_page(addr));
		return -ENXIO;
	}

	return 0;
}

/*
 * Check why a protected range delegation failed at @ipa.
 *
 * Returns 1 when an existing matching protected mapping covers @ipa and the
 * caller can retry after @next_ipa, -EAGAIN when a child RTT blocks the
 * current mapping level, 0 when no existing RTTE explains the delegation
 * failure, or a negative errno for an invalid/conflicting RTTE.
 */
static int realm_map_target(unsigned long rd, unsigned long ipa,
			    phys_addr_t phys, int map_level,
			    unsigned long ipa_top, unsigned long *next_ipa)
{
	struct rtt_entry rtte;
	unsigned long map_size;
	phys_addr_t rtte_phys;
	int ret;

	ret = rmi_rtt_read_entry(rd, ipa, map_level, &rtte);
	if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT)
		return 0;
	if (ret)
		return -ENXIO;

	switch (rtte.state) {
	case RMI_UNASSIGNED:
		return 0;
	case RMI_TABLE:
		if (rtte.walk_level == map_level)
			return -EAGAIN;
		return 0;
	case RMI_ASSIGNED:
		break;
	default:
		return -ENXIO;
	}

	map_size = rmi_rtt_level_mapsize(rtte.walk_level);
	rtte_phys = kvm_pte_to_phys(rtte.desc) + (ipa & (map_size - 1));
	if ((rtte.ripas != RMI_RAM) || (rtte_phys != phys))
		return -EFAULT;

	*next_ipa = min(ALIGN_DOWN(ipa, map_size) + map_size, ipa_top);
	return 1;
}

/*
 * Delegate the next contiguous run of backing memory that still needs a
 * protected mapping.
 *
 * Range delegation normally covers the whole target in a single operation, but
 * it can stop early when part of the range was already delegated and mapped by
 * an earlier or concurrent population path. Leading already-mapped granules are
 * skipped, and delegation stops at the first granule that blocks it. The run
 * returned in [*run_ipa, *run_top) was therefore freshly delegated by this call
 * and contains no already-mapped granule, so the caller can map it and, on
 * failure, undelegate exactly the granules that changed ownership without ever
 * touching guest_memfd-backed mappings. The backing PA is the caller's @phys
 * offset by (*run_ipa - @ipa), since the IPA->PA mapping is linear.
 *
 * Returns 0 with *run_top == *run_ipa == ipa_top when nothing remains to map
 * (the rest of the range is already mapped), 0 with a non-empty run to map, or
 * a negative errno. On error this call leaves nothing delegated.
 */
static int realm_prepare_protected_map(struct realm *realm, unsigned long rd,
				       unsigned long ipa, phys_addr_t phys,
				       unsigned long ipa_top,
				       unsigned long *run_ipa,
				       unsigned long *run_top)
{
	unsigned long next_ipa;
	int map_level;
	int ret;

	while (ipa < ipa_top) {
		unsigned long delegated_size = 0;

		ret = realm_delegate_range(phys, ipa_top - ipa,
					   &delegated_size);
		if (delegated_size) {
			/*
			 * Hand back the freshly delegated prefix as the run to
			 * map. Delegation excludes any granule that stopped it,
			 * so the run never contains an already-mapped hole. Any
			 * terminal error is rediscovered on the next call, once
			 * this run has been mapped.
			 */
			*run_ipa = ipa;
			*run_top = ipa + delegated_size;
			return 0;
		}

		if (ret < 0)
			return ret;

		/*
		 * Delegation made no progress: the granule at @ipa is already
		 * delegated or mapped. If it is mapped to the expected PA, skip
		 * it and continue; otherwise it is a genuine conflict.
		 */
		map_level = find_aligned_map_level(realm, ipa, phys, ipa_top);
retry_check:
		ret = realm_map_target(rd, ipa, phys, map_level, ipa_top,
				       &next_ipa);
		if (ret > 0) {
			phys += next_ipa - ipa;
			ipa = next_ipa;
			continue;
		}

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

		return ret < 0 ? ret : -ENXIO;
	}

	/* The whole range is already mapped; nothing left to delegate or map. */
	*run_ipa = ipa_top;
	*run_top = ipa_top;
	return 0;
}

/*
 * Install protected RTT entries for memory that has already been delegated.
 *
 * @mapped_ipa tracks the exclusive end of the successfully mapped prefix so
 * realm_map_protected() can unwind only the portion that changed on failure.
 */
static int realm_map_delegated_range(struct realm *realm, unsigned long rd,
				     unsigned long ipa, phys_addr_t phys,
				     unsigned long ipa_top,
				     struct kvm_mmu_memory_cache *memcache,
				     unsigned long *mapped_ipa)
{
	int map_level;
	int ret = 0;

	*mapped_ipa = ipa;

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
				       range_desc,
				       &out_top);

		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
			/* Create missing RTTs and retry */
			int level = RMI_RETURN_INDEX(ret);

			if (level < map_level) {
				ret = realm_create_rtt_levels(realm, ipa, level,
							      map_level, memcache);
				if (ret)
					return ret;
				continue;
			}

			if (level == map_level &&
			    map_level < KVM_PGTABLE_LAST_LEVEL) {
				map_level++;
				goto retry_lower_level;
			}

			if (chunk_size > block_size) {
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
		*mapped_ipa = ipa;
	}

	return 0;
}

int realm_map_protected(struct kvm *kvm,
			unsigned long ipa,
			kvm_pfn_t pfn,
			unsigned long map_size,
			struct kvm_mmu_memory_cache *memcache)
{
	struct realm *realm = &kvm->arch.realm;
	phys_addr_t phys = __pfn_to_phys(pfn);
	phys_addr_t rd = virt_to_phys(realm->rd);
	unsigned long ipa_top = ipa + map_size;
	unsigned long cur_ipa = ipa;
	int ret;

	if (WARN_ON(!IS_ALIGNED(map_size | ipa, PAGE_SIZE)))
		return -EINVAL;

	/*
	 * Delegate and map one contiguous run at a time. Each run is hole-free
	 * (realm_prepare_protected_map() stops delegation at, and skips, any
	 * already-mapped granule), so on failure the cleanup only ever
	 * undelegates memory this call delegated - never a granule that is
	 * still mapped into guest_memfd. The IPA->PA mapping is linear, so each
	 * run's backing PA is @phys offset by (run_ipa - @ipa).
	 */
	while (cur_ipa < ipa_top) {
		unsigned long run_ipa;
		unsigned long run_top;
		unsigned long mapped_ipa;
		phys_addr_t run_phys;

		ret = realm_prepare_protected_map(realm, rd, cur_ipa,
						  phys + (cur_ipa - ipa),
						  ipa_top, &run_ipa, &run_top);
		if (ret)
			return ret;

		/* No more memory needs mapping (remainder already mapped). */
		if (run_top <= run_ipa)
			break;

		run_phys = phys + (run_ipa - ipa);
		ret = realm_map_delegated_range(realm, rd, run_ipa, run_phys,
						run_top, memcache, &mapped_ipa);
		if (ret) {
			/*
			 * Roll back only this run. The mapped prefix is
			 * unmapped+undelegated; the still-delegated tail
			 * [mapped_ipa, run_top) is undelegated. Earlier runs and
			 * pre-existing mappings are left untouched and are
			 * reclaimed on Realm teardown or reused on refault.
			 */
			if (run_ipa < mapped_ipa)
				realm_unmap_private_range(kvm, run_ipa,
							  mapped_ipa, true);
			if (mapped_ipa < run_top)
				realm_undelegate_map_range(run_phys +
							   (mapped_ipa - run_ipa),
							   run_top - mapped_ipa);
			return ret;
		}

		cur_ipa = run_top;
	}

	return 0;
}

static int realm_map_non_secure(struct kvm *kvm,
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

		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
			/* Create missing RTTs and retry */
			int level = RMI_RETURN_INDEX(ret);

			if (level < map_level) {
				ret = realm_create_rtt_levels(realm, ipa, level,
							      map_level, memcache);
				if (ret)
					return ret;
				continue;
			}

			if (level == map_level &&
			    map_level < KVM_PGTABLE_LAST_LEVEL) {
				map_level++;
				goto retry_lower_level;
			}

			if (chunk_size > block_size) {
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

int realm_map_ipa(struct kvm *kvm, phys_addr_t ipa,
		  kvm_pfn_t pfn, unsigned long map_size,
		  enum kvm_pgtable_prot prot,
		  struct kvm_mmu_memory_cache *memcache)
{
	struct realm *realm = &kvm->arch.realm;

	ipa = ALIGN_DOWN(ipa, map_size);
	trace_kvm_realm_map_ipa(ipa, pfn, map_size, prot,
				kvm_realm_is_private_address(realm, ipa));
	if (!kvm_realm_is_private_address(realm, ipa))
		return realm_map_non_secure(kvm, ipa, pfn, map_size, prot,
					    memcache);

	/* It is impossible to map protected pages read-only. */
	if (WARN_ON(!(prot & KVM_PGTABLE_PROT_W)))
		return -EFAULT;

	return realm_map_protected(kvm, ipa, pfn, map_size, memcache);
}

static int populate_region_cb(struct kvm *kvm, gfn_t gfn, kvm_pfn_t pfn,
			      struct page *src_page, void *opaque)
{
	unsigned long data_flags = *(unsigned long *)opaque;
	phys_addr_t ipa = gfn_to_gpa(gfn);

	if (!src_page)
		return -EOPNOTSUPP;

	return realm_data_map_init(kvm, ipa, pfn, page_to_pfn(src_page),
				   data_flags);
}

static long populate_region(struct kvm *kvm,
			    gfn_t base_gfn,
			    unsigned long pages,
			    u64 uaddr,
			    unsigned long data_flags)
{
	long ret = 0;

	mutex_lock(&kvm->slots_lock);
	ret = kvm_gmem_populate(kvm, base_gfn, u64_to_user_ptr(uaddr), pages,
				false, populate_region_cb, &data_flags);
	mutex_unlock(&kvm->slots_lock);

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

	ret = realm_ensure_created(kvm);
	if (ret)
		return ret;

	if (args->flags & KVM_ARM_RMI_POPULATE_FLAGS_MEASURE)
		data_flags |= RMI_MEASURE_CONTENT;

	pages_populated = populate_region(kvm, gpa_to_gfn(ipa_start),
					  args->size >> PAGE_SHIFT,
					  args->source_uaddr, data_flags);

	if (pages_populated < 0)
		return pages_populated;

	args->size -= pages_populated << PAGE_SHIFT;
	args->source_uaddr += pages_populated << PAGE_SHIFT;
	args->base += pages_populated << PAGE_SHIFT;

	return 0;
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

	if (rmi_delegate_page(rec_page_phys)) {
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
	if (WARN_ON(rmi_undelegate_page(rec_page_phys)))
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

	kfree(rec->sro);
	rec->sro = NULL;

	free_delegated_page(rec_page_phys);
	rec->rec_page = NULL;
	rec->rec_phys = 0;
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
		free_delegated_page(rd_phys);
		realm->rd = NULL;
	}

	if (WARN_ON(rmi_undelegate_range(kvm->arch.mmu.pgd_phys,
					 pgd_size, NULL)))
		return;

	kvm_set_realm_state(kvm, REALM_STATE_DEAD);

	/* Now that the Realm is destroyed, free the entry level RTTs */
	kvm_free_stage2_pgd(&kvm->arch.mmu);
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
