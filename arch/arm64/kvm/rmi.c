// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2026 ARM Ltd.
 */

#include <uapi/linux/psci.h>
#include <linux/kvm_host.h>
#include <linux/overflow.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/rmi_cmds.h>
#include <asm/virt.h>

#include "trace.h"

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

static bool rmi_has_feature(int reg, unsigned long feature)
{
	return !!u64_get_bits(rmi_feat_reg(reg), feature);
}

bool kvm_rmi_supports_sve(void)
{
	return rmi_has_feature(0, RMI_FEATURE_REGISTER_0_SVE);
}

u32 kvm_rmm_ipa_limit(void)
{
	return u64_get_bits(rmi_feat_reg(0), RMI_FEATURE_REGISTER_0_S2SZ);
}

unsigned int kvm_realm_sve_max_vl(void)
{
	return sve_vl_from_vq(u64_get_bits(rmi_feat_reg(0),
					   RMI_FEATURE_REGISTER_0_SVE_VL) + 1);
}

u64 kvm_realm_reset_id_aa64dfr0_el1(const struct kvm_vcpu *vcpu, u64 val)
{
	u32 bps = u64_get_bits(rmi_feat_reg(0), RMI_FEATURE_REGISTER_0_NUM_BPS);
	u32 wps = u64_get_bits(rmi_feat_reg(0), RMI_FEATURE_REGISTER_0_NUM_WPS);
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

int realm_psci_complete(struct kvm_vcpu *source, unsigned long status)
{
	long ret;

	ret = rmi_psci_complete(source->arch.rec.rec_phys, status);
	if (ret)
		return -ENXIO;

	return 0;
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

static long realm_rtt_create(struct realm *realm,
			     unsigned long addr,
			     int level,
			     phys_addr_t phys)
{
	addr = ALIGN_DOWN(addr, rmi_rtt_level_mapsize(level - 1));
	return rmi_rtt_create(virt_to_phys(realm->rd), phys, addr, level);
}

static long realm_rtt_fold(struct realm *realm,
			   unsigned long addr,
			   int level,
			   phys_addr_t *rtt_granule)
{
	unsigned long out_rtt;
	long ret;

	addr = ALIGN_DOWN(addr, rmi_rtt_level_mapsize(level - 1));
	ret = rmi_rtt_fold(virt_to_phys(realm->rd), addr, level, &out_rtt);

	if (rtt_granule)
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
static long realm_rtt_destroy(struct realm *realm, unsigned long addr,
			      int level, phys_addr_t *rtt_granule,
			      unsigned long *next_addr)
{
	unsigned long out_rtt;
	long ret;

	ret = rmi_rtt_destroy(virt_to_phys(realm->rd), addr, level,
			      &out_rtt, next_addr);

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
		long ret;

		if (rtt == PHYS_ADDR_MAX)
			return -ENOMEM;

		ret = realm_rtt_create(realm, ipa, level, rtt);
		if (ret < 0) {
			free_rtt(rtt);
			return ret;
		}

		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT &&
		    RMI_RETURN_INDEX(ret) == level - 1) {
			/* The RTT already exists, continue */
			free_rtt(rtt);
			continue;
		}

		if (ret) {
			WARN(1, "Failed to create RTT at level %d: %ld\n",
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
		long ret;
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
		if (ret < 0)
			return ret;

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
		long ret;
		unsigned long align_addr = ALIGN(addr, map_size);

		next_addr = ALIGN(addr + 1, map_size);

		ret = realm_rtt_fold(realm, align_addr, level, &rtt_granule);
		if (ret < 0)
			return ret;

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

static int realm_destroy_rtts(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned int ia_bits = realm->ia_bits;
	int ret;

	lockdep_assert_held(&kvm->arch.config_lock);

	if (realm->rtts_destroyed)
		return 0;

	ret = realm_tear_down_rtt_range(realm, 0, (1UL << ia_bits));
	if (ret)
		return ret;

	realm->rtts_destroyed = true;
	return 0;
}

static void realm_unmap_stage2(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;

	lockdep_assert_held(&kvm->arch.config_lock);

	if (realm->stage2_unmapped)
		return;

	write_lock(&kvm->mmu_lock);
	kvm_stage2_unmap_range(&kvm->arch.mmu, 0,
			       BIT(realm->ia_bits - 1), true);
	write_unlock(&kvm->mmu_lock);

	realm->stage2_unmapped = true;
}

int kvm_realm_teardown_stage2(struct kvm *kvm)
{
	lockdep_assert_held(&kvm->arch.config_lock);

	realm_unmap_stage2(kvm);
	return realm_destroy_rtts(kvm);
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

	if (start >= end)
		return;

	start += shared_bit;
	end += shared_bit;

	for (addr = start; addr < end; addr = next_addr) {
		long ret;

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
			 * DEN0137 v2.0-bet1 §B4.5.70). Advance and
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
	long ret;

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
	long ret;

	lockdep_assert_held(&kvm->slots_lock);
	lockdep_assert_held(&kvm->arch.config_lock);

	dst_phys = __pfn_to_phys(dst_pfn);
	src_phys = __pfn_to_phys(src_pfn);

	if (rmi_delegate_page(dst_phys))
		return -ENXIO;

retry:
	ret = rmi_rtt_data_map_init(rd, dst_phys, ipa, src_phys, flags);
	if (ret >= 0 && RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
		/* Create missing RTTs and retry */
		int level = RMI_RETURN_INDEX(ret);

		KVM_BUG_ON(level >= KVM_PGTABLE_LAST_LEVEL, kvm);

		ret = realm_create_rtt_levels(realm, ipa, level,
					      level + 1, NULL);
		if (!ret)
			goto retry;
	}

	if (ret && WARN_ON(rmi_undelegate_page(dst_phys))) {
		/* Leak the page if the undelegate fails */
		get_page(pfn_to_page(dst_pfn));
	}

	return ret <= 0 ? ret : -ENXIO;
}

static unsigned long addr_range_desc(unsigned long phys, unsigned long size)
{
	unsigned long count = MIN(size >> PAGE_SHIFT,
				  FIELD_MAX(RMI_ADDR_RANGE_COUNT_MASK));

	WARN_ON(phys & ~PAGE_MASK);

	return RMI_ADDR_RANGE_DESC(phys, count);
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

static int realm_map_protected(struct kvm *kvm,
			       unsigned long ipa,
			       kvm_pfn_t pfn,
			       unsigned long map_size,
			       struct kvm_mmu_memory_cache *memcache)
{
	struct realm *realm = &kvm->arch.realm;
	phys_addr_t base_phys = __pfn_to_phys(pfn);
	phys_addr_t phys = base_phys;
	phys_addr_t rd = virt_to_phys(realm->rd);
	unsigned long start_ipa = ipa;
	unsigned long base_ipa = ipa;
	unsigned long ipa_top = ipa + map_size;
	unsigned long delegate_ipa = ipa;
	phys_addr_t delegate_phys = phys;
	unsigned long delegated_size;
	unsigned long next_ipa;
	int map_level;
	int ret = 0;

	if (WARN_ON(!IS_ALIGNED(map_size, PAGE_SIZE) ||
		    !IS_ALIGNED(ipa, map_size)))
		return -EINVAL;

retry_delegate:
	delegated_size = 0;
	ret = realm_delegate_range(delegate_phys,
				   ipa_top - delegate_ipa, &delegated_size);
	delegate_ipa += delegated_size;
	delegate_phys += delegated_size;
	if (!ret || delegate_ipa == ipa_top)
		goto map_delegated;

	if (ret < 0)
		return ret;

	map_level = find_map_level(realm, delegate_ipa, ipa_top);
retry_check:
	ret = realm_map_target(rd, delegate_ipa, delegate_phys,
			       map_level, ipa_top, &next_ipa);
	if (ret > 0) {
		/*
		 * The delegate range stopped on an already mapped granule.
		 * Skip the matching RTTE and continue delegating the remaining
		 * suffix.
		 */
		if (base_ipa == delegate_ipa)
			base_ipa = next_ipa;
		delegate_phys += next_ipa - delegate_ipa;
		delegate_ipa = next_ipa;
		if (delegate_ipa == ipa_top)
			goto map_delegated;
		goto retry_delegate;
	}

	if (ret == -EAGAIN) {
		/*
		 * A child RTT exists at this level; inspect one level down to
		 * find the mapped target that blocked delegation.
		 */
		if (map_level >= KVM_PGTABLE_LAST_LEVEL)
			goto err_undelegate;
		map_level++;
		goto retry_check;
	}

	goto err_undelegate;

map_delegated:
	ipa = base_ipa;
	phys = base_phys + (ipa - start_ipa);

	while (ipa < ipa_top) {
		unsigned long top = ipa_top;
		unsigned long flags = RMI_ADDR_TYPE_SINGLE;
		unsigned long range_desc;
		unsigned long out_top;

retry_map:
		range_desc = addr_range_desc(phys, top - ipa);
		ret = rmi_rtt_data_map(rd, ipa, top, flags, range_desc,
				       &out_top);
		if (ret < 0)
			goto err_undelegate;

		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
			/* Create missing RTTs and retry */
			int map_level = find_map_level(realm, ipa, top);
			int level = RMI_RETURN_INDEX(ret);

			ret = realm_map_target(rd, ipa, phys, map_level,
					       top, &next_ipa);
			if (ret > 0) {
				/*
				 * This target was already mapped before the
				 * range delegate pass. Skip it and continue with
				 * the next unmapped target.
				 */
				base_ipa = next_ipa;
				phys += next_ipa - ipa;
				ipa = next_ipa;
				continue;
			}

			if (ret == -EAGAIN) {
				if (top - ipa <= PAGE_SIZE)
					goto err_unmap;
				top = ipa + PAGE_SIZE;
				goto retry_map;
			}

			if (ret < 0)
				goto err_unmap;

			if (WARN_ON(level >= map_level))
				goto err_unmap;

			ret = realm_create_rtt_levels(realm, ipa, level,
						      map_level, memcache);
			if (ret)
				goto err_unmap;
			continue;
		}

		if (WARN_ON(ret))
			goto err_unmap;

		if (WARN_ON(out_top <= ipa || out_top > top))
			goto err_unmap;

		phys += out_top - ipa;
		ipa = out_top;
	}

	return 0;

err_undelegate:
	if (delegate_ipa > base_ipa)
		realm_undelegate_map_range(base_phys + (base_ipa - start_ipa),
					   delegate_ipa - base_ipa);
	return ret < 0 ? ret : -ENXIO;

err_unmap:
	if (base_ipa < ipa)
		realm_unmap_private_range(kvm, base_ipa, ipa, true);
	if (ipa < ipa_top)
		realm_undelegate_map_range(phys,
					   ipa_top - ipa);
	return -ENXIO;
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
	long ret;

	if (WARN_ON(!IS_ALIGNED(size, PAGE_SIZE)))
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
		unsigned long range_desc = addr_range_desc(phys, ipa_top - ipa);
		unsigned long out_top;

		ret = rmi_rtt_unprot_map(rd, ipa, ipa_top, flags, range_desc,
					 &out_top);
		if (ret < 0)
			return ret;

		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
			/* Create missing RTTs and retry */
			int level = RMI_RETURN_INDEX(ret);
			int req_level = find_map_level(realm, ipa, ipa_top);

			/*
			 * There already exists a mapping at the level. May be
			 * we are relaxing a permission for the given range ?
			 */
			if (level >= req_level) {
				realm_unmap_shared_range(kvm, ipa, ipa_top, true);
				continue;
			}
			ret = realm_create_rtt_levels(realm, ipa, level,
						      req_level,
						      memcache);
			if (ret)
				return ret;
			continue;
		}

		if (ret)
			return ret;

		if (WARN_ON(out_top <= ipa || out_top > ipa_top))
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
	if (!kvm_realm_is_private_address(realm, ipa)) {
		return realm_map_non_secure(kvm, ipa, pfn, map_size, prot,
					    memcache);
	}

	/* It's impossible to map protected pages read-only. */
	if (WARN_ON(!(prot & KVM_PGTABLE_PROT_W)))
		return -EFAULT;
	return realm_map_protected(kvm, ipa, pfn, map_size, memcache);
}

static int populate_region_cb(struct kvm *kvm, gfn_t gfn, kvm_pfn_t pfn,
			      struct page *src_page, void *opaque)
{
	unsigned long data_flags = *(unsigned long *)opaque;
	phys_addr_t ipa = gfn_to_gpa(gfn);

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

	lockdep_assert_held(&kvm->slots_lock);
	lockdep_assert_held(&kvm->arch.config_lock);

	if (!uaddr)
		return -EINVAL;

	ret = kvm_gmem_populate(kvm, base_gfn, u64_to_user_ptr(uaddr), pages,
				false, populate_region_cb, &data_flags);

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
	long ret = 0;

	if (vcpu) {
		rec_phys = vcpu->arch.rec.rec_phys;
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

		if (ret < 0)
			goto out;

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
			ret = -ENXIO;
			goto out;
		}
	}

out:
	if (top_ipa)
		*top_ipa = ipa;

	return ret;
}

static int realm_set_ipa_state(struct kvm_vcpu *vcpu,
			       unsigned long start,
			       unsigned long end,
			       unsigned long ripas,
			       unsigned long *top_ipa)
{
	struct kvm *kvm = vcpu->kvm;
	int ret = ripas_change(kvm, vcpu, start, end, RIPAS_SET, top_ipa);

	if (!ret && ripas == RMI_EMPTY && *top_ipa != start)
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

	return realm_create_rd(kvm);
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
	    args->base + args->size < args->base ||
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

	if (args->size == 0)
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
		if (ret == -ENOMEM) {
			/* If no progress, then stop */
			if (top_ipa == base)
				break;
			base = top_ipa;
			continue;
		}

		if (WARN_RATELIMIT(ret,
				   "Unable to satisfy RIPAS_CHANGE for %#lx - %#lx, ripas: %#lx\n",
				   base, top, ripas))
			break;

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
	 * commands; rec_exit_hvc() only flags psci_complete_pending for
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
	case RMI_EXIT_RIPAS_CHANGE:
		return kvm_complete_ripas_change(vcpu);
	case RMI_EXIT_HOST_CALL:
		for (int i = 0; i < REC_RUN_GPRS; i++)
			rec->run->enter.gprs[i] = vcpu_get_reg(vcpu, i);
		break;
	default:
		KVM_BUG(1, vcpu->kvm, "Unhandled realm exit_reason");
		return -ENXIO;
	}

	return 1;
}

static void noinstr load_realm_timer_state(struct kvm_vcpu *vcpu)
{
	struct rec_exit *rec_exit = &vcpu->arch.rec.run->exit;

	/*
	 * The RMM reports the EL1 timer state on every REC exit. Install that
	 * state before returning to the generic KVM run loop, which expects
	 * the loaded vCPU's timers to be live.
	 */
	write_sysreg_el0(rec_exit->cntv_cval, SYS_CNTV_CVAL);
	write_sysreg_el0(rec_exit->cntp_cval, SYS_CNTP_CVAL);
	isb();

	write_sysreg_el0(rec_exit->cntv_ctl, SYS_CNTV_CTL);
	write_sysreg_el0(rec_exit->cntp_ctl, SYS_CNTP_CTL);
}

int noinstr kvm_rec_enter(struct kvm_vcpu *vcpu)
{
	struct realm_rec *rec = &vcpu->arch.rec;
	int ret;

	ret = rmi_rec_enter(rec->rec_phys, rec->run_phys);
	if (!ret)
		load_realm_timer_state(vcpu);

	return ret;
}

static int kvm_create_rec(struct kvm_vcpu *vcpu)
{
	struct user_pt_regs *vcpu_regs = vcpu_gp_regs(vcpu);
	unsigned long mpidr = kvm_vcpu_get_mpidr_aff(vcpu);
	unsigned long rec_mpidr;
	struct realm *realm = &vcpu->kvm->arch.realm;
	struct realm_rec *rec = &vcpu->arch.rec;
	struct rec_params *params;
	long rmi_ret;
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
	rec->run = (struct rec_run *)get_zeroed_page(GFP_KERNEL);
	rec->sro = kmalloc_obj(*rec->sro);
	if (!params || !rec->rec_page || !rec->run || !rec->sro) {
		r = -ENOMEM;
		goto out_free_pages;
	}

	for (i = 0; i < ARRAY_SIZE(params->gprs); i++)
		params->gprs[i] = vcpu_regs->regs[i];

	params->pc = vcpu_regs->pc;

	if (vcpu->vcpu_id == 0)
		params->flags |= REC_PARAMS_FLAG_RUNNABLE;

	rec->rec_phys = virt_to_phys(rec->rec_page);
	rec->run_phys = virt_to_phys(rec->run);

	if (rmi_delegate_page(rec->rec_phys)) {
		r = -ENXIO;
		goto out_free_pages;
	}

	params->mpidr = rec_mpidr;

	rmi_ret = rmi_rec_create(virt_to_phys(realm->rd), rec->rec_phys,
				 virt_to_phys(params), rec->sro);
	if (rmi_ret) {
		r = rmi_ret < 0 ? rmi_ret : -ENXIO;
		goto out_undelegate_rmm_rec;
	}

	rec->mpidr = mpidr;

	free_page((unsigned long)params);
	return 0;

out_undelegate_rmm_rec:
	if (WARN_ON(rmi_undelegate_page(rec->rec_phys)))
		rec->rec_page = NULL;
out_free_pages:
	free_page((unsigned long)rec->run);
	free_page((unsigned long)rec->rec_page);
	free_page((unsigned long)params);
	kfree(rec->sro);
	rec->run = NULL;
	rec->rec_page = NULL;
	rec->rec_phys = 0;
	rec->run_phys = 0;
	rec->sro = NULL;
	return r;
}

void kvm_destroy_rec(struct kvm_vcpu *vcpu)
{
	struct realm_rec *rec = &vcpu->arch.rec;

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
	if (WARN_ON(rmi_rec_destroy(rec->rec_phys, rec->sro)))
		return;

	free_page((unsigned long)rec->run);
	kfree(rec->sro);
	free_delegated_page(rec->rec_phys);
	rec->run = NULL;
	rec->sro = NULL;
	rec->rec_page = NULL;
	rec->rec_phys = 0;
	rec->run_phys = 0;
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

	guard(mutex)(&kvm->arch.config_lock);

	if (!kvm_realm_is_created(kvm)) {
		kfree(realm->sro);
		realm->sro = NULL;
		return;
	}

	kvm_set_realm_state(kvm, REALM_STATE_DYING);

	/*
	 * REALM_DESTROY requires the realm to be non-live: all RECs must have
	 * been destroyed and the root RTTs must be empty. Unmap the IPA space
	 * and destroy any non-root RTTs before tearing down the RD. The root
	 * RTT pages are still owned by the RMM at this point, so keep the KVM
	 * pgtable alive until after REALM_DESTROY and undelegation.
	 */
	realm_unmap_stage2(kvm);

	if (realm->rd) {
		phys_addr_t rd_phys = virt_to_phys(realm->rd);

		if (WARN_ON(rmi_realm_terminate(rd_phys, realm->sro)))
			return;

		if (WARN_ON(realm_destroy_rtts(kvm)))
			return;

		if (WARN_ON(rmi_realm_destroy(rd_phys, realm->sro)))
			return;
		free_delegated_page(rd_phys);
		realm->rd = NULL;
	}

	if (WARN_ON(rmi_undelegate_range(kvm->arch.mmu.pgd_phys,
					 pgd_size, NULL)))
		return;

	kvm_set_realm_state(kvm, REALM_STATE_DEAD);

	/* Now that the realm is destroyed, free the entry-level RTTs. */
	kvm_free_stage2_pgd(&kvm->arch.mmu);

	kfree(realm->sro);
	realm->sro = NULL;
}

int kvm_init_realm(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;

	realm->sro = kmalloc_obj(*realm->sro);
	if (!realm->sro)
		return -ENOMEM;

	return 0;
}

static int rmm_check_features(void)
{
	if (kvm_lpa2_is_enabled() &&
	    !rmi_has_feature(0, RMI_FEATURE_REGISTER_0_LPA2)) {
		kvm_err("RMM doesn't support LPA2\n");
		return -ENXIO;
	}

	if (!rmi_has_feature(1, RMI_FEATURE_REGISTER_1_HASH_SHA_256)) {
		kvm_err("RMM doesn't support SHA-256 measurements\n");
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

	if (!is_rmi_available())
		return;

	if (rmm_check_features())
		return;

	kvm_info("Realm guests supported\n");
	static_branch_enable(&kvm_rmi_is_available);
}
