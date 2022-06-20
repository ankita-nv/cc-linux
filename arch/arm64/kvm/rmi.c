// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2026 ARM Ltd.
 */

#include <linux/kvm_host.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
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

static bool rmi_has_feature(int reg, unsigned long feature)
{
	return !!u64_get_bits(rmi_feat_reg(reg), feature);
}

u32 kvm_rmm_ipa_limit(void)
{
	return u64_get_bits(rmi_feat_reg(0), RMI_FEATURE_REGISTER_0_S2SZ);
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

static unsigned long rmi_range_entry_size(int rmi_size)
{
	if (WARN_ON(rmi_size > KVM_PGTABLE_LAST_LEVEL))
		return 0;

	return kvm_granule_size(KVM_PGTABLE_LAST_LEVEL - rmi_size);
}

static int undelegate_range_desc(unsigned long desc)
{
	unsigned long size = rmi_range_entry_size(RMI_ADDR_RANGE_SIZE(desc));
	unsigned long count = RMI_ADDR_RANGE_COUNT(desc);
	unsigned long addr = RMI_ADDR_RANGE_ADDR(desc);
	unsigned long state = RMI_ADDR_RANGE_STATE(desc);

	if (state == RMI_OP_MEM_UNDELEGATED)
		return 0;

	if (size * count == 0)
		return 0;

	return rmi_undelegate_range(addr, size * count);
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

		ret = rmi_rtt_unprot_unmap(rd, addr, end, RMI_ADDR_TYPE_NONE,
					   0, &next_addr, NULL, NULL);
		if (WARN_ON(ret < 0))
			return;

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			break;
		case RMI_ERROR_RTT: {
			int err_level = RMI_RETURN_INDEX(ret);
			int level = find_map_level(realm, addr, end);

			if (err_level >= level) {
				/* Nothing present, so skip */
				next_addr = addr + rmi_rtt_level_mapsize(err_level);
				break;
			}

			ret = realm_create_rtt_levels(realm, addr, err_level,
						      level, NULL);
			if (WARN_ON(ret))
				return;
			/* Retry with the RTT levels in place */
			next_addr = addr;
			break;
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

static int realm_create_rd(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	struct realm_params *params __free(free_page) = NULL;
	void *rd = NULL;
	phys_addr_t rd_phys, params_phys, top_delegated;
	size_t pgd_size = kvm_pgtable_stage2_pgd_size(kvm->arch.mmu.vtcr);
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
	params->hash_algo = RMI_HASH_SHA_256;

	if (kvm->arch.arm_pmu) {
		params->pmu_num_ctrs = kvm->arch.nr_pmu_counters;
		params->flags0 |= RMI_REALM_PARAM_FLAG_PMU;
	}

	if (kvm_lpa2_is_enabled())
		params->flags0 |= RMI_REALM_PARAM_FLAG_LPA2;

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
					 top_delegated - kvm->arch.mmu.pgd_phys))) {
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
		unsigned long out_range;
		unsigned long flags = RMI_ADDR_TYPE_SINGLE;
		/* TODO: Optimise using RMI_ADDR_TYPE_LIST */

retry:
		ret = rmi_rtt_data_unmap(rd, addr, end, flags, 0,
					 &next_addr, &out_range, NULL);
		if (WARN_ON(ret < 0))
			return;

		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
			phys_addr_t rtt;

			if (next_addr > addr)
				continue; /* UNASSIGNED */

			rtt = alloc_rtt(NULL);
			if (WARN_ON(rtt == PHYS_ADDR_MAX))
				return;
			ret = realm_rtt_create(realm, addr,
					       RMI_RETURN_INDEX(ret) + 1, rtt);
			if (WARN_ON(ret)) {
				free_rtt(rtt);
				return;
			}
			goto retry;
		} else if (WARN_ON(ret)) {
			continue;
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
			ipa = next;
			break;
		case RMI_ERROR_RTT: {
			int err_level = RMI_RETURN_INDEX(ret);
			int level = find_map_level(realm, ipa, end);

			/*
			 * If the operation failed at deeper level than
			 * what is required for the address range, this
			 * implies encountering an unexpected entry,
			 * (e.g., RIPAS_DESTROYED), which the RMM prevents
			 * us from modifying. This is only applicable for
			 * RMI_RTT_INIT_RIPAS. All the other requests
			 * are generated by the Realm and thus RMM should
			 * be able to allow the transition.
			 */
			if (action == RIPAS_INIT && WARN_ON_ONCE(err_level >= level))
				return -ENXIO;

			ret = realm_create_rtt_levels(realm, ipa, err_level,
						      level, memcache);
			if (ret)
				goto out;
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

int kvm_rec_handle_request(struct kvm_vcpu *vcpu)
{
	struct realm_rec *rec = &vcpu->arch.rec;
	u64 esr;

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
	case RMI_EXIT_RIPAS_CHANGE:
		return kvm_complete_ripas_change(vcpu);
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

	params->mpidr = mpidr;

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
					 pgd_size)))
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

	/* Future patch will enable static branch kvm_rmi_is_available */
}
