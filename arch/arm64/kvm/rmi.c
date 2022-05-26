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

static void free_rtt(phys_addr_t phys)
{
	if (free_delegated_page(phys))
		return;

	kvm_account_pgtable_pages(phys_to_virt(phys), -1);
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

static int __maybe_unused kvm_create_rec(struct kvm_vcpu *vcpu)
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
