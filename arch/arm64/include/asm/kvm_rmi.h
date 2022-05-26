/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2026 ARM Ltd.
 */

#ifndef __ASM_KVM_RMI_H
#define __ASM_KVM_RMI_H

#include <linux/arm-smccc-rmi.h>

/**
 * enum realm_state - State of a Realm
 *
 * Mirrors the RMM's Realm lifecycle states where they are meaningful to KVM,
 * with REALM_STATE_DYING being a KVM-internal state used to prevent further
 * requests while teardown is in progress. KVM does not track REALM_SYSTEM_OFF
 * or REALM_ZOMBIE separately as they naturally lead to teardown.
 */
enum realm_state {
	/**
	 * @REALM_STATE_NONE:
	 *      Realm has not yet been created. rmi_realm_create() has not
	 *      yet been called.
	 */
	REALM_STATE_NONE,
	/**
	 * @REALM_STATE_NEW:
	 *      Realm is under construction, rmi_realm_create() has been
	 *      called, but it is not yet activated. Pages may be populated.
	 */
	REALM_STATE_NEW,
	/**
	 * @REALM_STATE_ACTIVE:
	 *      Realm has been created and is eligible for execution with
	 *      rmi_rec_enter(). Pages may no longer be populated with
	 *      rmi_data_create().
	 */
	REALM_STATE_ACTIVE,
	/**
	 * @REALM_STATE_DYING:
	 *      Realm is in the process of being destroyed or has already been
	 *      destroyed.
	 */
	REALM_STATE_DYING,
	/**
	 * @REALM_STATE_DEAD:
	 *      Realm has been destroyed.
	 */
	REALM_STATE_DEAD
};

/**
 * struct realm - Additional per VM data for a Realm
 *
 * @rd: Kernel mapping of the RMM-managed Realm Descriptor (RD) granule
 * @sro: Preallocated SRO state context for Realm MMU operations
 * @state: The lifetime state machine for the realm
 * @ia_bits: Number of valid Input Address bits in the IPA
 * @stage2_unmapped: The Realm stage-2 mappings have been removed
 * @rtts_destroyed: The non-root RTTs have been torn down
 */
struct realm {
	void *rd;
	/*
	 * Reused by RTT map/unmap SRO commands. Those commands are only
	 * issued from Realm stage-2 map/unmap paths while kvm->mmu_lock is
	 * held for write, including Realm fault handling where
	 * kvm_fault_lock() takes the write side, so concurrent use is
	 * serialized.
	 */
	struct rmi_sro_state *sro;
	enum realm_state state;
	unsigned int ia_bits;
	bool stage2_unmapped;
	bool rtts_destroyed;
};

/**
 * struct realm_rec - Additional per VCPU data for a Realm
 *
 * @mpidr: MPIDR (Multiprocessor Affinity Register) value to identify this VCPU
 * @rec_page: Kernel VA of the RMM's private page for this REC
 * @rec_phys: Physical address of @rec_page
 * @run: Kernel VA of the RmiRecRun structure shared with the RMM
 * @run_phys: Physical address of @run
 * @sro: A preallocated SRO state context
 */
struct realm_rec {
	unsigned long mpidr;
	void *rec_page;
	phys_addr_t rec_phys;
	struct rec_run *run;
	phys_addr_t run_phys;
	struct rmi_sro_state *sro;
};

void kvm_init_rmi(void);
u32 kvm_rmm_ipa_limit(void);

int kvm_init_realm(struct kvm *kvm);
void kvm_destroy_realm(struct kvm *kvm);
int kvm_realm_teardown_stage2(struct kvm *kvm);
void kvm_destroy_rec(struct kvm_vcpu *vcpu);

int kvm_rec_enter(struct kvm_vcpu *vcpu);
int kvm_rec_exit(struct kvm_vcpu *vcpu, int rec_run_status);
int kvm_rec_handle_request(struct kvm_vcpu *vcpu);
bool kvm_rec_handle_hvc(struct kvm_vcpu *vcpu, int *ret);

void kvm_realm_unmap_range(struct kvm *kvm,
			   unsigned long ipa,
			   unsigned long size,
			   bool unmap_private,
			   bool may_block);

static inline bool kvm_realm_is_private_address(struct realm *realm,
						unsigned long addr)
{
	return !(addr & BIT(realm->ia_bits - 1));
}

#endif /* __ASM_KVM_RMI_H */
