/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2026 ARM Ltd.
 */

#ifndef __ASM_KVM_RMI_H
#define __ASM_KVM_RMI_H

#include <asm/kvm_pgtable.h>
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
 * @dev_mappings: RMM VDEV mapping ranges, protected by kvm->mmu_lock
 * @ripas_user_init: Userspace initialized RIPAS with KVM_ARM_RMI_INIT_RIPAS
 * @stage2_unmapped: The Realm stage-2 mappings have been removed
 * @stage2_unmap_failed: An unmap could not be completed (retry required)
 * @rtts_destroyed: The non-root RTTs have been torn down
 * @unmap_desc_buf: Output address list used by range unmap commands
 * @unmap_desc_pa: Physical address of @unmap_desc_buf
 * @unmap_desc_cap: Maximum number of descriptors in @unmap_desc_buf
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
	struct list_head dev_mappings;
	bool ripas_user_init;
	bool stage2_unmapped;
	bool stage2_unmap_failed;
	bool rtts_destroyed;
	unsigned long *unmap_desc_buf;
	phys_addr_t unmap_desc_pa;
	unsigned long unmap_desc_cap;
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
 * @psci_complete_pending: Calling REC has a pending RMI_PSCI_COMPLETE
 * @psci_on_pending: Target REC waits for host to complete CPU_ON
 * @psci_on_source: Source vCPU whose CPU_ON reserved this target REC
 */
struct realm_rec {
	unsigned long mpidr;
	void *rec_page;
	phys_addr_t rec_phys;
	struct rec_run *run;
	phys_addr_t run_phys;
	struct rmi_sro_state *sro;
	bool psci_complete_pending;
	bool psci_on_pending;
	struct kvm_vcpu *psci_on_source;
};

void kvm_init_rmi(void);
u32 kvm_rmm_ipa_limit(void);
unsigned int kvm_realm_sve_max_vl(void);

u64 kvm_realm_reset_id_aa64dfr0_el1(const struct kvm_vcpu *vcpu, u64 val);

bool kvm_rmi_supports_sve(void);

int kvm_init_realm(struct kvm *kvm);
#ifdef CONFIG_KVM
int kvm_realm_ensure_created(struct kvm *kvm);
#else
static inline int kvm_realm_ensure_created(struct kvm *kvm)
{
	return -EOPNOTSUPP;
}
#endif
int kvm_activate_realm(struct kvm *kvm);
void kvm_destroy_realm(struct kvm *kvm);
int kvm_realm_teardown_stage2(struct kvm *kvm);
void kvm_destroy_rec(struct kvm_vcpu *vcpu);

int kvm_rec_enter(struct kvm_vcpu *vcpu);
int kvm_rec_exit(struct kvm_vcpu *vcpu, int rec_run_status);
int kvm_rec_handle_request(struct kvm_vcpu *vcpu);
bool kvm_rec_handle_hvc(struct kvm_vcpu *vcpu, int *ret);

struct kvm_arm_rmi_populate;
struct kvm_arm_rmi_init_ripas;

int kvm_arm_rmi_populate(struct kvm *kvm,
			 struct kvm_arm_rmi_populate *arg);
int kvm_arm_rmi_init_ripas(struct kvm *kvm,
			   struct kvm_arm_rmi_init_ripas *arg);
void kvm_realm_unmap_range(struct kvm *kvm,
			   unsigned long ipa,
			   unsigned long size,
			   bool unmap_private,
			   bool may_block);
int kvm_realm_prepare_unmap_range(struct kvm *kvm,
				  unsigned long ipa,
				  unsigned long size,
				  bool unmap_private);
int realm_map_protected(struct kvm *kvm,
			unsigned long base_ipa,
			kvm_pfn_t pfn,
			unsigned long size,
			struct rmi_sro_state *sro);
int realm_rtt_map_order(struct kvm *kvm, unsigned long ipa, int max_order);
int realm_recover_protected(struct kvm *kvm,
			    unsigned long ipa,
			    kvm_pfn_t pfn,
			    unsigned long size,
			    int map_ret,
			    struct rmi_sro_state *sro,
			    bool mmu_invalidated);
int realm_map_non_secure(struct kvm *kvm,
			 unsigned long ipa,
			 kvm_pfn_t pfn,
			 unsigned long size,
			 enum kvm_pgtable_prot prot,
			 struct rmi_sro_state *sro);
unsigned long realm_psci_complete(struct kvm_vcpu *vcpu, unsigned long status);

static inline bool kvm_realm_is_private_address(struct realm *realm,
						unsigned long addr)
{
	return !(addr & BIT(realm->ia_bits - 1));
}

int realm_dev_mem_map(struct kvm *kvm, unsigned long pdev_phys,
		unsigned long vdev_phys, unsigned long start_ipa,
		unsigned long end_ipa, unsigned long start_pa);
int realm_dev_mem_unmap(struct kvm *kvm, unsigned long vdev_phys);

#endif /* __ASM_KVM_RMI_H */
