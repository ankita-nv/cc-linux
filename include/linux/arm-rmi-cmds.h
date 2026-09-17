/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 ARM Ltd.
 */

#ifndef __LINUX_ARM_RMI_CMDS_H_
#define __LINUX_ARM_RMI_CMDS_H_

#include <linux/arm-smccc-rmi.h>
#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/numa.h>
#include <linux/processor.h>
#include <linux/types.h>
#include <linux/gfp_types.h>

#include <asm/page.h>

#define RMI_MAX_ADDR_LIST	256

#define RMI_SMC_SLOT_IDX(_fid) \
	((unsigned int)(((_fid) - SMC_RMI_VERSION) & 0xffUL))

struct rmi_sro_state {
	struct arm_smccc_1_2_regs regs;
	unsigned long addr_count;
	/* Complete DEN0137 v2.0-bet3 RmiAddrRangeDesc entries. */
	unsigned long addr_list[RMI_MAX_ADDR_LIST];
	u16 trackid;
};

struct rmi_smc_slot {
	unsigned long	fid;
	const char	*name;
	atomic64_t	count[2];
};

extern struct rmi_smc_slot rmi_smc_slots[256];

/*
 * Called from the noinstr REC entry path inside the guest Extended
 * Quiescent State via rmi_smccc_invoke_v1_1(), so use the uninstrumented
 * raw_atomic64_* accessors and force inlining to avoid an instrumentable
 * symbol.
 */
static __always_inline void kvm_rmi_smc_count(unsigned long fid)
{
	raw_atomic64_inc(&rmi_smc_slots[RMI_SMC_SLOT_IDX(fid)].count[0]);
}

static __always_inline void kvm_rmi_smc_busy_count(unsigned long fid)
{
	raw_atomic64_inc(&rmi_smc_slots[RMI_SMC_SLOT_IDX(fid)].count[1]);
}

/* Issue one SMCCC 1.1 RMI call without retrying the returned status. */
#define rmi_smccc_invoke_v1_1(fid, ...)					\
	do {								\
		unsigned long __fid = (fid);				\
		kvm_rmi_smc_count(__fid);				\
		arm_smccc_1_1_invoke(__fid, __VA_ARGS__);		\
	} while (0)

/* Retry temporary RMI_BUSY results, but return RMI_BLOCKED to the caller. */
#define rmi_smccc(fid, ...) do {						\
	unsigned long __fid = (fid);					\
	unsigned long __status;						\
	kvm_rmi_smc_count(__fid);					\
	do {								\
		arm_smccc_1_1_invoke(__fid, ##__VA_ARGS__);		\
		__status = RMI_RETURN_STATUS(res.a0);			\
		if (__status == RMI_BUSY) {				\
			kvm_rmi_smc_busy_count(__fid);			\
			cpu_relax();					\
		}							\
	} while (__status == RMI_BUSY);				\
} while (0)

unsigned long rmi_feat_reg(unsigned long id);

long rmi_delegate_range(phys_addr_t phys, unsigned long size,
			unsigned long *delegated_size);
long rmi_undelegate_range(phys_addr_t phys, unsigned long size,
			  unsigned long *undelegated_size);

int rmi_sro_topup_node(struct rmi_sro_state *sro, unsigned long capacity,
		       unsigned long min, int nid);

static inline int rmi_sro_topup(struct rmi_sro_state *sro,
				unsigned long capacity, unsigned long min)
{
	return rmi_sro_topup_node(sro, capacity, min, NUMA_NO_NODE);
}

phys_addr_t rmi_sro_alloc(struct rmi_sro_state *sro, gfp_t gfp);

/* Manage diagnostic Track IDs and RMM-owned physical ranges. */
int rmi_trackid_alloc(void);
void rmi_trackid_free(unsigned int trackid);
void rmi_region_track(struct rmi_sro_state *sro, phys_addr_t phys,
		      unsigned long size, unsigned long fid,
		      unsigned long ipa);
void rmi_region_untrack(struct rmi_sro_state *sro, phys_addr_t phys,
			unsigned long size);
u64 rmi_region_owned_bytes(struct rmi_sro_state *sro);

static inline long rmi_delegate_page(phys_addr_t phys)
{
	return rmi_delegate_range(phys, PAGE_SIZE, NULL);
}

static inline long rmi_undelegate_page(phys_addr_t phys)
{
	return rmi_undelegate_range(phys, PAGE_SIZE, NULL);
}

bool is_rmi_available(void);

long rmi_sro_execute(struct rmi_sro_state *sro, gfp_t gfp,
		     struct arm_smccc_1_2_regs *out_regs);
long rmi_sro_execute_no_xfer(struct arm_smccc_1_2_regs *regs);
void rmi_sro_free(struct rmi_sro_state *sro);

/**
 * rmi_rmm_config_set() - Configure the RMM
 * @cfg_ptr: PA of a struct rmm_config
 *
 * Sets configuration options on the RMM.
 *
 * Return: RMI return code
 */
static inline int rmi_rmm_config_set(unsigned long cfg_ptr)
{
	struct arm_smccc_res res;

	rmi_smccc_invoke_v1_1(SMC_RMI_RMM_CONFIG_SET, cfg_ptr, &res);

	return res.a0;
}

/**
 * rmi_rmm_activate() - Activate the RMM
 * @sro: Preallocated SRO context to be used
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_rmm_activate(struct rmi_sro_state *sro)
{
	sro->regs = (struct arm_smccc_1_2_regs){ SMC_RMI_RMM_ACTIVATE };

	return rmi_sro_execute(sro, GFP_KERNEL, NULL);
}

/**
 * rmi_rmm_deactivate() - Deactivate the RMM and reclaim its metadata
 * @sro: Preallocated SRO context to be used
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_rmm_deactivate(struct rmi_sro_state *sro)
{
	sro->regs = (struct arm_smccc_1_2_regs){ SMC_RMI_RMM_DEACTIVATE };

	return rmi_sro_execute(sro, GFP_KERNEL, NULL);
}

/**
 * rmi_granule_tracking_get() - Get configuration of a Granule tracking region
 * @start: Base PA of the tracking region
 * @end: End of the PA region
 * @out_category: Memory category
 * @out_state: Tracking region state
 * @out_top: Top of the memory region
 *
 * Return: RMI return code
 */
static inline int rmi_granule_tracking_get(unsigned long start,
					   unsigned long end,
					   unsigned long *out_category,
					   unsigned long *out_state,
					   unsigned long *out_top)
{
	struct arm_smccc_res res;

	rmi_smccc_invoke_v1_1(SMC_RMI_GRANULE_TRACKING_GET, start, end, &res);

	if (res.a0 == RMI_SUCCESS) {
		if (out_category)
			*out_category = res.a1;
		if (out_state)
			*out_state = res.a2;
		if (out_top)
			*out_top = res.a3;
	}

	return res.a0;
}

/**
 * rmi_granule_tracking_set() - Set a Granule tracking region configuration
 * @addr: Tracking-region-aligned PA
 * @category: RmiMemCategory value
 * @state: RmiTrackingRegionState value
 * @sro: Preallocated SRO context to be used
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_granule_tracking_set(unsigned long addr,
					    unsigned long category,
					    unsigned long state,
					    struct rmi_sro_state *sro)
{
	sro->regs = (struct arm_smccc_1_2_regs){
		SMC_RMI_GRANULE_TRACKING_SET, addr, category, state
	};

	return rmi_sro_execute(sro, GFP_KERNEL, NULL);
}

/**
 * rmi_gpt_info() - Query the L1 GPT state of a physical address range
 * @base: L0GPTSZ-aligned base PA of the target range
 * @top: L0GPTSZ-aligned top PA of the target range
 * @out_top: Top PA of the first subrange with a uniform GPT PAR state
 * @state: RmiGptParState of the returned subrange
 *
 * Return: RMI return code
 */
static inline int rmi_gpt_info(unsigned long base, unsigned long top,
			       unsigned long *out_top, unsigned long *state)
{
	struct arm_smccc_res res;

	rmi_smccc_invoke_v1_1(SMC_RMI_GPT_INFO, base, top, &res);

	if (res.a0 == RMI_SUCCESS) {
		if (out_top)
			*out_top = res.a1;
		if (state)
			*state = res.a2;
	}

	return res.a0;
}

/**
 * rmi_gpt_l1_create() - Create a Level 1 GPT
 * @addr: Base of physical address region described by the L1GPT
 * @sro: Preallocated SRO context to be used
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_gpt_l1_create(unsigned long addr,
				     struct rmi_sro_state *sro)
{
	sro->regs = (struct arm_smccc_1_2_regs){
		SMC_RMI_GPT_L1_CREATE, addr
	};

	return rmi_sro_execute(sro, GFP_KERNEL, NULL);
}

static inline long rmi_gpt_l1_destroy(unsigned long addr,
				      struct rmi_sro_state *sro)
{
	sro->regs = (struct arm_smccc_1_2_regs){
		SMC_RMI_GPT_L1_DESTROY, addr
	};

	return rmi_sro_execute(sro, GFP_KERNEL, NULL);
}

/**
 * rmi_features() - Read feature register
 * @index: Feature register index
 * @out: Feature register value is written to this pointer
 *
 * Return: RMI return code
 */
static inline int rmi_features(unsigned long index, unsigned long *out)
{
	struct arm_smccc_res res;

	rmi_smccc_invoke_v1_1(SMC_RMI_FEATURES, index, &res);

	if (res.a0 == RMI_SUCCESS && out)
		*out = res.a1;

	return res.a0;
}

/**
 * rmi_granule_range_delegate() - Delegate granules
 * @base: PA of the first granule of the range
 * @top: PA of the first granule after the range
 * @out_top: PA of the first granule not delegated
 *
 * Delegate a range of granule for use by the realm world. If the entire range
 * was delegated then @out_top == @top, otherwise the function should be called
 * again with @base == @out_top.
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_granule_range_delegate(unsigned long base,
					      unsigned long top,
					      unsigned long *out_top)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_GRANULE_RANGE_DELEGATE, base, top
	};
	long ret = rmi_sro_execute_no_xfer(&regs);

	if (ret >= 0 && RMI_RETURN_STATUS(ret) == RMI_SUCCESS && out_top)
		*out_top = regs.a1;

	return ret;
}

/**
 * rmi_granule_range_undelegate() - Undelegate a range of granules
 * @base: Base PA of the target range
 * @top: Top PA of the target range
 * @out_top: Returns the top PA of range whose state is undelegated
 *
 * Undelegate a range of granules to allow use by the normal world. Will fail if
 * the granules are in use.
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_granule_range_undelegate(unsigned long base,
						unsigned long top,
						unsigned long *out_top)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_GRANULE_RANGE_UNDELEGATE, base, top
	};
	long ret = rmi_sro_execute_no_xfer(&regs);

	if (ret >= 0 && RMI_RETURN_STATUS(ret) == RMI_SUCCESS && out_top)
		*out_top = regs.a1;

	return ret;
}

#endif
