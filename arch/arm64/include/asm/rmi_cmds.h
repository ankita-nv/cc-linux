/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2026 ARM Ltd.
 */

#ifndef __ASM_RMI_CMDS_H
#define __ASM_RMI_CMDS_H

#include <linux/arm-rmi-cmds.h>
#include <linux/arm-smccc-rmi.h>
#include <linux/processor.h>

struct rtt_entry {
	unsigned long walk_level;
	unsigned long desc;
	int state;
	int ripas;
};

static inline int rmi_rtt_read_entry(unsigned long rd, unsigned long ipa,
				     unsigned long level, struct rtt_entry *rtt)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_RTT_READ_ENTRY, rd, ipa, level
	};
	struct arm_smccc_1_2_regs res;
	unsigned long status;

	kvm_rmi_smc_count(regs.a0);
	do {
		arm_smccc_1_2_invoke(&regs, &res);
		status = RMI_RETURN_STATUS(res.a0);
		if (status == RMI_BUSY) {
			kvm_rmi_smc_busy_count(regs.a0);
			cpu_relax();
		}
	} while (status == RMI_BUSY);

	if (res.a0 == RMI_SUCCESS && rtt) {
		rtt->walk_level = res.a1;
		rtt->state = res.a2;
		rtt->desc = res.a3;
		rtt->ripas = res.a4;
	}

	return res.a0;
}

/**
 * rmi_rtt_data_map_init() - Create a protected mapping with data contents
 * @rd: PA of the RD
 * @data: PA of the target granule
 * @ipa: IPA at which the granule will be mapped in the guest
 * @src: PA of the source granule
 * @flags: RMI_MEASURE_CONTENT if the contents should be measured
 *
 * Create a mapping from Protected IPA space to conventional memory, copying
 * contents from a Non-secure Granule provided by the caller.
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_rtt_data_map_init(unsigned long rd, unsigned long data,
					 unsigned long ipa, unsigned long src,
					 unsigned long flags)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_RTT_DATA_MAP_INIT, rd, data, ipa, src, flags
	};

	return rmi_sro_execute_no_xfer(&regs);
}

/**
 * rmi_rtt_data_map() - Create mappings in protected IPA with unknown contents
 * @rd: PA of the RD
 * @base: Base of the target IPA range
 * @top: Top of the target IPA range
 * @flags: Flags
 * @oaddr: Output address set descriptor
 * @out_top: Top address of range which was processed.
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_rtt_data_map(unsigned long rd,
				    unsigned long base,
				    unsigned long top,
				    unsigned long flags,
				    unsigned long oaddr,
				    unsigned long *out_top)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_RTT_DATA_MAP, rd, base, top, flags, oaddr
	};
	long ret;

	ret = rmi_sro_execute_no_xfer(&regs);

	if (ret >= 0 && RMI_RETURN_STATUS(ret) == RMI_SUCCESS && out_top)
		*out_top = regs.a1;

	return ret;
}

/**
 * rmi_rtt_data_unmap() - Remove mappings to conventional memory
 * @rd: PA of the RD for the target Realm
 * @base: Base of the target IPA range
 * @top: Top of the target IPA range
 * @flags: Flags
 * @oaddr: Output address set descriptor
 * @out_top: Returns top IPA of range which has been unmapped
 * @out_range: Output address range
 * @out_count: Number of entries in output address list
 *
 * Removes mappings to convention memory with a target Protected IPA range.
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_rtt_data_unmap(unsigned long rd,
				      unsigned long base,
				      unsigned long top,
				      unsigned long flags,
				      unsigned long oaddr,
				      unsigned long *out_top,
				      unsigned long *out_range,
				      unsigned long *out_count)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_RTT_DATA_UNMAP, rd, base, top, flags, oaddr
	};
	long ret;

	ret = rmi_sro_execute_no_xfer(&regs);

	if (ret >= 0 && RMI_RETURN_STATUS(ret) == RMI_SUCCESS) {
		if (out_top)
			*out_top = regs.a1;
		if (out_range)
			*out_range = regs.a2;
		if (out_count)
			*out_count = regs.a3;
	}

	return ret;
}

/**
 * rmi_psci_complete() - Complete pending PSCI command
 * @calling_rec: PA of the calling REC
 * @status: Status of the PSCI request
 *
 * Completes a pending PSCI command.
 *
 * Return: RMI return code
 */
static inline long rmi_psci_complete(unsigned long calling_rec,
				     unsigned long status)
{
	struct arm_smccc_res res;

	rmi_smccc(SMC_RMI_PSCI_COMPLETE, calling_rec, status, &res);

	return res.a0;
}

/**
 * rmi_realm_activate() - Active a realm
 * @rd: PA of the RD
 *
 * Mark a realm as Active signalling that creation is complete and allowing
 * execution of the realm.
 *
 * Return: RMI return code
 */
static inline long rmi_realm_activate(unsigned long rd)
{
	struct arm_smccc_res res;

	rmi_smccc_invoke_v1_1(SMC_RMI_REALM_ACTIVATE, rd, &res);

	return res.a0;
}

/**
 * rmi_realm_create() - Create a realm
 * @rd: PA of the RD
 * @params: PA of realm parameters
 * @sro: Preallocated SRO context to be used
 *
 * Create a new realm using the given parameters.
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_realm_create(unsigned long rd, unsigned long params,
				    struct rmi_sro_state *sro)
{
	sro->regs = (struct arm_smccc_1_2_regs){
		SMC_RMI_REALM_CREATE, rd, params
	};

	return rmi_sro_execute(sro, GFP_KERNEL, NULL);
}

/**
 * rmi_realm_terminate() - Terminate a realm
 * @rd: PA of the RD
 *
 * Terminates a realm, moving it into a ZOMBIE state
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_realm_terminate(unsigned long rd)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_REALM_TERMINATE, rd
	};

	return rmi_sro_execute_no_xfer(&regs);
}

/**
 * rmi_realm_destroy() - Destroy a realm
 * @rd: PA of the RD
 * @sro: Preallocated SRO context to be used
 *
 * Destroys a realm, all objects belonging to the realm must be destroyed first.
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_realm_destroy(unsigned long rd,
				     struct rmi_sro_state *sro)
{
	sro->regs = (struct arm_smccc_1_2_regs){
		SMC_RMI_REALM_DESTROY, rd
	};

	return rmi_sro_execute(sro, GFP_KERNEL, NULL);
}

/**
 * rmi_rec_create() - Create a REC
 * @rd: PA of the RD
 * @rec: PA of the target REC
 * @params: PA of REC parameters
 * @sro: Allocated SRO context to be used
 *
 * Create a REC using the parameters specified in the struct rec_params pointed
 * to by @params.
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_rec_create(unsigned long rd,
				  unsigned long rec,
				  unsigned long params,
				  struct rmi_sro_state *sro)
{
	sro->regs = (struct arm_smccc_1_2_regs){
		SMC_RMI_REC_CREATE, rd, rec, params
	};

	return rmi_sro_execute(sro, GFP_KERNEL, NULL);
}

/**
 * rmi_rec_destroy() - Destroy a REC
 * @rec: PA of the target REC
 * @sro: Allocated SRO context to be used
 *
 * Destroys a REC. The REC must not be running.
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_rec_destroy(unsigned long rec,
				   struct rmi_sro_state *sro)
{
	sro->regs = (struct arm_smccc_1_2_regs){
		SMC_RMI_REC_DESTROY, rec
	};

	return rmi_sro_execute(sro, GFP_KERNEL, NULL);
}

/**
 * rmi_rec_enter() - Enter a REC
 * @rec: PA of the target REC
 * @run_ptr: PA of RecRun structure
 *
 * Starts (or continues) execution within a REC.
 *
 * Return: RMI return code
 */
static inline long rmi_rec_enter(unsigned long rec, unsigned long run_ptr)
{
	struct arm_smccc_res res;

	rmi_smccc_invoke_v1_1(SMC_RMI_REC_ENTER, rec, run_ptr, &res);

	return res.a0;
}

/**
 * rmi_rtt_create() - Creates an RTT
 * @rd: PA of the RD
 * @rtt: PA of the target RTT
 * @ipa: Base of the IPA range described by the RTT
 * @level: Depth of the RTT within the tree
 *
 * Creates an RTT (Realm Translation Table) at the specified level for the
 * translation of the specified address within the realm.
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_rtt_create(unsigned long rd, unsigned long rtt,
				  unsigned long ipa, long level)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_RTT_CREATE, rd, rtt, ipa, level
	};

	return rmi_sro_execute_no_xfer(&regs);
}

/**
 * rmi_rtt_destroy() - Destroy an RTT
 * @rd: PA of the RD for the target realm
 * @ipa: Base of the IPA range described by the RTT
 * @level: RTT level
 * @out_rtt: Pointer to write the PA of the RTT which was destroyed
 * @out_top: Pointer to write the top IPA of non-live RTT entries, from entry
 * at which the RTT walk terminated.
 *
 * Destroys an RTT. The RTT must be non-live, i.e. none of the entries in the
 * table are in ASSIGNED or TABLE state.
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code.
 */
static inline long rmi_rtt_destroy(unsigned long rd,
				   unsigned long ipa,
				   long level,
				   unsigned long *out_rtt,
				   unsigned long *out_top)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_RTT_DESTROY, rd, ipa, level
	};
	long ret = rmi_sro_execute_no_xfer(&regs);

	if (ret == RMI_SUCCESS && out_rtt)
		*out_rtt = regs.a1;
	if (ret >= 0 && out_top)
		*out_top = regs.a2;

	return ret;
}

/**
 * rmi_rtt_fold() - Fold an RTT
 * @rd: PA of the RD
 * @ipa: Base of the IPA range described by the RTT
 * @level: Depth of the RTT within the tree
 * @out_rtt: Pointer to write the PA of the RTT which was destroyed
 *
 * Folds an RTT. If all entries with the RTT are 'homogeneous' the RTT can be
 * folded into the parent and the RTT destroyed.
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_rtt_fold(unsigned long rd, unsigned long ipa,
				long level, unsigned long *out_rtt)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_RTT_FOLD, rd, ipa, level
	};
	long ret = rmi_sro_execute_no_xfer(&regs);

	if (ret == RMI_SUCCESS && out_rtt)
		*out_rtt = regs.a1;

	return ret;
}

/**
 * rmi_rtt_init_ripas() - Set RIPAS for new realm
 * @rd: PA of the RD
 * @base: Base of target IPA region
 * @top: Top of target IPA region
 * @out_top: Top IPA of range whose RIPAS was modified
 *
 * Sets the RIPAS of a target IPA range to RAM, for a realm in the NEW state.
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_rtt_init_ripas(unsigned long rd, unsigned long base,
				      unsigned long top, unsigned long *out_top)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_RTT_INIT_RIPAS, rd, base, top
	};
	long ret = rmi_sro_execute_no_xfer(&regs);

	if (ret >= 0 && out_top)
		*out_top = regs.a1;

	return ret;
}

/**
 * rmi_rtt_unprot_map() - Map unprotected granules into a realm
 * @rd: PA of the RD
 * @base: Base IPA of the mapping
 * @top: Top of the target IPA range
 * @flags: Flags
 * @oaddr: Output address set descriptor
 * @out_top: Top IPA of range which has been mapped
 *
 * Create mappings to memory within a target unprotected IPA range.
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_rtt_unprot_map(unsigned long rd,
				      unsigned long base,
				      unsigned long top,
				      unsigned long flags,
				      unsigned long oaddr,
				      unsigned long *out_top)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_RTT_UNPROT_MAP, rd, base, top, flags, oaddr
	};
	long ret = rmi_sro_execute_no_xfer(&regs);

	if (ret >= 0 && RMI_RETURN_STATUS(ret) == RMI_SUCCESS && out_top)
		*out_top = regs.a1;

	return ret;
}

/**
 * rmi_rtt_set_ripas() - Set RIPAS for an running realm
 * @rd: PA of the RD
 * @rec: PA of the REC making the request
 * @base: Base of target IPA region
 * @top: Top of target IPA region
 * @out_top: Pointer to write top IPA of range whose RIPAS was modified
 *
 * Completes a request made by the realm to change the RIPAS of a target IPA
 * range.
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_rtt_set_ripas(unsigned long rd, unsigned long rec,
				     unsigned long base, unsigned long top,
				     unsigned long *out_top)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_RTT_SET_RIPAS, rd, rec, base, top
	};
	long ret = rmi_sro_execute_no_xfer(&regs);

	if (ret >= 0 && out_top)
		*out_top = regs.a1;

	return ret;
}

/**
 * rmi_rtt_unprot_unmap() - Remove mappings within an unprotected IPA range
 * @rd: PA of the RD
 * @base: Base IPA of the mapping
 * @top: Top of the target IPA range
 * @flags: Flags
 * @oaddr: Output address set descriptor
 * @out_top: Top IPA which has been unmapped
 * @out_range: Output address range
 * @out_count: Number of entries in output address list
 *
 * Removes mappings to memory within a target unprotected IPA range.
 *
 * Return: 0 on success, positive RMI result code or negative Linux error code
 */
static inline long rmi_rtt_unprot_unmap(unsigned long rd,
					unsigned long base,
					unsigned long top,
					unsigned long flags,
					unsigned long oaddr,
					unsigned long *out_top,
					unsigned long *out_range,
					unsigned long *out_count)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_RTT_UNPROT_UNMAP, rd, base, top, flags, oaddr
	};
	long ret = rmi_sro_execute_no_xfer(&regs);

	if (ret >= 0 && RMI_RETURN_STATUS(ret) == RMI_SUCCESS) {
		if (out_top)
			*out_top = regs.a1;
		if (out_range)
			*out_range = regs.a2;
		if (out_count)
			*out_count = regs.a3;
	}

	return ret;
}

static inline unsigned long rmi_pdev_get_state(unsigned long pdev_phys, enum rmi_pdev_state *state)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_PDEV_GET_STATE, pdev_phys, &res);

	*state = res.a1;
	return res.a0;
}

static inline unsigned long rmi_pdev_communicate(unsigned long pdev_phys,
						 unsigned long pdev_comm_data_phys)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_PDEV_COMMUNICATE,
			     pdev_phys, pdev_comm_data_phys, &res);

	return res.a0;
}

static inline unsigned long rmi_pdev_abort(unsigned long pdev_phys)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_PDEV_ABORT, pdev_phys, &res);

	return res.a0;
}

static inline unsigned long rmi_pdev_stop(unsigned long pdev_phys)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_PDEV_STOP, pdev_phys, &res);

	return res.a0;
}

static inline unsigned long rmi_pdev_set_pubkey(unsigned long pdev_phys, unsigned long key_phys)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_PDEV_SET_PUBKEY, pdev_phys, key_phys, &res);

	return res.a0;
}


static inline unsigned long rmi_pdev_stream_connect(unsigned long stream_params_phys,
		unsigned long *stream_handle)
{

	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_PDEV_STREAM_CONNECT, stream_params_phys, &res);

	*stream_handle = res.a1;
	return res.a0;
}

static inline unsigned long rmi_pdev_stream_complete(unsigned long pdev1_phys,
		unsigned long pdev2_phys, unsigned long stream_handle)
{

	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_PDEV_STREAM_COMPLETE, pdev1_phys,
			     pdev2_phys, stream_handle, &res);

	return res.a0;
}

static inline unsigned long rmi_pdev_stream_disconnect(unsigned long pdev1_phys,
		unsigned long pdev2_phys, unsigned long stream_handle)
{

	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_PDEV_STREAM_DISCONNECT, pdev1_phys,
			     pdev2_phys, stream_handle, &res);

	return res.a0;
}

#endif /* __ASM_RMI_CMDS_H */
