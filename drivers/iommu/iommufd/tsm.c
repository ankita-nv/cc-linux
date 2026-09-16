// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 ARM Ltd.
 */

#include <linux/tsm.h>
#include "iommufd_private.h"

static bool iommufd_vdevice_tsm_req_arch_valid(u32 tvm_arch)
{
	switch (tvm_arch) {
	case IOMMU_VDEVICE_TSM_TVM_ARCH_CCA:
	case IOMMU_VDEVICE_TSM_TVM_ARCH_SEV:
	case IOMMU_VDEVICE_TSM_TVM_ARCH_TDX:
		return true;
	default:
		return false;
	}
}

static bool iommufd_vdevice_tsm_req_op_valid(u32 op, u32 tvm_arch)
{
	switch (op) {
	case TSM_REQ_VALIDATE_MMIO:
	case TSM_REQ_SET_TDI_STATE:
		return true;
	case TSM_REQ_SEV_ENABLE_DMA:
	case TSM_REQ_SEV_DISABLE_DMA:
		return tvm_arch == IOMMU_VDEVICE_TSM_TVM_ARCH_SEV;
	case TSM_REQ_READ_OBJECT:
	case TSM_REQ_REGEN_OBJECT:
	case TSM_REQ_OBJECT_INFO:
		return true;
	default:
		return false;
	}
}

/**
 * iommufd_vdevice_tsm_req_ioctl - Forward TSM requests
 * @ucmd: user command data for IOMMU_VDEVICE_TSM_REQ
 *
 * Resolve @iommu_vdevice_tsm_req::vdevice_id to a vdevice and pass the
 * request/response buffers to its vIOMMU provider.
 *
 * Return:
 *  -errno on error.
 *  positive residue if response/request bytes were left unconsumed.
 *    if response buffer is provided, residue indicates the number of bytes
 *    not used in response buffer
 *    if there is no response buffer, residue indicates the number of bytes
 *    not consumed in req buffer
 *  0 otherwise.
 */
int iommufd_vdevice_tsm_req_ioctl(struct iommufd_ucmd *ucmd)
{
	int ret;
	struct iommufd_vdevice *vdev;
	struct iommu_vdevice_tsm_req *cmd = ucmd->cmd;
	struct tsm_guest_req_info info = {
		.op = cmd->op,
		.tvm_arch = cmd->tvm_arch,
		.req   = {
			.user = u64_to_user_ptr(cmd->req_uptr),
			.is_kernel = false,
		},
		.req_len = cmd->req_len,
		.resp    =  {
			.user = u64_to_user_ptr(cmd->resp_uptr),
			.is_kernel = false,
		},
		.resp_len = cmd->resp_len,
	};

	if (!iommufd_vdevice_tsm_req_arch_valid(cmd->tvm_arch))
		return -EINVAL;

	if (!iommufd_vdevice_tsm_req_op_valid(cmd->op, cmd->tvm_arch))
		return -EINVAL;

	vdev = iommufd_get_vdevice(ucmd->ictx, cmd->vdevice_id);
	if (IS_ERR(vdev))
		return PTR_ERR(vdev);

	cmd->tsm_code = 0;
	if (!vdev->viommu->ops || !vdev->viommu->ops->vdevice_tsm_req)
		ret = -EOPNOTSUPP;
	else
		ret = vdev->viommu->ops->vdevice_tsm_req(vdev, &info,
							 &cmd->tsm_code);

	/* Always copy the tsm_code as response */
	if (iommufd_ucmd_respond(ucmd, sizeof(*cmd)))
		ret = -EFAULT;

	iommufd_put_object(ucmd->ictx, &vdev->obj);
	return ret;
}
