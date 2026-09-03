// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Arm Ltd.
 */

#include <linux/arm-rmi-cmds.h>
#include <linux/arm-smmu-v3.h>
#include <linux/cleanup.h>
#include <linux/iommu.h>
#include <linux/iommufd.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci-tsm.h>
#include <linux/slab.h>
#include <linux/tsm.h>

#include <asm/kvm_emulate.h>
#include <asm/rmi_cmds.h>
#include <uapi/asm/rmi-da.h>

#include "rmi-da.h"

struct cca_psmmu {
	struct list_head node;
	phys_addr_t phys;
	unsigned int users;
};

struct cca_viommu {
	struct iommufd_viommu core;
	struct cca_psmmu *psmmu;
};

struct cca_vdevice {
	struct iommufd_vdevice core;
	struct pci_tsm_context *tsm_context;
	struct cca_host_tdi host_tdi;
	u32 l2_sid;
};

static LIST_HEAD(cca_psmmus);
static DEFINE_MUTEX(cca_psmmus_lock);

static struct cca_viommu *to_cca_viommu(struct iommufd_viommu *viommu)
{
	return container_of(viommu, struct cca_viommu, core);
}

static struct tsm_dev *cca_viommu_tsm_dev(struct iommufd_viommu *viommu)
{
	return viommu->provider_data;
}

static struct cca_psmmu *
cca_psmmu_get(const struct arm_smmu_realm_params *params)
{
	struct rmi_psmmu_params *rmi_params;
	struct cca_psmmu *psmmu;
	unsigned long rmi_ret = 0;
	int ret;

	guard(mutex)(&cca_psmmus_lock);
	list_for_each_entry(psmmu, &cca_psmmus, node) {
		if (psmmu->phys == params->psmmu_phys) {
			psmmu->users++;
			return psmmu;
		}
	}

	psmmu = kzalloc(sizeof(*psmmu), GFP_KERNEL);
	if (!psmmu)
		return ERR_PTR(-ENOMEM);
	rmi_params = (void *)get_zeroed_page(GFP_KERNEL);
	if (!rmi_params) {
		kfree(psmmu);
		return ERR_PTR(-ENOMEM);
	}
	rmi_params->flags = params->irq_flags;
	rmi_params->gerr_addr = params->gerr_addr;
	rmi_params->gerr_data = params->gerr_data;
	rmi_params->eventq_addr = params->eventq_addr;
	rmi_params->eventq_data = params->eventq_data;
	rmi_params->priq_addr = params->priq_addr;
	rmi_params->priq_data = params->priq_data;
	ret = rmi_psmmu_activate(params->psmmu_phys,
				 virt_to_phys(rmi_params), &rmi_ret);
	free_page((unsigned long)rmi_params);
	if (ret || rmi_ret) {
		kfree(psmmu);
		return ERR_PTR(-EIO);
	}

	psmmu->phys = params->psmmu_phys;
	psmmu->users = 1;
	list_add(&psmmu->node, &cca_psmmus);
	return psmmu;
}

static void cca_psmmu_put(struct cca_psmmu *psmmu)
{
	unsigned long rmi_ret = 0;

	guard(mutex)(&cca_psmmus_lock);
	if (--psmmu->users)
		return;
	if (rmi_psmmu_deactivate(psmmu->phys, &rmi_ret) || rmi_ret) {
		pr_warn("failed to deactivate Realm pSMMU at %pa\n",
			&psmmu->phys);
	}
	list_del(&psmmu->node);
	kfree(psmmu);
}

static void cca_viommu_destroy(struct iommufd_viommu *viommu)
{
	struct cca_viommu *cca = to_cca_viommu(viommu);

	/*
	 * Tear down any VSMMU layered on this viommu first (no-op for the
	 * PSMMU-only case), before dropping the PSMMU reference below.
	 */
	kvm_realm_unregister_vsmmu(viommu->kvm_file->private_data,
				   viommu->obj.id);
	if (cca->psmmu)
		cca_psmmu_put(cca->psmmu);
}

static int cca_psmmu_create_l2(struct cca_psmmu *psmmu, u32 l2_sid)
{
	unsigned long rmi_ret = 0;
	int ret;

	guard(mutex)(&cca_psmmus_lock);
	ret = rmi_psmmu_st_l2_create(psmmu->phys, l2_sid, &rmi_ret);
	if (!ret && !rmi_ret)
		return 0;
	if (RMI_RETURN_STATUS(rmi_ret) == RMI_ERROR_PSMMU_ST &&
	    RMI_RETURN_INDEX(rmi_ret) == 2)
		return 0;
	return -EIO;
}

static void cca_psmmu_destroy_l2(struct cca_psmmu *psmmu, u32 l2_sid,
				 struct device *dev)
{
	unsigned long rmi_ret = 0;
	int ret;

	guard(mutex)(&cca_psmmus_lock);
	ret = rmi_psmmu_st_l2_destroy(psmmu->phys, l2_sid, &rmi_ret);
	if (!ret && !rmi_ret)
		return;
	if (RMI_RETURN_STATUS(rmi_ret) == RMI_ERROR_PSMMU_ST &&
	    RMI_RETURN_INDEX(rmi_ret) == 2)
		return;
	dev_warn(dev, "failed to destroy Realm stream mapping\n");
}

static int cca_vdevice_unmap(struct cca_vdevice *cca_vdev)
{
	struct cca_host_tdi *host_tdi = &cca_vdev->host_tdi;

	return realm_dev_mem_unmap(host_tdi->kvm,
				   virt_to_phys(host_tdi->rmm_vdev));
}

static void cca_vdevice_destroy(struct iommufd_vdevice *vdev)
{
	struct cca_vdevice *cca_vdev =
		container_of(vdev, struct cca_vdevice, core);
	struct cca_viommu *cca = to_cca_viommu(vdev->viommu);
	struct device *dev = iommufd_vdevice_to_device(vdev);
	struct pci_tsm_context *context = cca_vdev->tsm_context;
	struct pci_dev *pdev = to_pci_dev(dev);
	struct pci_tsm_pf0 *pf0 = pci_tsm_context_pf0(context);
	struct pci_dev *dsm_dev = pci_tsm_context_dsm_dev(context);
	struct cca_host_tdi *host_tdi = &cca_vdev->host_tdi;
	struct realm *realm = &host_tdi->kvm->arch.realm;

	scoped_guard(mutex, &pf0->lock) {
		cca_vdev_destroy(host_tdi, realm, pdev, dsm_dev);
		/*
		 * RMM dropped its reference to the VSMMU when the vdev was
		 * destroyed above; drop the reference held since
		 * cca_vdev_create().
		 */
		kvm_realm_put_vsmmu(host_tdi->vsmmu);
		host_tdi->vsmmu = NULL;
		kvfree(host_tdi->interface_report);
		kvfree(host_tdi->measurements);
		cca_psmmu_destroy_l2(cca->psmmu, cca_vdev->l2_sid, dev);
	}
	pci_tsm_context_put(context);
}

static int cca_vdevice_init(struct iommufd_vdevice *vdev)
{
	struct cca_vdevice *cca_vdev =
		container_of(vdev, struct cca_vdevice, core);
	struct arm_smmu_realm_params params;
	struct cca_viommu *cca = to_cca_viommu(vdev->viommu);
	struct cca_psmmu *psmmu = cca->psmmu;
	struct device *dev = iommufd_vdevice_to_device(vdev);
	struct tsm_dev *tsm_dev = cca_viommu_tsm_dev(vdev->viommu);
	struct pci_tsm_context *context;
	struct pci_dev *pdev;
	struct pci_tsm_pf0 *pf0;
	struct pci_dev *dsm_dev;
	struct cca_host_tdi *host_tdi = &cca_vdev->host_tdi;
	struct kvm *kvm = vdev->viommu->kvm_file->private_data;
	void *rmm_vdev;
	int ret;

	if (!dev_is_pci(dev))
		return 0;
	/* Devices without a Link TSM remain ordinary vdevices. */
	pdev = to_pci_dev(dev);
	context = pci_tsm_context_get(pdev);
	if (IS_ERR(context)) {
		if (PTR_ERR(context) == -EOPNOTSUPP)
			return 0;
		return PTR_ERR(context);
	}
	if (pci_tsm_context_tsm_dev(context) != tsm_dev) {
		ret = -EXDEV;
		goto out_put_context;
	}

	ret = iommu_viommu_get_params(dev,
		IOMMU_VIOMMU_TYPE_ARM_REALM_SMMUV3, &params,
		sizeof(params));
	if (ret)
		goto out_put_context;
	if (params.psmmu_phys != psmmu->phys) {
		ret = -EINVAL;
		goto out_put_context;
	}

	host_tdi->kvm = kvm;
	INIT_LIST_HEAD(&host_tdi->dpt_regions);
	cca_vdev->l2_sid = params.l2_sid;
	pf0 = pci_tsm_context_pf0(context);
	dsm_dev = pci_tsm_context_dsm_dev(context);

	scoped_guard(mutex, &pf0->lock) {
		ret = cca_psmmu_create_l2(psmmu, params.l2_sid);
		if (!ret) {
			rmm_vdev = cca_vdev_create(host_tdi, &kvm->arch.realm,
						   pdev, dsm_dev, vdev->virt_id,
						   vdev->viommu->obj.id);
			if (IS_ERR_OR_NULL(rmm_vdev)) {
				ret = rmm_vdev ? PTR_ERR(rmm_vdev) : -ENOMEM;
				cca_psmmu_destroy_l2(psmmu, params.l2_sid, dev);
			}
		}
		if (!ret)
			pci_tsm_context_mark_bound(context);
	}
	if (ret)
		goto out_put_context;
	cca_vdev->tsm_context = context;
	vdev->destroy = cca_vdevice_destroy;
	return 0;

out_put_context:
	pci_tsm_context_put(context);
	return ret;
}

static ssize_t cca_vdevice_tsm_req(struct iommufd_vdevice *vdev,
				   struct tsm_guest_req_info *info,
				   u64 *tsm_code)
{
	struct cca_vdevice *cca_vdev =
		container_of(vdev, struct cca_vdevice, core);
	struct cca_host_tdi *host_tdi = &cca_vdev->host_tdi;
	struct pci_tsm_context *context = cca_vdev->tsm_context;
	struct pci_tsm_pf0 *pf0;
	struct pci_dev *pdev;

	(void)tsm_code;
	if (!context)
		return -EOPNOTSUPP;
	if (info->tvm_arch != IOMMU_VDEVICE_TSM_TVM_ARCH_CCA)
		return -EINVAL;
	if (info->req.is_kernel || info->resp.is_kernel)
		return -EINVAL;

	pdev = to_pci_dev(iommufd_vdevice_to_device(vdev));
	pf0 = pci_tsm_context_pf0(context);
	guard(mutex)(&pf0->lock);
	switch (info->op) {
	case TSM_REQ_VALIDATE_MMIO: {
		struct arm64_vdev_validate_mmio_guest_req req;

		if (info->req_len != sizeof(req))
			return -EINVAL;
		if (copy_from_sockptr(&req, info->req, sizeof(req)))
			return -EFAULT;
		return cca_vdev_device_map(host_tdi, pdev, req.gpa_base,
					  req.gpa_top, req.pa_base);
	}
	case TSM_REQ_SET_TDI_STATE: {
		struct arm64_vdev_set_tdi_state_guest_req req;
		int ret;

		if (info->req_len != sizeof(req))
			return -EINVAL;
		if (copy_from_sockptr(&req, info->req, sizeof(req)))
			return -EFAULT;
		switch (req.tdi_state) {
		case RHI_DA_TDI_CONFIG_UNLOCKED:
			ret = cca_vdevice_unmap(cca_vdev);
			if (ret)
				return ret;
			return cca_vdev_device_unlock(host_tdi, pdev);
		case RHI_DA_TDI_CONFIG_LOCKED:
			return cca_vdev_device_lock(host_tdi, pdev);
		case RHI_DA_TDI_CONFIG_RUN:
			return cca_vdev_device_start(host_tdi, pdev);
		default:
			return -EINVAL;
		}
	}
	case TSM_REQ_OBJECT_INFO: {
		struct arm64_vdev_object_size_guest_req req;
		int object_size;

		if (info->req_len != sizeof(req))
			return -EINVAL;
		if (copy_from_sockptr(&req, info->req, sizeof(req)))
			return -EFAULT;
		object_size = cca_vdev_get_object_size(host_tdi, pdev,
						       req.object_type);
		if (object_size <= 0)
			return object_size;
		if (info->resp_len < sizeof(object_size))
			return -EINVAL;
		if (copy_to_sockptr(info->resp, &object_size,
				    sizeof(object_size)))
			return -EFAULT;
		return info->resp_len - sizeof(object_size);
	}
	case TSM_REQ_READ_OBJECT: {
		struct arm64_vdev_object_read_guest_req req;
		int len;

		if (info->req_len != sizeof(req))
			return -EINVAL;
		if (copy_from_sockptr(&req, info->req, sizeof(req)))
			return -EFAULT;
		len = cca_vdev_read_cached_object(host_tdi, pdev,
						  req.object_type, req.offset,
						  info->resp_len,
						  info->resp.user);
		if (len <= 0)
			return len;
		return info->resp_len - len;
	}
	case TSM_REQ_REGEN_OBJECT: {
		struct arm64_vdev_object_regen_guest_req req;

		if (info->req_len != sizeof(req))
			return -EINVAL;
		if (copy_from_sockptr(&req, info->req, sizeof(req)))
			return -EFAULT;
		if (req.object_type == RHI_DA_OBJECT_INTERFACE_REPORT)
			return cca_vdev_update_interface_report(host_tdi, pdev);
		if (req.object_type == RHI_DA_OBJECT_MEASUREMENT)
			return cca_vdev_update_device_measurements(host_tdi, pdev,
							   req.flags,
							   (u8 *)req.nonce);
		return -EINVAL;
	}
	default:
		return -EINVAL;
	}
}

static const struct iommufd_viommu_ops cca_viommu_ops = {
	.destroy = cca_viommu_destroy,
	.vdevice_size = VDEVICE_STRUCT_SIZE(struct cca_vdevice, core),
	.vdevice_init = cca_vdevice_init,
	.vdevice_tsm_req = cca_vdevice_tsm_req,
};

size_t cca_viommu_get_size(struct device *dev, enum iommu_viommu_type type)
{
	struct arm_smmu_realm_params params;

	if (type != IOMMU_VIOMMU_TYPE_ARM_REALM_SMMUV3)
		return 0;
	if (iommu_viommu_get_params(dev, type, &params, sizeof(params)))
		return 0;
	return VIOMMU_STRUCT_SIZE(struct cca_viommu, core);
}

int cca_viommu_init(struct iommufd_viommu *viommu, struct device *dev,
		    struct iommu_domain *parent,
		    const struct iommu_user_data *user_data)
{
	struct iommu_viommu_arm_realm_vsmmuv3 arg = {};
	struct arm_smmu_realm_params params;
	struct cca_viommu *cca = to_cca_viommu(viommu);
	struct cca_psmmu *psmmu;
	struct kvm *kvm;
	int ret;

	if (viommu->type != IOMMU_VIOMMU_TYPE_ARM_REALM_SMMUV3)
		return -EOPNOTSUPP;
	if (!viommu->kvm_file)
		return -EINVAL;

	/*
	 * No user_data => PSMMU-only (VSMMU-off / no-iommu guest). With the
	 * VSMMU flag set, a guest-visible VSMMU is layered on the PSMMU below.
	 */
	if (user_data) {
		ret = iommu_copy_struct_from_user(&arg, user_data,
						  IOMMU_VIOMMU_TYPE_ARM_REALM_SMMUV3,
						  idr);
		if (ret)
			return ret;
	}
	if (arg.flags & ~IOMMU_VIOMMU_ARM_REALM_SMMUV3_FLAGS_VSMMU)
		return -EOPNOTSUPP;
	kvm = viommu->kvm_file->private_data;
	ret = kvm_realm_ensure_created(kvm);
	if (ret)
		return ret;

	ret = iommu_viommu_validate_parent(dev, viommu->type, parent);
	if (ret)
		return ret;
	ret = iommu_viommu_get_params(dev, viommu->type, &params,
				      sizeof(params));
	if (ret)
		return ret;

	psmmu = cca_psmmu_get(&params);
	if (IS_ERR(psmmu))
		return PTR_ERR(psmmu);

	/*
	 * PSMMU is now active for this device. If the guest wants a VSMMU,
	 * create it on top (per-viommu, keyed by viommu->obj.id). On failure,
	 * drop the PSMMU reference taken above.
	 */
	if (arg.flags & IOMMU_VIOMMU_ARM_REALM_SMMUV3_FLAGS_VSMMU) {
		struct rmi_vsmmu_params *vparams;
		int i;

		vparams = (struct rmi_vsmmu_params *)get_zeroed_page(GFP_KERNEL);
		if (!vparams) {
			ret = -ENOMEM;
		} else {
			vparams->reg_base = arg.reg_base;
			vparams->reg_top = arg.reg_top;
			vparams->aidr = arg.aidr;
			for (i = 0; i < ARRAY_SIZE(vparams->idr); i++)
				vparams->idr[i] = arg.idr[i];
			/*
			 * bet3 split the trailing IDR slot into SMMU_IIDR
			 * (RmiVsmmuParams §B4.6.109, FENIMORE-1601). It keeps the
			 * same byte offset (0x50) as the old idr[7] tail, so the
			 * iommufd uapi idr[7] layout is unchanged and existing
			 * user space keeps working; forward its last element.
			 */
			vparams->iidr = arg.idr[ARRAY_SIZE(vparams->idr)];

			ret = kvm_realm_register_vsmmu(kvm, viommu->obj.id,
						       vparams);
			free_page((unsigned long)vparams);
		}
		if (ret) {
			cca_psmmu_put(psmmu);
			return ret;
		}
	}

	cca->psmmu = psmmu;
	viommu->ops = &cca_viommu_ops;
	return 0;
}

MODULE_IMPORT_NS("IOMMUFD");
