/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_ARM_SMMU_V3_H
#define _LINUX_ARM_SMMU_V3_H

#include <linux/types.h>

/* Kernel parameter buffer for IOMMU_VIOMMU_TYPE_ARM_REALM_SMMUV3 support. */
struct arm_smmu_realm_params {
	phys_addr_t psmmu_phys;
	u32 l2_sid;
	u64 irq_flags;
	u64 gerr_addr;
	u64 gerr_data;
	u64 eventq_addr;
	u64 eventq_data;
	u64 priq_addr;
	u64 priq_data;
};

#endif /* _LINUX_ARM_SMMU_V3_H */
