// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 ARM Ltd.
 */

#include <linux/arm-smccc-rmi.h>
#include <linux/arm-smmu-v3.h>
#include <linux/interrupt.h>
#include <linux/msi.h>
#include <linux/tsm.h>

#include <asm/rmi_cmds.h>

#include "arm-smmu-v3.h"

/*
 * An RMI PSMMU L2 stream table occupies one RMI granule, so it holds
 * fewer STEs than the STRTAB_NUM_L2_STES this driver uses for its own
 * stream tables. The RMM sizes it the same way, with STRTAB_SPLIT = 6.
 */
#define RMI_STRTAB_NUM_L2_STES (PAGE_SIZE / sizeof(struct arm_smmu_ste))

#define	RMI_PSMMU_IRQ_PEND_GERROR	BIT(0)
#define	RMI_PSMMU_IRQ_PEND_EVENTQ	BIT(1)
#define	RMI_PSMMU_IRQ_PEND_PRIQ		BIT(2)
#define	RMI_PSMMU_IRQ_PEND_CMDQ		BIT(3)

#define	RMI_PSMMU_IRQ_EVENT_NONE	0
#define	RMI_PSMMU_IRQ_EVENT_ERROR	1
#define	RMI_PSMMU_IRQ_EVENT_PSMMU	2
#define	RMI_PSMMU_IRQ_EVENT_VSMMU	3
#define RMI_PSMMU_IRQ_EVENT_MASK	GENMASK(2, 1)
#define RMI_PSMMU_IRQ_EVENT_SHIFT	1
#define RMI_PSMMU_IRQ_EVENT_PENDING	0x1

#define	RMI_PSMMU_IRQ_GERROR	0
#define	RMI_PSMMU_IRQ_EVENTQ	1
#define	RMI_PSMMU_IRQ_PRIQ	2
#define	RMI_PSMMU_IRQ_CMDQ	3

/*
 * Return true if RMM did not consume the physical event and the caller must
 * discard it explicitly.
 */
static bool arm_smmu_realm_handle_vsmmu_event(
	struct arm_smmu_device *smmu, unsigned long event_irq,
	const struct rmi_psmmu_event_details *event)
{
	struct device *master_dev = NULL;
	struct arm_smmu_master *master;
	int ret;

	/* PRI support is added separately. */
	if (event_irq != RMI_PSMMU_IRQ_EVENTQ)
		return true;

	mutex_lock(&smmu->streams_mutex);
	master = arm_smmu_find_master(smmu, event->stream_id);
	if (master)
		master_dev = get_device(master->dev);
	mutex_unlock(&smmu->streams_mutex);

	if (!master_dev)
		return true;

	ret = tsm_vsmmu_event_handle(master_dev, smmu->base_phys);
	if (ret)
		dev_warn_ratelimited(smmu->dev, "VSMMU route failed: %d\n", ret);
	put_device(master_dev);

	return ret != 0;
}

static irqreturn_t arm_smmu_realm_notify_thread(int irq, void *dev)
{
	int rmi_psmmu_event;
	unsigned long notify_flags, psmmu_irq;
	struct arm_smmu_device *smmu = dev;
	struct rmi_psmmu_event_details event;
	bool consume;

	if (irq == smmu->realm.evtq_irq) {
		notify_flags =  RMI_PSMMU_IRQ_PEND_EVENTQ;
		psmmu_irq = RMI_PSMMU_IRQ_EVENTQ;
	} else if (irq == smmu->realm.gerr_irq) {
		notify_flags =  RMI_PSMMU_IRQ_PEND_GERROR;
		psmmu_irq = RMI_PSMMU_IRQ_GERROR;
	} else if (irq == smmu->realm.pri_irq) {
		notify_flags =  RMI_PSMMU_IRQ_PEND_PRIQ;
		psmmu_irq = RMI_PSMMU_IRQ_PRIQ;
	} else {
		return IRQ_HANDLED;
	}

	do {
		if (rmi_psmmu_irq_notify(smmu->base_phys,
					 notify_flags, &event)) {
			dev_warn(smmu->dev,
				 "failed to notify RMM of a SMMU event\n");
			/* there is nothing much we could do. Mark it handled. */
			return IRQ_HANDLED;
		}
		rmi_psmmu_event = (event.flags & RMI_PSMMU_IRQ_EVENT_MASK) >>
				  RMI_PSMMU_IRQ_EVENT_SHIFT;
		switch (rmi_psmmu_event) {
		case RMI_PSMMU_IRQ_EVENT_NONE:
			consume = false;
			break;
		case RMI_PSMMU_IRQ_EVENT_ERROR:
			dev_warn(smmu->dev, "SMMU Error reported\n");
			consume = true;
			break;
		case RMI_PSMMU_IRQ_EVENT_PSMMU:
			dev_warn(smmu->dev,
				 "SMMU event (event num: 0x%llx syndrome 0x%llx "
				 "fetch_addr 0x%llx input_addr 0x%llx) reported\n",
				 event.event_num, event.syndrome,
				 event.fetch_addr, event.input_addr);
			consume = true;
			break;
		case RMI_PSMMU_IRQ_EVENT_VSMMU:
			consume = arm_smmu_realm_handle_vsmmu_event(
				smmu, psmmu_irq, &event);
			break;
		}

		if (consume &&
		    rmi_psmmu_event_consume(smmu->base_phys, psmmu_irq)) {
			dev_warn(smmu->dev,
				 "failed to consume an RMM SMMU event\n");
			return IRQ_HANDLED;
		}
	} while (event.flags & RMI_PSMMU_IRQ_EVENT_PENDING);

	return IRQ_HANDLED;
}

void arm_smmu_setup_realm_irqs(struct arm_smmu_device *smmu)
{
	int irq, ret;

	irq = smmu->realm.evtq_irq;
	if (irq) {
		ret = devm_request_threaded_irq(smmu->dev, irq, NULL,
						arm_smmu_realm_notify_thread,
						IRQF_ONESHOT,
						"arm-smmu-v3-realm-evtq",
						smmu);
		if (ret < 0)
			dev_warn(smmu->dev, "failed to enable realm evtq irq\n");
	} else {
		dev_warn(smmu->dev, "no realm evtq irq - events will not be reported!\n");
	}

	irq = smmu->realm.gerr_irq;
	if (irq) {
		ret = devm_request_threaded_irq(smmu->dev, irq, NULL,
						arm_smmu_realm_notify_thread,
						IRQF_ONESHOT,
						"arm-smmu-v3-realm-gerror",
						smmu);
		if (ret < 0)
			dev_warn(smmu->dev, "failed to enable realm gerror irq\n");
	} else {
		dev_warn(smmu->dev, "no realm gerr irq - errors will not be reported!\n");
	}

	if (smmu->features & ARM_SMMU_FEAT_PRI) {
		irq = smmu->realm.pri_irq;
		if (irq) {

			ret = devm_request_threaded_irq(smmu->dev, irq, NULL,
							arm_smmu_realm_notify_thread,
							IRQF_ONESHOT,
							"arm-smmu-v3-realm-priq",
							smmu);
			if (ret < 0)
				dev_warn(smmu->dev,
					 "failed to enable realm priq irq\n");
		} else {
			dev_warn(smmu->dev, "no realm priq irq - PRI will be broken\n");
		}
	}
}

static int get_irq_data(int irq, u64 *msi_addr, u64 *msi_data)
{
	struct msi_desc *desc;

	desc = irq_get_msi_desc(irq);
	if (!desc)
		return -EINVAL;

	*msi_addr = (((u64)desc->msg.address_hi) << 32) | desc->msg.address_lo;
	*msi_data = desc->msg.data;
	return 0;
}

int arm_smmu_get_realm_params(struct device *dev,
			      struct arm_smmu_realm_params *params)
{
	struct arm_smmu_master *master = dev_iommu_priv_get(dev);
	struct arm_smmu_device *smmu;

	if (!master || !params)
		return -EINVAL;
	smmu = master->smmu;
	if (!(smmu->features & ARM_SMMU_FEAT_RME))
		return -EOPNOTSUPP;

	memset(params, 0, sizeof(*params));
	params->psmmu_phys = smmu->base_phys;
	params->l2_sid = ALIGN_DOWN(master->streams[0].id,
				    RMI_STRTAB_NUM_L2_STES);

	/*
	 * Request ATS only if the SMMU, the RMM and the PSMMU all support it.
	 * PRI remains disabled.
	 */
	if ((smmu->features & ARM_SMMU_FEAT_ATS) &&
	    rmm_has_reg2_feature(RMI_FEATURE_REGISTER_2_ATS) &&
	    (smmu->realm.flags & RMI_PSMMU_ATS))
		params->irq_flags |= RMI_PSMMU_ATS;

	if ((smmu->realm.flags & RMI_PSMMU_IRQCFG_MASK) ==
	    RMI_PSMMU_IRQCFG_IRQ_DISABLED)
		return 0;

	if (!(smmu->features & ARM_SMMU_FEAT_RME_MSI)) {
		params->irq_flags |= RMI_PSMMU_IRQCFG_IRQ_WIRED;
		return 0;
	}

	params->irq_flags |= RMI_PSMMU_IRQCFG_IRQ_MSI;
	if (get_irq_data(smmu->realm.gerr_irq,
			 &params->gerr_addr, &params->gerr_data))
		return -EINVAL;
	if (get_irq_data(smmu->realm.evtq_irq,
			 &params->eventq_addr, &params->eventq_data))
		return -EINVAL;
	/*
	 * RMI_PSMMU_ACTIVATE validates every MSI doorbell in MSI mode, even
	 * with PRI disabled. Point the PRIQ at the event queue doorbell.
	 */
	params->priq_addr = params->eventq_addr;
	params->priq_data = params->eventq_data;
	return 0;
}
