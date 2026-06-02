// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 ARM Ltd.
 */

#include <linux/arm-rsi-cmds.h>
#include <linux/kstrtox.h>
#include <linux/mem_encrypt.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <crypto/hash.h>

#include "rsi-da.h"
#include "rhi-da.h"

int cca_device_lock(struct pci_dev *pdev)
{
	int ret;

	ret = rhi_vdev_set_tdi_state(pdev, RHI_DA_TDI_CONFIG_LOCKED);
	if (ret) {
		pci_err(pdev, "failed to lock the device (%d)\n", ret);
		return ret;
	}
	return 0;
}

int cca_device_unlock(struct pci_dev *pdev)
{
	int ret;

	ret = rhi_vdev_set_tdi_state(pdev, RHI_DA_TDI_CONFIG_UNLOCKED);
	if (ret) {
		pci_err(pdev, "failed to unlock the device (%d)\n", ret);
		return ret;
	}
	return 0;
}

struct page *alloc_shared_pages(int nid, gfp_t gfp_mask, unsigned long min_size)
{
	int ret;
	struct page *page;
	int page_order = get_order(mem_cc_align_to_shared_granule(min_size));

	page = alloc_pages_node(nid, gfp_mask | __GFP_ZERO, page_order);
	if (!page)
		return NULL;

	ret = set_memory_decrypted((unsigned long)page_address(page),
				   1 << page_order);
	/*
	 * If set_memory_decrypted() fails then we don't know what state the
	 * page is in, so we can't free it. Instead we leak it.
	 * set_memory_decrypted() will already have WARNed.
	 */
	if (ret)
		return NULL;

	return page;
}

int free_shared_pages(struct page *page, unsigned long size)
{
	int ret;
	/* We should normalize the size based on hypervisor page size */
	int page_order = get_order(mem_cc_align_to_shared_granule(size));

	ret = set_memory_encrypted((unsigned long)page_address(page), 1 << page_order);
	/* If we fail to mark it encrypted don't free it back */
	if (ret)
		return ret;

	__free_pages(page, page_order);
	return 0;
}

int cca_update_device_object_cache(struct pci_dev *pdev, const u8 *nonce)
{
	int ret;

	ret = rhi_update_vdev_interface_report_cache(pdev);
	if (ret) {
		pci_err(pdev, "failed to get interface report (%d)\n", ret);
		return ret;
	}

	return rhi_update_vdev_measurements_cache(pdev, nonce);
}

/*
 * IPA span requested per device-mapping call. The host services one validate
 * request by mapping the whole span and one invalidate request by unmapping
 * and undelegating it, so the span decides how long a single call keeps the
 * host busy on this vCPU's behalf -- a BAR asked for in one piece can be
 * hundreds of GiB.
 *
 * The host also picks its device block size within the span it is handed, so
 * a value >= SZ_1G keeps 1GiB device blocks reachable while a smaller one
 * caps them at that size. Must be a power of two and at least SZ_2M.
 */
static unsigned long dev_mem_chunk_size = SZ_1G;

static int dev_mem_chunk_size_set(const char *val,
				  const struct kernel_param *kp)
{
	unsigned long size;
	int ret;

	ret = kstrtoul(val, 0, &size);
	if (ret)
		return ret;

	if (size < SZ_2M || (size & (size - 1)))
		return -EINVAL;

	*(unsigned long *)kp->arg = size;
	return 0;
}

static const struct kernel_param_ops dev_mem_chunk_size_ops = {
	.set = dev_mem_chunk_size_set,
	.get = param_get_ulong,
};
module_param_cb(dev_mem_chunk_size, &dev_mem_chunk_size_ops,
		&dev_mem_chunk_size, 0644);
MODULE_PARM_DESC(dev_mem_chunk_size,
		 "IPA bytes per device mapping validate/invalidate call (power of two, >= 2MiB); >= 1GiB keeps 1GiB device blocks");

static phys_addr_t dev_mem_chunk_end(phys_addr_t ipa, phys_addr_t end_ipa)
{
	unsigned long chunk = READ_ONCE(dev_mem_chunk_size);

	return min_t(phys_addr_t, end_ipa, ALIGN_DOWN(ipa, chunk) + chunk);
}

static inline int
rsi_validate_dev_mapping(unsigned long vdev_id, phys_addr_t start_ipa,
		phys_addr_t end_ipa, phys_addr_t io_pa,
		unsigned long flags, unsigned long lock_seq,
		unsigned long meas_seq, unsigned long report_seq)
{
	unsigned long ret;
	phys_addr_t next_ipa;

	while (start_ipa < end_ipa) {
		phys_addr_t chunk_end = dev_mem_chunk_end(start_ipa, end_ipa);

		ret = rsi_vdev_validate_mapping(vdev_id, start_ipa, chunk_end,
						io_pa, &next_ipa, flags,
						lock_seq, meas_seq, report_seq);
		if (ret || next_ipa <= start_ipa || next_ipa > chunk_end)
			return -EINVAL;
		io_pa += next_ipa - start_ipa;
		start_ipa = next_ipa;

		cond_resched();
	}
	return 0;
}

static inline int rsi_invalidate_dev_mapping(phys_addr_t start_ipa, phys_addr_t end_ipa)
{
	while (start_ipa < end_ipa) {
		phys_addr_t chunk_end = dev_mem_chunk_end(start_ipa, end_ipa);
		int ret = rsi_set_memory_range(start_ipa, chunk_end,
					       RSI_RIPAS_EMPTY,
					       RSI_CHANGE_DESTROYED);

		if (ret)
			return ret;
		start_ipa = chunk_end;

		cond_resched();
	}
	return 0;
}

static int cca_apply_evidence_report_range(struct pci_dev *pdev,
		struct pci_tsm_mmio *mmio, bool map)
{
	int i, ret;
	struct resource *res;
	int vdev_id = rsi_vdev_id(pdev);
	struct pci_tsm_mmio_entry *entry;
	struct cca_guest_dsc *dsc = to_cca_guest_dsc(pdev);

	for (i = 0; i < mmio->nr; i++) {
		entry = pci_tsm_mmio_entry(mmio, i);
		res = &entry->res;

		if (res->desc != IORES_DESC_ENCRYPTED)
			continue;

		if (map) {
			unsigned long mmio_flags = 0; /* not limited order */

			if (entry->flags & PCI_TSM_MMIO_F_COHERENT)
				mmio_flags |= RSI_DEV_MEM_COHERENT;

			ret = rsi_validate_dev_mapping(vdev_id, res->start,
						       res->end + 1, entry->tsm_offset,
						       mmio_flags,
						       dsc->dev_info.lock_seq,
						       dsc->dev_info.meas_seq,
						       dsc->dev_info.report_seq);
		} else {
			ret = rsi_invalidate_dev_mapping(res->start, res->end + 1);
		}
		if (ret)
			goto err_rollback;
	}
	return 0;

err_rollback:
	if (!map)
		return ret;

	/*
	 * Best-effort rollback. The failed entry is included, as the host
	 * may have validated part of it before rejecting the rest.
	 */
	for (; i >= 0; i--) {
		entry = pci_tsm_mmio_entry(mmio, i);
		res = &entry->res;
		if (res->desc != IORES_DESC_ENCRYPTED)
			continue;
		rsi_invalidate_dev_mapping(res->start, res->end + 1);
	}
	return ret;
}

int cca_map_evidence_report_range(struct pci_dev *pdev, struct pci_tsm_mmio *mmio)
{
	return cca_apply_evidence_report_range(pdev, mmio, true);
}

int cca_unmap_evidence_report_range(struct pci_dev *pdev)
{
	struct cca_guest_dsc *dsc = to_cca_guest_dsc(pdev);
	struct pci_tsm_mmio *tsm_mmio = dsc->pci.mmio;

	if (!tsm_mmio)
		return 0;

	return cca_apply_evidence_report_range(pdev, tsm_mmio, false);
}

int cca_verify_digest(u64 hash_algo, uint8_t *report,
		size_t report_size, uint8_t *report_digest)
{
	u8 digest[SHA512_DIGEST_SIZE];
	size_t digest_size;
	void (*digest_func)(const u8 *data, size_t len, u8 *out);

	switch (hash_algo) {
	case RSI_HASH_SHA_256:
		digest_func = sha256;
		digest_size = SHA256_DIGEST_SIZE;
		break;
	case RSI_HASH_SHA_512:
		digest_func = sha512;
		digest_size = SHA512_DIGEST_SIZE;
		break;
	case RSI_HASH_SHA_384:
		digest_func = sha384;
		digest_size = SHA384_DIGEST_SIZE;
		break;
	default:
		return -EINVAL;
	}

	digest_func(report, report_size, digest);
	if (memcmp(report_digest, digest, digest_size))
		return -EINVAL;

	return 0;
}

int cca_verify_digests(u64 hash_algo,
		uint8_t *certificate, size_t certificate_size,
		uint8_t *vca, size_t vca_size,
		uint8_t *interface_report, size_t interface_report_size,
		uint8_t *measurements, size_t measurements_size,
		struct rsi_vdevice_info *dev_info)
{
	int ret;
	struct {
		uint8_t *report;
		size_t size;
		uint8_t *digest;
	} reports[] = {
		{
			certificate,
			certificate_size,
			dev_info->identity_digest
		},
		{
			vca,
			vca_size,
			dev_info->protocol_data_digest
		},
		{
			interface_report,
			interface_report_size,
			dev_info->report_digest
		},
		{
			measurements,
			measurements_size,
			dev_info->meas_digest
		}

	};

	for (int i = 0; i < ARRAY_SIZE(reports); i++) {
		ret = cca_verify_digest(hash_algo, reports[i].report,
					reports[i].size, reports[i].digest);
		if (ret)
			return ret;
	}
	return 0;
}

static inline int rsi_vdev_enable_dma(int vdev_id, struct dsm_device_info *dev_info)
{
	unsigned long flags = 0;
	unsigned long ret;

	if (rsi_has_ats_feature())
		flags |= RSI_VDEV_DMA_FLAGS_ATS;

	do {
		ret = __rsi_vdev_dma_enable(vdev_id, flags, 0, dev_info->lock_seq,
					    dev_info->meas_seq,
					    dev_info->report_seq);
		cond_resched();
	} while (ret == RSI_INCOMPLETE);

	return ret;
}

int cca_device_disable_dma(struct pci_dev *pdev)
{
	unsigned long ret;

	do {
		ret = rsi_vdev_dma_disable(rsi_vdev_id(pdev));
		cond_resched();
	} while (ret == RSI_INCOMPLETE);

	return ret;
}

/*
 * The host may have relocked the device or refreshed its evidence since
 * the guest collected it. Re-read RsiVdevInfo so that mappings and DMA are
 * never accepted against stale lock, measurement or report sequences.
 */
static int cca_vdev_check_fresh_info(struct pci_dev *pdev,
				     unsigned long lock_seq,
				     struct dsm_device_info *cached)
{
	struct rsi_vdevice_info *info __free(kfree) =
		kmalloc_obj(struct rsi_vdevice_info);

	if (!info)
		return -ENOMEM;

	if (rsi_vdev_get_info(rsi_vdev_id(pdev), virt_to_phys(info))) {
		pci_err(pdev, "failed to refresh device information\n");
		return -EIO;
	}

	if (info->lock_seq != lock_seq ||
	    info->lock_seq != cached->lock_seq ||
	    info->meas_seq != cached->meas_seq ||
	    info->report_seq != cached->report_seq) {
		pci_err(pdev, "Device evidence generation mismatch\n");
		return -EIO;
	}

	return 0;
}

int cca_device_accept(struct pci_dev *pdev, unsigned long lock_seq)
{
	int ret;
	struct pci_tsm_mmio *tsm_mmio;
	u16 cmd;
	int vdev_id = rsi_vdev_id(pdev);
	struct cca_guest_dsc *dsc = to_cca_guest_dsc(pdev);

	ret = cca_vdev_check_fresh_info(pdev, lock_seq, &dsc->dev_info);
	if (ret)
		return ret;

	if (dsc->pci.mmio)
		return -EBUSY;

	/* Allocation private mmio range based on interface report. */
	tsm_mmio = pci_tsm_mmio_alloc(pdev);
	if (!tsm_mmio) {
		pci_err(pdev, "Protected mmio range allocation failure\n");
		return -ENOMEM;
	}

	/*
	 * Present the private mmio range in the resource hierarchy.
	 * We don't use this for ioremap, ioremap check the RIPAS value.
	 */
	ret = pci_tsm_mmio_setup(pdev, tsm_mmio);
	if (ret) {
		pci_err(pdev, "Protected mmio setup failure\n");
		goto err_mmio_setup;
	}
	/*
	 * Past this point any failure must unwind via the err_* labels so
	 * iomem and RSI mapping state are reverted before returning.
	 */
	dsc->pci.mmio = tsm_mmio;

	/*
	 * Accept runs with no driver bound, so nothing has enabled memory
	 * decode on the device. Set PCI_COMMAND_MEMORY so the assigned device's
	 * BARs respond to memory accesses.
	 *
	 * The host does not trust a guest-supplied PA for the protected
	 * mapping: it derives the PA itself by faulting in the VMM's mapping of
	 * the IPA (realm_dev_faultin_pfn() -> __kvm_faultin_pfn()) and rejects
	 * anything that is not device MMIO the VMM already mapped (no memslot,
	 * poisoned pages, or ordinary system RAM), then requires the whole
	 * range to be physically contiguous (realm_dev_verify_run()). That
	 * faultin only succeeds while the device decodes memory: vfio-pci gates
	 * it on __vfio_pci_memory_enabled(), so with MSE clear
	 * vfio_pci_vmf_insert_pfn() returns VM_FAULT_SIGBUS, the host resolves
	 * no PFN, and the mapping below fails.
	 */
	pci_read_config_word(pdev, PCI_COMMAND, &cmd);
	if (!(cmd & PCI_COMMAND_MEMORY))
		pci_write_config_word(pdev, PCI_COMMAND, cmd | PCI_COMMAND_MEMORY);

	ret = cca_map_evidence_report_range(pdev, dsc->pci.mmio);
	if (ret) {
		pci_err(pdev, "failed to validate the interface report\n");
		goto err_teardown;
	}

	ret = rhi_vdev_set_tdi_state(pdev, RHI_DA_TDI_CONFIG_RUN);
	if (ret) {
		pci_err(pdev, "failed to switch the device (%u) to RUN state\n", ret);
		goto err_unmap;
	}

	if (rsi_vdev_enable_dma(vdev_id, &dsc->dev_info)) {
		pci_err(pdev, "failed to enable DMA from the device\n");
		ret = -EIO;
		goto err_run;
	}

	return 0;

err_run:
	if (rhi_vdev_set_tdi_state(pdev, RHI_DA_TDI_CONFIG_LOCKED))
		pci_err(pdev, "failed to revert the device to LOCKED state\n");
err_unmap:
	if (cca_unmap_evidence_report_range(pdev))
		pci_err(pdev, "failed to invalidate the interface report\n");
err_teardown:
	pci_tsm_mmio_teardown(tsm_mmio);
	dsc->pci.mmio = NULL;
err_mmio_setup:
	pci_tsm_mmio_free(pdev, tsm_mmio);
	return ret;
}
