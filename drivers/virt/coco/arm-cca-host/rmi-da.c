// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 ARM Ltd.
 */

#include <linux/arm-rmi-cmds.h>
#include <linux/pci.h>
#include <linux/pci-ecam.h>
#include <linux/pci-doe.h>
#include <linux/delay.h>
#include <crypto/internal/rsa.h>
#include <keys/asymmetric-type.h>
#include <keys/x509-parser.h>
#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <asm/rmi_cmds.h>
#include <asm/kvm_rmi.h>

#include "rmi-da.h"

/*
 * RmiPdevParams.hb_base is the PCI segment's bus-0 ECAM base. The config
 * window associated with a subordinate bus may begin at a non-zero bus, so
 * account for that offset explicitly.
 */
static u64 cca_pdev_ecam_base(struct pci_dev *pdev)
{
	struct pci_bus *root = pdev->bus;
	struct pci_config_window *cfg;

	while (root->parent)
		root = root->parent;

	cfg = root->sysdata;
	return cfg->res.start - ((u64)cfg->busr.start << cfg->bus_shift);
}

static int init_pdev_params(struct pci_dev *pdev, struct rmi_pdev_params *params)
{
	int rid;
	unsigned long category;

	/* check we are ECAM compliant */
	if (!pdev->bus->ops->map_bus)
		return -EINVAL;

	switch (pci_pcie_type(pdev)) {
	case PCI_EXP_TYPE_ENDPOINT: {
		struct cca_host_pf0_ep_dsc *pf0_ep_dsc = to_cca_pf0_ep_dsc(pdev);

		/* Endpoint needs DOE mailbox */
		if (!pf0_ep_dsc->pci.doe_mb)
			return -EINVAL;

		params->flags = RMI_PDEV_FLAGS_SPDM;
		category = RMI_PDEV_FLAGS_CATEGORY_OFF_CHIP_EP;
		break;
	}
	case PCI_EXP_TYPE_ROOT_PORT: {
		category = RMI_PDEV_FLAGS_CATEGORY_ROOT_PORT;
		break;
	}
	case PCI_EXP_TYPE_RC_END: {
		struct cca_host_pf0_ep_dsc *pf0_ep_dsc = to_cca_pf0_ep_dsc(pdev);

		/* Use SPDM if present */
		if (pf0_ep_dsc->pci.doe_mb)
			params->flags = RMI_PDEV_FLAGS_SPDM;

		category = RMI_PDEV_FLAGS_CATEGORY_ON_CHIP_EP;
		break;
	}
	default:
		return -EINVAL;
	}

	params->flags |= (category << RMI_PDEV_FLAGS_CATEGORY_SHIFT);
	rid = pci_dev_id(pdev);
	params->hb_base = cca_pdev_ecam_base(pdev);
	params->pdev_id = rid;
	params->routing_id = pci_domain_nr(pdev->bus);
	/* slot number for certificate chain default to zero */
	params->id_index = 0;
	params->hash_algo = RMI_HASH_SHA_256;
	if (category == RMI_PDEV_FLAGS_CATEGORY_ROOT_PORT) {
		params->rid_base = 0;
		params->rid_top = 0;
	} else {
		params->rid_base = rid;
		params->rid_top = rid + 1;
	}
	return 0;
}

static inline int rmi_pdev_create(unsigned long pdev_phys,
		unsigned long pdev_params_phys, unsigned long *rmi_ret)
{
	struct rmi_sro_state *sro __free(kfree) = kzalloc_obj(*sro);
	if (!sro)
		return -ENOMEM;

	sro->regs = (struct arm_smccc_1_2_regs){
		SMC_RMI_PDEV_CREATE, pdev_phys, pdev_params_phys
	};
	*rmi_ret = rmi_sro_execute(sro, GFP_KERNEL, NULL);
	rmi_sro_free(sro);

	return 0;
}

int cca_pdev_create(struct pci_dev *pci_dev)
{
	int ret;
	void *rmm_pdev;
	bool should_free = true;
	phys_addr_t rmm_pdev_phys;
	struct rmi_pdev_params *params;
	struct cca_host_pdev_dsc *pdev_dsc = to_cca_pdev_dsc(pci_dev);

	rmm_pdev = (void *)get_zeroed_page(GFP_KERNEL);
	if (!rmm_pdev)
		return -ENOMEM;

	rmm_pdev_phys = virt_to_phys(rmm_pdev);
	if (rmi_delegate_page(rmm_pdev_phys)) {
		ret = -EIO;
		goto err_granule_delegate;
	}

	params = (struct rmi_pdev_params *)get_zeroed_page(GFP_KERNEL);
	if (!params) {
		ret = -ENOMEM;
		goto err_param_alloc;
	}

	ret = init_pdev_params(pci_dev, params);
	if (ret)
		goto err_init_pdev_params;

	{
		unsigned long rmi_ret;

		ret = rmi_pdev_create(rmm_pdev_phys, virt_to_phys(params),
				      &rmi_ret);
		if (ret || rmi_ret) {
			if (!ret)
				ret = -EIO;
			goto err_init_pdev_params;
		}
	}

	pdev_dsc->rmm_pdev = rmm_pdev;
	free_page((unsigned long)params);
	return 0;

err_init_pdev_params:
	free_page((unsigned long)params);
err_param_alloc:
	if (rmi_undelegate_page(rmm_pdev_phys))
		should_free = false;
err_granule_delegate:
	if (should_free)
		free_page((unsigned long)rmm_pdev);
	return ret;
}

static int doe_send_req_resp(struct pci_tsm *tsm)
{
	int data_obj_type;
	struct cca_host_comm_data *comm_data = to_cca_comm_data(tsm->pdev);
	struct rmi_dev_comm_exit *io_exit = &comm_data->io_params->exit;
	u8 protocol = io_exit->protocol;

	if (protocol == RMI_PROTOCOL_SPDM)
		data_obj_type = PCI_DOE_FEATURE_CMA;
	else if (protocol == RMI_PROTOCOL_SECURE_SPDM)
		data_obj_type = PCI_DOE_FEATURE_SSESSION;
	else
		return -EINVAL;

	/* delay the send */
	if (io_exit->req_delay)
		fsleep(io_exit->req_delay);

	return pci_tsm_doe_transfer(tsm->dsm_dev, data_obj_type,
				    comm_data->req_buff, io_exit->req_len,
				    comm_data->rsp_buff, PAGE_SIZE);
}

static inline bool pending_dev_communicate(struct rmi_dev_comm_exit *io_exit)
{
	bool pending = io_exit->flags & (RMI_DEV_COMM_EXIT_CACHE_REQ |
					 RMI_DEV_COMM_EXIT_CACHE_RSP |
					 RMI_DEV_COMM_EXIT_SEND |
					 RMI_DEV_COMM_EXIT_WAIT |
					 RMI_DEV_COMM_EXIT_MULTI);
	return pending;
}

static inline gfp_t cache_obj_id_to_gfp_flags(u8 cache_obj_id)
{
	/* These two cache objects are system objects. */
	if (cache_obj_id == RMI_DEV_VCA || cache_obj_id == RMI_DEV_CERTIFICATE)
		return GFP_KERNEL;
	/* rest are per TDI which is associated to a VM */
	return GFP_KERNEL_ACCOUNT;
}

static int _do_dev_communicate(enum dev_comm_type type, struct pci_tsm *tsm,
			       struct cca_host_tdi *host_tdi,
			       int *stream_wait)
{
	unsigned long rmi_ret;
	gfp_t cache_alloc_flags;
	int nbytes, cp_len;
	struct cache_object **cache_objp, *cache_obj;
	struct cca_host_pdev_dsc *pdev_dsc = to_cca_pdev_dsc(tsm->dsm_dev);
	struct cca_host_comm_data *comm_data = to_cca_comm_data(tsm->pdev);
	struct rmi_dev_comm_enter *io_enter = &comm_data->io_params->enter;
	struct rmi_dev_comm_exit *io_exit = &comm_data->io_params->exit;

redo_communicate:

	if (type == PDEV_COMMUNICATE)
		rmi_ret = rmi_pdev_communicate(virt_to_phys(pdev_dsc->rmm_pdev),
					       virt_to_phys(comm_data->io_params));
	else
		rmi_ret = rmi_vdev_communicate(virt_to_phys(host_tdi->realm->rd),
					       virt_to_phys(pdev_dsc->rmm_pdev),
					       virt_to_phys(host_tdi->rmm_vdev),
					       virt_to_phys(comm_data->io_params));
	if (rmi_ret != RMI_SUCCESS) {
		if (rmi_ret == RMI_BUSY)
			return -EBUSY;
		return -EIO;
	}

	if (io_exit->flags & RMI_DEV_COMM_EXIT_CACHE_REQ ||
	    io_exit->flags & RMI_DEV_COMM_EXIT_CACHE_RSP) {
		struct cca_host_pf0_ep_dsc *pf0_ep_dsc = to_cca_pf0_ep_dsc(tsm->dsm_dev);

		if (!pf0_ep_dsc) {
			WARN(1,
			     "Device communication got cache request on wrong device\n");
			return -EINVAL;
		}

		switch (io_exit->cache_object_id) {
		case RMI_DEV_VCA:
			cache_objp = &pf0_ep_dsc->vca;
			break;
		case RMI_DEV_CERTIFICATE:
			cache_objp = &pf0_ep_dsc->cert_chain.cache;
			break;
		case RMI_DEV_INTERFACE_REPORT:
			cache_objp = &host_tdi->interface_report;
			break;
		case RMI_DEV_MEASUREMENTS:
			cache_objp = &host_tdi->measurements;
			break;
		default:
			return -EINVAL;
		}
		cache_obj = *cache_objp;
		cache_alloc_flags = cache_obj_id_to_gfp_flags(io_exit->cache_object_id);
		int cache_remaining;

		if (io_exit->flags & RMI_DEV_COMM_EXIT_CACHE_REQ)
			cp_len = io_exit->req_cache_len;
		else
			cp_len = io_exit->rsp_cache_len;

		/* response and request len should be <= SZ_4k */
		if (cp_len > CACHE_CHUNK_SIZE)
			return -EINVAL;

		/* new allocation */
		if (!cache_obj) {
			int obj_size = struct_size(cache_obj, buf,
						   CACHE_CHUNK_SIZE);

			cache_obj = kvmalloc(obj_size, cache_alloc_flags);
			if (!cache_obj)
				return -ENOMEM;

			cache_obj->size = CACHE_CHUNK_SIZE;
			cache_obj->offset = 0;
			*cache_objp = cache_obj;
		}

		cache_remaining = cache_obj->size - cache_obj->offset;
		if (cp_len > cache_remaining) {
			struct cache_object *new_obj;
			int new_size = struct_size(cache_obj, buf,
						   cache_obj->size +
						   CACHE_CHUNK_SIZE);

			if (cache_obj->size + CACHE_CHUNK_SIZE > MAX_CACHE_OBJ_SIZE)
				return -EINVAL;

			new_obj = kvrealloc(cache_obj, new_size, cache_alloc_flags);
			if (!new_obj)
				return -ENOMEM;
			new_obj->size = cache_obj->size + CACHE_CHUNK_SIZE;
			*cache_objp = new_obj;
		}

		/* cache object can change above. */
		cache_obj = *cache_objp;
	}


	if (io_exit->flags & RMI_DEV_COMM_EXIT_CACHE_REQ) {
		memcpy(cache_obj->buf + cache_obj->offset,
		       (comm_data->req_buff + io_exit->req_cache_offset), io_exit->req_cache_len);
		cache_obj->offset += io_exit->req_cache_len;
	}

	if (io_exit->flags & RMI_DEV_COMM_EXIT_CACHE_RSP) {
		memcpy(cache_obj->buf + cache_obj->offset,
		       (comm_data->rsp_buff + io_exit->rsp_cache_offset), io_exit->rsp_cache_len);
		cache_obj->offset += io_exit->rsp_cache_len;
	}

	/*
	 * wait for last packet request from RMM.
	 * We should not find this because our device communication is synchronous
	 */
	if (io_exit->flags & RMI_DEV_COMM_EXIT_WAIT)
		return -EIO;

	/* next packet to send */
	if (io_exit->flags & RMI_DEV_COMM_EXIT_SEND) {
		nbytes = doe_send_req_resp(tsm);
		if (nbytes < 0) {
			/* report error back to RMM */
			io_enter->status = RMI_DEV_COMM_ERROR;
		} else {
			/* send response back to RMM */
			io_enter->resp_len = nbytes;
			io_enter->status = RMI_DEV_COMM_RESPONSE;
		}
	} else {
		/* no data transmitted => no data received */
		io_enter->resp_len = 0;
		io_enter->status = RMI_DEV_COMM_NONE;
	}

	if (pending_dev_communicate(io_exit))
		goto redo_communicate;

	if (io_exit->flags & RMI_DEV_COMM_EXIT_STREAM_WAIT) {
		if (stream_wait)
			*stream_wait = 1;
		else
			WARN(1, "Unexpected Stream wait status\n");
	}
	return 0;
}

/*
 * RMI_BUSY is a transient refusal (DEN0137 SSRHCJ), not a device error: retry
 * until it clears, aborting only if it makes no progress for this long.
 */
#define CCA_DEV_COMM_BUSY_TIMEOUT_MS	10000U

static int do_dev_communicate(enum dev_comm_type type,
		struct pci_tsm *tsm, struct cca_host_tdi *host_tdi,
		unsigned long error_state, int *stream_wait)
{
	int ret, state;
	unsigned long rmi_ret;
	unsigned long busy_deadline = jiffies +
			msecs_to_jiffies(CCA_DEV_COMM_BUSY_TIMEOUT_MS);
	struct rmi_dev_comm_enter *io_enter;
	struct cca_host_pdev_dsc *pdev_dsc = to_cca_pdev_dsc(tsm->dsm_dev);

	io_enter = &pdev_dsc->comm_data.io_params->enter;
	io_enter->resp_len = 0;
	io_enter->status = RMI_DEV_COMM_NONE;
	if (stream_wait)
		*stream_wait = 0;

	ret = _do_dev_communicate(type, tsm, host_tdi, stream_wait);
	while (ret == -EBUSY && time_before(jiffies, busy_deadline)) {
		cond_resched();
		ret = _do_dev_communicate(type, tsm, host_tdi, stream_wait);
	}
	if (ret) {
		state = error_state;
	} else {
		/*
		 * Some device communication error will transition the
		 * device to error state. Report that.
		 */
		if (type == PDEV_COMMUNICATE)
			rmi_ret = rmi_pdev_get_state(virt_to_phys(pdev_dsc->rmm_pdev),
						     (enum rmi_pdev_state *)&state);
		else
			rmi_ret = rmi_vdev_get_state(virt_to_phys(host_tdi->rmm_vdev),
						     (enum rmi_vdev_state *)&state);
		if (rmi_ret)
			state = error_state;
	}

	if (state == error_state) {
		/*
		 * A successful communicate call can still leave the device in
		 * an error state after an SPDM failure. Only abort returns the
		 * communication state to idle so teardown can make progress.
		 */
		if (type == PDEV_COMMUNICATE)
			rmi_pdev_abort(virt_to_phys(pdev_dsc->rmm_pdev));
		else
			rmi_vdev_abort(virt_to_phys(host_tdi->realm->rd),
				       virt_to_phys(pdev_dsc->rmm_pdev),
				       virt_to_phys(host_tdi->rmm_vdev));

		pci_err(tsm->pdev, "device communication error\n");
	}

	return state;
}

static int wait_for_dev_state(enum dev_comm_type type, struct pci_tsm *tsm,
		struct cca_host_tdi *host_tdi, unsigned long target_state,
		unsigned long error_state)
{
	int state, prev_state = -1;

	do {
		state = do_dev_communicate(type, tsm, host_tdi, error_state, NULL);

		if (state == target_state || state == error_state)
			return state;

		/*
		 * do_dev_communicate() returns only once the round is complete
		 * (RmiDevCommExitFlags clear), so an unchanged non-terminal
		 * state means the RMM is parked awaiting an out-of-band Host
		 * action this generic waiter cannot supply (e.g. a KROU
		 * refresh/purge). Re-polling is deterministic and will not
		 * advance, so give up rather than spin.
		 */
		if (state == prev_state) {
			pci_err(tsm->pdev,
				"device parked in state %d waiting for %lu, no pending communication; giving up\n",
				state, target_state);
			return error_state;
		}
		prev_state = state;
		cond_resched();
	} while (1);

	/* can't reach */
	return error_state;
}

static int wait_for_pdev_state(struct pci_tsm *tsm, enum rmi_pdev_state target_state)
{
	return wait_for_dev_state(PDEV_COMMUNICATE, tsm, NULL, target_state,
				  RMI_PDEV_ERROR);
}

static int wait_for_vdev_state(struct pci_tsm *tsm,
			       struct cca_host_tdi *host_tdi,
			       enum rmi_vdev_state target_state)
{
	return wait_for_dev_state(VDEV_COMMUNICATE, tsm, host_tdi,
				  target_state, RMI_VDEV_ERROR);
}

static int parse_certificate_chain(struct pci_tsm *tsm)
{
	struct cca_host_pf0_ep_dsc *pf0_ep_dsc;
	unsigned int chain_size;
	unsigned int offset = 0;
	u8 *chain_data;

	pf0_ep_dsc = to_cca_pf0_ep_dsc(tsm->pdev);

	/* If device communication didn't results in certificate caching. */
	if (!pf0_ep_dsc->cert_chain.cache || !pf0_ep_dsc->cert_chain.cache->offset)
		return -EINVAL;

	chain_size = pf0_ep_dsc->cert_chain.cache->offset;
	chain_data = pf0_ep_dsc->cert_chain.cache->buf;

	while (offset < chain_size) {
		ssize_t cert_len =
			x509_get_certificate_length(chain_data + offset,
						    chain_size - offset);
		if (cert_len < 0)
			return cert_len;

		struct x509_certificate *cert __free(x509_free_certificate) =
			x509_cert_parse(chain_data + offset, cert_len);

		if (IS_ERR(cert)) {
			pci_warn(tsm->pdev, "parsing of certificate chain not successful\n");
			return PTR_ERR(cert);
		}

		/* The key in the last cert in the chain is used */
		if (offset + cert_len == chain_size) {
			char *signature_algorithm __free(kfree) = NULL;
			void *public_key __free(kfree) =
				kzalloc(cert->pub->keylen, GFP_KERNEL);

			if (!public_key)
				return -ENOMEM;

			if (!strcmp("rsa", cert->pub->pkey_algo)) {
				struct rsa_key rsa_key = {0};
				size_t skip = 0;
				int ret;

				ret = rsa_parse_pub_key(&rsa_key, cert->pub->key,
							cert->pub->keylen);
				if (ret)
					return ret;

				while (skip < rsa_key.n_sz && !rsa_key.n[skip])
					skip++;

				/* check we have 3072 bits len */
				if ((rsa_key.n_sz - skip) != (3072 >> 3))
					return -EINVAL;
			} else if (strcmp("ecdsa-nist-p256", cert->pub->pkey_algo) &&
				   strcmp("ecdsa-nist-p384", cert->pub->pkey_algo)) {
				return -EINVAL;
			}

			signature_algorithm = kstrdup(cert->pub->pkey_algo, GFP_KERNEL);
			if (!signature_algorithm)
				return -ENOMEM;

			memcpy(public_key, cert->pub->key, cert->pub->keylen);
			pf0_ep_dsc->rmi_signature_algorithm =
				no_free_ptr(signature_algorithm);
			pf0_ep_dsc->cert_chain.public_key = no_free_ptr(public_key);
			pf0_ep_dsc->cert_chain.public_key_size = cert->pub->keylen;
			pf0_ep_dsc->cert_chain.valid = true;
			return 0;
		}

		offset += cert_len;
	}

	/* something wrong with chain size and parsing. */
	return -EINVAL;
}

static inline void key_param_free(struct rmi_public_key_params *param)
{
	return free_page((unsigned long)param);
}

static inline int copy_key_part(u8 *buf, const u8 *key_buf, size_t sz)
{
	int skip;

	/* skip leading zero in asn.1 */
	for (skip = 0; skip < sz; skip++)
		if (key_buf[skip])
			break;

	memcpy(buf, key_buf + skip, sz - skip);
	return sz - skip;
}

DEFINE_FREE(key_param_free, struct rmi_public_key_params *, if (_T) key_param_free(_T))
static int pdev_set_public_key(struct pci_tsm *tsm)
{
	struct cca_host_pf0_ep_dsc *pf0_ep_dsc;

	pf0_ep_dsc = to_cca_pf0_ep_dsc(tsm->pdev);
	/* Check that all the necessary information was captured from communication */
	if (!pf0_ep_dsc->cert_chain.valid)
		return -EINVAL;

	u8 *key __free(free_page) = (u8 *)get_zeroed_page(GFP_KERNEL);
	u8 *metadata __free(free_page) = (u8 *)get_zeroed_page(GFP_KERNEL);
	struct rmi_public_key_params *key_params __free(key_param_free) =
		(struct rmi_public_key_params *)get_zeroed_page(GFP_KERNEL);
	if (!key_params || !key || !metadata)
		return -ENOMEM;

	if (!strcmp("ecdsa-nist-p384", pf0_ep_dsc->rmi_signature_algorithm) ||
	    !strcmp("ecdsa-nist-p256", pf0_ep_dsc->rmi_signature_algorithm)) {
		key_params->key_len = pf0_ep_dsc->cert_chain.public_key_size;
		memcpy(key, pf0_ep_dsc->cert_chain.public_key,
		       pf0_ep_dsc->cert_chain.public_key_size);
		key_params->metadata_len = 0;
	} else if (!strcmp("rsa", pf0_ep_dsc->rmi_signature_algorithm)) {
		int ret;
		struct rsa_key rsa_key = {0};

		ret = rsa_parse_pub_key(&rsa_key,
					pf0_ep_dsc->cert_chain.public_key,
					pf0_ep_dsc->cert_chain.public_key_size);
		if (ret)
			return ret;

		key_params->key_len = copy_key_part(key, rsa_key.n, rsa_key.n_sz);
		key_params->metadata_len = copy_key_part(metadata,
							 rsa_key.e, rsa_key.e_sz);
	} else {
		return -EINVAL;
	}

	key_params->key_addr = virt_to_phys(key);
	key_params->metadata_addr = virt_to_phys(metadata);

	if (rmi_pdev_set_pubkey(virt_to_phys(pf0_ep_dsc->pdev.rmm_pdev),
				virt_to_phys(key_params)))
		return -ENXIO;
	return 0;
}

static void pdev_state_transition_workfn(struct work_struct *work)
{
	unsigned long state;
	struct pci_tsm *tsm;
	struct dev_comm_work *setup_work;
	struct cca_host_pdev_dsc *pdev_dsc;

	setup_work = container_of(work, struct dev_comm_work, work);
	tsm = setup_work->tsm;
	pdev_dsc = to_cca_pdev_dsc(tsm->dsm_dev);

	guard(mutex)(&pdev_dsc->object_lock);
	state = wait_for_pdev_state(tsm, setup_work->target_state);
	WARN_ON(state != setup_work->target_state);
}

static int submit_pdev_state_transition_work(struct pci_dev *pdev,
		enum rmi_pdev_state target_state)
{
	enum rmi_pdev_state state;
	struct dev_comm_work comm_work;
	struct cca_host_pdev_dsc *pdev_dsc = to_cca_pdev_dsc(pdev);
	struct cca_host_comm_data *comm_data = to_cca_comm_data(pdev);

	INIT_WORK_ONSTACK(&comm_work.work, pdev_state_transition_workfn);
	comm_work.tsm = pdev->tsm;
	comm_work.target_state = target_state;

	queue_work(comm_data->work_queue, &comm_work.work);

	flush_work(&comm_work.work);
	destroy_work_on_stack(&comm_work.work);

	/* check if we reached target state */
	if (rmi_pdev_get_state(virt_to_phys(pdev_dsc->rmm_pdev), &state))
		return -EIO;

	if (state != target_state)
		/* no specific error for this */
		return -1;
	return 0;
}

static void vdev_state_transition_workfn(struct work_struct *work)
{
	unsigned long state;
	struct pci_tsm *tsm;
	struct dev_comm_work *setup_work;
	struct cca_host_pdev_dsc *pdev_dsc;

	setup_work = container_of(work, struct dev_comm_work, work);
	tsm = setup_work->tsm;

	pdev_dsc = to_cca_pdev_dsc(tsm->dsm_dev);
	guard(mutex)(&pdev_dsc->object_lock);

	state = wait_for_vdev_state(tsm, setup_work->host_tdi,
				    setup_work->target_state);
	WARN_ON(state != setup_work->target_state);
}

static int submit_vdev_state_transition_work(struct cca_host_tdi *host_tdi,
					     struct pci_dev *pdev,
					     int target_state)
{
	enum rmi_vdev_state state;
	struct dev_comm_work comm_work;
	struct cca_host_comm_data *comm_data = to_cca_comm_data(pdev);

	INIT_WORK_ONSTACK(&comm_work.work, vdev_state_transition_workfn);
	comm_work.tsm = pdev->tsm;
	comm_work.host_tdi = host_tdi;
	comm_work.target_state = target_state;

	queue_work(comm_data->work_queue, &comm_work.work);

	flush_work(&comm_work.work);
	destroy_work_on_stack(&comm_work.work);

	/* check if we reached target state */
	if (rmi_vdev_get_state(virt_to_phys(host_tdi->rmm_vdev), &state))
		return -ENXIO;

	if (state != target_state)
		/* Protocol didn't take it to expected target state */
		return -EPROTO;
	return 0;
}

static void pdev_collect_identity_workfn(struct work_struct *work)
{
	struct pci_tsm *tsm;
	struct dev_comm_work *setup_work;
	struct cca_host_pdev_dsc *pdev_dsc;

	setup_work = container_of(work, struct dev_comm_work, work);
	tsm = setup_work->tsm;
	pdev_dsc = to_cca_pdev_dsc(tsm->dsm_dev);

	guard(mutex)(&pdev_dsc->object_lock);

	do_dev_communicate(PDEV_COMMUNICATE, tsm, NULL, RMI_PDEV_ERROR, NULL);

	/*
	 * Don't worry about communication error. The caller will look at
	 * device state to find more about error
	 */
}

int cca_pdev_collect_identity(struct pci_dev *pdev)
{
	enum rmi_pdev_state state;
	struct dev_comm_work comm_work;
	struct cca_host_pdev_dsc *pdev_dsc = to_cca_pdev_dsc(pdev);
	struct cca_host_comm_data *comm_data = to_cca_comm_data(pdev);

	/*
	 * Device identity is collected by doing a device communication
	 * after a pdev_create
	 */
	INIT_WORK_ONSTACK(&comm_work.work, pdev_collect_identity_workfn);
	comm_work.tsm = pdev->tsm;

	queue_work(comm_data->work_queue, &comm_work.work);

	flush_work(&comm_work.work);
	destroy_work_on_stack(&comm_work.work);

	/* check for device communication error*/
	if (rmi_pdev_get_state(virt_to_phys(pdev_dsc->rmm_pdev), &state))
		return -EIO;

	if (state == RMI_PDEV_ERROR)
		return -EPROTO;

	return 0;
}

bool cca_pdev_needs_key(struct pci_dev *pdev)
{
	enum rmi_pdev_state state;
	struct cca_host_pdev_dsc *pdev_dsc = to_cca_pdev_dsc(pdev);

	/*
	 * Consider pdev_get_state failure as need key transition
	 * and that will result in device communication failure, which
	 * will handle this error.
	 */
	if (rmi_pdev_get_state(virt_to_phys(pdev_dsc->rmm_pdev), &state))
		return true;

	if (state == RMI_PDEV_NEEDS_KEY)
		return true;
	return false;
}

int cca_pdev_set_public_key(struct pci_dev *pdev)
{
	int ret;

	/*
	 * we now have certificate chain in dsm->cert_chain. Parse that and set
	 * the pubkey.
	 */
	ret = parse_certificate_chain(pdev->tsm);
	if (ret)
		return ret;

	ret = pdev_set_public_key(pdev->tsm);
	if (ret)
		return ret;

	return submit_pdev_state_transition_work(pdev, RMI_PDEV_READY);
}

static inline int rmi_pdev_destroy(unsigned long pdev_phys,
		unsigned long *rmi_ret)
{
	struct rmi_sro_state *sro __free(kfree) = kzalloc_obj(*sro);
	if (!sro)
		return -ENOMEM;

	sro->regs = (struct arm_smccc_1_2_regs){
		SMC_RMI_PDEV_DESTROY, pdev_phys
	};
	*rmi_ret = rmi_sro_execute(sro, GFP_KERNEL, NULL);
	rmi_sro_free(sro);

	return 0;
}

void cca_pdev_stop_and_destroy(struct pci_dev *pdev)
{
	int ret;
	unsigned long rmi_ret;
	enum rmi_pdev_state state;
	struct cca_host_pdev_dsc *pdev_dsc = to_cca_pdev_dsc(pdev);
	struct cca_host_pf0_ep_dsc *pf0_ep_dsc = to_cca_pf0_ep_dsc(pdev);
	phys_addr_t rmm_pdev_phys = virt_to_phys(pdev_dsc->rmm_pdev);

	if (WARN_ON(rmi_pdev_get_state(rmm_pdev_phys, &state)))
		return;

	if (state != RMI_PDEV_STOPPED) {
		if (state == RMI_PDEV_NEW || state == RMI_PDEV_HAS_KEY) {
			if (WARN_ON(rmi_pdev_abort(rmm_pdev_phys)))
				return;
		} else if (state != RMI_PDEV_NEEDS_KEY &&
			   state != RMI_PDEV_READY && state != RMI_PDEV_ERROR) {
			WARN_ON(1);
			return;
		}

		if (WARN_ON(rmi_pdev_stop(rmm_pdev_phys)))
			return;

		ret = submit_pdev_state_transition_work(pdev, RMI_PDEV_STOPPED);
		if (ret)
			return;
	}

	ret = rmi_pdev_destroy(rmm_pdev_phys, &rmi_ret);
	if (WARN_ON(ret || rmi_ret))
		return;

	if (pf0_ep_dsc) {
		kfree(pf0_ep_dsc->rmi_signature_algorithm);
		kfree(pf0_ep_dsc->cert_chain.public_key);
		kvfree(pf0_ep_dsc->cert_chain.cache);
		kvfree(pf0_ep_dsc->vca);
		pf0_ep_dsc->cert_chain.cache = NULL;
		pf0_ep_dsc->vca = NULL;
	}

	if (!rmi_undelegate_page(rmm_pdev_phys))
		free_page((unsigned long)pdev_dsc->rmm_pdev);
	pdev_dsc->rmm_pdev = NULL;
}

static void stream_connect_workfn(struct work_struct *work)
{
	int state;
	int peer_wait = 0;
	struct pci_tsm *tsm;
	int my_index, peer_index, target;
	struct stream_connect_work *stream_work;
	struct cca_host_pdev_dsc *pdev_dsc;

	stream_work = container_of(work, struct stream_connect_work, work);
	tsm = stream_work->tsm;
	pdev_dsc = to_cca_pdev_dsc(tsm->dsm_dev);

	my_index = stream_work->my_index;
	peer_index = my_index ^ 0x1;

redo_communicate:
	mutex_lock(&pdev_dsc->object_lock);

	state = do_dev_communicate(PDEV_COMMUNICATE, tsm, NULL,
				   RMI_PDEV_ERROR, &peer_wait);
	if (state != RMI_PDEV_ERROR && peer_wait) {

		if (!stream_work->has_peer) {
			WARN(1, "Unexpected STREAM_WAIT without peer stream\n");
			mutex_unlock(&pdev_dsc->object_lock);
			return;
		}
		/*
		 * Record a fresh target val for this side, then wait until
		 * peer reaches at least the same target.
		 */
		target = atomic_inc_return(&stream_work->sync->val[my_index]);

		wake_up_all(&stream_work->sync->wq);

		mutex_unlock(&pdev_dsc->object_lock);

		/*
		 * Wait for the peer to match our target, but break too if it
		 * stopped participating (done[]): its counter is then frozen and
		 * would never reach the target. If it left short, bail and let
		 * submit_stream_work()'s completion check report the failure.
		 */
		wait_event(stream_work->sync->wq,
			   atomic_read(&stream_work->sync->val[peer_index]) >= target ||
			   atomic_read(&stream_work->sync->done[peer_index]));
		if (atomic_read(&stream_work->sync->val[peer_index]) < target) {
			atomic_set(&stream_work->sync->done[my_index], 1);
			wake_up_all(&stream_work->sync->wq);
			return;
		}
		goto redo_communicate;
	}

	/*
	 * Done (completed or errored): bump the counter to its final value
	 * before latching done[] so a waiting peer sees the final count and can
	 * tell whether we matched its target.
	 */
	atomic_inc_return(&stream_work->sync->val[my_index]);
	atomic_set(&stream_work->sync->done[my_index], 1);
	wake_up_all(&stream_work->sync->wq);

	mutex_unlock(&pdev_dsc->object_lock);
}

static int submit_stream_work(struct pci_dev *pdev1, struct pci_dev *pdev2,
		unsigned long stream_handle)
{
	phys_addr_t rmm_pdev1_phys, rmm_pdev2_phys = 0;
	struct cca_host_comm_data *comm_data_pdev1, *comm_data_pdev2;
	struct cca_host_pdev_dsc *pdev_dsc1, *pdev_dsc2 = NULL;
	struct stream_sync sync;
	struct stream_connect_work stream_work_pdev1, stream_work_pdev2;

	comm_data_pdev1 = to_cca_comm_data(pdev1);
	init_waitqueue_head(&sync.wq);
	atomic_set(&sync.val[0], 0);
	atomic_set(&sync.val[1], 0);
	atomic_set(&sync.done[0], 0);
	atomic_set(&sync.done[1], 0);

	pdev_dsc1 = to_cca_pdev_dsc(pdev1);
	INIT_WORK_ONSTACK(&stream_work_pdev1.work, stream_connect_workfn);
	stream_work_pdev1.tsm = pdev1->tsm;
	stream_work_pdev1.sync = &sync;
	stream_work_pdev1.my_index = 0;
	stream_work_pdev1.has_peer = !!pdev2;
	queue_work(comm_data_pdev1->work_queue, &stream_work_pdev1.work);

	if (pdev2) {
		comm_data_pdev2 = to_cca_comm_data(pdev2);
		pdev_dsc2 = to_cca_pdev_dsc(pdev2);
		INIT_WORK_ONSTACK(&stream_work_pdev2.work, stream_connect_workfn);
		stream_work_pdev2.tsm = pdev2->tsm;
		stream_work_pdev2.sync = &sync;
		stream_work_pdev2.my_index = 1;
		stream_work_pdev2.has_peer = true;
		queue_work(comm_data_pdev2->work_queue, &stream_work_pdev2.work);
	}

	flush_work(&stream_work_pdev1.work);
	if (pdev2) {
		flush_work(&stream_work_pdev2.work);
		destroy_work_on_stack(&stream_work_pdev2.work);
	}

	destroy_work_on_stack(&stream_work_pdev1.work);

	rmm_pdev1_phys = virt_to_phys(pdev_dsc1->rmm_pdev);
	if (pdev2)
		rmm_pdev2_phys = virt_to_phys(pdev_dsc2->rmm_pdev);
	/*
	 * If we had device communication error, this will error out.
	 */
	if (rmi_pdev_stream_complete(rmm_pdev1_phys, rmm_pdev2_phys, stream_handle))
		return -EIO;

	return 0;
}

static int stream_pair_not_errored(struct pci_dev *pdev1,
		struct pci_dev *pdev2)
{
	struct cca_host_pdev_dsc *pdev_dsc1 = to_cca_pdev_dsc(pdev1);
	enum rmi_pdev_state state;

	if (rmi_pdev_get_state(virt_to_phys(pdev_dsc1->rmm_pdev), &state) ||
	    state == RMI_PDEV_ERROR)
		return -EIO;

	if (pdev2) {
		struct cca_host_pdev_dsc *pdev_dsc2 =
			to_cca_pdev_dsc(pdev2);

		if (rmi_pdev_get_state(virt_to_phys(pdev_dsc2->rmm_pdev),
				       &state) || state == RMI_PDEV_ERROR)
			return -EIO;
	}

	return 0;
}

int cca_pdev_stream_connect(struct pci_dev *pdev1, struct pci_dev *pdev2,
		struct rmi_pdev_stream_params *stream_params,
		unsigned long *stream_handle)
{
	phys_addr_t stream_params_phys = virt_to_phys(stream_params);
	phys_addr_t rmm_pdev1_phys, rmm_pdev2_phys = 0;
	struct rmi_pdev_stream_info info;
	int ret;

	if (rmi_pdev_stream_connect(stream_params_phys, stream_handle))
		return -EIO;

	ret = submit_stream_work(pdev1, pdev2, *stream_handle);
	if (ret)
		return ret;

	ret = stream_pair_not_errored(pdev1, pdev2);
	if (ret)
		return ret;

	rmm_pdev1_phys = virt_to_phys(to_cca_pdev_dsc(pdev1)->rmm_pdev);
	if (pdev2)
		rmm_pdev2_phys = virt_to_phys(to_cca_pdev_dsc(pdev2)->rmm_pdev);

	if (rmi_pdev_stream_info(rmm_pdev1_phys, rmm_pdev2_phys, *stream_handle,
				 &info))
		return -EIO;

	if (info.state != RMI_PDEV_STREAM_CONNECTED)
		return -EPROTO;

	return 0;
}

int cca_pdev_disconnect_stream(struct pci_dev *pdev1,
		struct pci_dev *pdev2, unsigned long stream_handle)
{

	phys_addr_t rmm_pdev2_phys = 0;
	struct cca_host_pdev_dsc *pdev_dsc1 = to_cca_pdev_dsc(pdev1);
	phys_addr_t rmm_pdev1_phys = virt_to_phys(pdev_dsc1->rmm_pdev);
	struct rmi_pdev_stream_info info;
	int ret;

	if (pdev2)
		rmm_pdev2_phys = virt_to_phys(to_cca_pdev_dsc(pdev2)->rmm_pdev);

	if (rmi_pdev_stream_disconnect(rmm_pdev1_phys, rmm_pdev2_phys,
				       stream_handle))
		return -EIO;

	ret = submit_stream_work(pdev1, pdev2, stream_handle);
	if (ret)
		return ret;

	ret = stream_pair_not_errored(pdev1, pdev2);
	if (ret)
		return ret;

	/*
	 * A completed disconnect releases the stream handle, so INFO normally
	 * stops resolving it. If it still resolves, require DISCONNECTED.
	 */
	ret = rmi_pdev_stream_info(rmm_pdev1_phys, rmm_pdev2_phys,
				   stream_handle, &info);
	if (RMI_RETURN_STATUS(ret) != RMI_SUCCESS &&
	    RMI_RETURN_STATUS(ret) != RMI_ERROR_INPUT)
		return -EIO;
	if (RMI_RETURN_STATUS(ret) == RMI_SUCCESS &&
	    info.state != RMI_PDEV_STREAM_DISCONNECTED)
		return -EPROTO;

	return 0;
}

static unsigned long pci_get_tdi_id(struct pci_dev *pdev)
{
	/* requester segment is marked reserved. */
	return pci_dev_id(pdev);
}

static void cca_vdev_assert_locked(struct pci_dev *pdev)
{
	struct cca_host_pf0_ep_dsc *pf0_ep_dsc;

	pf0_ep_dsc = to_cca_pf0_ep_dsc(pdev->tsm->dsm_dev);
	lockdep_assert_held(&pf0_ep_dsc->pci.lock);
}

static void init_vdev_params_mmio_range(struct pci_dev *pdev,
		struct rmi_vdev_params *params)
{
	int index = 0;

	for (int i = 0; i < PCI_STD_NUM_BARS; i++) {
		struct resource *res = &pdev->resource[i];

		if (!(res->flags & IORESOURCE_MEM))
			continue;

		if (resource_size(res) == 0)
			continue;

		index = insert_addr_range_sorted(params->addr_range, index,
						 res->start, res->end + 1);
	}

	params->num_addr_range = index;
}

static int cca_vdev_unlock_for_destroy(struct cca_host_tdi *host_tdi,
		struct pci_dev *pdev, phys_addr_t rd_phys,
		phys_addr_t rmm_pdev_phys, phys_addr_t rmm_vdev_phys)
{
	enum rmi_vdev_state state;

	if (rmi_vdev_get_state(rmm_vdev_phys, &state))
		return -EIO;

	if (state == RMI_VDEV_NEW) {
		if (rmi_vdev_abort(rd_phys, rmm_pdev_phys, rmm_vdev_phys))
			return -EIO;

		if (rmi_vdev_get_state(rmm_vdev_phys, &state))
			return -EIO;
	}

	if (state == RMI_VDEV_UNLOCKED)
		return 0;

	if (state != RMI_VDEV_LOCKED && state != RMI_VDEV_ERROR)
		return -EPROTO;

	if (rmi_vdev_unlock(rd_phys, rmm_pdev_phys, rmm_vdev_phys))
		return -EIO;

	return submit_vdev_state_transition_work(host_tdi, pdev,
						 RMI_VDEV_UNLOCKED);
}

void *cca_vdev_create(struct cca_host_tdi *host_tdi, struct realm *realm,
		      struct pci_dev *pdev, struct pci_dev *pf0_dev,
		      u32 guest_rid)
{
	phys_addr_t rd_phys = virt_to_phys(realm->rd);
	struct rmi_vdev_params *params = NULL;
	struct cca_host_pdev_dsc *pdev_dsc;
	phys_addr_t rmm_pdev_phys;
	phys_addr_t rmm_vdev_phys;
	bool should_free = true;
	bool rmm_vdev_created = false;
	bool rmm_vdev_destroyed = false;
	void *rmm_vdev;
	int ret;

	cca_vdev_assert_locked(pdev);

	pdev_dsc = to_cca_pdev_dsc(pf0_dev);
	if (!pdev_dsc->rmm_pdev) {
		ret = -EINVAL;
		goto err_out;
	}

	rmm_vdev = (void *)get_zeroed_page(GFP_KERNEL);
	if (!rmm_vdev) {
		ret =  -ENOMEM;
		goto err_out;
	}

	rmm_vdev_phys = virt_to_phys(rmm_vdev);
	if (rmi_delegate_page(rmm_vdev_phys)) {
		ret = -ENXIO;
		goto err_granule_delegate;
	}

	params = (struct rmi_vdev_params *)get_zeroed_page(GFP_KERNEL);
	if (!params) {
		ret = -ENOMEM;
		goto err_params_alloc;
	}

	params->flags = 0;
	params->vdev_id = guest_rid;
	params->tdi_id = pci_get_tdi_id(pdev);

	init_vdev_params_mmio_range(pdev, params);

	rmm_pdev_phys = virt_to_phys(pdev_dsc->rmm_pdev);
	if (rmi_vdev_create(rd_phys, rmm_pdev_phys,
			    rmm_vdev_phys, virt_to_phys(params))) {
		ret = -ENXIO;
		goto err_vdev_create;
	}
	rmm_vdev_created = true;

	/* Set up host_tdi before calling device communicate. */
	host_tdi->rmm_vdev = rmm_vdev;
	host_tdi->realm = realm;
	host_tdi->state = RMI_VDEV_NEW;

	ret = submit_vdev_state_transition_work(host_tdi, pdev,
						RMI_VDEV_UNLOCKED);
	/* failure is treated as rmi_vdev_create failure */
	if (ret)
		goto err_vdev_comm;
	host_tdi->state = RMI_VDEV_UNLOCKED;

	free_page((unsigned long)params);
	return rmm_vdev;

err_vdev_comm:
	if (!cca_vdev_unlock_for_destroy(host_tdi, pdev, rd_phys,
					 rmm_pdev_phys, rmm_vdev_phys) &&
	    !rmi_vdev_destroy(rd_phys, rmm_pdev_phys, rmm_vdev_phys)) {
		rmm_vdev_destroyed = true;
	} else {
		pci_err(pdev, "failed to destroy vdev after create failure\n");
		should_free = false;
	}
	host_tdi->rmm_vdev = NULL;
	host_tdi->realm = NULL;
err_vdev_create:
	free_page((unsigned long)params);
err_params_alloc:
	if ((!rmm_vdev_created || rmm_vdev_destroyed) &&
	    rmi_undelegate_page(rmm_vdev_phys))
		should_free = false;
err_granule_delegate:
	if (should_free)
		free_page((unsigned long)rmm_vdev);
err_out:
	return ERR_PTR(ret);
}

int cca_pdev_refresh_stream_key(struct pci_dev *pdev1,
		struct pci_dev *pdev2, unsigned long stream_handle)
{

	phys_addr_t rmm_pdev2_phys = 0;
	struct cca_host_pdev_dsc *pdev_dsc1 = to_cca_pdev_dsc(pdev1);
	struct rmi_pdev_stream_info info_before, info_after;
	phys_addr_t rmm_pdev1_phys = virt_to_phys(pdev_dsc1->rmm_pdev);
	int ret;

	if (pdev2)
		rmm_pdev2_phys = virt_to_phys(to_cca_pdev_dsc(pdev2)->rmm_pdev);

	if (rmi_pdev_stream_info(rmm_pdev1_phys, rmm_pdev2_phys, stream_handle,
				 &info_before))
		return -EIO;

	if (info_before.state != RMI_PDEV_STREAM_CONNECTED)
		return -EPROTO;

	if (rmi_pdev_stream_key_refresh(rmm_pdev1_phys, rmm_pdev2_phys,
					stream_handle))
		return -EIO;

	ret = submit_stream_work(pdev1, pdev2, stream_handle);
	if (ret)
		return ret;

	ret = stream_pair_not_errored(pdev1, pdev2);
	if (ret)
		return ret;

	if (rmi_pdev_stream_info(rmm_pdev1_phys, rmm_pdev2_phys, stream_handle,
				 &info_after))
		return -EIO;

	if (info_after.state != RMI_PDEV_STREAM_CONNECTED ||
	    info_after.refresh_count != info_before.refresh_count + 1)
		return -EPROTO;

	return 0;
}


int cca_pdev_purge_stream_key(struct pci_dev *pdev1,
		struct pci_dev *pdev2, unsigned long stream_handle)
{

	phys_addr_t rmm_pdev2_phys = 0;
	struct cca_host_pdev_dsc *pdev_dsc1 = to_cca_pdev_dsc(pdev1);
	struct rmi_pdev_stream_info info_before, info_after;
	phys_addr_t rmm_pdev1_phys = virt_to_phys(pdev_dsc1->rmm_pdev);
	int ret;

	if (pdev2)
		rmm_pdev2_phys = virt_to_phys(to_cca_pdev_dsc(pdev2)->rmm_pdev);

	if (rmi_pdev_stream_info(rmm_pdev1_phys, rmm_pdev2_phys, stream_handle,
				 &info_before))
		return -EIO;

	if (info_before.state != RMI_PDEV_STREAM_CONNECTED)
		return -EPROTO;

	if (rmi_pdev_stream_key_purge(rmm_pdev1_phys, rmm_pdev2_phys,
				      stream_handle))
		return -EIO;

	ret = submit_stream_work(pdev1, pdev2, stream_handle);
	if (ret)
		return ret;

	ret = stream_pair_not_errored(pdev1, pdev2);
	if (ret)
		return ret;

	if (rmi_pdev_stream_info(rmm_pdev1_phys, rmm_pdev2_phys, stream_handle,
				 &info_after))
		return -EIO;

	if (info_after.state != RMI_PDEV_STREAM_CONNECTED ||
	    info_after.purge_count != info_before.purge_count + 1)
		return -EPROTO;

	return 0;
}

int cca_vdev_device_unlock(struct cca_host_tdi *host_tdi,
			   struct pci_dev *pdev)
{
	struct pci_dev *pf0_dev = pdev->tsm->dsm_dev;
	struct cca_host_pf0_ep_dsc *pf0_ep_dsc = to_cca_pf0_ep_dsc(pf0_dev);
	phys_addr_t rmm_pdev_phys;
	phys_addr_t rmm_vdev_phys;
	struct cca_host_pdev_dsc *pdev_dsc;
	enum rmi_vdev_state state;
	bool retry_error = true;
	unsigned long rmi_ret;
	phys_addr_t rd_phys;
	int ret;

	cca_vdev_assert_locked(pdev);

	if (host_tdi->state == RMI_VDEV_UNLOCKED ||
	    host_tdi->state == RMI_VDEV_NEW)
		return -EINVAL;

	rd_phys = virt_to_phys(host_tdi->realm->rd);
	rmm_vdev_phys = virt_to_phys(host_tdi->rmm_vdev);
	pdev_dsc = to_cca_pdev_dsc(pf0_dev);
	rmm_pdev_phys = virt_to_phys(pdev_dsc->rmm_pdev);

retry_unlock:
	rmi_ret = rmi_vdev_unlock(rd_phys, rmm_pdev_phys, rmm_vdev_phys);
	if (RMI_RETURN_STATUS(rmi_ret) == RMI_ERROR_GRANULE) {
		/*
		 * Device memory of the VDEV is still mapped, e.g. after an
		 * abrupt guest or VMM teardown. Force-unmap it and retry once.
		 */
		ret = realm_dev_mem_unmap(host_tdi->kvm, rmm_vdev_phys);
		if (ret)
			pci_err(pdev, "failed to force-unmap vdev memory (%d)\n",
				ret);
		else
			rmi_ret = rmi_vdev_unlock(rd_phys, rmm_pdev_phys,
						  rmm_vdev_phys);
	}
	if (rmi_ret) {
		pci_err(pdev, "failed to unlock vdev\n");
		return -ENXIO;
	}

	/*
	 * KROU: a live IDE stream at unlock parks the VDEV in KEY_REFRESH.
	 * Refresh the stream keys, step the VDEV to KEY_PURGE (the RMM
	 * snapshots the purge counter on that transition, so it must precede
	 * the purge), then purge. Streams without IDE keys skip the stream
	 * operations. If the rotation fails, disconnecting the stream lets
	 * the unlock complete.
	 */
	if (rmm_has_reg2_feature(RMI_FEATURE_REGISTER_2_VDEV_KROU) &&
	    !rmi_vdev_get_state(rmm_vdev_phys, &state) &&
	    state == RMI_VDEV_KEY_REFRESH) {
		struct pci_dev *rp = pcie_find_root_port(pf0_dev);
		unsigned long stream_handle = pf0_ep_dsc->stream_handle;
		struct rmi_pdev_stream_info info;
		phys_addr_t peer_phys = 0;
		bool has_ide;

		if (rp)
			peer_phys = virt_to_phys(to_cca_pdev_dsc(rp)->rmm_pdev);

		ret = rmi_pdev_stream_info(rmm_pdev_phys, peer_phys,
					   stream_handle, &info) ? -EIO : 0;
		has_ide = !ret && (info.type == RMI_PDEV_STREAM_NCOH ||
				   info.type == RMI_PDEV_STREAM_COH);
		if (has_ide)
			ret = cca_pdev_refresh_stream_key(pf0_dev, rp,
							  stream_handle);
		if (!ret)
			ret = submit_vdev_state_transition_work(host_tdi, pdev,
							RMI_VDEV_KEY_PURGE);
		if (!ret && has_ide)
			ret = cca_pdev_purge_stream_key(pf0_dev, rp,
							stream_handle);
		if (ret) {
			pci_err(pf0_dev,
				"vdev key rotation on unlock failed (%d); disconnecting stream\n",
				ret);
			ret = cca_pdev_disconnect_stream(pf0_dev, rp,
							 stream_handle);
			if (ret)
				goto out_sync_state;
		}
	}

	ret = submit_vdev_state_transition_work(host_tdi, pdev,
						RMI_VDEV_UNLOCKED);
	if (ret && retry_error && !rmi_vdev_get_state(rmm_vdev_phys, &state) &&
	    (state == RMI_VDEV_ERROR || state == RMI_VDEV_LOCKED)) {
		retry_error = false;
		goto retry_unlock;
	}
	if (ret) {
		pci_err(pdev, "failed to unlock vdev (%d)\n", ret);
		goto out_sync_state;
	}

	host_tdi->state = RMI_VDEV_UNLOCKED;
	return 0;

out_sync_state:
	/* Track the state the RMM left the VDEV in so destroy can retry. */
	if (!rmi_vdev_get_state(rmm_vdev_phys, &state))
		host_tdi->state = state;
	return ret;
}

static void cca_vdev_drain_dpt_regions(struct cca_host_tdi *host_tdi,
				       bool destroy)
{
	struct cca_vdev_dpt_region *region, *tmp;

	list_for_each_entry_safe(region, tmp, &host_tdi->dpt_regions, node) {
		if (destroy)
			realm_destroy_dpt_l1(host_tdi->kvm, region->base);
		list_del(&region->node);
		kfree(region);
	}
}

void cca_vdev_destroy(struct cca_host_tdi *host_tdi, struct realm *realm,
		      struct pci_dev *pdev, struct pci_dev *pf0_dev)
{
	phys_addr_t rmm_pdev_phys;
	phys_addr_t rmm_vdev_phys;
	struct cca_host_pdev_dsc *pdev_dsc;
	phys_addr_t rd_phys = virt_to_phys(realm->rd);
	enum rmi_vdev_state state;
	int ret;

	cca_vdev_assert_locked(pdev);
	rmm_vdev_phys = virt_to_phys(host_tdi->rmm_vdev);

	if (host_tdi->state != RMI_VDEV_UNLOCKED) {
		ret = realm_dev_mem_unmap(host_tdi->kvm, rmm_vdev_phys);
		if (ret) {
			pci_err(pdev,
				"failed to unmap vdev memory before destroy (%d)\n",
				ret);
			cca_vdev_drain_dpt_regions(host_tdi, false);
			return;
		}

		ret = cca_vdev_device_unlock(host_tdi, pdev);
		if (ret)
			pci_err(pdev, "failed to unlock vdev (%d)\n", ret);
	}

	pdev_dsc = to_cca_pdev_dsc(pf0_dev);
	rmm_pdev_phys = virt_to_phys(pdev_dsc->rmm_pdev);

	/*
	 * VDEV_DESTROY requires an UNLOCKED VDEV. Keep the delegated granule
	 * if the VDEV could not be unlocked or destroyed, as the RMM still
	 * owns it.
	 */
	if (rmi_vdev_get_state(rmm_vdev_phys, &state) ||
	    state != RMI_VDEV_UNLOCKED) {
		pci_err(pdev, "vdev is not unlocked for destruction\n");
		cca_vdev_drain_dpt_regions(host_tdi, false);
		return;
	}

	/* A successful unlock proves that no device mappings remain. */
	cca_vdev_drain_dpt_regions(host_tdi, true);

	if (rmi_vdev_destroy(rd_phys, rmm_pdev_phys, rmm_vdev_phys)) {
		pci_err(pdev, "failed to destroy vdev\n");
		return;
	}

	if (!rmi_undelegate_page(rmm_vdev_phys))
		free_page((unsigned long)host_tdi->rmm_vdev);

	host_tdi->rmm_vdev = NULL;
	host_tdi->realm = NULL;
}

static void vdev_fetch_object_workfn(struct work_struct *work)
{
	int state;
	struct pci_tsm *tsm;
	struct cca_host_pdev_dsc *pdev_dsc;
	struct dev_comm_work *setup_work;

	setup_work = container_of(work, struct dev_comm_work, work);
	tsm = setup_work->tsm;
	pdev_dsc = to_cca_pdev_dsc(tsm->dsm_dev);

	guard(mutex)(&pdev_dsc->object_lock);

	if (setup_work->cache_size) {
		memset(setup_work->cache_buf, 0, setup_work->cache_size);
		*setup_work->cache_offset = 0;
	}
	state = do_dev_communicate(VDEV_COMMUNICATE, tsm,
				   setup_work->host_tdi, RMI_VDEV_ERROR, NULL);
	/* return status through dev_comm_work.cache_cache */
	if (state == RMI_VDEV_ERROR)
		setup_work->cache_size = 0;
	else
		/* indicate success. This value is not used. */
		setup_work->cache_size = CACHE_CHUNK_SIZE;
}

static int cca_vdev_track_dpt_regions(struct cca_host_tdi *host_tdi,
				      phys_addr_t pa_base, u64 size)
{
	phys_addr_t base = ALIGN_DOWN(pa_base, RMI_DPT_L0_REGION_SIZE);
	phys_addr_t end = ALIGN(pa_base + size, RMI_DPT_L0_REGION_SIZE);
	struct cca_vdev_dpt_region *region;

	if (!rmm_has_reg2_feature(RMI_FEATURE_REGISTER_2_ATS))
		return 0;

	for (; base < end; base += RMI_DPT_L0_REGION_SIZE) {
		bool seen = false;

		list_for_each_entry(region, &host_tdi->dpt_regions, node) {
			if (region->base == base) {
				seen = true;
				break;
			}
		}
		if (seen)
			continue;

		region = kzalloc_obj(*region);
		if (!region)
			return -ENOMEM;

		region->base = base;
		list_add_tail(&region->node, &host_tdi->dpt_regions);
	}

	return 0;
}

int cca_vdev_device_map(struct cca_host_tdi *host_tdi, struct pci_dev *pdev,
			unsigned long gpa_base, unsigned long gpa_top,
			unsigned long pa_base)
{
	struct kvm *kvm;
	phys_addr_t rmm_pdev_phys;
	phys_addr_t rmm_vdev_phys;
	struct cca_host_pdev_dsc *pdev_dsc;
	int ret;

	cca_vdev_assert_locked(pdev);

	pdev_dsc = to_cca_pdev_dsc(pdev->tsm->dsm_dev);
	kvm = host_tdi->kvm;
	rmm_vdev_phys = virt_to_phys(host_tdi->rmm_vdev);
	rmm_pdev_phys = virt_to_phys(pdev_dsc->rmm_pdev);

	ret = cca_vdev_track_dpt_regions(host_tdi, pa_base,
					 gpa_top - gpa_base);
	if (ret)
		return ret;

	return realm_dev_mem_map(kvm, rmm_pdev_phys, rmm_vdev_phys,
				 gpa_base, gpa_top, pa_base);
}

int cca_vdev_device_start(struct cca_host_tdi *host_tdi,
			  struct pci_dev *pdev)
{
	phys_addr_t rmm_pdev_phys;
	phys_addr_t rmm_vdev_phys;
	struct cca_host_pdev_dsc *pdev_dsc;
	struct realm *realm;
	phys_addr_t rd_phys;

	cca_vdev_assert_locked(pdev);

	if (host_tdi->state != RMI_VDEV_LOCKED)
		return -EINVAL;

	rmm_vdev_phys = virt_to_phys(host_tdi->rmm_vdev);
	realm = &host_tdi->kvm->arch.realm;
	rd_phys = virt_to_phys(realm->rd);

	pdev_dsc = to_cca_pdev_dsc(pdev->tsm->dsm_dev);
	rmm_pdev_phys = virt_to_phys(pdev_dsc->rmm_pdev);

	if (rmi_vdev_start(rd_phys, rmm_pdev_phys, rmm_vdev_phys))
		return -ENXIO;
	host_tdi->state = RMI_VDEV_STARTED;
	return submit_vdev_state_transition_work(host_tdi, pdev,
						 RMI_VDEV_STARTED);
}

int cca_vdev_device_lock(struct cca_host_tdi *host_tdi,
			 struct pci_dev *pdev)
{
	struct cca_host_pdev_dsc *pdev_dsc;
	phys_addr_t rmm_pdev_phys;
	phys_addr_t rmm_vdev_phys;
	phys_addr_t rd_phys;

	cca_vdev_assert_locked(pdev);

	if (host_tdi->state != RMI_VDEV_UNLOCKED)
		return -EINVAL;

	rmm_vdev_phys = virt_to_phys(host_tdi->rmm_vdev);
	rd_phys = virt_to_phys(host_tdi->realm->rd);
	pdev_dsc = to_cca_pdev_dsc(pdev->tsm->dsm_dev);
	rmm_pdev_phys = virt_to_phys(pdev_dsc->rmm_pdev);

	if (rmi_vdev_lock(rd_phys, rmm_pdev_phys, rmm_vdev_phys))
		return -ENXIO;

	/* Ensure teardown unlocks the VDEV if device communication fails. */
	host_tdi->state = RMI_VDEV_LOCKED;
	return submit_vdev_state_transition_work(host_tdi, pdev,
						 RMI_VDEV_LOCKED);
}

int cca_vdev_get_object_size(struct cca_host_tdi *host_tdi,
			     struct pci_dev *pdev, int type)
{
	long len;
	struct cca_host_pf0_ep_dsc *pf0_ep_dsc;
	struct pci_tsm *tsm = pdev->tsm;
	struct cca_host_pdev_dsc *pdev_dsc;

	cca_vdev_assert_locked(pdev);

	if (!tsm)
		return -EINVAL;

	pdev_dsc = to_cca_pdev_dsc(tsm->dsm_dev);
	pf0_ep_dsc = to_cca_pf0_ep_dsc(tsm->dsm_dev);

	guard(mutex)(&pdev_dsc->object_lock);
	/* Determine the buffer that should be used */
	if (type == RHI_DA_OBJECT_INTERFACE_REPORT) {
		if (!host_tdi->interface_report)
			return -EINVAL;
		len = host_tdi->interface_report->offset;
	} else if (type == RHI_DA_OBJECT_MEASUREMENT) {
		if (!host_tdi->measurements)
			return -EINVAL;
		len = host_tdi->measurements->offset;
	} else if (type == RHI_DA_OBJECT_CERTIFICATE) {
		if (!pf0_ep_dsc->cert_chain.cache)
			return -EINVAL;
		len = pf0_ep_dsc->cert_chain.cache->offset;
	} else if (type == RHI_DA_OBJECT_VCA) {
		if (!pf0_ep_dsc->vca)
			return -EINVAL;
		len = pf0_ep_dsc->vca->offset;
	} else {
		return -EINVAL;
	}

	return len;
}

int cca_vdev_read_cached_object(struct cca_host_tdi *host_tdi,
				struct pci_dev *pdev, int type,
				unsigned long offset, unsigned long max_len,
				void __user *user_buf)
{
	void *buf;
	unsigned long len;
	struct cca_host_pf0_ep_dsc *pf0_ep_dsc;
	struct pci_tsm *tsm = pdev->tsm;
	struct cca_host_pdev_dsc *pdev_dsc;

	cca_vdev_assert_locked(pdev);

	if (!tsm)
		return -EINVAL;

	pdev_dsc = to_cca_pdev_dsc(tsm->dsm_dev);
	pf0_ep_dsc = to_cca_pf0_ep_dsc(tsm->dsm_dev);

	guard(mutex)(&pdev_dsc->object_lock);
	/* Determine the buffer that should be used */
	if (type == RHI_DA_OBJECT_INTERFACE_REPORT) {
		if (!host_tdi->interface_report)
			return -EINVAL;
		len = host_tdi->interface_report->offset;
		buf = host_tdi->interface_report->buf;
	} else if (type == RHI_DA_OBJECT_MEASUREMENT) {
		if (!host_tdi->measurements)
			return -EINVAL;
		len = host_tdi->measurements->offset;
		buf = host_tdi->measurements->buf;
	} else if (type == RHI_DA_OBJECT_CERTIFICATE) {
		if (!pf0_ep_dsc->cert_chain.cache)
			return -EINVAL;
		len = pf0_ep_dsc->cert_chain.cache->offset;
		buf = pf0_ep_dsc->cert_chain.cache->buf;
	} else if (type == RHI_DA_OBJECT_VCA) {
		if (!pf0_ep_dsc->vca)
			return -EINVAL;
		len = pf0_ep_dsc->vca->offset;
		buf = pf0_ep_dsc->vca->buf;
	} else {
		return -EINVAL;
	}

	/* Assume that the buffer is large enough for the whole report */
	if (max_len < len)
		return -E2BIG;

	if (copy_to_user(user_buf, buf + offset, len))
		return -EIO;

	return len;
}

static int vdev_update_interface_report_cache(struct cca_host_tdi *host_tdi,
					      struct pci_dev *pdev)
{
	struct dev_comm_work comm_work;
	struct cca_host_comm_data *comm_data = to_cca_comm_data(pdev);

	INIT_WORK_ONSTACK(&comm_work.work, vdev_fetch_object_workfn);
	comm_work.tsm = pdev->tsm;
	comm_work.host_tdi = host_tdi;
	if (host_tdi->interface_report) {
		comm_work.cache_buf = host_tdi->interface_report->buf;
		comm_work.cache_offset = &host_tdi->interface_report->offset;
		comm_work.cache_size = host_tdi->interface_report->size;
	} else {
		comm_work.cache_buf = NULL;
		comm_work.cache_offset = NULL;
		comm_work.cache_size = 0;
	}

	queue_work(comm_data->work_queue, &comm_work.work);
	flush_work(&comm_work.work);
	destroy_work_on_stack(&comm_work.work);

	if (comm_work.cache_size == 0)
		return -ENXIO;
	return 0;
}

int cca_vdev_update_interface_report(struct cca_host_tdi *host_tdi,
				     struct pci_dev *pdev)
{
	phys_addr_t rmm_pdev_phys;
	phys_addr_t rmm_vdev_phys;
	struct cca_host_pdev_dsc *pdev_dsc;
	struct realm *realm;
	phys_addr_t rd_phys;

	cca_vdev_assert_locked(pdev);

	rmm_vdev_phys = virt_to_phys(host_tdi->rmm_vdev);
	realm = &host_tdi->kvm->arch.realm;
	rd_phys = virt_to_phys(realm->rd);

	pdev_dsc = to_cca_pdev_dsc(pdev->tsm->dsm_dev);
	rmm_pdev_phys = virt_to_phys(pdev_dsc->rmm_pdev);

	if (rmi_vdev_get_interface_report(rd_phys,
					  rmm_pdev_phys, rmm_vdev_phys))
		return -ENXIO;

	/* get and update the interface report cache. */
	return vdev_update_interface_report_cache(host_tdi, pdev);
}

static int
vdev_update_device_measurements_cache(struct cca_host_tdi *host_tdi,
				      struct pci_dev *pdev)
{
	struct dev_comm_work comm_work;
	struct cca_host_comm_data *comm_data = to_cca_comm_data(pdev);

	INIT_WORK_ONSTACK(&comm_work.work, vdev_fetch_object_workfn);
	comm_work.tsm = pdev->tsm;
	comm_work.host_tdi = host_tdi;
	if (host_tdi->measurements) {
		comm_work.cache_buf = host_tdi->measurements->buf;
		comm_work.cache_offset = &host_tdi->measurements->offset;
		comm_work.cache_size = host_tdi->measurements->size;
	} else {
		comm_work.cache_buf = NULL;
		comm_work.cache_offset = NULL;
		comm_work.cache_size = 0;
	}

	queue_work(comm_data->work_queue, &comm_work.work);
	flush_work(&comm_work.work);
	destroy_work_on_stack(&comm_work.work);

	if (comm_work.cache_size == 0)
		return -ENXIO;
	return 0;
}

static inline void vdev_measurement_param_free(struct rmi_vdev_measurement_params *param)
{
	if (param)
		free_page((unsigned long)param);
}

DEFINE_FREE(measurement_param_free, struct rmi_vdev_measurement_params *,
	    vdev_measurement_param_free(_T))

int cca_vdev_update_device_measurements(struct cca_host_tdi *host_tdi,
					struct pci_dev *pdev,
					unsigned long flags, u8 *nonce)
{
	struct realm *realm;
	phys_addr_t rd_phys;
	phys_addr_t rmm_pdev_phys;
	phys_addr_t rmm_vdev_phys;
	struct cca_host_pdev_dsc *pdev_dsc;

	cca_vdev_assert_locked(pdev);

	rmm_vdev_phys = virt_to_phys(host_tdi->rmm_vdev);
	realm = &host_tdi->kvm->arch.realm;
	rd_phys = virt_to_phys(realm->rd);

	pdev_dsc = to_cca_pdev_dsc(pdev->tsm->dsm_dev);
	rmm_pdev_phys = virt_to_phys(pdev_dsc->rmm_pdev);

	struct rmi_vdev_measurement_params *params __free(measurement_param_free) =
		(struct rmi_vdev_measurement_params *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
	if (!params)
		return -ENOMEM;

	params->flags = flags;

	if (copy_from_user(params->nonce, nonce, sizeof(params->nonce)))
		return -EFAULT;

	if (rmi_vdev_get_device_measurements(rd_phys, rmm_pdev_phys,
					     rmm_vdev_phys, virt_to_phys(params)))
		return -ENXIO;

	/* get and update the interface report cache. */
	return vdev_update_device_measurements_cache(host_tdi, pdev);
}
