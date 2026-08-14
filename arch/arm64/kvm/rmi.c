// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2025 ARM Ltd.
 */

#include <uapi/linux/psci.h>
#include <linux/kvm_host.h>
#include <linux/overflow.h>
#include <linux/sort.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/rmi_cmds.h>
#include <asm/virt.h>

#define RMM_RTT_MAX_LEVEL	KVM_PGTABLE_LAST_LEVEL

/* Two RTT levels at each end of both the protected and shared IPA ranges. */
#define REALM_UNMAP_RTT_RESERVE	(2 * 2 * (KVM_PGTABLE_LAST_LEVEL - 1))

/*
 * Track every granule the host delegates to the RMM in a global region tree and
 * report the amount currently owned by the RMM when a Realm shuts down. This
 * is a debug aid - it adds a maple-tree store/erase per RTT/RD/REC/PGD
 * delegate-undelegate - so it is off by default and enabled via the module
 * parameter when investigating ownership accounting.
 *
 * The value is sampled when a Realm is created. Runtime changes affect only
 * subsequently created Realms.
 */
static bool realm_track_leaks;
module_param(realm_track_leaks, bool, 0644);
MODULE_PARM_DESC(realm_track_leaks,
		 "Track RMM-owned memory for newly created Realms (debug)");

static __always_inline void realm_region_track(struct realm *realm,
					       phys_addr_t phys, unsigned long size,
					       unsigned long fid, unsigned long ipa)
{
	if (unlikely(realm->sro && realm->sro->trackid))
		rmi_region_track(realm->sro, phys, size, fid, ipa);
}

static __always_inline void realm_region_untrack(struct realm *realm,
						 phys_addr_t phys,
						 unsigned long size)
{
	if (unlikely(realm->sro && realm->sro->trackid))
		rmi_region_untrack(realm->sro, phys, size);
}

struct realm_dev_mapping {
	struct list_head node;
	unsigned long vdev_phys;
	unsigned long start;
	unsigned long end;
};

static inline unsigned long rmi_rtt_level_mapsize(int level)
{
	if (WARN_ON(level > KVM_PGTABLE_LAST_LEVEL))
		return PAGE_SIZE;

	return (1UL << ARM64_HW_PGTABLE_LEVEL_SHIFT(level));
}

static inline unsigned long rmi_rtt_next_addr(unsigned long addr,
					      unsigned long end, int level)
{
	return min(ALIGN(addr + 1, rmi_rtt_level_mapsize(level)), end);
}

static bool rmi_has_feature(unsigned long reg, unsigned long feature)
{
	return !!u64_get_bits(rmi_feat_reg(reg), feature);
}

bool kvm_rmi_supports_sve(void)
{
	return rmi_has_feature(0, RMI_FEATURE_REGISTER_0_SVE);
}

u32 kvm_rmm_ipa_limit(void)
{
	return u64_get_bits(rmi_feat_reg(0), RMI_FEATURE_REGISTER_0_S2SZ);
}

unsigned int kvm_realm_sve_max_vl(void)
{
	return sve_vl_from_vq(u64_get_bits(rmi_feat_reg(0),
					   RMI_FEATURE_REGISTER_0_SVE_VL) + 1);
}

u64 kvm_realm_reset_id_aa64dfr0_el1(const struct kvm_vcpu *vcpu, u64 val)
{
	u32 bps = u64_get_bits(rmi_feat_reg(0), RMI_FEATURE_REGISTER_0_NUM_BPS);
	u32 wps = u64_get_bits(rmi_feat_reg(0), RMI_FEATURE_REGISTER_0_NUM_WPS);
	u32 ctx_cmps;

	/* Ensure CTX_CMPs is still valid */
	ctx_cmps = FIELD_GET(ID_AA64DFR0_EL1_CTX_CMPs, val);
	ctx_cmps = min(bps, ctx_cmps);

	val &= ~(ID_AA64DFR0_EL1_BRPs_MASK | ID_AA64DFR0_EL1_WRPs_MASK |
		 ID_AA64DFR0_EL1_CTX_CMPs);
	val |= FIELD_PREP(ID_AA64DFR0_EL1_BRPs_MASK, bps) |
	       FIELD_PREP(ID_AA64DFR0_EL1_WRPs_MASK, wps) |
	       FIELD_PREP(ID_AA64DFR0_EL1_CTX_CMPs, ctx_cmps);

	return val;
}

static int get_start_level(struct realm *realm)
{
	return 4 - stage2_pgtable_levels(realm->ia_bits);
}

static int find_map_level(struct realm *realm,
			  unsigned long start,
			  unsigned long end)
{
	int level = KVM_PGTABLE_LAST_LEVEL;

	while (level > get_start_level(realm)) {
		unsigned long map_size = rmi_rtt_level_mapsize(level - 1);

		if (!IS_ALIGNED(start, map_size) ||
		    (start + map_size) > end)
			break;

		level--;
	}

	return level;
}

static int find_aligned_map_level(struct realm *realm,
				  unsigned long ipa,
				  phys_addr_t phys,
				  unsigned long end)
{
	int level = KVM_PGTABLE_LAST_LEVEL;

	while (level > get_start_level(realm)) {
		unsigned long map_size = rmi_rtt_level_mapsize(level - 1);

		if (!IS_ALIGNED(ipa | phys, map_size) ||
		    (ipa + map_size) > end)
			break;

		level--;
	}

	return level;
}

/* Report the amount of memory still attributed to this Track ID. */
static u64 realm_report_owned_granules(struct realm *realm)
{
	u64 owned;

	if (!realm->sro->trackid)
		return 0;

	owned = rmi_region_owned_bytes(realm->sro);
	if (owned)
		pr_err("realm: Track ID %u, RMM currently owns %llu pages\n",
		       realm->sro->trackid, owned >> PAGE_SHIFT);

	return owned;
}

static void realm_free_sro(struct realm *realm)
{
	if (realm->sro) {
		u64 owned;

		rmi_sro_free(realm->sro);
		owned = realm_report_owned_granules(realm);
		if (realm->sro->trackid && !owned)
			rmi_trackid_free(realm->sro->trackid);
		kfree(realm->sro);
		realm->sro = NULL;
	}
}

static int realm_alloc_sro(struct realm *realm, u16 trackid)
{
	if (WARN_ONCE(realm->sro, "RMI: Realm SRO already allocated: %d\n",
		      -EEXIST))
		return -EEXIST;

	realm->sro = kzalloc_obj(*realm->sro, GFP_KERNEL_ACCOUNT);
	if (!realm->sro)
		return -ENOMEM;

	/*
	 * Track this Realm's SRO donations in the shared RMI tree. When
	 * realm_track_leaks is off, Track ID remains zero and every track/report path is
	 * a no-op.
	 */
	realm->sro->trackid = trackid;

	return 0;
}

/*
 * Delegate a PA range using caller-owned SRO state.
 *
 * RMI_GRANULE_RANGE_DELEGATE may make forward progress on only a prefix of
 * the requested range. Return that delegated prefix to the caller so it can
 * either consume the granules or undelegate exactly the granules that changed
 * ownership.
 */
static long realm_delegate_range(struct realm *realm, phys_addr_t phys,
				 unsigned long size,
				 unsigned long *delegated_size)
{
	unsigned long done;
	long ret;

	ret = rmi_delegate_range(phys, size, &done);
	if (delegated_size)
		*delegated_size = done;

	/*
	 * The delegated prefix [phys, phys + done) is now RMM-owned, so record it as
	 * donated (treat delegated as donated). On a partial failure the caller
	 * undelegates the prefix, dropping it again via realm_undelegate_range();
	 * otherwise it stays tracked until the Realm returns the memory.
	 */
	realm_region_track(realm, phys, done,
			   SMC_RMI_GRANULE_RANGE_DELEGATE, 0);
	return ret;
}

static long realm_undelegate_range(struct realm *realm, phys_addr_t phys,
				   unsigned long size,
				   unsigned long *undelegated_size)
{
	unsigned long done;
	long ret;

	ret = rmi_undelegate_range(phys, size, &done);
	if (undelegated_size)
		*undelegated_size = done;

	/*
	 * Drop the prefix returned to NS from the ownership tree. On an error,
	 * any unprocessed suffix remains RMM-owned and tracked.
	 */
	realm_region_untrack(realm, phys, done);
	return ret;
}

static int realm_rmi_to_errno(long ret)
{
	if (ret == RMI_SUCCESS)
		return 0;

	return ret < 0 ? (int)ret : -ENXIO;
}

static int realm_undelegate_map_range(struct realm *realm, phys_addr_t phys,
				      unsigned long size)
{
	phys_addr_t addr;
	phys_addr_t end = phys + size;
	unsigned long undelegated_size = 0;
	long ret;

	if (!size)
		return 0;

	ret = realm_undelegate_range(realm, phys, size, &undelegated_size);
	if (WARN_ONCE(ret != RMI_SUCCESS,
		      "RMI: range undelegate failed: rmi=%ld err=%d\n",
		      ret, -ENXIO)) {
		/* Pages can't be returned to NS world so are lost */
		for (addr = phys + undelegated_size; addr < end;
		     addr += PAGE_SIZE)
			get_page(phys_to_page(addr));
		return -ENXIO;
	}

	return 0;
}

static int rmi_addr_range_desc_decode(unsigned long desc,
				      unsigned long expected_state,
				      phys_addr_t *addr, unsigned long *size)
{
	unsigned long block_size;
	unsigned long count = RMI_ADDR_RANGE_COUNT(desc);
	phys_addr_t base = RMI_ADDR_RANGE_ADDR(desc);
	phys_addr_t end;

	if (!count) {
		if (desc)
			return -EPROTO;
		*addr = 0;
		*size = 0;
		return 0;
	}

	block_size = RMI_ADDR_BSIZE_BYTES(RMI_ADDR_RANGE_SIZE(desc));
	if ((desc & RMI_ADDR_RANGE_RESERVED_MASK) ||
	    RMI_ADDR_RANGE_STATE(desc) != expected_state ||
	    !IS_ALIGNED(base, block_size) ||
	    check_mul_overflow(block_size, count, size) ||
	    check_add_overflow(base, *size, &end))
		return -EPROTO;

	*addr = base;
	return 0;
}

static int undelegate_range_desc(struct kvm *kvm, unsigned long desc,
				 bool may_block)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long size;
	phys_addr_t addr;
	int ret;

	ret = rmi_addr_range_desc_decode(desc, RMI_OP_MEM_DELEGATED,
					 &addr, &size);
	if (ret)
		return ret;
	if (!size)
		return 0;

	while (size) {
		unsigned long step = min(size, rmi_granule_range_step());
		long rmi_ret;

		rmi_ret = realm_undelegate_range(realm, addr, step, NULL);
		ret = realm_rmi_to_errno(rmi_ret);
		if (ret)
			return ret;

		addr += step;
		size -= step;
		if (may_block)
			cond_resched_rwlock_write(&kvm->mmu_lock);
	}

	return 0;
}

static int rmi_addr_range_desc_cmp(const void *a, const void *b)
{
	unsigned long addr_a = RMI_ADDR_RANGE_ADDR(*(const unsigned long *)a);
	unsigned long addr_b = RMI_ADDR_RANGE_ADDR(*(const unsigned long *)b);

	if (addr_a < addr_b)
		return -1;
	if (addr_a > addr_b)
		return 1;
	return 0;
}

static int undelegate_range_descs(struct realm *realm, unsigned long *descs,
				  unsigned long count)
{
	unsigned long run_start = 0, run_end = 0;
	bool have_run = false;
	unsigned long i;
	long rmi_ret;
	int ret;

	if (!count)
		return 0;

	sort(descs, count, sizeof(*descs), rmi_addr_range_desc_cmp, NULL);

	for (i = 0; i < count; i++) {
		unsigned long size;
		phys_addr_t addr;

		ret = rmi_addr_range_desc_decode(descs[i],
						 RMI_OP_MEM_DELEGATED,
						 &addr, &size);
		if (ret)
			return ret;
		if (!size)
			return -EPROTO;

		if (have_run && addr == run_end) {
			run_end += size;
			continue;
		}

		if (have_run) {
			rmi_ret = realm_undelegate_range(realm, run_start,
							 run_end - run_start, NULL);
			if (rmi_ret)
				return realm_rmi_to_errno(rmi_ret);
		}

		run_start = addr;
		run_end = addr + size;
		have_run = true;
	}

	if (!have_run)
		return 0;

	rmi_ret = realm_undelegate_range(realm, run_start,
					 run_end - run_start, NULL);
	return realm_rmi_to_errno(rmi_ret);
}

static void realm_alloc_unmap_desc_buf(struct realm *realm)
{
	unsigned long *buf;

	if (WARN_ON(realm->unmap_desc_buf))
		return;

	buf = (unsigned long *)__get_free_page(GFP_KERNEL_ACCOUNT);
	if (!buf)
		return;

	realm->unmap_desc_buf = buf;
	realm->unmap_desc_pa = virt_to_phys(buf);
	realm->unmap_desc_cap = min_t(unsigned long,
				      PAGE_SIZE / sizeof(*buf),
				      FIELD_MAX(RMI_RTT_UNMAP_FLAGS_LIST_COUNT_MASK));
}

static void realm_free_unmap_desc_buf(struct realm *realm)
{
	if (!realm->unmap_desc_buf)
		return;

	free_page((unsigned long)realm->unmap_desc_buf);
	realm->unmap_desc_buf = NULL;
	realm->unmap_desc_pa = 0;
	realm->unmap_desc_cap = 0;
}

static phys_addr_t alloc_delegated_granule(struct realm *realm,
					   struct rmi_sro_state *sro,
					   gfp_t gfp)
{
	phys_addr_t phys = rmi_sro_alloc(sro, gfp);

	/*
	 * Account the granule handed to the Realm as RMM-owned in the Realm's
	 * ownership tree for leak detection. The allocation @sro may be NULL (fresh
	 * fallback alloc) or a per-REC SRO, so always track via realm->sro, whose
	 * Track ID identifies the owning Realm.
	 */
	if (phys != PHYS_ADDR_MAX)
		realm_region_track(realm, phys, PAGE_SIZE,
				   SMC_RMI_GRANULE_RANGE_DELEGATE, 0);
	return phys;
}

static int realm_free_delegated_page(struct realm *realm, phys_addr_t phys)
{
	long ret;

	ret = realm_undelegate_range(realm, phys, PAGE_SIZE, NULL);
	if (WARN_ONCE(ret,
		      "RMI: page undelegate failed: rmi=%ld err=%d\n",
		      ret, -EBUSY)) {
		/* Undelegate failed: leak the page */
		return -EBUSY;
	}

	free_page((unsigned long)phys_to_virt(phys));
	return 0;
}

static phys_addr_t alloc_rtt(struct realm *realm, struct rmi_sro_state *sro)
{
	phys_addr_t phys = alloc_delegated_granule(realm, sro, GFP_ATOMIC);

	if (phys != PHYS_ADDR_MAX)
		kvm_account_pgtable_pages(phys_to_virt(phys), 1);

	return phys;
}

static void free_rtt(struct realm *realm, phys_addr_t phys)
{
	if (realm_free_delegated_page(realm, phys))
		return;

	kvm_account_pgtable_pages(phys_to_virt(phys), -1);
}

unsigned long realm_psci_complete(struct kvm_vcpu *vcpu, unsigned long status)
{
	return rmi_psci_complete(virt_to_phys(vcpu->arch.rec.rec_page), status);
}

static int kvm_mpidr_to_rmi_rec_mpidr(unsigned long mpidr,
				      unsigned long *rec_mpidr)
{
	unsigned long aff0 = MPIDR_AFFINITY_LEVEL(mpidr, 0);

	if (aff0 & ~0xfUL)
		return -EINVAL;

	*rec_mpidr = aff0 |
		     (MPIDR_AFFINITY_LEVEL(mpidr, 1) << 8) |
		     (MPIDR_AFFINITY_LEVEL(mpidr, 2) << 16) |
		     (MPIDR_AFFINITY_LEVEL(mpidr, 3) << 24);

	return 0;
}

static int realm_rtt_create(struct realm *realm,
			    unsigned long addr,
			    int level,
			    phys_addr_t phys)
{
	addr = ALIGN_DOWN(addr, rmi_rtt_level_mapsize(level - 1));
	return rmi_rtt_create(virt_to_phys(realm->rd), phys, addr, level);
}

static int realm_rtt_fold(struct realm *realm,
			  unsigned long addr,
			  int level,
			  phys_addr_t *rtt_granule)
{
	unsigned long out_rtt = 0;
	int ret;

	addr = ALIGN_DOWN(addr, rmi_rtt_level_mapsize(level - 1));
	ret = rmi_rtt_fold(virt_to_phys(realm->rd), addr, level, &out_rtt);

	if (ret == RMI_SUCCESS && rtt_granule)
		*rtt_granule = out_rtt;

	return ret;
}

/*
 * realm_rtt_destroy - Destroy an RTT at @level for @addr.
 *
 * Returns - Result of the RMI_RTT_DESTROY call, and:
 * @rtt_granule:	RTT granule, if the RTT was destroyed.
 * @next_addr:		IPA corresponding to the next possible valid entry we
 *			can target
 */
static int realm_rtt_destroy(struct realm *realm, unsigned long addr,
			     int level, phys_addr_t *rtt_granule,
			     unsigned long *next_addr)
{
	unsigned long out_rtt;
	int ret;

	ret = rmi_rtt_destroy(virt_to_phys(realm->rd), addr, level,
			      &out_rtt, next_addr);

	if (ret == RMI_SUCCESS)
		*rtt_granule = out_rtt;

	return ret;
}

static int realm_create_rtt_levels(struct realm *realm,
				   unsigned long ipa,
				   int level,
				   int max_level,
				   struct rmi_sro_state *sro)
{
	while (level++ < max_level) {
		phys_addr_t rtt = alloc_rtt(realm, sro);
		int ret;

		if (rtt == PHYS_ADDR_MAX)
			return -ENOMEM;

		ret = realm_rtt_create(realm, ipa, level, rtt);
		if ((ret >= 0) &&
		    (RMI_RETURN_STATUS(ret) == RMI_BLOCKED)) {
			free_rtt(realm, rtt);
			return -EAGAIN;
		}

		if ((ret >= 0) &&
		    (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) &&
		    RMI_RETURN_INDEX(ret) == level - 1) {
			/* The RTT already exists, continue */
			free_rtt(realm, rtt);
			continue;
		}

		if (ret) {
			WARN(1, "Failed to create RTT at level %d: %d\n",
			     level, ret);
			free_rtt(realm, rtt);
			return -ENXIO;
		}

		realm_region_track(realm, rtt, PAGE_SIZE,
				   SMC_RMI_RTT_CREATE, ipa);
	}

	return 0;
}

static int realm_tear_down_rtt_level(struct realm *realm, int level,
				     unsigned long start, unsigned long end)
{
	ssize_t map_size;
	unsigned long addr, next_addr;

	if (WARN_ONCE(level > KVM_PGTABLE_LAST_LEVEL,
		      "RMI: invalid teardown level %d: %d\n", level, -EINVAL))
		return -EINVAL;

	map_size = rmi_rtt_level_mapsize(level - 1);

	for (addr = start; addr < end; addr = next_addr) {
		phys_addr_t rtt_granule;
		int ret;
		unsigned long align_addr = ALIGN(addr, map_size);

		next_addr = ALIGN(addr + 1, map_size);

		if (next_addr > end || align_addr != addr) {
			/*
			 * The target range is smaller than what this level
			 * covers, recurse deeper.
			 */
			ret = realm_tear_down_rtt_level(realm,
							level + 1,
							addr,
							min(next_addr, end));
			if (ret)
				return ret;
			continue;
		}

		ret = realm_rtt_destroy(realm, addr, level,
					&rtt_granule, &next_addr);

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			realm_region_track(realm, rtt_granule, PAGE_SIZE,
					   SMC_RMI_RTT_DESTROY, addr);
			free_rtt(realm, rtt_granule);
			break;
		case RMI_ERROR_RTT:
			if (next_addr > addr) {
				/* Missing RTT, skip */
				break;
			}
			/*
			 * We tear down the RTT range for the full IPA
			 * space, after everything is unmapped. Also we
			 * descend down only if we cannot tear down a
			 * top level RTT. Thus RMM must be able to walk
			 * to the requested level. e.g., a block mapping
			 * exists at L1 or L2.
			 */
			if (WARN_ONCE(RMI_RETURN_INDEX(ret) != level,
				      "RMI: RTT destroy level mismatch %#x: %d\n",
				      ret, -EBUSY))
				return -EBUSY;
			if (WARN_ONCE(level == KVM_PGTABLE_LAST_LEVEL,
				      "RMI: live terminal RTT %#x: %d\n",
				      ret, -EBUSY))
				return -EBUSY;

			/*
			 * The table has active entries in it, recurse deeper
			 * and tear down the RTTs.
			 */
			next_addr = ALIGN(addr + 1, map_size);
			ret = realm_tear_down_rtt_level(realm,
							level + 1,
							addr,
							next_addr);
			if (ret)
				return ret;
			/*
			 * Now that the child RTTs are destroyed,
			 * retry at this level.
			 */
			next_addr = addr;
			break;
		default:
			WARN_ONCE(1, "RMI: RTT destroy failed %#x: %d\n",
				  ret, -ENXIO);
			return -ENXIO;
		}
	}

	return 0;
}

static int realm_tear_down_rtt_range(struct realm *realm,
				     unsigned long start, unsigned long end)
{
	/*
	 * Root level RTTs can only be destroyed after the RD is destroyed. So
	 * tear down everything below the root level
	 */
	return realm_tear_down_rtt_level(realm, get_start_level(realm) + 1,
					 start, end);
}

/*
 * DEN0137 v2.0-bet3 defines RMI_RTT_FOLD as a one-entry operation; there is no
 * counted or LIST form to fold a range. The unmap output descriptors report
 * PA ranges, not the level of the removed RTTE, so probe L3 after any command
 * that removed a mapping. A successful fold makes the enclosing RTT a
 * candidate. On RMI_ERROR_RTT, an error at the target level means the target
 * RTT is non-homogeneous and stops the upward probe. A lower error level leaves
 * the enclosing RTT as a possible candidate, so continue upward.
 */
static bool realm_fold_rtt_level(struct kvm *kvm, int level,
				 unsigned long start, unsigned long end)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long map_size;
	unsigned long addr;
	bool probe_parent = false;

	/*
	 * Final teardown does not need homogeneous RTTs. RMI_RTT_DESTROY can
	 * reclaim any non-live RTT and its @top output skips RTTs which do not
	 * exist. Avoid speculative bottom-up folds while the complete stage-2 is
	 * being removed: a 1 GiB block mapping has no L3 RTT, but probing from L3
	 * would still issue 512 failing RMI_RTT_FOLD calls before reaching L2.
	 *
	 * Keep folding for partial unmaps of a live Realm, where reclaiming an
	 * empty RTT allows a larger block mapping to be installed later.
	 */
	if (kvm_realm_state(kvm) == REALM_STATE_DYING)
		return false;

	if (WARN_ON(level > RMM_RTT_MAX_LEVEL))
		return false;
	if (start >= end || level <= get_start_level(realm))
		return false;

	map_size = rmi_rtt_level_mapsize(level - 1);
	start = ALIGN_DOWN(start, map_size);
	end = ALIGN(end, map_size);

	if (start >= end)
		return false;

	for (addr = start; addr < end; addr += map_size) {
		phys_addr_t rtt_granule;
		int ret;

		ret = realm_rtt_fold(realm, addr, level, &rtt_granule);

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			free_rtt(realm, rtt_granule);
			probe_parent = true;
			break;
		case RMI_ERROR_RTT:
			if (RMI_RETURN_INDEX(ret) < level)
				probe_parent = true;
			break;
		default:
			WARN_ON(1);
			return false;
		}
	}

	/* RMI_RTT_FOLD cannot target the Realm's starting-level root RTT. */
	if (probe_parent && level > (get_start_level(realm) + 1))
		realm_fold_rtt_level(kvm, level - 1, start, end);

	return probe_parent;
}

static bool realm_unmap_output_is_dense_pages(unsigned long start,
					      unsigned long end,
					      unsigned long out_range)
{
	unsigned long count;

	if (RMI_ADDR_RANGE_SIZE(out_range) != RMI_ADDR_RANGE_SIZE_PAGE)
		return false;

	count = RMI_ADDR_RANGE_COUNT(out_range);
	if (!count)
		return false;

	return end - start == count * PAGE_SIZE;
}

static bool realm_unmap_outputs_are_dense_pages(unsigned long start,
						unsigned long end,
						unsigned long *descs,
						unsigned long out_count)
{
	unsigned long i, count = 0;

	if (!out_count)
		return false;

	for (i = 0; i < out_count; i++) {
		if (RMI_ADDR_RANGE_SIZE(descs[i]) != RMI_ADDR_RANGE_SIZE_PAGE)
			return false;
		count += RMI_ADDR_RANGE_COUNT(descs[i]);
	}

	return count && end - start == count * PAGE_SIZE;
}

static int realm_destroy_rtts(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned int ia_bits = realm->ia_bits;
	int ret;

	lockdep_assert_held(&kvm->arch.config_lock);

	if (realm->rtts_destroyed)
		return 0;

	ret = realm_tear_down_rtt_range(realm, 0, (1UL << ia_bits));
	if (ret)
		return ret;

	realm->rtts_destroyed = true;
	return 0;
}

static void realm_unmap_stage2(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;

	lockdep_assert_held(&kvm->arch.config_lock);

	if (realm->stage2_unmapped)
		return;

	realm->stage2_unmap_failed = false;

	write_lock(&kvm->mmu_lock);
	kvm_stage2_unmap_range(&kvm->arch.mmu, 0,
			       BIT(realm->ia_bits - 1), true);
	write_unlock(&kvm->mmu_lock);

	/*
	 * Only record the stage-2 as unmapped if every range was actually
	 * removed. A swallowed unmap failure (e.g. RTT split under memory
	 * pressure) must stay retryable, otherwise realm_destroy_rtts() would
	 * later trip over live RTTEs and leak granules.
	 */
	if (realm->stage2_unmap_failed)
		return;

	realm->stage2_unmapped = true;
	realm_free_unmap_desc_buf(realm);
}

int kvm_realm_teardown_stage2(struct kvm *kvm)
{
	lockdep_assert_held(&kvm->arch.config_lock);

	realm_unmap_stage2(kvm);
	return realm_destroy_rtts(kvm);
}

static int realm_unmap_shared_range(struct kvm *kvm,
				    unsigned long start,
				    unsigned long end,
				    bool may_block,
				    struct rmi_sro_state *sro)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long rd = virt_to_phys(realm->rd);
	unsigned long next_addr, addr;
	unsigned long shared_bit = BIT(realm->ia_bits - 1);

	lockdep_assert_held_write(&kvm->mmu_lock);

	if (start >= end)
		return 0;

	/*
	 * Convert the private IPA interval to its shared alias. Use addition
	 * rather than setting the shared bit so a full private range ending at
	 * @shared_bit maps to the open end of the shared half, not to an empty
	 * range.
	 */
	start += shared_bit;
	end += shared_bit;

	for (addr = start; addr < end; addr = next_addr) {
		unsigned long out_range = 0;
		int ret;

retry:
		ret = rmi_rtt_unprot_unmap(rd, addr, end,
					   RMI_ADDR_TYPE_SINGLE, 0,
					   &next_addr, &out_range, NULL);
		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS: {
			unsigned long range_size;
			phys_addr_t range_addr;

			if (WARN_ON(next_addr <= addr || next_addr > end))
				return -EPROTO;
			ret = rmi_addr_range_desc_decode(
				out_range, RMI_OP_MEM_UNDELEGATED,
				&range_addr, &range_size);
			if (WARN_ON_ONCE(ret))
				return ret;
			if (range_size) {
				realm_region_untrack(realm, range_addr, range_size);
				realm_fold_rtt_level(kvm, RMM_RTT_MAX_LEVEL,
						     addr, next_addr);
			}
			break;
		}
		case RMI_ERROR_RTT: {
			unsigned long map_size;
			int err_level = RMI_RETURN_INDEX(ret);

			if (WARN_ON(err_level > KVM_PGTABLE_LAST_LEVEL))
				return -EPROTO;

			map_size = rmi_rtt_level_mapsize(err_level);
			if (err_level == KVM_PGTABLE_LAST_LEVEL ||
			    (IS_ALIGNED(addr, map_size) &&
			     addr + map_size <= end)) {
				next_addr = rmi_rtt_next_addr(addr, end,
							     err_level);
				break;
			}

			ret = realm_create_rtt_levels(realm,
						      addr, err_level,
						      err_level + 1,
						      sro);
			if (ret)
				return ret;
			goto retry;
		}
		default:
			WARN_ON(1);
			return ret < 0 ? ret : -ENXIO;
		}

		if (may_block)
			cond_resched_rwlock_write(&kvm->mmu_lock);
	}

	return 0;
}

static int realm_init_sve_param(struct kvm *kvm, struct realm_params *params)
{
	unsigned long i;
	struct kvm_vcpu *vcpu;
	int vl, last_vl = -1;

	if (!kvm_has_sve(kvm))
		return 0;

	/*
	 * Get the preferred SVE configuration, set by userspace with the
	 * KVM_ARM_VCPU_SVE feature and KVM_REG_ARM64_SVE_VLS pseudo-register.
	 */
	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (!kvm_arm_vcpu_sve_finalized(vcpu))
			return -EINVAL;

		vl = vcpu->arch.sve_max_vl;

		/* We need all vCPUs to have the same SVE config */
		if (last_vl >= 0 && last_vl != vl)
			return -EINVAL;

		last_vl = vl;
	}

	if (last_vl > 0) {
		params->sve_vl = sve_vq_from_vl(last_vl) - 1;
		params->flags0 |= RMI_REALM_PARAM_FLAG_SVE;
	}
	return 0;
}

static int realm_create_rd(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	struct realm_params *params __free(free_page) = NULL;
	void *rd = NULL;
	phys_addr_t rd_phys, params_phys;
	size_t pgd_size = kvm_pgtable_stage2_pgd_size(kvm->arch.mmu.vtcr);
	unsigned long pgd_delegated_size = 0;
	u64 dfr0 = kvm_read_vm_id_reg(kvm, SYS_ID_AA64DFR0_EL1);
	long rmi_ret;
	long cleanup_ret;
	int r;

	realm->ia_bits = VTCR_EL2_IPA(kvm->arch.mmu.vtcr);

	if (WARN_ONCE(realm->rd,
		      "RMI: invalid Realm create state: %d\n", -EEXIST))
		return -EEXIST;

	params = (void *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
	if (!params)
		return -ENOMEM;

	/*
	 * Pre-warm the SRO hot list during Realm creation (process context,
	 * outside mmu_lock) so the RD and the Realm's initial RTTs are served
	 * from pre-delegated entries. Best-effort: a failure just leaves the
	 * allocators on the per-granule fallback path.
	 */
	rmi_sro_topup(realm->sro, SZ_2M >> PAGE_SHIFT,
		      kvm_mmu_cache_min_pages(&kvm->arch.mmu));

	rd_phys = alloc_delegated_granule(realm, realm->sro,
					  GFP_KERNEL_ACCOUNT);
	if (rd_phys == PHYS_ADDR_MAX)
		return -ENOMEM;
	rd = phys_to_virt(rd_phys);

	rmi_ret = realm_delegate_range(realm, kvm->arch.mmu.pgd_phys,
				       pgd_size, &pgd_delegated_size);
	if (rmi_ret) {
		r = realm_rmi_to_errno(rmi_ret);
		goto out_undelegate_tables;
	}

	params->s2sz = VTCR_EL2_IPA(kvm->arch.mmu.vtcr);
	params->rtt_level_start = get_start_level(realm);
	params->rtt_num_start = pgd_size / PAGE_SIZE;
	params->rtt_base = kvm->arch.mmu.pgd_phys;
	params->num_bps = SYS_FIELD_GET(ID_AA64DFR0_EL1, BRPs, dfr0);
	params->num_wps = SYS_FIELD_GET(ID_AA64DFR0_EL1, WRPs, dfr0);
	params->hash_algo = RMI_HASH_SHA_256;

	if (kvm->arch.arm_pmu) {
		params->pmu_num_ctrs = kvm->arch.nr_pmu_counters;
		params->flags0 |= RMI_REALM_PARAM_FLAG_PMU;
	}

	r = realm_init_sve_param(kvm, params);
	if (r)
		goto out_undelegate_tables;

	/* For now default enable DA */
	if (rmm_has_reg2_feature(RMI_FEATURE_REGISTER_2_DA)) {
		params->flags0 |= RMI_REALM_PARAM_FLAG_DA;
		params->max_num_vdevs = rmm_realm_max_vdevs();
	}
	if (rmm_has_reg2_feature(RMI_FEATURE_REGISTER_2_ATS))
		params->flags1 |= RMI_REALM_PARAM_FLAG1_ATS;
	params_phys = virt_to_phys(params);

	rmi_ret = rmi_realm_create(rd_phys, params_phys, realm->sro);
	if (rmi_ret) {
		r = rmi_ret < 0 ? rmi_ret : -ENXIO;
		goto out_undelegate_tables;
	}

	realm->rd = rd;
	realm_alloc_unmap_desc_buf(realm);
	kvm_set_realm_state(kvm, REALM_STATE_NEW);

	return 0;

out_undelegate_tables:
	if (pgd_delegated_size) {
		cleanup_ret = realm_undelegate_range(realm,
						     kvm->arch.mmu.pgd_phys,
						     pgd_delegated_size, NULL);
		if (WARN_ONCE(cleanup_ret,
			      "RMI: Realm PGD undelegate failed: %ld\n",
			      cleanup_ret))
			/* Leak the pages if they cannot be returned */
			kvm->arch.mmu.pgt = NULL;
	}
	/* Undelegate + free (leaks on undelegate failure). */
	realm_free_delegated_page(realm, rd_phys);
	return r;
}

static int __realm_dev_mem_unmap(struct kvm *kvm, unsigned long start,
				 unsigned long end, bool may_block);

/*
 * RMI_RTT_DATA_UNMAP does not consume device RTTEs and reports them like
 * holes, so a teardown that walks a range with the DATA unmap would leave
 * the device mappings live and RTT destruction would fail. Drain the device
 * mappings tracked within [start, end) through RMI_RTT_DEV_UNMAP first.
 */
static int realm_unmap_dev_ranges(struct kvm *kvm, unsigned long start,
				  unsigned long end, bool may_block)
{
	struct realm *realm = &kvm->arch.realm;
	struct realm_dev_mapping *mapping, *iter;
	int ret;

	lockdep_assert_held_write(&kvm->mmu_lock);

	for (;;) {
		mapping = NULL;
		list_for_each_entry(iter, &realm->dev_mappings, node) {
			if (iter->start < end && start < iter->end) {
				mapping = iter;
				break;
			}
		}
		if (!mapping)
			return 0;

		ret = __realm_dev_mem_unmap(kvm, max(start, mapping->start),
					    min(end, mapping->end), may_block);
		if (ret)
			return ret;
	}
}

static int realm_unmap_private_range_single(struct kvm *kvm,
					    unsigned long start,
					    unsigned long end,
					    bool may_block,
					    struct rmi_sro_state *sro)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long rd = virt_to_phys(realm->rd);
	unsigned long next_addr, addr;
	int ret;

	lockdep_assert_held_write(&kvm->mmu_lock);

	for (addr = start; addr < end; addr = next_addr) {
		unsigned long out_range = 0;
		unsigned long flags = RMI_ADDR_TYPE_SINGLE;

retry:
		ret = rmi_rtt_data_unmap(rd, addr, end, flags, 0,
					 &next_addr, &out_range, NULL);

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			if (WARN_ON(next_addr <= addr || next_addr > end))
				return -EPROTO;
			if (realm_unmap_output_is_dense_pages(addr, next_addr,
							      out_range))
				realm_fold_rtt_level(kvm, RMM_RTT_MAX_LEVEL,
						     addr, next_addr);
			break;
		case RMI_ERROR_RTT: {
			unsigned long map_size;
			int err_level = RMI_RETURN_INDEX(ret);

			if (WARN_ON(err_level > KVM_PGTABLE_LAST_LEVEL))
				return -EPROTO;

			map_size = rmi_rtt_level_mapsize(err_level);
			if (err_level == KVM_PGTABLE_LAST_LEVEL ||
			    (IS_ALIGNED(addr, map_size) &&
			     addr + map_size <= end)) {
				next_addr = rmi_rtt_next_addr(addr, end,
							     err_level);
				break;
			}

			ret = realm_create_rtt_levels(realm,
						      addr, err_level,
						      err_level + 1,
						      sro);
			if (ret)
				return ret;
			goto retry;
		}
		default:
			WARN_ON(1);
			return ret < 0 ? ret : -ENXIO;
		}

		ret = undelegate_range_desc(kvm, out_range, may_block);
		if (WARN_ONCE(ret, "RMI: descriptor undelegate failed: %d\n",
			      ret))
			return ret < 0 ? ret : -ENXIO;

		if (may_block)
			cond_resched_rwlock_write(&kvm->mmu_lock);
	}

	return 0;
}

static int realm_unmap_private_range(struct kvm *kvm,
				     unsigned long start,
				     unsigned long end,
				     bool may_block,
				     struct rmi_sro_state *sro)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long rd = virt_to_phys(realm->rd);
	unsigned long next_addr, addr;
	unsigned long flags;
	int ret;

	/*
	 * Protected unmaps need the PA output set for undelegation. Use a
	 * Realm-wide LIST buffer to batch the RMM output; mmu_lock serializes
	 * users of the buffer.
	 */
	if (!realm->unmap_desc_buf) {
		return realm_unmap_private_range_single(kvm, start, end,
							may_block, sro);
	}

	lockdep_assert_held_write(&kvm->mmu_lock);

	flags = RMI_ADDR_TYPE_LIST |
		FIELD_PREP(RMI_RTT_UNMAP_FLAGS_LIST_COUNT_MASK,
			   realm->unmap_desc_cap);

	for (addr = start; addr < end; addr = next_addr) {
		unsigned long out_count = 0;

retry:
		ret = rmi_rtt_data_unmap(rd, addr, end, flags,
					 realm->unmap_desc_pa, &next_addr,
					 NULL, &out_count);

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			if (WARN_ON(next_addr <= addr || next_addr > end))
				return -EPROTO;
			if (WARN_ON(out_count > realm->unmap_desc_cap))
				return -EPROTO;
			if (realm_unmap_outputs_are_dense_pages(addr, next_addr,
								realm->unmap_desc_buf,
								out_count))
				realm_fold_rtt_level(kvm, RMM_RTT_MAX_LEVEL,
						     addr, next_addr);
			break;
		case RMI_ERROR_RTT: {
			unsigned long map_size;
			int err_level = RMI_RETURN_INDEX(ret);

			if (WARN_ON(err_level > KVM_PGTABLE_LAST_LEVEL))
				return -EPROTO;

			map_size = rmi_rtt_level_mapsize(err_level);
			if (err_level == KVM_PGTABLE_LAST_LEVEL ||
			    (IS_ALIGNED(addr, map_size) &&
			     addr + map_size <= end)) {
				next_addr = rmi_rtt_next_addr(addr, end,
							     err_level);
				break;
			}

			ret = realm_create_rtt_levels(realm,
						      addr, err_level,
						      err_level + 1,
						      sro);
			if (ret)
				return ret;
			goto retry;
		}
		default:
			WARN_ON(1);
			return ret < 0 ? ret : -ENXIO;
		}

		ret = undelegate_range_descs(realm, realm->unmap_desc_buf,
					     out_count);
		if (WARN_ONCE(ret,
			      "RMI: descriptor list undelegate failed: %d\n",
			      ret))
			return ret < 0 ? ret : -ENXIO;

		if (may_block)
			cond_resched_rwlock_write(&kvm->mmu_lock);
	}

	return 0;
}

static int realm_get_ripas(struct kvm *kvm, unsigned long addr,
			   enum rmi_ripas *ripas)
{
	struct realm *realm = &kvm->arch.realm;
	struct rtt_entry rtt_entry;
	unsigned long rd = virt_to_phys(realm->rd);

	lockdep_assert_held_write(&kvm->mmu_lock);

	if (rmi_rtt_read_entry(rd, addr, KVM_PGTABLE_LAST_LEVEL, &rtt_entry))
		return -ENOENT;

	*ripas = rtt_entry.ripas;
	return 0;
}

static int __kvm_realm_unmap_range(struct kvm *kvm, unsigned long start,
				   unsigned long size, bool unmap_private,
				   bool may_block,
				   struct rmi_sro_state *sro)
{
	unsigned long end = start + size;
	struct realm *realm = &kvm->arch.realm;
	enum rmi_ripas src_ripas;
	int ret;

	if (!kvm_realm_is_created(kvm))
		return 0;

	end = min(BIT(realm->ia_bits - 1), end);

	ret = realm_unmap_shared_range(kvm, start, end, may_block, sro);
	if (ret || !unmap_private)
		return ret;

	ret = realm_unmap_dev_ranges(kvm, start, end, may_block);
	if (ret)
		return ret;

	/* An unmap request won't mix different RIPAS ranges. */
	if (!realm_get_ripas(kvm, start, &src_ripas) && src_ripas == RMI_DEV)
		return __realm_dev_mem_unmap(kvm, start, end, may_block);

	return realm_unmap_private_range(kvm, start, end, may_block, sro);
}

void kvm_realm_unmap_range(struct kvm *kvm, unsigned long start,
			   unsigned long size, bool unmap_private,
			   bool may_block)
{
	struct realm *realm = &kvm->arch.realm;
	int ret;

	ret = __kvm_realm_unmap_range(kvm, start, size, unmap_private,
				      may_block, NULL);
	if (ret) {
		WARN_ONCE(1, "RMI: stage-2 unmap failed at %#lx: %d\n",
			  start, ret);
		realm->stage2_unmap_failed = true;
	}
}

int kvm_realm_prepare_unmap_range(struct kvm *kvm, unsigned long start,
				  unsigned long size, bool unmap_private)
{
	struct rmi_sro_state *sro;
	unsigned long min;
	int ret;

	if (!kvm_realm_is_created(kvm))
		return 0;

	sro = kzalloc_obj(*sro, GFP_KERNEL_ACCOUNT);
	if (!sro)
		return -ENOMEM;

	/*
	 * A partial L1 block needs an L2 and an L3 RTT at each boundary.
	 * Reserve for both boundaries and both IPA aliases before taking
	 * mmu_lock.  Grow one page at a time so fragmented memory does not turn
	 * a readily satisfiable order-0 reservation into an order-3 failure.
	 * Best-effort, as at the other topup sites: on failure the RTT
	 * allocator falls back to the per-granule delegate path under the lock.
	 */
	for (min = 1; min <= REALM_UNMAP_RTT_RESERVE; min++) {
		if (rmi_sro_topup(sro, min, min))
			break;
	}

	write_lock(&kvm->mmu_lock);
	ret = __kvm_realm_unmap_range(kvm, start, size, unmap_private, true,
				      sro);
	write_unlock(&kvm->mmu_lock);

	rmi_sro_free(sro);
	kfree(sro);
	return ret;
}

static int realm_data_map_init(struct kvm *kvm, unsigned long ipa,
			       kvm_pfn_t dst_pfn, kvm_pfn_t src_pfn,
			       unsigned long flags)
{
	struct realm *realm = &kvm->arch.realm;
	phys_addr_t rd = virt_to_phys(realm->rd);
	phys_addr_t dst_phys, src_phys;
	int ret;

	lockdep_assert_held(&kvm->slots_lock);
	lockdep_assert_held(&kvm->arch.config_lock);

	dst_phys = __pfn_to_phys(dst_pfn);
	src_phys = __pfn_to_phys(src_pfn);

	ret = rmi_rtt_data_map_init(rd, dst_phys, ipa, src_phys, flags);
	if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
		/* Create missing RTTs and retry */
		int level = RMI_RETURN_INDEX(ret);

		KVM_BUG_ON(level == KVM_PGTABLE_LAST_LEVEL, kvm);

		ret = realm_create_rtt_levels(realm, ipa, level,
					      KVM_PGTABLE_LAST_LEVEL,
					      realm->sro);
		if (ret)
			return ret;

		ret = rmi_rtt_data_map_init(rd, dst_phys, ipa, src_phys,
					    flags);
	}

	if (ret)
		return -ENXIO;

	realm_region_track(realm, dst_phys, PAGE_SIZE,
			   SMC_RMI_RTT_DATA_MAP_INIT, ipa);

	return 0;
}

static unsigned long addr_range_size(int level)
{
	switch (level) {
	case 0:
		return RMI_ADDR_RANGE_SIZE_P4D;
	case 1:
		return RMI_ADDR_RANGE_SIZE_PUD;
	case 2:
		return RMI_ADDR_RANGE_SIZE_PMD;
	case 3:
		return RMI_ADDR_RANGE_SIZE_PAGE;
	}

	WARN_ON_ONCE(1);
	return RMI_ADDR_RANGE_SIZE_PAGE;
}

static unsigned long desc_range_size(unsigned long size,
				     unsigned long remaining)
{
	remaining = min(remaining, size * FIELD_MAX(RMI_ADDR_RANGE_COUNT_MASK));

	return ALIGN_DOWN(remaining, size);
}

static unsigned long addr_range_desc(unsigned long phys, int level,
				     unsigned long range_size,
				     unsigned long state)
{
	unsigned long size = rmi_rtt_level_mapsize(level);
	unsigned long count = range_size / size;

	if (WARN_ON(!count || count > FIELD_MAX(RMI_ADDR_RANGE_COUNT_MASK) ||
		    !IS_ALIGNED(phys | range_size, size)))
		count = 1;

	WARN_ON(phys & (size - 1));

	return RMI_ADDR_RANGE_DESC(phys, addr_range_size(level), count, state);
}

/*
 * Read and classify the primary RTTE covering @ipa.
 *
 * Return 0 for an assigned or unassigned entry, -EAGAIN if a table exists at
 * @map_level and the caller must descend, -EBUSY if the RMM reports
 * RMI_BLOCKED, or -ENXIO if the RTTE cannot be read or has an unsupported
 * state. For assigned and unassigned entries, @next_ipa is set to the
 * exclusive end of the entry.
 */
static int realm_read_rtte(unsigned long rd, unsigned long ipa, int map_level,
			   unsigned long ipa_top, struct rtt_entry *rtte,
			   unsigned long *next_ipa)
{
	unsigned long map_size;
	unsigned long read_ipa;
	int ret;

	read_ipa = ALIGN_DOWN(ipa, rmi_rtt_level_mapsize(map_level));
	ret = rmi_rtt_read_entry(rd, read_ipa, map_level, rtte);

	if (RMI_RETURN_STATUS(ret) == RMI_BLOCKED)
		return -EBUSY;

	if (ret != RMI_SUCCESS)
		return -ENXIO;

	if (WARN_ONCE(rtte->walk_level > map_level ||
		      rtte->walk_level > KVM_PGTABLE_LAST_LEVEL,
		      "RMI: invalid RTT walk level %lu/%d: %d\n",
		      rtte->walk_level, map_level, -ENXIO))
		return -ENXIO;

	map_size = rmi_rtt_level_mapsize(rtte->walk_level);
	*next_ipa = min(ALIGN_DOWN(ipa, map_size) + map_size, ipa_top);

	switch (rtte->state) {
	case RMI_UNASSIGNED:
	case RMI_ASSIGNED:
		break;
	case RMI_TABLE:
		return (rtte->walk_level == map_level) ? -EAGAIN : -ENXIO;
	default:
		return -ENXIO;
	}

	return 0;
}

/*
 * Select the largest block order supported by the existing RTT hierarchy at
 * @ipa. A single walk to L2 distinguishes an L1 block from an L2 block and an
 * L2 table. Keep @max_order if the hierarchy cannot be classified so the map
 * path retains its existing retry and recovery behaviour.
 */
int realm_rtt_map_order(struct kvm *kvm, unsigned long ipa, int max_order)
{
	struct realm *realm = &kvm->arch.realm;
	const int map_level = KVM_PGTABLE_LAST_LEVEL - 1;
	unsigned long next_ipa;
	struct rtt_entry rtte;
	int ret;

	lockdep_assert_held(&kvm->mmu_lock);

	ret = realm_read_rtte(virt_to_phys(realm->rd), ipa, map_level,
			      ALIGN_DOWN(ipa, PMD_SIZE) + PMD_SIZE,
			      &rtte, &next_ipa);
	if (ret == -EAGAIN)
		return 0;
	if (ret || rtte.walk_level < map_level)
		return max_order;

	return min(max_order, PMD_ORDER);
}

/*
 * Check the protected mapping covering @ipa.
 *
 * Return 1 if an assigned RAM entry maps @ipa to @phys. Return 0 for an
 * unassigned entry, -EAGAIN if the caller must descend through an RTT table,
 * -EBUSY if the RMM reports RMI_BLOCKED, -EFAULT for a conflicting mapping,
 * or -ENXIO if the RTTE cannot be read or has an unsupported state. For
 * matching and unassigned entries, @next_ipa is set to the exclusive end of
 * the entry.
 */
static int realm_check_protected_mapping(unsigned long rd, unsigned long ipa,
					 phys_addr_t phys, int map_level,
					 unsigned long ipa_top,
					 unsigned long *next_ipa)
{
	struct rtt_entry rtte;
	unsigned long map_size;
	phys_addr_t rtte_phys;
	int ret;

	ret = realm_read_rtte(rd, ipa, map_level, ipa_top, &rtte, next_ipa);
	if (ret)
		return ret;

	if (rtte.state == RMI_UNASSIGNED)
		return 0;

	map_size = rmi_rtt_level_mapsize(rtte.walk_level);
	rtte_phys = kvm_pte_to_phys(rtte.desc) + (ipa & (map_size - 1));

	if ((rtte.ripas != RMI_RAM) || (rtte_phys != phys))
		return -EFAULT;

	return 1;
}

struct realm_map_run {
	unsigned long ipa;
	unsigned long top;
	phys_addr_t phys;
};

/*
 * Check whether an Unprotected IPA already has the requested mapping.
 * RMI_RTT_READ_ENTRY returns the architectural stage-2 descriptor, so compare
 * the PA, MemAttr and direct permissions before accepting an existing entry.
 * Unprotected mappings must also be execute-never per DEN0137 §A5.6.11.3.
 */
static int realm_check_unprotected_mapping(unsigned long rd,
					   unsigned long ipa,
					   phys_addr_t phys, int map_level,
					   unsigned long ipa_top,
					   unsigned long attr,
					   unsigned long *next_ipa)
{
	enum kvm_pgtable_prot prot;
	struct rtt_entry rtte;
	unsigned long map_size;
	phys_addr_t rtte_phys;
	int ret;

	ret = realm_read_rtte(rd, ipa, map_level, ipa_top, &rtte, next_ipa);
	if (ret)
		return ret;

	if (rtte.state == RMI_UNASSIGNED)
		return 0;

	map_size = rmi_rtt_level_mapsize(rtte.walk_level);
	rtte_phys = kvm_pte_to_phys(rtte.desc) + (ipa & (map_size - 1));
	prot = kvm_pgtable_stage2_pte_prot(rtte.desc);

	if (rtte.ripas != RMI_EMPTY || rtte_phys != phys ||
	    FIELD_GET(KVM_PTE_LEAF_ATTR_LO_S2_MEMATTR, rtte.desc) != attr ||
	    (prot & KVM_PGTABLE_PROT_RWX) != KVM_PGTABLE_PROT_RW)
		return -EFAULT;

	return 1;
}

/*
 * Delegate the next contiguous run of backing memory that still needs a
 * protected mapping.
 *
 * Range delegation can skip granules already in the delegated state, including
 * granules delegated by another fault. If delegation makes no progress, inspect
 * the RTT and either skip a matching mapping or retry the delegation bounded to
 * the unmapped span the walk found. The backing PA is the caller's @phys offset
 * by (run->ipa - @ipa), since the IPA->PA mapping is linear.
 *
 * Returns 0 with run->top == run->ipa == ipa_top when nothing remains to map
 * (the rest of the range is already mapped), 0 with a non-empty run to map, or
 * -E2BIG when a coarse zero-progress request should be retried around the
 * fault, or another negative errno.
 */
static int realm_prepare_protected_map(struct realm *realm, unsigned long ipa,
				       phys_addr_t phys, unsigned long ipa_top,
				       bool allow_fault_fallback,
				       struct realm_map_run *run)
{
	phys_addr_t rd = virt_to_phys(realm->rd);
	unsigned long next_ipa;
	long rmi_ret;
	int map_level;
	int ret;

	while (ipa < ipa_top) {
		unsigned long request_size = ipa_top - ipa;
		unsigned long delegated_size;
		bool skipped = false;

retry_delegate:
		delegated_size = 0;
		rmi_ret = realm_delegate_range(realm, phys, request_size,
					       &delegated_size);
		if (delegated_size) {
			/*
			 * Hand back the delegated prefix as the run to map. It may
			 * include granules already delegated by another fault, but
			 * RMI_RTT_DATA_MAP treats an exact existing mapping as
			 * success.
			 */
			run->ipa = ipa;
			run->top = ipa + delegated_size;
			run->phys = phys;
			return 0;
		}

		if (rmi_ret < 0)
			return realm_rmi_to_errno(rmi_ret);
		if (RMI_RETURN_STATUS(rmi_ret) == RMI_BUSY ||
		    RMI_RETURN_STATUS(rmi_ret) == RMI_BLOCKED)
			return -EAGAIN;

		/*
		 * A failed range made no state change. Let the fault handler retry
		 * only the fault-containing subrange.
		 */
		if (allow_fault_fallback && (request_size > PAGE_SIZE) &&
		    (RMI_RETURN_STATUS(rmi_ret) == RMI_ERROR_INPUT))
			return -E2BIG;

		/*
		 * Delegation made no progress. This can be a Granule-state conflict
		 * or a tracking-region constraint. If @ipa is already mapped to the
		 * expected PA, skip it and continue; otherwise propagate the
		 * conflict through the mapping recovery path.
		 */
		map_level = find_aligned_map_level(realm, ipa, phys,
						   ipa + request_size);
retry_check:
		ret = realm_check_protected_mapping(rd, ipa, phys, map_level,
						    ipa_top, &next_ipa);
		if (ret > 0) {
			if (WARN_ON_ONCE(next_ipa <= ipa))
				return -ENXIO;

			phys += next_ipa - ipa;
			ipa = next_ipa;
			if (ipa >= ipa_top)
				break;

			/*
			 * Walk the rest of an already-mapped span with
			 * RTT_READ_ENTRY alone. Re-entering the loop would issue
			 * a whole-range delegate per mapped entry, and that
			 * delegate cannot succeed until the walk reaches an entry
			 * which is not already mapped.
			 */
			skipped = true;
			map_level = find_aligned_map_level(realm, ipa, phys,
							   ipa_top);
			goto retry_check;
		}

		if (ret == -EBUSY)
			return -EAGAIN;

		if (ret == -EAGAIN) {
			/*
			 * A child RTT exists at this level; inspect one level
			 * down to find the mapped target that blocked
			 * delegation.
			 */
			if (map_level >= KVM_PGTABLE_LAST_LEVEL)
				return -ENXIO;
			map_level++;
			goto retry_check;
		}

		if (ret == 0) {
			/* Reissue delegation from the first entry not already mapped. */
			if (skipped)
				continue;

			/*
			 * DEN0137 §B4.5.10 leaves out_top UNKNOWN unless the
			 * result is RMI_SUCCESS, and permits the RMM to refuse
			 * the whole request with RMI_ERROR_INPUT when the range
			 * spans a Granule which is unpopulated or whose state is
			 * neither GRAN_UNDELEGATED nor GRAN_DELEGATED. An RMM
			 * which instead stops short of that Granule reports the
			 * delegated prefix, which is handled above. Such a
			 * failure carries no usable progress, so bound the
			 * request to [ipa, next_ipa), which no RTTE maps.
			 */
			if ((RMI_RETURN_STATUS(rmi_ret) == RMI_ERROR_INPUT) &&
			    ((next_ipa - ipa) < request_size)) {
				request_size = next_ipa - ipa;
				goto retry_delegate;
			}
		}

		return ret < 0 ? ret : -ENXIO;
	}

	/* The whole range is already mapped; nothing left to delegate or map. */
	run->ipa = ipa_top;
	run->top = ipa_top;
	run->phys = phys;
	return 0;
}

/*
 * Install protected RTT entries for memory that has already been delegated.
 *
 * Matching mappings installed by another fault are treated as progress.
 */
static int realm_map_delegated_range(struct realm *realm,
				     const struct realm_map_run *run,
				     struct rmi_sro_state *sro)
{
	phys_addr_t rd = virt_to_phys(realm->rd);
	phys_addr_t phys = run->phys;
	unsigned long ipa = run->ipa;
	unsigned long ipa_top = run->top;
	int map_level;
	int ret = 0;

	while (ipa < ipa_top) {
		unsigned long block_size;
		unsigned long chunk_size;
		unsigned long flags;
		unsigned long range_desc;
		unsigned long out_top;

		map_level = find_aligned_map_level(realm, ipa, phys, ipa_top);

retry_lower_level:
		block_size = rmi_rtt_level_mapsize(map_level);
		chunk_size = desc_range_size(block_size, ipa_top - ipa);

retry_chunk:
		flags = RMI_ADDR_TYPE_SINGLE;
		range_desc = addr_range_desc(phys, map_level, chunk_size,
					    RMI_OP_MEM_DELEGATED);

		ret = rmi_rtt_data_map(rd, ipa, ipa + chunk_size, flags,
				       range_desc, &out_top);
		if ((ret >= 0) && (RMI_RETURN_STATUS(ret) == RMI_BLOCKED))
			return -EAGAIN;

		if ((ret >= 0) && (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT)) {
			unsigned long next_ipa;
			int level = RMI_RETURN_INDEX(ret);
			int state;

			if (WARN_ONCE(level > KVM_PGTABLE_LAST_LEVEL,
				      "RMI: DATA_MAP invalid RTT level %d: %d\n",
				      level, -ENXIO))
				return -ENXIO;

			/*
			 * RMI_ERROR_RTT also reports incompatible or concurrently
			 * modified entries. Read the walk result before assuming that
			 * an RTT is missing.
			 */
			state = realm_check_protected_mapping(rd, ipa, phys, level,
								ipa_top, &next_ipa);
			if (state > 0) {
				phys += next_ipa - ipa;
				ipa = next_ipa;
				continue;
			}

			/* Retry the fault after a blocked RTTE read. */
			if (state == -EBUSY)
				return -EAGAIN;

			if (state == -EAGAIN) {
				/*
				 * A table appeared at the level reported by the failed
				 * command. Retry if the target is below it; otherwise
				 * descend into it.
				 */
				if (level < map_level)
					goto retry_chunk;
				if (map_level < KVM_PGTABLE_LAST_LEVEL) {
					map_level++;
					goto retry_lower_level;
				}
				return -ENXIO;
			}

			/* Propagate a conflicting or malformed RTTE. */
			if (state < 0)
				return state;

			if (level < map_level) {
				/* The walk stopped above the target; create its RTTs. */
				ret = realm_create_rtt_levels(realm, ipa,
							      level, map_level, sro);
				if (ret)
					return ret;
				continue;
			}

			if (level == map_level &&
			    map_level < KVM_PGTABLE_LAST_LEVEL) {
				/* Retry an unassigned target at a finer level. */
				map_level++;
				goto retry_lower_level;
			}

			if (chunk_size > block_size) {
				/* Retry the first entry of the failing counted range. */
				chunk_size = block_size;
				goto retry_chunk;
			}

			if (WARN_ONCE(1,
				      "RMI: DATA_MAP unresolved RTT error %#x: %d\n",
				      ret, -ENXIO))
				return -ENXIO;
		}

		/* Let the caller classify concurrent mapping failures. */
		if (ret)
			return ret;

		if (WARN_ONCE(out_top <= ipa || out_top > ipa + chunk_size ||
			      !IS_ALIGNED(out_top - ipa, block_size),
			      "RMI: DATA_MAP invalid progress %#lx: %d\n",
			      out_top, -ENXIO))
			return -ENXIO;

		realm_region_track(realm, phys, out_top - ipa,
				   SMC_RMI_RTT_DATA_MAP, ipa);

		phys += out_top - ipa;
		ipa = out_top;
	}

	return 0;
}

static int __realm_map_protected(struct kvm *kvm, unsigned long ipa,
				 kvm_pfn_t pfn, unsigned long map_size,
				 struct rmi_sro_state *sro,
				 bool allow_fault_fallback)
{
	struct realm *realm = &kvm->arch.realm;
	phys_addr_t phys = __pfn_to_phys(pfn);
	unsigned long ipa_top = ipa + map_size;
	unsigned long cur_ipa = ipa;
	int ret;

	lockdep_assert_held(&kvm->mmu_lock);

	if (WARN_ONCE(!IS_ALIGNED(map_size | ipa, PAGE_SIZE),
		      "RMI: unaligned protected map %#lx/%#lx: %d\n",
		      ipa, map_size, -EINVAL))
		return -EINVAL;

	/*
	 * Delegate and map one contiguous run at a time. A run can include
	 * granules already delegated by another fault. The IPA->PA mapping is
	 * linear, so each run's backing PA is @phys offset by (run.ipa - @ipa).
	 */
	while (cur_ipa < ipa_top) {
		struct realm_map_run run;

		ret = realm_prepare_protected_map(realm, cur_ipa,
						  phys + (cur_ipa - ipa),
						  ipa_top,
						  allow_fault_fallback, &run);
		if (ret)
			return ret;

		/* No more memory needs mapping (remainder already mapped). */
		if (run.top <= run.ipa)
			break;

		ret = realm_map_delegated_range(realm, &run, sro);
		if (ret)
			return ret;

		cur_ipa = run.top;
	}

	return 0;
}

int realm_map_protected(struct kvm *kvm, unsigned long ipa, kvm_pfn_t pfn,
			unsigned long map_size, struct rmi_sro_state *sro)
{
	bool allow_fault_fallback;

	allow_fault_fallback = (map_size == PUD_SIZE ||
				map_size == PMD_SIZE) &&
			       IS_ALIGNED(ipa | __pfn_to_phys(pfn), map_size);

	return __realm_map_protected(kvm, ipa, pfn, map_size, sro,
				     allow_fault_fallback);
}

enum realm_map_recovery {
	REALM_MAP_RECOVER_RETRY,
	REALM_MAP_RECOVER_FAIL,
	REALM_MAP_RECOVER_REFAULT,
};

struct realm_map_request {
	struct kvm *kvm;
	unsigned long ipa;
	kvm_pfn_t pfn;
	unsigned long size;
	struct rmi_sro_state *sro;
};

static int realm_recover_protected_map(const struct realm_map_request *req,
				       int map_ret, enum realm_map_recovery recovery)
{
	struct kvm *kvm = req->kvm;
	struct realm *realm = &kvm->arch.realm;
	phys_addr_t start_phys = __pfn_to_phys(req->pfn);
	phys_addr_t phys = start_phys;
	phys_addr_t rd = virt_to_phys(realm->rd);
	unsigned long start_ipa = req->ipa;
	unsigned long end_ipa = start_ipa + req->size;
	unsigned long ipa = start_ipa;
	bool has_unmapped = false;
	int ret;

	lockdep_assert_held_write(&kvm->mmu_lock);

	while (ipa < end_ipa) {
		unsigned long next_ipa;
		int map_level;
		int entry_state;

		map_level = find_aligned_map_level(realm, ipa, phys, end_ipa);
retry:
		entry_state = realm_check_protected_mapping(rd, ipa, phys,
							    map_level, end_ipa,
							    &next_ipa);
		if (entry_state > 0) {
			phys += next_ipa - ipa;
			ipa = next_ipa;
			continue;
		}

		if (entry_state == -EBUSY)
			return -EAGAIN;

		if (entry_state == -EAGAIN) {
			if (map_level >= KVM_PGTABLE_LAST_LEVEL)
				return -ENXIO;
			map_level++;
			goto retry;
		}

		if (entry_state < 0) {
			pr_warn_ratelimited("RMI: DATA_MAP recovery failed ret=%d status=%ld err=%d\n",
					    map_ret,
					    map_ret >= 0 ?
					    (long)RMI_RETURN_STATUS(map_ret) : -1L,
					    entry_state);
			return entry_state;
		}

		/* No RTTE maps this part of the failed range. */
		if (recovery != REALM_MAP_RECOVER_RETRY) {
			ret = realm_undelegate_map_range(realm, phys,
							 next_ipa - ipa);
			if (ret) {
				pr_warn_ratelimited("RMI: DATA_MAP cleanup failed ret=%d status=%ld err=%d\n",
						    map_ret,
						    map_ret >= 0 ?
						    (long)RMI_RETURN_STATUS(map_ret) : -1L,
						    ret);
				return ret;
			}
		}

		has_unmapped = true;
		phys += next_ipa - ipa;
		ipa = next_ipa;
	}

	if (!has_unmapped)
		return 0;

	/*
	 * Another fault can complete part of the range between delegation and
	 * DATA_MAP. Linux may also have converted the resulting RMI failure to
	 * -ENXIO before reaching this recovery path. Retry the complete
	 * delegate+map sequence once while the write lock excludes all other fault
	 * handlers. Leave delegated, unassigned granules in place for the retry;
	 * clean them up only if the serialized attempt also fails.
	 */
	if ((recovery == REALM_MAP_RECOVER_RETRY) &&
	    ((map_ret == -ENXIO) || (map_ret == -EAGAIN) ||
	     ((map_ret >= 0) &&
	      (RMI_RETURN_STATUS(map_ret) == RMI_ERROR_INPUT)))) {
		ret = __realm_map_protected(kvm, start_ipa, req->pfn, req->size,
					    req->sro, false);
		if (!ret)
			return 0;

		return realm_recover_protected_map(req, ret,
						   REALM_MAP_RECOVER_FAIL);
	}

	/* Clean up an unassigned tail before propagating a terminal failure. */
	if (recovery == REALM_MAP_RECOVER_RETRY)
		return realm_recover_protected_map(req, map_ret,
						   REALM_MAP_RECOVER_FAIL);

	if (recovery == REALM_MAP_RECOVER_REFAULT)
		return 0;

	if (map_ret >= 0) {
		pr_warn_ratelimited("RMI: DATA_MAP failed ipa=%#lx phys=%pa size=%#lx ret=%#x status=%u\n",
				    start_ipa, &start_phys, req->size,
				    (unsigned int)map_ret,
				    (unsigned int)RMI_RETURN_STATUS(map_ret));
		return -ENXIO;
	}

	pr_warn_ratelimited("RMI: DATA_MAP failed ipa=%#lx phys=%pa size=%#lx err=%d\n",
			    start_ipa, &start_phys, req->size, map_ret);
	return map_ret;
}

int realm_recover_protected(struct kvm *kvm, unsigned long ipa,
			    kvm_pfn_t pfn, unsigned long map_size,
			    int map_ret, struct rmi_sro_state *sro,
			    bool mmu_invalidated)
{
	const struct realm_map_request req = {
		.kvm = kvm,
		.ipa = ipa,
		.pfn = pfn,
		.size = map_size,
		.sro = sro,
	};
	enum realm_map_recovery recovery;

	recovery = mmu_invalidated ? REALM_MAP_RECOVER_REFAULT :
					   REALM_MAP_RECOVER_RETRY;

	return realm_recover_protected_map(&req, map_ret, recovery);
}

int realm_map_non_secure(struct kvm *kvm,
			 unsigned long ipa,
			 kvm_pfn_t pfn,
			 unsigned long size,
			 enum kvm_pgtable_prot prot,
			 struct rmi_sro_state *sro)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long attr, flags = 0;
	phys_addr_t rd = virt_to_phys(realm->rd);
	phys_addr_t phys = __pfn_to_phys(pfn);
	unsigned long ipa_top = ipa + size;
	unsigned long block_size;
	unsigned long chunk_size;
	unsigned long range_desc;
	unsigned long out_top;
	int map_level;
	int ret;

	lockdep_assert_held(&kvm->mmu_lock);

	if (WARN_ONCE(!IS_ALIGNED(size | ipa, PAGE_SIZE),
		      "RMI: unaligned unprotected map %#lx/%#lx: %d\n",
		      ipa, size, -EINVAL))
		return -EINVAL;

	switch (prot & (KVM_PGTABLE_PROT_DEVICE | KVM_PGTABLE_PROT_NORMAL_NC)) {
	case KVM_PGTABLE_PROT_DEVICE | KVM_PGTABLE_PROT_NORMAL_NC:
		return -EINVAL;
	case KVM_PGTABLE_PROT_DEVICE:
		attr = MT_S2_FWB_DEVICE_nGnRE;
		break;
	case KVM_PGTABLE_PROT_NORMAL_NC:
		attr = MT_S2_FWB_NORMAL_NC;
		break;
	default:
		attr = MT_S2_FWB_NORMAL;
	}

	flags |= FIELD_PREP(RMI_RTT_UNPROT_MAP_FLAGS_MEMATTR_MASK, attr);
	if ((prot & (KVM_PGTABLE_PROT_R | KVM_PGTABLE_PROT_W)) ==
	    (KVM_PGTABLE_PROT_R | KVM_PGTABLE_PROT_W))
		flags |= FIELD_PREP(RMI_RTT_UNPROT_MAP_FLAGS_S2AP_MASK,
				    RMI_S2AP_RW);
	else if (prot & KVM_PGTABLE_PROT_R)
		flags |= FIELD_PREP(RMI_RTT_UNPROT_MAP_FLAGS_S2AP_MASK,
				    RMI_S2AP_RO);
	else if (prot & KVM_PGTABLE_PROT_W)
		flags |= FIELD_PREP(RMI_RTT_UNPROT_MAP_FLAGS_S2AP_MASK,
				    RMI_S2AP_WO);

	flags |= RMI_ADDR_TYPE_SINGLE;

	while (ipa < ipa_top) {
		map_level = find_aligned_map_level(realm, ipa, phys, ipa_top);

retry_lower_level:
		block_size = rmi_rtt_level_mapsize(map_level);
		chunk_size = desc_range_size(block_size, ipa_top - ipa);

retry_chunk:
		range_desc = addr_range_desc(phys, map_level, chunk_size,
					    RMI_OP_MEM_UNDELEGATED);

		ret = rmi_rtt_unprot_map(rd, ipa, ipa + chunk_size,
					 flags, range_desc,
					 &out_top);
		if ((ret >= 0) &&
		    (RMI_RETURN_STATUS(ret) == RMI_BLOCKED))
			return -EAGAIN;

		if ((ret >= 0) &&
		    (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT)) {
			unsigned long next_ipa;
			int level = RMI_RETURN_INDEX(ret);
			int state;

			if (WARN_ONCE(level > KVM_PGTABLE_LAST_LEVEL,
				      "RMI: UNPROT_MAP invalid RTT level %d: %d\n",
				      level, -ENXIO))
				return -ENXIO;

			/*
			 * RMI_ERROR_RTT also reports an incompatible mapping. Read
			 * the entry before assuming that an RTT is missing.
			 */
			state = realm_check_unprotected_mapping(rd, ipa, phys, level,
								      ipa_top, attr,
								      &next_ipa);
			if (state > 0) {
				phys += next_ipa - ipa;
				ipa = next_ipa;
				continue;
			}

			/* Retry the fault after a blocked RTTE read. */
			if (state == -EBUSY)
				return -EAGAIN;

			if (state == -EAGAIN) {
				/*
				 * A table appeared at the level reported by the failed
				 * command. Retry if the target is below it; otherwise
				 * descend into it.
				 */
				if (level < map_level)
					goto retry_chunk;
				if (map_level < KVM_PGTABLE_LAST_LEVEL) {
					map_level++;
					goto retry_lower_level;
				}
				return -ENXIO;
			}

			/* Propagate a conflicting or malformed RTTE. */
			if (state < 0)
				return state;

			if (level < map_level) {
				/* The walk stopped above the target; create its RTTs. */
				ret = realm_create_rtt_levels(realm, ipa,
							      level, map_level, sro);
				if (ret)
					return ret;
				continue;
			}

			if (level == map_level &&
			    map_level < KVM_PGTABLE_LAST_LEVEL) {
				/* Retry an unassigned target at a finer level. */
				map_level++;
				goto retry_lower_level;
			}

			if (chunk_size > block_size) {
				/* Retry the first entry of the failing counted range. */
				chunk_size = block_size;
				goto retry_chunk;
			}

			if (WARN_ONCE(1,
				      "RMI: UNPROT_MAP unresolved RTT error %#x: %d\n",
				      ret, -ENXIO))
				return -ENXIO;
		}

		if (WARN_ONCE(ret,
			      "RMI: unprotected map failed: rmi=%d err=%d\n",
			      ret, ret < 0 ? ret : -ENXIO))
			return ret < 0 ? ret : -ENXIO;

		if (WARN_ONCE(out_top <= ipa || out_top > ipa + chunk_size ||
			      !IS_ALIGNED(out_top - ipa, block_size),
			      "RMI: UNPROT_MAP invalid progress %#lx: %d\n",
			      out_top, -ENXIO))
			return -ENXIO;

		realm_region_track(realm, phys, out_top - ipa,
				   SMC_RMI_RTT_UNPROT_MAP, ipa);

		phys += out_top - ipa;
		ipa = out_top;
	}

	return 0;
}

static int populate_region_cb(struct kvm *kvm, gfn_t gfn, kvm_pfn_t pfn,
			      struct page *src_page, void *opaque)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long *data_flags = opaque;
	unsigned long delegated_size = 0;
	phys_addr_t phys = __pfn_to_phys(pfn);
	phys_addr_t ipa = gfn_to_gpa(gfn);
	long rmi_ret;
	int ret;

	if (!src_page)
		return -EOPNOTSUPP;

	/*
	 * kvm_gmem_populate() protects only the folio containing this page for
	 * the duration of this callback. Do not leave later folio pages
	 * delegated across callbacks, as a concurrent hole punch may remove
	 * those pages before their DATA_INIT mappings are installed.
	 */
	rmi_ret = realm_delegate_range(realm, phys, PAGE_SIZE,
				       &delegated_size);
	if (rmi_ret) {
		if (delegated_size)
			realm_undelegate_map_range(realm, phys, delegated_size);
		return realm_rmi_to_errno(rmi_ret);
	}

	if (WARN_ONCE(delegated_size != PAGE_SIZE,
		      "RMI: DATA_MAP_INIT delegated %#lx bytes: %d\n",
		      delegated_size, -ENXIO)) {
		realm_undelegate_map_range(realm, phys, delegated_size);
		return -ENXIO;
	}

	ret = realm_data_map_init(kvm, ipa, pfn, page_to_pfn(src_page),
				  *data_flags);
	if (ret)
		realm_undelegate_map_range(realm, phys, PAGE_SIZE);

	return ret;
}

static long populate_region(struct kvm *kvm,
			    gfn_t base_gfn,
			    unsigned long pages,
			    u64 uaddr,
			    unsigned long data_flags)
{
	long ret = 0;

	lockdep_assert_held(&kvm->slots_lock);
	lockdep_assert_held(&kvm->arch.config_lock);

	if (!pages)
		return -EINVAL;

	ret = kvm_gmem_populate(kvm, base_gfn, u64_to_user_ptr(uaddr),
				pages, false, populate_region_cb, &data_flags);

	return ret;
}

enum ripas_action {
	RIPAS_INIT,
	RIPAS_SET,
};

static int ripas_change(struct kvm *kvm,
			struct kvm_vcpu *vcpu,
			unsigned long ipa,
			unsigned long end,
			enum ripas_action action,
			unsigned long *top_ipa)
{
	struct realm *realm = &kvm->arch.realm;
	phys_addr_t rd_phys = virt_to_phys(realm->rd);
	struct rmi_sro_state *sro = realm->sro;
	phys_addr_t rec_phys;
	int ret = 0;

	if (vcpu) {
		rec_phys = virt_to_phys(vcpu->arch.rec.rec_page);
		sro = vcpu->arch.rec.sro;
		WARN_ON(action != RIPAS_SET);
	} else {
		WARN_ON(action != RIPAS_INIT);
	}

	while (ipa < end) {
		unsigned long next = ~0;

		switch (action) {
		case RIPAS_INIT:
			ret = rmi_rtt_init_ripas(rd_phys, ipa, end, &next);
			break;
		case RIPAS_SET:
			ret = rmi_rtt_set_ripas(rd_phys, rec_phys, ipa, end,
						&next);
			break;
		}

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			if (WARN_ONCE((next <= ipa) || (next > end),
				      "RMI: RIPAS invalid progress %#lx: %d\n",
				      next, -ENXIO)) {
				if (top_ipa)
					*top_ipa = ipa;
				return -ENXIO;
			}
			ipa = next;
			break;
		case RMI_ERROR_RTT: {
			int err_level = RMI_RETURN_INDEX(ret);
			int level = find_map_level(realm, ipa, end);

			/*
			 * DEN0137 v2.0-bet3 reports terminal RIPAS failures, such as
			 * no_progress, as RMI_ERROR_RTT at the current walk level. If
			 * the walk did not stop above @level, no RTT can be created
			 * and retrying would issue the same command forever.
			 */
			if (err_level >= level) {
				if (top_ipa)
					*top_ipa = ipa;
				return -ENXIO;
			}

			ret = realm_create_rtt_levels(realm, ipa, err_level,
						      level, sro);
			if (ret) {
				/*
				 * Report progress so the caller retries from
				 * @ipa and any EMPTY-RIPAS unmap is bounded to
				 * the range actually changed, rather than
				 * reading an uninitialised top_ipa.
				 */
				if (top_ipa)
					*top_ipa = ipa;
				return ret;
			}
			/* Retry with the RTT levels in place */
			break;
		}
		default:
			WARN_ONCE(1, "RMI: RIPAS command failed %#x: %d\n",
				  ret, -ENXIO);
			if (top_ipa)
				*top_ipa = ipa;
			return -ENXIO;
		}
	}

	if (top_ipa)
		*top_ipa = ipa;

	return 0;
}

static int realm_set_ipa_state(struct kvm_vcpu *vcpu,
			       unsigned long start,
			       unsigned long end,
			       enum rmi_ripas src_ripas,
			       enum rmi_ripas target_ripas,
			       unsigned long *top_ipa)
{
	struct kvm *kvm = vcpu->kvm;
	int ret = ripas_change(kvm, vcpu, start, end, RIPAS_SET, top_ipa);

	if (target_ripas == RMI_EMPTY && *top_ipa != start) {
		int unmap_ret;

		/*
		 * Private RAM is also unmapped when userspace converts the
		 * guest_memfd range, but nothing does that for a device
		 * mapping, so unmap it explicitly. The range already reads
		 * RIPAS_EMPTY here, hence the source RIPAS sampled before the
		 * change selects the unmap.
		 */
		if (src_ripas == RMI_DEV)
			unmap_ret = __realm_dev_mem_unmap(kvm, start, *top_ipa,
							  false);
		else
			unmap_ret = realm_unmap_private_range(kvm, start,
							      *top_ipa, false,
							      vcpu->arch.rec.sro);
		if (!ret)
			ret = unmap_ret;
	}

	return ret;
}

static int realm_init_ipa_state(struct kvm *kvm,
				unsigned long gfn,
				unsigned long pages)
{
	return ripas_change(kvm, NULL, gfn_to_gpa(gfn), gfn_to_gpa(gfn + pages),
			    RIPAS_INIT, NULL);
}

static int realm_ensure_created(struct kvm *kvm)
{
	int ret;

	lockdep_assert_held(&kvm->arch.config_lock);

	switch (kvm_realm_state(kvm)) {
	case REALM_STATE_NONE:
		break;
	case REALM_STATE_NEW:
		return 0;
	case REALM_STATE_DEAD:
		return -ENXIO;
	default:
		return -EBUSY;
	}

	ret = realm_create_rd(kvm);
	return ret;
}

static int set_ripas_of_protected_regions(struct kvm *kvm)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	int idx, bkt;
	int ret = 0;

	lockdep_assert_held(&kvm->arch.config_lock);

	idx = srcu_read_lock(&kvm->srcu);

	slots = kvm_memslots(kvm);
	kvm_for_each_memslot(memslot, bkt, slots) {
		if (!kvm_slot_has_gmem(memslot))
			continue;

		ret = realm_init_ipa_state(kvm, memslot->base_gfn,
					   memslot->npages);
		if (ret)
			break;
	}
	srcu_read_unlock(&kvm->srcu, idx);

	return ret;
}

int kvm_realm_ensure_created(struct kvm *kvm)
{
	int ret;

	if (!kvm_is_realm(kvm))
		return -EINVAL;

	guard(mutex)(&kvm->arch.config_lock);
	ret = realm_ensure_created(kvm);

	return ret;
}
EXPORT_SYMBOL_GPL(kvm_realm_ensure_created);

int kvm_arm_rmi_init_ripas(struct kvm *kvm,
			   struct kvm_arm_rmi_init_ripas *args)
{
	struct kvm_memory_slot *memslot;
	unsigned long mmu_seq;
	unsigned long start, end;
	gfn_t start_gfn, end_gfn;
	int ret;

	if (args->flags || memchr_inv(args->reserved, 0,
				      sizeof(args->reserved)) ||
	    !args->size || args->base + args->size < args->base ||
	    !PAGE_ALIGNED(args->base) || !PAGE_ALIGNED(args->size))
		return -EINVAL;

	start = args->base;
	end = start + args->size;
	start_gfn = gpa_to_gfn(start);
	end_gfn = gpa_to_gfn(end);

	mutex_lock(&kvm->slots_lock);
	mutex_lock(&kvm->arch.config_lock);

	ret = realm_ensure_created(kvm);
	if (ret)
		goto out_unlock;

	memslot = gfn_to_memslot(kvm, start_gfn);
	if (!kvm_slot_has_gmem(memslot) ||
	    end_gfn > memslot->base_gfn + memslot->npages) {
		ret = -EINVAL;
		goto out_unlock;
	}

	if (gmem_in_place_conversion) {
		ret = kvm_gmem_set_attributes(memslot, start_gfn, end_gfn,
					      KVM_MEMORY_ATTRIBUTE_PRIVATE);
		if (ret)
			goto out_unlock;
	}

	mmu_seq = kvm->mmu_invalidate_seq;
	smp_rmb();
	if (gmem_in_place_conversion) {
		if (!kvm_gmem_range_has_memory_attributes(memslot, start_gfn,
							  end_gfn,
							  KVM_MEMORY_ATTRIBUTE_PRIVATE)) {
			ret = -EAGAIN;
			goto out_unlock;
		}
	} else if (!kvm_range_has_vm_memory_attributes(kvm, start_gfn, end_gfn,
						       KVM_MEMORY_ATTRIBUTE_PRIVATE,
						       KVM_MEMORY_ATTRIBUTE_PRIVATE)) {
		/* Per-VM attributes are converted by userspace beforehand. */
		ret = -EINVAL;
		goto out_unlock;
	}

	write_lock(&kvm->mmu_lock);
	if (mmu_invalidate_retry(kvm, mmu_seq)) {
		write_unlock(&kvm->mmu_lock);
		ret = -EAGAIN;
		goto out_unlock;
	}
	ret = realm_init_ipa_state(kvm, start_gfn, end_gfn - start_gfn);
	write_unlock(&kvm->mmu_lock);
	if (!ret)
		kvm->arch.realm.ripas_user_init = true;

out_unlock:
	mutex_unlock(&kvm->arch.config_lock);
	mutex_unlock(&kvm->slots_lock);

	return ret;
}

int kvm_arm_rmi_populate(struct kvm *kvm,
			 struct kvm_arm_rmi_populate *args)
{
	unsigned long data_flags = 0;
	unsigned long ipa_start = args->base;
	unsigned long ipa_end = ipa_start + args->size;
	long pages_populated;
	int ret;

	if (args->reserved ||
	    (args->flags & ~KVM_ARM_RMI_POPULATE_FLAGS_MEASURE) ||
	    !IS_ALIGNED(ipa_start, PAGE_SIZE) ||
	    !IS_ALIGNED(ipa_end, PAGE_SIZE) ||
	    !IS_ALIGNED(args->source_uaddr, PAGE_SIZE))
		return -EINVAL;

	if (args->flags & KVM_ARM_RMI_POPULATE_FLAGS_MEASURE)
		data_flags |= RMI_MEASURE_CONTENT;

	mutex_lock(&kvm->slots_lock);
	mutex_lock(&kvm->arch.config_lock);

	ret = realm_ensure_created(kvm);
	if (ret)
		goto out_unlock;

	pages_populated = populate_region(kvm, gpa_to_gfn(ipa_start),
					  args->size >> PAGE_SHIFT,
					  args->source_uaddr, data_flags);

	if (pages_populated < 0) {
		ret = pages_populated;
		goto out_unlock;
	}

	args->size -= pages_populated << PAGE_SHIFT;
	args->source_uaddr += pages_populated << PAGE_SHIFT;
	args->base += pages_populated << PAGE_SHIFT;

out_unlock:
	mutex_unlock(&kvm->arch.config_lock);
	mutex_unlock(&kvm->slots_lock);
	return ret;
}

/*
 * Slots without guest_memfd backing are always shared with in-place
 * conversion, and use the per-VM attributes otherwise. They can never back
 * RIPAS_RAM.
 */
static bool realm_slot_range_has_attrs(struct kvm *kvm,
				       struct kvm_memory_slot *slot,
				       gfn_t start, gfn_t end, u64 attrs)
{
	if (!kvm_slot_has_gmem(slot) && attrs)
		return false;

	if (gmem_in_place_conversion)
		return !kvm_slot_has_gmem(slot) ||
		       kvm_gmem_range_has_memory_attributes(slot, start, end,
							    attrs);

	return kvm_range_has_vm_memory_attributes(kvm, start, end,
						  KVM_MEMORY_ATTRIBUTE_PRIVATE,
						  attrs);
}

static bool realm_ripas_attributes_match(struct kvm_vcpu *vcpu,
					 unsigned long start,
					 unsigned long end,
					 enum rmi_ripas ripas,
					 unsigned long *mmu_seq)
{
	struct kvm *kvm = vcpu->kvm;
	gfn_t gfn = gpa_to_gfn(start);
	gfn_t end_gfn = gpa_to_gfn(ALIGN(end, PAGE_SIZE));
	u64 attributes = ripas == RMI_RAM ? KVM_MEMORY_ATTRIBUTE_PRIVATE : 0;
	bool match = true;
	int idx;

	/* RIPAS_DEV is not backed by ordinary guest_memfd RAM. */
	if (ripas == RMI_DEV)
		return true;

	*mmu_seq = kvm->mmu_invalidate_seq;
	smp_rmb();
	idx = srcu_read_lock(&kvm->srcu);
	while (gfn < end_gfn) {
		struct kvm_memory_slot *slot = gfn_to_memslot(kvm, gfn);
		gfn_t slot_end;

		if (!slot) {
			match = false;
			break;
		}

		slot_end = min(end_gfn, slot->base_gfn + slot->npages);
		if (!realm_slot_range_has_attrs(kvm, slot, gfn, slot_end,
						attributes)) {
			match = false;
			break;
		}
		gfn = slot_end;
	}
	srcu_read_unlock(&kvm->srcu, idx);

	return match;
}

static int kvm_complete_ripas_change(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct realm_rec *rec = &vcpu->arch.rec;
	unsigned long base = rec->run->exit.ripas_base;
	unsigned long top = rec->run->exit.ripas_top;
	enum rmi_ripas target_ripas = rec->run->exit.ripas_value;
	enum rmi_ripas src_ripas = RMI_EMPTY;
	unsigned long top_ipa = base;
	unsigned long mmu_seq = 0;
	bool attributes_match;
	int ret;

	if (base >= top)
		return 1;

	do {
		unsigned long min_pages =
			kvm_mmu_cache_min_pages(vcpu->arch.hw_mmu);

		attributes_match = realm_ripas_attributes_match(vcpu, base, top,
								target_ripas,
								&mmu_seq);

		kvm_mmu_topup_memory_cache(&vcpu->arch.mmu_page_cache,
					   min_pages);
		/*
		 * Best-effort refill of the SRO hot list outside mmu_lock; on
		 * failure alloc_delegated_granule() falls back to the
		 * per-granule delegate path under the lock.
		 */
		rmi_sro_topup(vcpu->arch.rec.sro, SZ_2M >> PAGE_SHIFT,
			      min_pages);
		write_lock(&kvm->mmu_lock);
		/*
		 * Device mappings are not backed by guest_memfd. Detect the
		 * source RIPAS while holding mmu_lock so DEV -> EMPTY can unmap
		 * the device mapping without requiring memory attributes.
		 */
		src_ripas = RMI_EMPTY;
		if (target_ripas == RMI_EMPTY) {
			ret = realm_get_ripas(kvm, base, &src_ripas);
			if (ret) {
				write_unlock(&kvm->mmu_lock);
				goto out_handle_error;
			}
		}

		/* Device RIPAS transitions have no guest_memfd backing. */
		if (target_ripas != RMI_DEV && src_ripas != RMI_DEV) {
			if (!attributes_match) {
				write_unlock(&kvm->mmu_lock);
				rec->run->exit.ripas_base = base;
				kvm_prepare_memory_fault_exit(vcpu,
							      ALIGN_DOWN(base, PAGE_SIZE),
							      ALIGN(top, PAGE_SIZE) -
							      ALIGN_DOWN(base, PAGE_SIZE),
							      false, false,
							      target_ripas == RMI_RAM);
				/*
				 * KVM_REQ_RMI has been consumed. Re-arm it so
				 * the next KVM_RUN completes the change once
				 * userspace has converted the range.
				 */
				kvm_make_request(KVM_REQ_RMI, vcpu);
				return -EFAULT;
			}
			if (mmu_invalidate_retry(kvm, mmu_seq)) {
				write_unlock(&kvm->mmu_lock);
				continue;
			}
		}
		ret = realm_set_ipa_state(vcpu, base, top, src_ripas,
					  target_ripas, &top_ipa);
		write_unlock(&kvm->mmu_lock);

out_handle_error:
		if (ret) {
			if (ret != -ENOMEM) {
				WARN_RATELIMIT(1,
					       "Unable to satisfy RIPAS_CHANGE for %#lx - "
					       "%#lx, ripas: %#x\n",
					       base, top, target_ripas);
				/* Reject a request that KVM cannot complete. */
				rec->run->enter.flags |= REC_ENTER_FLAG_RIPAS_RESPONSE;
				base = top_ipa;
				break;
			}
			/*
			 * Retry -ENOMEM only while the previous attempt made
			 * progress; otherwise leave the pending range for the
			 * next REC_ENTER instead of spinning here.
			 */
			if (top_ipa == base)
				break;
		}

		base = top_ipa;
	} while (base < top);

	/*
	 * If this function is called again before the REC_ENTER call then
	 * avoid calling realm_set_ipa_state() again by changing to the value
	 * of ripas_base for the part that has already been covered. The RMM
	 * ignores the contains of the rec_exit structure so this doesn't
	 * affect the RMM.
	 */
	rec->run->exit.ripas_base = base;

	return 1;
}

static int kvm_rec_complete_psci(struct kvm_vcpu *vcpu)
{
	struct rec_run *run = vcpu->arch.rec.run;
	struct kvm_vcpu *target = NULL;
	unsigned long status;
	unsigned long psci_ret = vcpu_get_reg(vcpu, 0);
	unsigned long rmi_ret;
	bool owner = false;

	switch (run->exit.gprs[0]) {
	/*
	 * DEN0137 v2.0-bet3 only requires RMI_PSCI_COMPLETE after
	 * PSCI_CPU_ON. Other PSCI exits are notifications or RMM-handled
	 * commands; rec_exit_psci() only flags psci_complete_pending for
	 * CPU_ON so this switch can never see anything else.
	 */
	case PSCI_0_2_FN_CPU_ON:
	case PSCI_0_2_FN64_CPU_ON:
		target = kvm_mpidr_to_vcpu(vcpu->kvm, run->exit.gprs[1]);
		status = (psci_ret == PSCI_RET_SUCCESS ||
			  psci_ret == PSCI_RET_ALREADY_ON) ?
				 PSCI_RET_SUCCESS : PSCI_RET_DENIED;
		break;
	default:
		return 0;
	}

	/*
	 * Concurrent CPU_ON requests to the same target all take a PSCI exit
	 * and reach this path, but only the source recorded in psci_on_source
	 * actually reserved the target. A source whose CPU_ON was denied must
	 * not clear the winner's reservation, otherwise a third caller could
	 * overwrite the target's reset state before the winner completes.
	 *
	 * DEN0137 v2.0-bet3 also forbids a DENIED completion once the target
	 * REC is runnable, so a denied source that raced the winner reports
	 * SUCCESS (PSCI ALREADY_ON) instead of DENIED.
	 */
	if (target) {
		spin_lock(&target->arch.mp_state_lock);
		owner = target->arch.rec.psci_on_source == vcpu;
		if (!owner)
			status = kvm_arm_vcpu_stopped(target) ?
					 PSCI_RET_DENIED : PSCI_RET_SUCCESS;
		spin_unlock(&target->arch.mp_state_lock);
	}

	rmi_ret = realm_psci_complete(vcpu, status);
	if (rmi_ret) {
		WARN_RATELIMIT(1,
			       "RMI_PSCI_COMPLETE: vcpu=%u psci=%#lx rmi=%#lx\n",
			       vcpu->vcpu_id, status, rmi_ret);
		/*
		 * KVM_REQ_RMI was already consumed by the caller. Re-arm it so
		 * a later KVM_RUN retries the completion instead of re-entering
		 * the REC with the PSCI request still outstanding.
		 */
		kvm_make_request(KVM_REQ_RMI, vcpu);
		return -EINVAL;
	}

	vcpu->arch.rec.psci_complete_pending = false;

	if (owner) {
		if (status == PSCI_RET_SUCCESS)
			kvm_psci_vcpu_on_complete(target);
		else
			kvm_psci_vcpu_on_abort(target);
	}

	return 0;
}

static long rmi_rtt_dev_map(unsigned long rd_phys, unsigned long vdev_phys,
			    unsigned long base, unsigned long top,
			    unsigned long flags, unsigned long range_desc,
			    unsigned long *out_top)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_RTT_DEV_MAP, rd_phys, vdev_phys, base, top, flags,
		range_desc
	};
	long ret;

	ret = rmi_sro_execute_no_xfer(&regs);
	if (ret >= 0 && RMI_RETURN_STATUS(ret) == RMI_SUCCESS)
		*out_top = regs.a1;

	return ret;
}

static long rmi_rtt_dev_unmap(unsigned long rd_phys,
			      unsigned long base, unsigned long top,
			      unsigned long *out_top, unsigned long *out_desc)
{
	unsigned long flags = RMI_ADDR_TYPE_SINGLE;
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_RTT_DEV_UNMAP, rd_phys, base, top, flags, 0
	};
	long ret;

	ret = rmi_sro_execute_no_xfer(&regs);
	if (ret >= 0 && RMI_RETURN_STATUS(ret) == RMI_SUCCESS) {
		*out_top = regs.a1;
		*out_desc = regs.a2;
	}

	return ret;
}

static bool realm_dev_mapping_overlaps(struct realm *realm,
				       unsigned long start,
				       unsigned long end)
{
	struct realm_dev_mapping *mapping;

	list_for_each_entry(mapping, &realm->dev_mappings, node)
		if (mapping->start < end && start < mapping->end)
			return true;

	return false;
}

static void realm_dev_mappings_free(struct realm *realm)
{
	struct realm_dev_mapping *mapping, *tmp;

	list_for_each_entry_safe(mapping, tmp, &realm->dev_mappings, node) {
		list_del(&mapping->node);
		kfree(mapping);
	}
}

static bool realm_dev_mapping_needs_split(struct realm *realm,
					  unsigned long ipa)
{
	struct realm_dev_mapping *mapping;

	list_for_each_entry(mapping, &realm->dev_mappings, node) {
		if (mapping->start < ipa && ipa < mapping->end)
			return true;
	}

	return false;
}

static void realm_dev_mapping_remove(struct realm *realm,
				     unsigned long start,
				     unsigned long end,
				     struct realm_dev_mapping *split)
{
	struct realm_dev_mapping *mapping, *tmp;

	list_for_each_entry_safe(mapping, tmp, &realm->dev_mappings, node) {
		if (mapping->end <= start || mapping->start >= end)
			continue;

		if (start <= mapping->start && end >= mapping->end) {
			list_del(&mapping->node);
			kfree(mapping);
		} else if (start <= mapping->start) {
			mapping->start = end;
		} else if (end >= mapping->end) {
			mapping->end = start;
		} else {
			if (WARN_ON(!split))
				continue;
			split->vdev_phys = mapping->vdev_phys;
			split->start = end;
			split->end = mapping->end;
			mapping->end = start;
			list_add(&split->node, &mapping->node);
			split = NULL;
		}
	}

	kfree(split);
}

static int __realm_dev_mem_unmap(struct kvm *kvm, unsigned long start,
				 unsigned long end, bool may_block)
{
	struct realm *realm = &kvm->arch.realm;
	struct realm_dev_mapping *split;
	phys_addr_t rd_phys = virt_to_phys(realm->rd);
	unsigned long ipa = start;
	int ret = 0;

	lockdep_assert_held_write(&kvm->mmu_lock);

	while (ipa < end) {
		unsigned long next_ipa = ipa;
		unsigned long range_desc = 0;
		long rmi_ret;

		split = NULL;
		if (realm_dev_mapping_needs_split(realm, ipa)) {
			split = kmalloc_obj(*split, GFP_ATOMIC);
			if (!split)
				return -ENOMEM;
		}

retry:
		rmi_ret = rmi_rtt_dev_unmap(rd_phys, ipa, end, &next_ipa,
					    &range_desc);

		switch (RMI_RETURN_STATUS(rmi_ret)) {
		case RMI_SUCCESS:
			if (WARN_ON(next_ipa <= ipa || next_ipa > end)) {
				kfree(split);
				return -EPROTO;
			}
			break;
		case RMI_ERROR_RTT: {
			unsigned long map_size;
			int err_level = RMI_RETURN_INDEX(rmi_ret);

			if (WARN_ON(err_level > KVM_PGTABLE_LAST_LEVEL)) {
				kfree(split);
				return -EPROTO;
			}

			map_size = rmi_rtt_level_mapsize(err_level);
			if (err_level == KVM_PGTABLE_LAST_LEVEL ||
			    (IS_ALIGNED(ipa, map_size) &&
			     ipa + map_size <= end)) {
				next_ipa = rmi_rtt_next_addr(ipa, end,
							    err_level);
				realm_dev_mapping_remove(realm, ipa, next_ipa,
							 split);
				ipa = next_ipa;
				continue;
			}

			ret = realm_create_rtt_levels(realm, ipa, err_level,
						      err_level + 1, NULL);
			if (ret) {
				kfree(split);
				return ret;
			}
			goto retry;
		}
		default:
			WARN_ON(1);
			kfree(split);
			return rmi_ret < 0 ? rmi_ret : -ENXIO;
		}

		realm_dev_mapping_remove(realm, ipa, next_ipa, split);
		if (RMI_ADDR_RANGE_COUNT(range_desc))
			realm_fold_rtt_level(kvm, RMM_RTT_MAX_LEVEL, ipa,
					     next_ipa);
		ipa = next_ipa;

		ret = undelegate_range_desc(kvm, range_desc, may_block);
		if (WARN_ONCE(ret, "RMI: device descriptor undelegate failed: %d\n",
			      ret))
			return ret < 0 ? ret : -ENXIO;

		if (may_block)
			cond_resched_rwlock_write(&kvm->mmu_lock);
	}

	return 0;
}

static long rmi_rtt_dev_validate(unsigned long rd_phys, unsigned long rec_phys,
				 unsigned long base, unsigned long top,
				 unsigned long *out_top)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_RTT_DEV_VALIDATE, rd_phys, rec_phys, base, top
	};
	long ret;

	ret = rmi_sro_execute_no_xfer(&regs);
	if (ret >= 0 && RMI_RETURN_STATUS(ret) == RMI_SUCCESS)
		*out_top = regs.a1;

	return ret;
}

/*
 * The device range is delegated up front, then mapped with the largest
 * block size the IPA/PA alignment allows, down to L1 (1GiB) blocks. A block
 * which the RMM refuses at that level is retried one level down. Whether an
 * L1 block is reached is additionally bounded by realm_dev_map_chunk_size
 * (the run is aligned down to it), so lowering that parameter below 1GiB
 * caps device mappings at 2MiB without any code change.
 */
static int __realm_dev_mem_map(struct kvm *kvm, struct rmi_sro_state *sro,
		unsigned long pdev_phys, unsigned long vdev_phys,
		unsigned long start_ipa, unsigned long end_ipa,
		phys_addr_t phys, unsigned long *top_ipa)
{
	struct realm *realm = &kvm->arch.realm;
	phys_addr_t rd_phys = virt_to_phys(realm->rd);
	unsigned long ipa = start_ipa;
	unsigned long delegated = 0;
	long rmi_ret;
	int ret = 0;

	lockdep_assert_held_write(&kvm->mmu_lock);

	*top_ipa = start_ipa;
	rmi_ret = rmi_delegate_range(phys, end_ipa - start_ipa, &delegated);
	if (rmi_ret) {
		if (delegated)
			WARN_ON(rmi_undelegate_range(phys, delegated, NULL));
		return -EINVAL;
	}
	realm_region_track(realm, phys, end_ipa - start_ipa,
			   SMC_RMI_RTT_DEV_MAP, start_ipa);

	while (ipa < end_ipa) {
		unsigned long chunk_size, range_desc, next_ipa = ipa;
		int map_level;

		map_level = find_aligned_map_level(realm, ipa, phys, end_ipa);
		map_level = max(map_level, KVM_PGTABLE_MIN_BLOCK_LEVEL);

retry_level:
		chunk_size = desc_range_size(rmi_rtt_level_mapsize(map_level),
					     end_ipa - ipa);
		range_desc = addr_range_desc(phys, map_level, chunk_size,
					     RMI_OP_MEM_DELEGATED);

		rmi_ret = rmi_rtt_dev_map(rd_phys, vdev_phys, ipa,
					  ipa + chunk_size, RMI_ADDR_TYPE_SINGLE,
					  range_desc, &next_ipa);

		if (RMI_RETURN_STATUS(rmi_ret) == RMI_ERROR_RTT) {
			int level = RMI_RETURN_INDEX(rmi_ret);

			if (level < map_level) {
				/* Create missing RTTs and retry */
				ret = realm_create_rtt_levels(realm, ipa, level,
							      map_level, sro);
				if (ret)
					goto err_undelegate_tail;
				goto retry_level;
			}
			if (map_level < RMM_RTT_MAX_LEVEL) {
				map_level++;
				goto retry_level;
			}
		}

		if (RMI_RETURN_STATUS(rmi_ret) == RMI_BLOCKED) {
			ret = -EAGAIN;
			goto err_undelegate_tail;
		}

		if (WARN_ON(rmi_ret != RMI_SUCCESS || next_ipa <= ipa ||
			    next_ipa > ipa + chunk_size)) {
			ret = -EIO;
			goto err_undelegate_tail;
		}

		phys += next_ipa - ipa;
		ipa = next_ipa;
	}

	*top_ipa = end_ipa;
	return 0;

err_undelegate_tail:
	*top_ipa = ipa;
	/*
	 * Undelegate the unmapped tail. The mapped head is removed by the
	 * caller.
	 */
	if (end_ipa > ipa)
		WARN_ON(realm_undelegate_range(realm, phys, end_ipa - ipa, NULL));

	return ret;
}

/*
 * With ATS, the SMMU checks device accesses against the DPT, which the RMM
 * only describes for physical ranges that have a Level 1 table. Boot creates
 * them for system memory; device ranges get theirs when first mapped. A
 * range that already has a Level 1 table makes the create fail harmlessly.
 */
static void realm_create_dpt_l1_range(struct rmi_sro_state *sro,
				      phys_addr_t phys, unsigned long size)
{
	phys_addr_t base = ALIGN_DOWN(phys, RMI_DPT_L0_REGION_SIZE);
	phys_addr_t end = ALIGN(phys + size, RMI_DPT_L0_REGION_SIZE);

	if (!rmm_has_reg2_feature(RMI_FEATURE_REGISTER_2_ATS))
		return;

	for (; base < end; base += RMI_DPT_L0_REGION_SIZE)
		rmi_dpt_l1_create(base, sro);
	rmi_sro_free(sro);
}

/*
 * The RMM only folds a Level 1 DPT whose entries all describe the same
 * permission state, so this fails harmlessly while any device in the
 * region still has DPT permissions.
 */
void realm_destroy_dpt_l1(struct kvm *kvm, phys_addr_t base)
{
	struct rmi_sro_state *sro;

	if (!kvm_realm_is_created(kvm))
		return;
	if (!rmm_has_reg2_feature(RMI_FEATURE_REGISTER_2_ATS))
		return;

	sro = kzalloc_obj(*sro, GFP_KERNEL_ACCOUNT);
	if (!sro)
		return;

	rmi_dpt_l1_destroy(base, sro);
	rmi_sro_free(sro);
	kfree(sro);
}
EXPORT_SYMBOL_GPL(realm_destroy_dpt_l1);

/*
 * IPA span processed per device-map iteration. It bounds the mmu_lock hold
 * time between cond_resched() points, and because each run is aligned down to
 * this size it also bounds the largest block the mapper can pick: a value
 * >= SZ_1G lets 1GiB (PUD) device blocks form, while a smaller value throttles
 * harder and effectively caps device mappings at that size (e.g. SZ_2M
 * restores 2MiB-only device mappings). Must be a power of two and at least
 * SZ_2M. Runtime changes affect subsequent mapping iterations.
 */
static unsigned long realm_dev_map_chunk_size = SZ_1G;

static int realm_dev_map_chunk_size_set(const char *val,
					const struct kernel_param *kp)
{
	unsigned long size;
	int ret;

	ret = kstrtoul(val, 0, &size);
	if (ret)
		return ret;

	/* Power of two so ALIGN_DOWN() is valid; >= SZ_2M so a block still fits. */
	if (size < SZ_2M || (size & (size - 1)))
		return -EINVAL;

	*(unsigned long *)kp->arg = size;
	return 0;
}

static const struct kernel_param_ops realm_dev_map_chunk_size_ops = {
	.set = realm_dev_map_chunk_size_set,
	.get = param_get_ulong,
};
module_param_cb(realm_dev_map_chunk_size, &realm_dev_map_chunk_size_ops,
		&realm_dev_map_chunk_size, 0644);
MODULE_PARM_DESC(realm_dev_map_chunk_size,
		 "Device-mapping throttle window in bytes (power of two, >= 2MiB); >= 1GiB enables 1GiB device blocks");

/* Per-run budget for mmu-notifier invalidation retries; then -EAGAIN. */
#define REALM_DEV_MAP_MAX_RETRIES	16

/*
 * Resolve device IPA @ipa to the host PFN backing it in the VMM's mapping,
 * returning it in @pfnp. Returns 0 on success, or -EINVAL if @ipa has no
 * memslot or does not resolve to device MMIO (system RAM and poisoned pages
 * are rejected, so only what the VMM mapped can be made protected).
 */
static int realm_dev_faultin_pfn(struct kvm *kvm, unsigned long ipa,
				 kvm_pfn_t *pfnp)
{
	gfn_t gfn = kvm_gpa_from_fault(kvm, ipa) >> PAGE_SHIFT;
	struct kvm_memory_slot *memslot = gfn_to_memslot(kvm, gfn);
	struct page *page = NULL;
	bool writable;
	kvm_pfn_t pfn;

	if (!memslot) {
		kvm_err("realm dev map: ipa %#lx has no memslot\n", ipa);
		return -EINVAL;
	}

	pfn = __kvm_faultin_pfn(memslot, gfn, FOLL_WRITE, &writable, &page);

	/*
	 * Classify @pfn from most-specific to most-general. HWPOISON is a
	 * specific error pfn whose bits are a subset of is_error_noslot_pfn()'s
	 * mask, so it must be tested first or it would be misreported as a
	 * generic fault. pfn_is_map_memory() is only meaningful once @pfn is
	 * known to be a valid pfn, so it comes last.
	 */
	if (pfn == KVM_PFN_ERR_HWPOISON) {
		kvm_err("realm dev map: ipa %#lx backed by a poisoned page\n",
			ipa);
		kvm_release_page_clean(page);
		return -EINVAL;
	}
	if (is_error_noslot_pfn(pfn)) {
		kvm_err("realm dev map: ipa %#lx not faultable in VMM (pfn %#llx); is device MMIO decode (PCI_COMMAND_MEMORY) enabled?\n",
			ipa, pfn);
		kvm_release_page_clean(page);
		return -EINVAL;
	}
	if (pfn_is_map_memory(pfn)) {
		kvm_err("realm dev map: ipa %#lx resolves to system RAM (pfn %#llx), not device MMIO\n",
			ipa, pfn);
		kvm_release_page_clean(page);
		return -EINVAL;
	}

	/* Accepted MMIO is PFNMAP: @page is NULL, so this is a no-op. */
	kvm_release_page_clean(page);
	*pfnp = pfn;
	return 0;
}

/*
 * Verify every page of [start_ipa, end_ipa) is backed by device MMIO in the
 * VMM's mapping and is physically contiguous starting at @phys. The API maps a
 * single contiguous PA range, so a hole, a non-device page, or any discontinuity
 * is a malformed request. Returns 0 on success, -EINVAL on mismatch, or -EINTR
 * on a fatal signal.
 */
static int realm_dev_verify_run(struct kvm *kvm, unsigned long start_ipa,
				unsigned long end_ipa, phys_addr_t phys)
{
	kvm_pfn_t base_pfn = __phys_to_pfn(phys);
	unsigned long ipa;

	for (ipa = start_ipa; ipa < end_ipa; ipa += PAGE_SIZE) {
		kvm_pfn_t pfn;
		int ret;

		/* Keep a multi-GiB scan preemptible and killable. */
		cond_resched();
		if (fatal_signal_pending(current))
			return -EINTR;

		ret = realm_dev_faultin_pfn(kvm, ipa, &pfn);
		if (ret)
			return ret;

		if (pfn != base_pfn + ((ipa - start_ipa) >> PAGE_SHIFT)) {
			kvm_err("realm dev map: ipa %#lx pfn %#llx not contiguous with expected pfn %#llx (pa_base %#llx); non-contiguous PA or wrong start_pa\n",
				ipa, pfn,
				(u64)(base_pfn + ((ipa - start_ipa) >> PAGE_SHIFT)),
				(u64)__pfn_to_phys(base_pfn));
			return -EINVAL;
		}
	}

	return 0;
}

int realm_dev_mem_map(struct kvm *kvm, unsigned long pdev_phys,
		unsigned long vdev_phys, unsigned long start_ipa,
		unsigned long end_ipa, unsigned long start_pa)
{
	struct realm_dev_mapping *mapping;
	struct rmi_sro_state *sro;
	bool mapping_added;
	int ret = 0;
	unsigned long top_ipa;
	unsigned long base_ipa = start_ipa;
	unsigned int seq_retries = 0;
	struct realm *realm = &kvm->arch.realm;
	struct kvm_s2_mmu *mmu = &kvm->arch.mmu;

	/* TODO: This should be done in VMM to handle
	 * NS IOMMU mappings correctly. For now, remove the
	 * potential NS mappings to avoid duplicate mappings
	 * to the same ranges.
	 */
	write_lock(&kvm->mmu_lock);
	kvm_realm_unmap_range(kvm, start_ipa, end_ipa - start_ipa, false, true);
	write_unlock(&kvm->mmu_lock);

	ret = rmi_init_device_gpt_range(start_pa, end_ipa - start_ipa);
	if (ret)
		return ret;

	sro = kzalloc_obj(*sro, GFP_KERNEL_ACCOUNT);
	if (!sro)
		return -ENOMEM;

	realm_create_dpt_l1_range(sro, start_pa, end_ipa - start_ipa);

	while (start_ipa < end_ipa) {
		phys_addr_t chunk_phys = start_pa + (start_ipa - base_ipa);
		unsigned long mmu_seq;
		unsigned long chunk_end;
		unsigned long chunk;

		mapping = kmalloc_obj(*mapping);
		if (!mapping) {
			ret = -ENOMEM;
			break;
		}
		mapping_added = false;

		ret = rmi_sro_topup(sro, kvm_mmu_cache_min_pages(mmu),
				    kvm_mmu_cache_min_pages(mmu));
		if (ret) {
			kfree(mapping);
			break;
		}

		/* Snapshot before resolving; rechecked under mmu_lock below. */
		mmu_seq = kvm->mmu_invalidate_seq;
		smp_rmb();

		/*
		 * Throttle mappings to at most @realm_dev_map_chunk_size bytes.
		 * The top is always aligned to the next chunk boundary to keep
		 * block mapping optimizations functional.
		 */
		chunk = READ_ONCE(realm_dev_map_chunk_size);
		chunk_end = min(end_ipa,
				ALIGN_DOWN(start_ipa, chunk) + chunk);

		ret = realm_dev_verify_run(kvm, start_ipa, chunk_end, chunk_phys);
		if (ret) {
			kfree(mapping);
			break;
		}

		write_lock(&kvm->mmu_lock);
		if (mmu_invalidate_retry(kvm, mmu_seq)) {
			/* Mapping changed while resolving: retry the run. */
			write_unlock(&kvm->mmu_lock);
			kfree(mapping);
			if (++seq_retries > REALM_DEV_MAP_MAX_RETRIES) {
				ret = -EAGAIN;
				break;
			}
			continue;
		}
		if (realm_dev_mapping_overlaps(realm, start_ipa, chunk_end)) {
			ret = -EEXIST;
			top_ipa = start_ipa;
		} else {
			ret = __realm_dev_mem_map(kvm, sro, pdev_phys,
						  vdev_phys, start_ipa, chunk_end,
						  chunk_phys, &top_ipa);
			if (top_ipa > start_ipa) {
				mapping->vdev_phys = vdev_phys;
				mapping->start = start_ipa;
				mapping->end = top_ipa;
				list_add_tail(&mapping->node,
					      &realm->dev_mappings);
				mapping_added = true;
			}
		}
		write_unlock(&kvm->mmu_lock);
		if (!mapping_added)
			kfree(mapping);

		/* Forward progress resets the retry budget. */
		if (top_ipa != start_ipa)
			seq_retries = 0;
		start_ipa = top_ipa;
		if (ret && ret != -ENOMEM && ret != -EAGAIN)
			break;

		cond_resched();
	}

	rmi_sro_free(sro);
	kfree(sro);

	if (ret && start_ipa > base_ipa) {
		int unmap_ret;

		write_lock(&kvm->mmu_lock);
		unmap_ret = __realm_dev_mem_unmap(kvm, base_ipa, start_ipa, false);
		write_unlock(&kvm->mmu_lock);
		WARN_ON(unmap_ret);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(realm_dev_mem_map);

int realm_dev_mem_unmap(struct kvm *kvm, unsigned long vdev_phys)
{
	struct realm *realm = &kvm->arch.realm;
	struct realm_dev_mapping *mapping, *iter;
	int ret = 0;

	write_lock(&kvm->mmu_lock);
	for (;;) {
		mapping = NULL;
		list_for_each_entry(iter, &realm->dev_mappings, node) {
			if (iter->vdev_phys == vdev_phys) {
				mapping = iter;
				break;
			}
		}
		if (!mapping)
			break;

		ret = __realm_dev_mem_unmap(kvm, mapping->start, mapping->end,
					    false);
		if (ret)
			break;
	}
	write_unlock(&kvm->mmu_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(realm_dev_mem_unmap);

/*
 * Complete device-backed RIPAS EMPTY requests before returning to userspace.
 * Device mappings otherwise get removed by the VMM before the deferred RIPAS
 * completion, reopening an unmap-before-EMPTY window across that round trip.
 */
void kvm_complete_dev_empty_change(struct kvm_vcpu *vcpu,
				   unsigned long base, unsigned long top)
{
	struct kvm *kvm = vcpu->kvm;
	unsigned long rd = virt_to_phys(kvm->arch.realm.rd);
	unsigned long min_pages = kvm_mmu_cache_min_pages(vcpu->arch.hw_mmu);
	struct rtt_entry rtte;

	write_lock(&kvm->mmu_lock);
	if (rmi_rtt_read_entry(rd, base, RMM_RTT_MAX_LEVEL, &rtte) ||
	    rtte.state != RMI_ASSIGNED_DEV) {
		write_unlock(&kvm->mmu_lock);
		return;
	}
	write_unlock(&kvm->mmu_lock);

	while (base < top) {
		unsigned long chunk = READ_ONCE(realm_dev_map_chunk_size);
		unsigned long chunk_end = min(top, ALIGN_DOWN(base, chunk) +
					      chunk);
		unsigned long top_ipa = base;
		int ret;

		rmi_sro_topup(vcpu->arch.rec.sro, SZ_2M >> PAGE_SHIFT,
			      min_pages);

		write_lock(&kvm->mmu_lock);
		ret = realm_set_ipa_state(vcpu, base, chunk_end, RMI_DEV,
					  RMI_EMPTY, &top_ipa);
		write_unlock(&kvm->mmu_lock);

		vcpu->arch.rec.run->exit.ripas_base = top_ipa;
		if (top_ipa == base || ret)
			break;

		base = top_ipa;
		cond_resched();
	}
}

static int realm_vsmmu_unmap_pages(struct realm_vsmmu *vsmmu, size_t npages)
{
	phys_addr_t rd_phys = virt_to_phys(vsmmu->kvm->arch.realm.rd);
	phys_addr_t vsmmu_phys = virt_to_phys(vsmmu->vsmmu_page);
	unsigned long rmi_ret;
	int first_err = 0;
	size_t i;

	for (i = 0; i < npages; i++) {
		unsigned long ipa = vsmmu->params->reg_base + i * PAGE_SIZE;
		int ret;

		ret = rmi_vsmmu_unmap(rd_phys, ipa, vsmmu_phys, &rmi_ret);
		if (WARN_ONCE(ret || RMI_RETURN_STATUS(rmi_ret) != RMI_SUCCESS,
			      "RMI: vSMMU unmap failed: ret=%d rmi=%lx\n", ret,
			      rmi_ret)) {
			if (!first_err)
				first_err = ret ?: -EIO;
		}
	}

	return first_err;
}

static bool realm_vsmmu_destroy_object(struct realm_vsmmu *vsmmu)
{
	phys_addr_t rd_phys = virt_to_phys(vsmmu->kvm->arch.realm.rd);
	phys_addr_t vsmmu_phys = virt_to_phys(vsmmu->vsmmu_page);
	unsigned long rmi_ret;
	int ret;

	ret = rmi_vsmmu_destroy(rd_phys, vsmmu_phys, &rmi_ret);
	if (WARN_ONCE(ret || RMI_RETURN_STATUS(rmi_ret) != RMI_SUCCESS,
		      "RMI: vSMMU destroy failed: ret=%d rmi=%lx\n", ret,
		      rmi_ret))
		return false;

	return true;
}

static void realm_vsmmu_release(struct kref *kref)
{
	struct realm_vsmmu *vsmmu =
		container_of(kref, struct realm_vsmmu, kref);
	phys_addr_t vsmmu_phys = virt_to_phys(vsmmu->vsmmu_page);
	size_t npages;

	npages = (vsmmu->params->reg_top - vsmmu->params->reg_base) / PAGE_SIZE;
	realm_vsmmu_unmap_pages(vsmmu, npages);
	if (realm_vsmmu_destroy_object(vsmmu))
		realm_free_delegated_page(&vsmmu->kvm->arch.realm, vsmmu_phys);
	else
		WARN_ONCE(1, "RMI: leaking live vSMMU granule %pa\n",
			  &vsmmu_phys);
	free_page((unsigned long)vsmmu->params);
	kvm_put_kvm(vsmmu->kvm);
	kfree(vsmmu);
}

/*
 * Register a Realm VSMMU. @vsmmu_id is the iommufd viommu object id; @params
 * carries the guest VSMMU register values. The host delegates a granule that
 * becomes the VSMMU handle for RMI_VSMMU_CREATE/DESTROY. VSMMU registration is
 * independent of the realm PSMMU.
 */
int kvm_realm_register_vsmmu(struct kvm *kvm, u32 vsmmu_id,
			     struct rmi_vsmmu_params *params, u32 msi_devid,
			     bool msi_devid_valid)
{
	struct realm *realm = &kvm->arch.realm;
	phys_addr_t rd_phys = virt_to_phys(realm->rd);
	phys_addr_t vsmmu_phys;
	struct realm_vsmmu *vsmmu, *old;
	unsigned long rmi_ret = 0;
	size_t mmio_size, npages, i;
	int ret;

	if (WARN_ON(!vsmmu_id))
		return -ENXIO;
	if (!PAGE_ALIGNED(params->reg_base) || !PAGE_ALIGNED(params->reg_top) ||
	    params->reg_top <= params->reg_base)
		return -EINVAL;

	vsmmu = kzalloc_obj(*vsmmu);
	if (!vsmmu)
		return -ENOMEM;

	kref_init(&vsmmu->kref);
	kvm_get_kvm(kvm);
	vsmmu->kvm = kvm;
	vsmmu->msi_devid = msi_devid;
	vsmmu->msi_devid_valid = msi_devid_valid;

	vsmmu_phys = alloc_delegated_granule(realm, realm->sro, GFP_KERNEL);
	if (vsmmu_phys == PHYS_ADDR_MAX) {
		ret = -ENOMEM;
		goto out_free;
	}
	vsmmu->vsmmu_page = phys_to_virt(vsmmu_phys);

	static_assert(sizeof(struct rmi_vsmmu_params) <= PAGE_SIZE);

	vsmmu->params = (struct rmi_vsmmu_params *)get_zeroed_page(GFP_KERNEL);
	if (!vsmmu->params) {
		ret = -ENOMEM;
		goto out_undelegate;
	}
	*vsmmu->params = *params;

	ret = rmi_vsmmu_create(rd_phys, vsmmu_phys, virt_to_phys(vsmmu->params),
			       &rmi_ret);
	if (ret || RMI_RETURN_STATUS(rmi_ret) != RMI_SUCCESS) {
		ret = -EIO;
		goto out_free_params;
	}

	mmio_size = params->reg_top - params->reg_base;
	npages = mmio_size / PAGE_SIZE;
	for (i = 0; i < npages; i++) {
		unsigned long ipa = params->reg_base + i * PAGE_SIZE;
		struct rtt_entry rtte;

		ret = rmi_rtt_read_entry(rd_phys, ipa, RMM_RTT_MAX_LEVEL,
					 &rtte);
		if (ret)
			goto out_unmap_vsmmu;

		if (rtte.walk_level != RMM_RTT_MAX_LEVEL) {
			ret = realm_create_rtt_levels(realm, ipa,
						      rtte.walk_level,
						      RMM_RTT_MAX_LEVEL,
						      realm->sro);
			if (ret)
				goto out_unmap_vsmmu;
		}

		ret = rmi_vsmmu_map(rd_phys, vsmmu_phys, ipa, RMM_RTT_MAX_LEVEL,
				    &rmi_ret);
		if (ret || RMI_RETURN_STATUS(rmi_ret) != RMI_SUCCESS) {
			ret = ret ?: -EIO;
			goto out_unmap_vsmmu;
		}
	}

	/*
	 * Publish only after the vsmmu is fully built, so a concurrent
	 * kvm_realm_get_vsmmu() never observes a half-initialized object.
	 */
	old = xa_cmpxchg(&realm->vsmmus, vsmmu_id, NULL, vsmmu, GFP_KERNEL);
	if (xa_is_err(old)) {
		ret = xa_err(old);
		goto out_unmap_vsmmu;
	}
	if (old) {
		ret = -EEXIST;
		goto out_unmap_vsmmu;
	}
	return 0;

out_unmap_vsmmu:
	realm_vsmmu_unmap_pages(vsmmu, i);
	if (!realm_vsmmu_destroy_object(vsmmu)) {
		WARN_ONCE(1, "RMI: leaking live vSMMU granule %pa\n",
			  &vsmmu_phys);
		goto out_free_params_leak;
	}
out_free_params:
	free_page((unsigned long)vsmmu->params);
out_undelegate:
	realm_free_delegated_page(realm, vsmmu_phys);
	goto out_free;
out_free_params_leak:
	free_page((unsigned long)vsmmu->params);
out_free:
	kvm_put_kvm(vsmmu->kvm);
	kfree(vsmmu);
	return ret;
}
EXPORT_SYMBOL_GPL(kvm_realm_register_vsmmu);

void kvm_realm_unregister_vsmmu(struct kvm *kvm, u32 vsmmu_id)
{
	struct realm_vsmmu *vsmmu;

	vsmmu = xa_erase(&kvm->arch.realm.vsmmus, vsmmu_id);
	if (!vsmmu)
		return;
	/* Drop the alloc-time ref; teardown runs once the last ref is put. */
	kref_put(&vsmmu->kref, realm_vsmmu_release);
}
EXPORT_SYMBOL_GPL(kvm_realm_unregister_vsmmu);

struct realm_vsmmu *kvm_realm_get_vsmmu(struct kvm *kvm, u32 vsmmu_id)
{
	struct xarray *xa = &kvm->arch.realm.vsmmus;
	struct realm_vsmmu *vsmmu;

	xa_lock(xa);
	vsmmu = xa_load(xa, vsmmu_id);
	if (vsmmu)
		kref_get(&vsmmu->kref);
	xa_unlock(xa);
	return vsmmu;
}
EXPORT_SYMBOL_GPL(kvm_realm_get_vsmmu);

struct realm_vsmmu *kvm_realm_get_vsmmu_by_base(struct kvm *kvm,
						unsigned long reg_base)
{
	struct xarray *xa = &kvm->arch.realm.vsmmus;
	struct realm_vsmmu *vsmmu;
	unsigned long index;

	xa_lock(xa);
	xa_for_each(xa, index, vsmmu) {
		if (vsmmu->params->reg_base != reg_base)
			continue;
		kref_get(&vsmmu->kref);
		xa_unlock(xa);
		return vsmmu;
	}
	xa_unlock(xa);
	return NULL;
}
EXPORT_SYMBOL_GPL(kvm_realm_get_vsmmu_by_base);

void kvm_realm_put_vsmmu(struct realm_vsmmu *vsmmu)
{
	if (vsmmu)
		kref_put(&vsmmu->kref, realm_vsmmu_release);
}
EXPORT_SYMBOL_GPL(kvm_realm_put_vsmmu);

int kvm_realm_inject_vsmmu_msi(struct realm_vsmmu *vsmmu, u64 addr,
			       u32 data)
{
	struct kvm_msi msi = {
		.address_lo = lower_32_bits(addr),
		.address_hi = upper_32_bits(addr),
		.data = data,
		.flags = KVM_MSI_VALID_DEVID,
		.devid = vsmmu->msi_devid,
	};

	if (!vsmmu->msi_devid_valid)
		return -EOPNOTSUPP;

	return kvm_send_userspace_msi(vsmmu->kvm, &msi);
}
EXPORT_SYMBOL_GPL(kvm_realm_inject_vsmmu_msi);

static int kvm_complete_vdev_map_validate(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct realm_rec *rec = &vcpu->arch.rec;
	struct kvm_run *run = vcpu->run;
	struct realm *realm = &kvm->arch.realm;
	phys_addr_t rd_phys = virt_to_phys(realm->rd);
	phys_addr_t rec_phys = virt_to_phys(rec->rec_page);

	/* reject the vdev_map validate request  */
	if (run->cca_exit.response) {
		rec->run->enter.flags = REC_ENTER_FLAG_DEV_MEM_RESPONSE;
	} else {
		unsigned long next_ipa;
		unsigned long start_ipa = run->cca_exit.gpa_base;

		while (start_ipa < run->cca_exit.gpa_top) {
			long rmi_ret;

			rmi_ret = rmi_rtt_dev_validate(rd_phys, rec_phys,
						       start_ipa,
						       run->cca_exit.gpa_top,
						       &next_ipa);
			if (rmi_ret >= 0 &&
			    RMI_RETURN_STATUS(rmi_ret) == RMI_BLOCKED) {
				/*
				 * Entering the REC now would hand the Realm a
				 * partial result. KVM_REQ_RMI has been
				 * consumed, so re-arm it and resume from
				 * @start_ipa on the next KVM_RUN instead.
				 */
				if (signal_pending(current)) {
					run->cca_exit.gpa_base = start_ipa;
					run->exit_reason = KVM_EXIT_INTR;
					kvm_make_request(KVM_REQ_RMI, vcpu);
					return -EINTR;
				}
				cond_resched();
				continue;
			}
			if (rmi_ret || next_ipa <= start_ipa) {
				rec->run->enter.flags = REC_ENTER_FLAG_DEV_MEM_RESPONSE;
				break;
			}
			start_ipa = next_ipa;
		}
	}

	return 1;
}

static int kvm_complete_vsmmu_command(struct kvm_vcpu *vcpu)
{
	struct realm *realm = &vcpu->kvm->arch.realm;
	struct realm_rec *rec = &vcpu->arch.rec;
	struct rmi_vsmmu_cmd_result cmd;
	struct realm_vsmmu *vsmmu;
	phys_addr_t rd, vsmmu_phys;
	int ret = 0;

	vsmmu = kvm_realm_get_vsmmu_by_base(vcpu->kvm, rec->run->exit.vsmmu);
	if (!vsmmu) {
		vcpu_err(vcpu, "Unknown VSMMU at IPA %#llx\n",
			 rec->run->exit.vsmmu);
		return -ENODEV;
	}

	rd = virt_to_phys(realm->rd);
	vsmmu_phys = kvm_realm_vsmmu_phys(vsmmu);
	do {
		unsigned long rmi_ret;

		rmi_ret = rmi_vsmmu_cmd_get(vsmmu_phys, rd, &cmd);
		if (rmi_ret) {
			vcpu_err(vcpu, "RMI_VSMMU_CMD_GET failed: %#lx\n",
				 rmi_ret);
			ret = -EIO;
			break;
		}

		if (cmd.flags & RMI_VSMMU_CMD_FLAGS_CMD_COMPLETE) {
			vcpu_err(vcpu,
				 "VSMMU command requires unsupported PRI completion\n");
			ret = -EOPNOTSUPP;
			break;
		}

		if (cmd.flags & RMI_VSMMU_CMD_FLAGS_IRQ) {
			ret = kvm_realm_inject_vsmmu_msi(vsmmu, cmd.msi_addr,
							 cmd.msi_data);
			if (ret < 0) {
				vcpu_err(vcpu, "VSMMU MSI injection failed: %d\n",
					 ret);
				break;
			}
			ret = 0;
		}
		cond_resched();
	} while (cmd.flags & RMI_VSMMU_CMD_FLAGS_PENDING);

	kvm_realm_put_vsmmu(vsmmu);
	return ret ?: 1;
}

int kvm_rec_handle_request(struct kvm_vcpu *vcpu)
{
	struct realm_rec *rec = &vcpu->arch.rec;
	u64 esr;

	/*
	 * REC exit state may still describe the previous PSCI exit after a
	 * retryable REC_ENTER failure. Drive RMI_PSCI_COMPLETE from KVM-owned
	 * state so the host completes each PSCI request exactly once.
	 */
	if (rec->psci_complete_pending)
		return kvm_rec_complete_psci(vcpu) ?: 1;

	switch (rec->run->exit.exit_reason) {
	case RMI_EXIT_SYNC:
		esr = rec->run->exit.esr;
		if (ESR_ELx_EC(esr) == ESR_ELx_EC_SYS64 &&
		    (esr & ESR_ELx_SYS64_ISS_DIR_MASK) ==
				ESR_ELx_SYS64_ISS_DIR_READ) {
			int rt = ESR_ELx_SYS64_ISS_RT(esr);

			if (rt < REC_RUN_GPRS)
				rec->run->enter.gprs[rt] =
					vcpu_get_reg(vcpu, rt);
		}
		break;
	case RMI_EXIT_PSCI:
		break;
	case RMI_EXIT_HOST_CALL:
		for (int i = 0; i < REC_RUN_GPRS; i++)
			rec->run->enter.gprs[i] = vcpu_get_reg(vcpu, i);
		break;
	case RMI_EXIT_RIPAS_CHANGE:
		return kvm_complete_ripas_change(vcpu);
	case RMI_EXIT_VDEV_VALIDATE_MAPPING:
		return kvm_complete_vdev_map_validate(vcpu);
	case RMI_EXIT_VSMMU_COMMAND:
		return kvm_complete_vsmmu_command(vcpu);
	default:
		KVM_BUG(1, vcpu->kvm, "Unhandled realm exit_reason");
		return -ENXIO;
	}

	return 1;
}

int noinstr kvm_rec_enter(struct kvm_vcpu *vcpu)
{
	struct realm_rec *rec = &vcpu->arch.rec;

	return rmi_rec_enter(rec->rec_phys, rec->run_phys);
}

static int kvm_create_rec(struct kvm_vcpu *vcpu)
{
	struct user_pt_regs *vcpu_regs = vcpu_gp_regs(vcpu);
	unsigned long mpidr = kvm_vcpu_get_mpidr_aff(vcpu);
	unsigned long rec_mpidr;
	struct realm *realm = &vcpu->kvm->arch.realm;
	struct realm_rec *rec = &vcpu->arch.rec;
	unsigned long rec_page_phys;
	struct rec_params *params;
	int r, i;

	if (rec->run)
		return -EBUSY;

	/*
	 * The RMM will report PSCI v1.0 to Realms and the KVM_ARM_VCPU_PSCI_0_2
	 * flag covers v0.2 and onwards.
	 */
	if (!vcpu_has_feature(vcpu, KVM_ARM_VCPU_PSCI_0_2))
		return -EINVAL;

	r = kvm_mpidr_to_rmi_rec_mpidr(mpidr, &rec_mpidr);
	if (r)
		return r;

	BUILD_BUG_ON(sizeof(*params) > PAGE_SIZE);
	BUILD_BUG_ON(sizeof(*rec->run) > PAGE_SIZE);

	params = (struct rec_params *)get_zeroed_page(GFP_KERNEL);
	rec->run = (void *)get_zeroed_page(GFP_KERNEL);
	rec->sro = kzalloc_obj(*rec->sro, GFP_KERNEL);
	if (!params || !rec->run || !rec->sro) {
		r = -ENOMEM;
		goto out_free_pages;
	}
	rec->run_phys = virt_to_phys(rec->run);

	/*
	 * Attach this REC's SRO to the shared tree with the Track ID so its
	 * auxiliary granules are attributed to the same Realm.
	 */
	rec->sro->trackid = realm->sro->trackid;

	/*
	 * Pre-warm the SRO hot list (process context, outside mmu_lock) so the
	 * REC page and the aux granules donated by RMI_REC_CREATE are served
	 * from pre-delegated entries. Best-effort: a failure just leaves the
	 * allocator on the per-granule fallback path.
	 */
	rmi_sro_topup(rec->sro, SZ_2M >> PAGE_SHIFT,
		      kvm_mmu_cache_min_pages(&vcpu->kvm->arch.mmu));

	/* Pre-delegated granule for the RMM-private REC page (or fallback). */
	rec_page_phys = alloc_delegated_granule(realm, rec->sro, GFP_KERNEL);
	if (rec_page_phys == PHYS_ADDR_MAX) {
		r = -ENOMEM;
		goto out_free_pages;
	}
	rec->rec_page = phys_to_virt(rec_page_phys);
	rec->rec_phys = rec_page_phys;

	for (i = 0; i < ARRAY_SIZE(params->gprs); i++)
		params->gprs[i] = vcpu_regs->regs[i];

	params->pc = vcpu_regs->pc;

	if (vcpu->vcpu_id == 0)
		params->flags |= REC_PARAMS_FLAG_RUNNABLE;

	params->mpidr = rec_mpidr;

	if (rmi_rec_create(virt_to_phys(realm->rd), rec_page_phys,
			   virt_to_phys(params), rec->sro)) {
		r = -ENXIO;
		goto out_free_rec_page;
	}

	rec->mpidr = mpidr;

	free_page((unsigned long)params);
	return 0;

out_free_rec_page:
	/* Undelegate + free (leaks on undelegate failure). */
	realm_free_delegated_page(realm, rec_page_phys);
	rec->rec_page = NULL;
out_free_pages:
	free_page((unsigned long)rec->run);
	free_page((unsigned long)params);
	rmi_sro_free(rec->sro);
	kfree(rec->sro);
	rec->run = NULL;
	rec->run_phys = 0;
	rec->rec_page = NULL;
	rec->rec_phys = 0;
	rec->sro = NULL;
	return r;
}

void kvm_destroy_rec(struct kvm_vcpu *vcpu)
{
	struct realm_rec *rec = &vcpu->arch.rec;
	unsigned long rec_page_phys;
	int ret;

	if (!vcpu_is_rec(vcpu))
		return;

	if (!rec->run) {
		/* Nothing to do if the VCPU hasn't been finalized */
		return;
	}

	/*
	 * If a CPU_ON completion was pending on this REC, release the target's
	 * psci_on_pending flag so it isn't wedged in DENIED-for-future-CPU_ON
	 * state after we destroy the source. The RMM has no spec hook to be
	 * told the source died; KVM-owned state is the only thing to unwind.
	 * Must run before rec->run is freed below, since the saved CPU_ON
	 * arguments live in rec->run->exit.gprs[].
	 */
	if (rec->psci_complete_pending) {
		unsigned long fn = rec->run->exit.gprs[0];

		if (fn == PSCI_0_2_FN_CPU_ON || fn == PSCI_0_2_FN64_CPU_ON) {
			struct kvm_vcpu *target =
				kvm_mpidr_to_vcpu(vcpu->kvm,
						  rec->run->exit.gprs[1]);

			if (target)
				kvm_psci_vcpu_on_abort(target);
		}
		rec->psci_complete_pending = false;
	}

	rec_page_phys = virt_to_phys(rec->rec_page);

	ret = rmi_rec_destroy(rec_page_phys, rec->sro);
	if (WARN_ONCE(ret, "RMI: REC destroy failed: %d\n", ret))
		return;

	free_page((unsigned long)rec->run);
	rec->run = NULL;
	rec->run_phys = 0;

	realm_free_delegated_page(&vcpu->kvm->arch.realm, rec_page_phys);
	rec->rec_page = NULL;
	rec->rec_phys = 0;

	rmi_sro_free(rec->sro);
	kfree(rec->sro);
	rec->sro = NULL;
}

int kvm_activate_realm(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	struct kvm_vcpu *vcpu;
	unsigned long i;
	int ret;

	if (kvm_realm_state(kvm) >= REALM_STATE_ACTIVE)
		return 0;

	if (!irqchip_in_kernel(kvm)) {
		/* Userspace irqchip not yet supported with realms */
		return -EOPNOTSUPP;
	}

	guard(mutex)(&kvm->arch.config_lock);
	/* Check again with the lock held */
	if (kvm_realm_state(kvm) >= REALM_STATE_ACTIVE)
		return 0;

	ret = realm_ensure_created(kvm);
	if (ret)
		return ret;

	/* Mark state as dead in case we fail */
	kvm_set_realm_state(kvm, REALM_STATE_DEAD);

	kvm_for_each_vcpu(i, vcpu, kvm) {
		ret = kvm_create_rec(vcpu);
		if (ret)
			return ret;
	}

	/*
	 * Every RMI_RTT_INIT_RIPAS extends the RIM, so the RIPAS of a Realm is
	 * initialized either by userspace through KVM_ARM_RMI_INIT_RIPAS or,
	 * if userspace never used it, for every guest_memfd memslot here.
	 */
	if (!realm->ripas_user_init) {
		ret = set_ripas_of_protected_regions(kvm);
		if (ret)
			return ret;
	}

	ret = rmi_realm_activate(virt_to_phys(realm->rd));
	if (ret)
		return -ENXIO;

	kvm_set_realm_state(kvm, REALM_STATE_ACTIVE);
	return 0;
}

void kvm_destroy_realm(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	size_t pgd_size = kvm_pgtable_stage2_pgd_size(kvm->arch.mmu.vtcr);
	long rmi_ret;
	int ret;

	guard(mutex)(&kvm->arch.config_lock);

	if (!kvm_realm_is_created(kvm)) {
		realm_free_unmap_desc_buf(realm);
		realm_free_sro(realm);
		realm_dev_mappings_free(realm);
		return;
	}

	kvm_set_realm_state(kvm, REALM_STATE_DYING);

	realm_unmap_stage2(kvm);

	if (realm->rd) {
		phys_addr_t rd_phys = virt_to_phys(realm->rd);

		ret = rmi_realm_terminate(rd_phys);
		if (WARN_ONCE(ret, "RMI: Realm terminate failed: %d\n", ret))
			goto out_free_host;

		ret = realm_destroy_rtts(kvm);
		if (WARN_ONCE(ret, "RMI: Realm RTT destroy failed: %d\n", ret))
			goto out_free_host;

		ret = rmi_realm_destroy(rd_phys, realm->sro);
		if (WARN_ONCE(ret, "RMI: Realm destroy failed: %d\n", ret))
			goto out_free_host;
		realm_free_delegated_page(realm, rd_phys);
		realm->rd = NULL;
	}

	rmi_ret = realm_undelegate_range(realm, kvm->arch.mmu.pgd_phys,
					 pgd_size, NULL);
	if (WARN_ONCE(rmi_ret, "RMI: Realm PGD undelegate failed: %ld\n",
		      rmi_ret))
		goto out_free_host;

	kvm_set_realm_state(kvm, REALM_STATE_DEAD);

	/* Now that the Realm is destroyed, free the entry level RTTs */
	kvm_free_stage2_pgd(&kvm->arch.mmu);

	WARN_ON(!list_empty(&realm->dev_mappings));

out_free_host:
	/*
	 * The SRO context and the LIST-unmap scratch buffer are host-owned
	 * (never delegated), so release them even when the RMM-state teardown
	 * above bailed out and intentionally leaked the Realm-owned (delegated)
	 * granules. realm_free_unmap_desc_buf() is idempotent.
	 */
	/*
	 * Registered vsmmus each hold a kvm_get_kvm() reference, so by VM
	 * teardown the xarray is empty; free its internal radix nodes.
	 */
	xa_destroy(&realm->vsmmus);
	realm_free_unmap_desc_buf(realm);
	realm_free_sro(realm);
	realm_dev_mappings_free(realm);
}

int kvm_init_realm(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	int trackid = 0;
	int ret;

	INIT_LIST_HEAD(&realm->dev_mappings);

	if (READ_ONCE(realm_track_leaks)) {
		trackid = rmi_trackid_alloc();
		if (trackid < 0)
			return trackid;
	}

	xa_init(&realm->vsmmus);

	ret = realm_alloc_sro(realm, trackid);
	if (ret) {
		rmi_trackid_free(trackid);
		realm_free_sro(realm);
		return ret;
	}

	return 0;
}

static int rmm_check_features(void)
{
	if (kvm_lpa2_is_enabled() &&
	    !rmi_has_feature(0, RMI_FEATURE_REGISTER_0_LPA2)) {
		kvm_err("RMM doesn't support LPA2");
		return -ENXIO;
	}

	if (!rmi_has_feature(1, RMI_FEATURE_REGISTER_1_HASH_SHA_256)) {
		kvm_err("RMM doesn't support SHA-256 realms");
		return -ENXIO;
	}

	return 0;
}

void kvm_init_rmi(void)
{
	/*
	 * TODO: Support Realm guests in nVHE mode, this will require adding
	 * EL2 stub(s) for REC entry and possibly other things.
	 */
	if (!is_kernel_in_hyp_mode())
		return;

	if (!is_rmi_available())
		return;

	if (rmm_check_features())
		return;

	kvm_info("Realm guests supported");
	static_branch_enable(&kvm_rmi_is_available);
}
