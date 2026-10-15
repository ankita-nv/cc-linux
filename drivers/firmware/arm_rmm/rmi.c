// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2026 ARM Ltd.
 */

#include <linux/arm-rmi-cmds.h>
#include <linux/atomic.h>
#include <linux/cpufeature.h>
#include <linux/crash_dump.h>
#include <linux/debugfs.h>
#include <linux/idr.h>
#include <linux/kexec.h>
#include <linux/kstrtox.h>
#include <linux/maple_tree.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/numa.h>
#include <linux/overflow.h>
#include <linux/processor.h>
#include <linux/reboot.h>
#include <linux/sched/mm.h>
#include <linux/seq_file.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/xarray.h>

#include <asm/memory.h>
#include <asm/pgtable-hwdef.h>

static bool arm64_rmi_is_available;

/* DEN0137 v2.0-bet3 defines feature registers 0 through 4. */
#define RMI_FEAT_REG_COUNT	5
static __ro_after_init unsigned long rmi_feat_reg_cache[RMI_FEAT_REG_COUNT];

static unsigned long granule_range_step = SZ_1G;

static int granule_range_step_set(const char *val,
				  const struct kernel_param *kp)
{
	unsigned long size;
	int ret;

	ret = kstrtoul(val, 0, &size);
	if (ret)
		return ret;
	if (size < SZ_2M || size > SZ_64G || !is_power_of_2(size))
		return -EINVAL;

	*(unsigned long *)kp->arg = size;
	return 0;
}

static const struct kernel_param_ops granule_range_step_ops = {
	.set = granule_range_step_set,
	.get = param_get_ulong,
};
module_param_cb(granule_range_step, &granule_range_step_ops,
		&granule_range_step, 0644);
MODULE_PARM_DESC(granule_range_step,
		 "Bytes per granule range operation (power of two, 2MiB to 64GiB)");

unsigned long rmi_granule_range_step(void)
{
	return READ_ONCE(granule_range_step);
}
EXPORT_SYMBOL_GPL(rmi_granule_range_step);

unsigned long rmi_feat_reg(unsigned long id)
{
	if (WARN_ON(id >= RMI_FEAT_REG_COUNT))
		return 0;

	return rmi_feat_reg_cache[id];
}
EXPORT_SYMBOL_GPL(rmi_feat_reg);

/*
 * Range delegate may complete a prefix before a later invocation fails.
 * Track that prefix so callers can undo only the granules whose ownership
 * really changed; out_top is unknown for the failing invocation.
 */
long rmi_delegate_range(phys_addr_t phys, unsigned long size,
			unsigned long *delegated_size)
{
	phys_addr_t base = phys;
	unsigned long top = phys + size;
	long ret = RMI_SUCCESS;

	if (delegated_size)
		*delegated_size = 0;

	/*
	 * RMI_GRANULE_RANGE_DELEGATE is a non-memory-transferring SRO
	 * (DEN0137 v2.0-bet3 §B4.3.2), so it needs no address-list buffer.
	 * Drive it with the lean no-xfer executor to
	 * avoid a per-call struct rmi_sro_state allocation.
	 */
	while (phys < top) {
		unsigned long req_top = min_t(unsigned long, top,
					      phys + rmi_granule_range_step());
		unsigned long out_top;

		ret = rmi_granule_range_delegate(phys, req_top, &out_top);
		if (ret != RMI_SUCCESS)
			return ret;

		if (WARN_ONCE(out_top <= phys || out_top > req_top,
			      "RMI: invalid delegate progress %#lx: %d\n",
			      out_top, -ENXIO)) {
			return -ENXIO;
		}
		phys = out_top;
		if (delegated_size)
			*delegated_size = phys - base;
	}

	return ret;
}

long rmi_undelegate_range(phys_addr_t phys, unsigned long size,
			  unsigned long *undelegated_size)
{
	phys_addr_t base = phys;
	unsigned long top = phys + size;
	long ret = RMI_SUCCESS;

	if (undelegated_size)
		*undelegated_size = 0;

	/*
	 * RMI_GRANULE_RANGE_UNDELEGATE is a non-memory-transferring SRO
	 * (DEN0137 v2.0-bet3 §B4.3.2); drive it with the lean no-xfer
	 * executor and avoid a per-call struct rmi_sro_state allocation.
	 */
	while (phys < top) {
		unsigned long req_top = min_t(unsigned long, top,
					      phys + rmi_granule_range_step());
		unsigned long out_top;

		ret = rmi_granule_range_undelegate(phys, req_top, &out_top);
		if (ret != RMI_SUCCESS)
			return ret;

		if (WARN_ONCE(out_top <= phys || out_top > req_top,
			      "RMI: invalid undelegate progress %#lx: %d\n",
			      out_top, -ENXIO)) {
			return -ENXIO;
		}
		phys = out_top;
		if (undelegated_size)
			*undelegated_size = phys - base;
	}

	return ret;
}

/*
 * Free an allocation after range delegation failed. The delegated prefix must
 * be undelegated before it can be returned to the page allocator; if that
 * recovery also fails, free any prefix that came back and leak only the
 * still-delegated middle.
 */
static void rmi_free_failed_delegation(void *virt, unsigned long size,
				       unsigned long delegated_size)
{
	phys_addr_t phys = virt_to_phys(virt);
	unsigned long undelegated_size = 0;
	long ret;

	if (WARN_ON(delegated_size > size))
		delegated_size = size;

	if (delegated_size) {
		ret = rmi_undelegate_range(phys, delegated_size,
					   &undelegated_size);
		if (WARN_ONCE(ret != RMI_SUCCESS,
			      "RMI: failed delegation cleanup: %ld\n", ret)) {
			if (undelegated_size)
				free_pages_exact(virt, undelegated_size);
			virt = (char *)virt + delegated_size;
			size -= delegated_size;
		}
	}

	if (size)
		free_pages_exact(virt, size);
}

static unsigned long rmi_sro_allocatable_pages(unsigned long entry)
{
	unsigned long bsize = RMI_ADDR_RANGE_SIZE(entry);
	unsigned long count = RMI_ADDR_RANGE_COUNT(entry);
	unsigned long nr_pages;

	if (!count)
		return 0;

	nr_pages = count *
		   (RMI_ADDR_BSIZE_BYTES(bsize) >> PAGE_SHIFT);
	if ((nr_pages - 1) > FIELD_MAX(RMI_ADDR_RANGE_COUNT_MASK))
		return 0;

	return nr_pages;
}

/*
 * Ensure at least @min undelegated granules are cached in sro->addr_list[], up
 * to @capacity, preferring allocations from @nid. Already-cached undelegated
 * granules count towards the target, so only the shortfall is allocated. The
 * donate path's existing cached-entry matching picks the entries up without any
 * extra mechanism, and delegates them (or not) based on the donation request's
 * RmiOpMemState. Must run outside atomic context.
 *
 * Allocates the shortfall in large contiguous chunks (up to MAX_ORDER_NR_PAGES)
 * and stores each as one addr_list entry with size = PAGE (so the count is
 * always in pages), marked UNDELEGATED. The chunks are cached Non-secure; the
 * PAS transition is deferred to donate time (see rmi_op_mem_needs_delegation()),
 * so a donation that requires Non-secure memory is handed the cached page as-is
 * while one that requires delegation transitions it then. Each cached entry is
 * a complete Beta3 RmiAddrRangeDesc containing its block size and memory state.
 *
 * Best-effort: if capacity or allocation limits the count, whatever was
 * successfully stored is still useful; the donate path falls back to fresh
 * allocation for the rest.
 */
int rmi_sro_topup_node(struct rmi_sro_state *sro, unsigned long capacity,
		       unsigned long min, int nid)
{
	unsigned long available = 0;
	unsigned long max_chunk;
	unsigned long total = 0;
	unsigned long nr_pages;

	/*
	 * Count cached undelegated memory that rmi_sro_alloc() can consume.
	 * Descriptor counts are in units of the architected block size, and the
	 * remainder after one page is consumed must fit one PAGE descriptor.
	 */
	for (unsigned long i = 0; i < sro->addr_count; i++) {
		unsigned long entry = sro->addr_list[i];

		if (RMI_ADDR_RANGE_STATE(entry) != RMI_OP_MEM_UNDELEGATED)
			continue;

		available += rmi_sro_allocatable_pages(entry);
	}

	if (available >= min || available >= capacity)
		return 0;

	nr_pages = capacity - available;
	if ((!nr_pages) || (sro->addr_count >= RMI_MAX_ADDR_LIST))
		return 0;

	max_chunk = min_t(unsigned long, MAX_ORDER_NR_PAGES,
			  FIELD_MAX(RMI_ADDR_RANGE_COUNT_MASK));

	while ((total < nr_pages) && (sro->addr_count < RMI_MAX_ADDR_LIST)) {
		unsigned long chunk;
		unsigned int order;
		phys_addr_t phys;
		struct page *page;

		/*
		 * Allocate a power-of-two chunk, capped by the buddy allocator
		 * and the address-range count field used for cached PAGE blocks.
		 * A power-of-two size keeps the buddy allocation naturally
		 * aligned to its size. Prefer @nid, then split the order
		 * allocation so cached pages can later be freed one by one after
		 * partial donation.
		 */
		chunk = min(nr_pages - total, max_chunk);
		chunk = rounddown_pow_of_two(chunk);
		order = ilog2(chunk);
		page = alloc_pages_node(nid,
					GFP_KERNEL_ACCOUNT | __GFP_ZERO |
					__GFP_NORETRY | __GFP_NOWARN,
					order);
		if (!page)
			break;
		split_page(page, order);
		phys = page_to_phys(page);

		/*
		 * Cache the chunk UNDELEGATED (Non-secure). The PAS transition,
		 * if the donation requires one, is performed at donate time
		 * based on the request's RmiOpMemState
		 * (rmi_op_mem_needs_delegation()). Stored as one contiguous
		 * PAGE-block descriptor (count is in pages) so the donate path
		 * can reuse it.
		 */
		sro->addr_list[sro->addr_count] =
			RMI_ADDR_RANGE_DESC(phys, RMI_ADDR_RANGE_SIZE_PAGE,
					    chunk, RMI_OP_MEM_UNDELEGATED);
		sro->addr_count++;
		total += chunk;
	}

	return total ? 0 : -ENOMEM;
}

/*
 * RMM-owned range metadata stored as a 63-bit xa_value payload:
 *
 *   [62:48] TRACKID[14:0]
 *   [47:12] IPA[47:12] (reserved, currently zero)
 *   [11:4]  RMI FID ordinal relative to SMC_RMI_VERSION
 *   [3:0]   reserved flags
 *
 * Payload bit 0 is shifted to entry bit 1 by xa_mk_value(); entry bit 0
 * remains the XArray value tag. This preserves all four flag bits while keeping
 * the entry allocation-free for updates from atomic context.
 */
#define RMI_MT_TRACKID_MASK	GENMASK_ULL(62, 48)
#define RMI_MT_IPA_MASK		GENMASK_ULL(47, 12)
#define RMI_MT_SLOT_MASK		GENMASK_ULL(11, 4)

#define RMI_TRACKID_MAX		0x7fff
#define RMI_TRACKID_GLOBAL	1
#define RMI_TRACKID_REALM_MIN	(RMI_TRACKID_GLOBAL + 1)

static DEFINE_MTREE(rmi_mt);
static DEFINE_IDA(realm_trackid_ida);
static bool rmi_sro_donate_tracking_failed;

/* Boot SRO for global RMI allocations. */
static struct rmi_sro_state *rmi_sro;
/* Serialises use of rmi_sro after boot. */
static DEFINE_MUTEX(rmi_sro_lock);

int rmi_trackid_alloc(void)
{
	return ida_alloc_range(&realm_trackid_ida, RMI_TRACKID_REALM_MIN,
			       RMI_TRACKID_MAX, GFP_KERNEL);
}

void rmi_trackid_free(unsigned int trackid)
{
	if (trackid)
		ida_free(&realm_trackid_ida, trackid);
}

static inline u16 rmi_sro_trackid(struct rmi_sro_state *sro)
{
	if (!sro)
		return 0;

	return sro == rmi_sro ? RMI_TRACKID_GLOBAL : sro->trackid;
}

static void rmi_region_store(struct rmi_sro_state *sro, phys_addr_t phys,
			     unsigned long size, void *entry)
{
	int ret;

	if (!rmi_sro_trackid(sro) || !size)
		return;

	ret = mtree_store_range(&rmi_mt, phys, phys + size - 1,
				entry, GFP_ATOMIC);
	if (ret && entry && sro == rmi_sro)
		WRITE_ONCE(rmi_sro_donate_tracking_failed, true);

	WARN_ONCE(ret, "RMI: ownership tracking update failed: %d\n", ret);
}

void rmi_region_track(struct rmi_sro_state *sro, phys_addr_t phys,
		      unsigned long size, unsigned long fid,
		      unsigned long ipa)
{
	unsigned long mark;
	u16 trackid = rmi_sro_trackid(sro);

	if (!trackid || !size)
		return;

	if (fid == SMC_RMI_GPT_L1_CREATE)
		ipa = sro->regs.a1;

	mark = FIELD_PREP(RMI_MT_TRACKID_MASK, trackid) |
	       (ipa & RMI_MT_IPA_MASK) |
	       FIELD_PREP(RMI_MT_SLOT_MASK, RMI_SMC_SLOT_IDX(fid));

	rmi_region_store(sro, phys, size, xa_mk_value(mark));
}

void rmi_region_untrack(struct rmi_sro_state *sro, phys_addr_t phys,
			unsigned long size)
{
	rmi_region_store(sro, phys, size, NULL);
}

static u64 rmi_mt_owned_bytes(int trackid)
{
	MA_STATE(mas, &rmi_mt, 0, 0);
	void *entry;
	u64 total = 0;

	rcu_read_lock();
	mas_for_each(&mas, entry, ULONG_MAX) {
		unsigned long mark = xa_to_value(entry);

		if (trackid >= 0 &&
		    FIELD_GET(RMI_MT_TRACKID_MASK, mark) != trackid)
			continue;
		total += mas.last - mas.index + 1;
	}
	rcu_read_unlock();

	return total;
}

u64 rmi_region_owned_bytes(struct rmi_sro_state *sro)
{
	u16 trackid = rmi_sro_trackid(sro);

	if (!trackid)
		return 0;

	return rmi_mt_owned_bytes(trackid);
}

/*
 * Allocate one delegated page for RMM use.
 *
 * First try to pop a page from @sro's hot list (when an SRO is attached),
 * accepting either a delegated or an undelegated cached entry. After carving
 * one page, describe the remainder in PAGE units. A remainder converted from
 * a larger block size is non-contiguous. As the caller needs a delegated page,
 * a page taken from an undelegated entry is delegated before it is returned
 * (and freed if that delegation fails).
 *
 * On a hot-list miss - or when @sro is NULL - fall back to allocating a fresh
 * zeroed page with @gfp and delegating it to the RMM.
 *
 * Returns the physical address or PHYS_ADDR_MAX on failure. The caller takes
 * ownership and is responsible for undelegation + free.
 */
phys_addr_t rmi_sro_alloc(struct rmi_sro_state *sro, gfp_t gfp)
{
	phys_addr_t phys;
	void *virt;

	/* Find the first cached entry in the delegated or undelegated state. */
	for (unsigned long i = 0; sro && i < sro->addr_count; i++) {
		unsigned long entry, new_count, nr_pages, state;
		phys_addr_t new_phys;

		entry = sro->addr_list[i];
		state = RMI_ADDR_RANGE_STATE(entry);
		if (state != RMI_OP_MEM_DELEGATED &&
		    state != RMI_OP_MEM_UNDELEGATED)
			continue;

		nr_pages = rmi_sro_allocatable_pages(entry);
		if (!nr_pages)
			continue;

		/* Hand out the first page of the entry to the caller. */
		phys = RMI_ADDR_RANGE_ADDR(entry);

		if (nr_pages == 1) {
			/* Last page in entry: remove by swap with tail. */
			sro->addr_count--;
			swap(sro->addr_list[sro->addr_count],
			     sro->addr_list[i]);
		} else {
			new_phys = phys + PAGE_SIZE;
			new_count = nr_pages - 1;

			sro->addr_list[i] =
				RMI_ADDR_RANGE_DESC(new_phys,
						    RMI_ADDR_RANGE_SIZE_PAGE,
						    new_count, state);
		}

		/* Delegated entry is ready; undelegated must be delegated first. */
		if (state != RMI_OP_MEM_UNDELEGATED)
			return phys;

		virt = phys_to_virt(phys);
		goto delegate;
	}

	/*
	 * Hot-list miss (or no SRO): allocate a fresh zeroed page and delegate
	 * it to the RMM.
	 */
	virt = (void *)__get_free_page(gfp | __GFP_ZERO | __GFP_ACCOUNT);
	if (!virt)
		return PHYS_ADDR_MAX;

delegate:
	phys = virt_to_phys(virt);
	if (rmi_delegate_page(phys)) {
		free_page((unsigned long)virt);
		return PHYS_ADDR_MAX;
	}

	return phys;
}

static bool rmi_op_mem_needs_delegation(unsigned long state)
{
	return state != RMI_OP_MEM_UNDELEGATED;
}

static void rmi_smccc_invoke(const struct arm_smccc_1_2_regs *regs_in,
			     struct arm_smccc_1_2_regs *regs_out)
{
	struct arm_smccc_1_2_regs regs = *regs_in;
	unsigned long status;

	/*
	 * BUSY  : another CPU is currently driving an SRO context; spin
	 *         while it makes progress.
	 * BLOCKED: per DEN0137 v2.0-bet3 §B4.3.2, an incomplete operation
	 *         must complete before this command can proceed. Return it
	 *         to the caller instead of spinning with no possible local
	 *         forward progress.
	 *
	 * cpu_relax() is safe in atomic context (callers run under
	 * kvm->mmu_lock on the hot path) and gives the bus/sibling-CPU
	 * hint that keeps a BUSY retry burst from being mistaken for a
	 * softlockup.
	 */
	kvm_rmi_smc_count(regs.a0);
	do {
		arm_smccc_1_2_invoke(&regs, regs_out);
		status = RMI_RETURN_STATUS(regs_out->a0);
		if (status == RMI_BUSY) {
			kvm_rmi_smc_busy_count(regs.a0);
			cpu_relax();
		}
	} while (status == RMI_BUSY);
}

/*
 * Return a contiguous host-owned range to the page allocator. The RMM can hand
 * back memory that is not available to the page allocator, such as a no-map
 * range without a struct page or a memblock-reserved range. Freeing the former
 * faults on the unpopulated vmemmap; freeing the latter corrupts the allocator.
 * Such ranges are returned whole, so if any part is no-map or reserved, leak
 * the entire range rather than free it; otherwise free it in one shot.
 */
static void rmi_free_host_range(phys_addr_t phys, unsigned long size)
{
	if (!size)
		return;

	if (!memblock_is_region_memory(phys, size) ||
	    !memblock_is_map_memory(phys) ||
	    (!pfn_valid(PHYS_PFN(phys))) ||
	    (!pfn_valid(PHYS_PFN(phys + size - 1))) ||
	    memblock_is_region_reserved(phys, size)) {
		pr_warn_ratelimited("rmi: leak reserved range phys=%pa size=0x%lx\n",
				    &phys, size);
		return;
	}

	free_pages_exact(phys_to_virt(phys), size);
}

static void rmi_sro_free_entry(unsigned long entry)
{
	unsigned long addr = RMI_ADDR_RANGE_ADDR(entry);
	unsigned long bsize = RMI_ADDR_RANGE_SIZE(entry);
	unsigned long count = RMI_ADDR_RANGE_COUNT(entry);
	unsigned long state = RMI_ADDR_RANGE_STATE(entry);
	unsigned long size = RMI_ADDR_BSIZE_BYTES(bsize) * count;
	long ret;

	if (rmi_op_mem_needs_delegation(state)) {
		unsigned long undelegated_size = 0;

		ret = rmi_undelegate_range(addr, size, &undelegated_size);
		if (WARN_ONCE(ret != RMI_SUCCESS,
			      "RMI: failed SRO entry undelegate: %ld\n", ret)) {
			/* Leak the still-delegated tail. */
			rmi_free_host_range(addr, undelegated_size);
			return;
		}
	}
	rmi_free_host_range(addr, size);
}

static int rmi_sro_ensure_capacity(struct rmi_sro_state *sro,
				   unsigned long count)
{
	if (WARN_ONCE(sro->addr_count > RMI_MAX_ADDR_LIST,
		      "RMI: SRO address list overflow %lu: %d\n",
		      sro->addr_count, -EOVERFLOW))
		return -EOVERFLOW;

	if (count > RMI_MAX_ADDR_LIST)
		return -ENOSPC;

	/* Make room by dropping cached entries that are still host-owned. */
	while (count > (RMI_MAX_ADDR_LIST - sro->addr_count)) {
		sro->addr_count--;
		rmi_sro_free_entry(sro->addr_list[sro->addr_count]);
	}

	return 0;
}

/*
 * Return the host-owned tail [phys, phys+size) of a partially-donated
 * allocation: the RMM consumed the prefix, so this contiguous remainder is
 * still host memory. For a delegation-requiring donation the tail is still
 * delegated, so undelegate the whole range in one command (rather than a
 * per-page undelegate) before freeing. On undelegate failure the pages
 * remain owned by the Realm world and cannot be freed safely, so warn and
 * leak the range.
 */
static void rmi_sro_free_donated_tail(phys_addr_t phys, unsigned long size,
				      unsigned long state)
{
	unsigned long undelegated_size = 0;
	long ret;

	if (rmi_op_mem_needs_delegation(state)) {
		ret = rmi_undelegate_range(phys, size, &undelegated_size);
		if (WARN_ONCE(ret != RMI_SUCCESS,
			      "RMI: failed donated tail undelegate: %ld\n", ret)) {
			rmi_free_host_range(phys, undelegated_size);
			return;
		}
	}

	rmi_free_host_range(phys, size);
}

static bool rmi_sro_cache_entry_matches(unsigned long entry,
					unsigned long bsize,
					unsigned long state)
{
	return RMI_ADDR_RANGE_SIZE(entry) == bsize &&
	       RMI_ADDR_RANGE_STATE(entry) == state;
}

/*
 * Preserve a host-owned tail left behind after a partial donation. The original
 * descriptor now covers memory with mixed ownership, so cache the remainder as
 * PAGE-sized descriptors and free only the part that does not fit.
 */
static void rmi_sro_cache_donated_tail(struct rmi_sro_state *sro,
				       phys_addr_t phys, unsigned long size,
				       unsigned long state)
{
	unsigned long max_count = FIELD_MAX(RMI_ADDR_RANGE_COUNT_MASK);
	unsigned long nr_pages = size >> PAGE_SHIFT;

	while (nr_pages && (sro->addr_count < RMI_MAX_ADDR_LIST)) {
		unsigned long count = min(nr_pages, max_count);

		sro->addr_list[sro->addr_count] =
			RMI_ADDR_RANGE_DESC(phys, RMI_ADDR_RANGE_SIZE_PAGE,
					    count, state);
		sro->addr_count++;

		phys += count << PAGE_SHIFT;
		nr_pages -= count;
	}

	if (nr_pages)
		rmi_sro_free_donated_tail(phys, nr_pages << PAGE_SHIFT, state);
}

/*
 * Find a cached contiguous range in @state which satisfies the requested
 * block size, count, and alignment. Prefer an exact count; otherwise return
 * the first larger range which can be split.
 */
static long rmi_sro_find_contig_state(struct rmi_sro_state *sro,
				      unsigned long bsize,
				      unsigned long block_count,
				      unsigned long state)
{
	unsigned long size = RMI_ADDR_BSIZE_BYTES(bsize) * block_count;
	long larger = -1;

	for (unsigned long i = 0; i < sro->addr_count; i++) {
		unsigned long entry = sro->addr_list[i];
		unsigned long entry_count = RMI_ADDR_RANGE_COUNT(entry);

		if (RMI_ADDR_RANGE_SIZE(entry) != bsize ||
		    RMI_ADDR_RANGE_STATE(entry) != state ||
		    entry_count < block_count ||
		    !IS_ALIGNED(RMI_ADDR_RANGE_ADDR(entry), size))
			continue;

		if (entry_count == block_count)
			return i;
		if (larger < 0)
			larger = i;
	}

	return larger;
}

/*
 * Select a cached range for a contiguous donation. Prefer memory already in
 * the requested state. If the request requires delegation and no such range
 * exists, allow an undelegated range which can be transitioned before use.
 */
static long rmi_sro_find_contig(struct rmi_sro_state *sro,
				unsigned long bsize,
				unsigned long block_count,
				unsigned long state)
{
	long selected;

	selected = rmi_sro_find_contig_state(sro, bsize, block_count, state);
	if (selected >= 0 || !rmi_op_mem_needs_delegation(state))
		return selected;

	return rmi_sro_find_contig_state(sro, bsize, block_count,
					 RMI_OP_MEM_UNDELEGATED);
}

/*
 * Satisfy one contiguous SRO donation. Reuse an exact or larger cached range,
 * splitting a larger range and transitioning its PAS when required. If the
 * cache has no suitable range, allocate fresh contiguous memory. Publish one
 * address-range descriptor to the RMM and preserve any unused donated tail.
 */
static int rmi_sro_donate_contig(struct rmi_sro_state *sro,
				 unsigned long sro_handle,
				 unsigned long donatereq,
				 struct arm_smccc_1_2_regs *out_regs,
				 gfp_t gfp)
{
	unsigned long bsize = RMI_DONATE_BSIZE(donatereq);
	unsigned long block_count = RMI_DONATE_COUNT(donatereq);
	unsigned long state = RMI_DONATE_STATE(donatereq);
	unsigned long size;
	unsigned long addr_range;
	unsigned long donated_granules;
	unsigned long donated_size;
	unsigned long delegated_size = 0;
	long selected;
	int ret;
	void *virt;
	phys_addr_t phys;
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_OP_MEM_DONATE,
		sro_handle
	};

	/*
	 * Contiguous donations require a power-of-two block count, and the
	 * single address-list entry must describe exactly the requested number
	 * of blocks.
	 */
	if (WARN_ONCE((!is_power_of_2(block_count)) ||
		      (block_count > FIELD_MAX(RMI_ADDR_RANGE_COUNT_MASK)),
		      "RMI: invalid contiguous donation count %lu: %d\n",
		      block_count, -EPROTO))
		return -EPROTO;

	/* CONDITIONAL donations are safely satisfied with delegated memory. */
	if (state == RMI_OP_MEM_CONDITIONAL)
		state = RMI_OP_MEM_DELEGATED;

	size = RMI_ADDR_BSIZE_BYTES(bsize) * block_count;
	ret = rmi_sro_ensure_capacity(sro, 1);
	if (ret)
		return ret;

	/*
	 * Prefer an exact same-state range, then a larger same-state range,
	 * followed by corresponding UNDELEGATED candidates which need a PAS
	 * transition. A larger range remains active in the cache while its
	 * aligned prefix occupies the inactive donation slot at @addr_count.
	 */
	selected = rmi_sro_find_contig(sro, bsize, block_count, state);

	if (selected >= 0) {
		unsigned long entry = sro->addr_list[selected];
		unsigned long entry_count = RMI_ADDR_RANGE_COUNT(entry);
		bool needs_delegation = RMI_ADDR_RANGE_STATE(entry) != state;

		phys = RMI_ADDR_RANGE_ADDR(entry);
		if (entry_count == block_count) {
			sro->addr_count--;
			swap(sro->addr_list[sro->addr_count],
			     sro->addr_list[selected]);
		} else {
			sro->addr_list[selected] =
				RMI_ADDR_RANGE_DESC(phys + size, bsize,
						    entry_count - block_count,
						    RMI_ADDR_RANGE_STATE(entry));
		}
		sro->addr_list[sro->addr_count] =
			RMI_ADDR_RANGE_DESC(phys, bsize, block_count, state);

		if (needs_delegation &&
		    rmi_delegate_range(phys, size, &delegated_size)) {
			rmi_free_failed_delegation(phys_to_virt(phys), size,
						   delegated_size);
			return -ENXIO;
		}

		goto out;
	}

	virt = alloc_pages_exact(size, gfp);
	if (!virt)
		return -ENOMEM;
	phys = virt_to_phys(virt);

	if (rmi_op_mem_needs_delegation(state)) {
		if (rmi_delegate_range(phys, size, &delegated_size)) {
			rmi_free_failed_delegation(virt, size, delegated_size);
			return -ENXIO;
		}
	}

	addr_range = RMI_ADDR_RANGE_DESC(phys, bsize, block_count, state);
	sro->addr_list[sro->addr_count] = addr_range;

out:
	regs.a2 = virt_to_phys(&sro->addr_list[sro->addr_count]);
	regs.a3 = 1;
	rmi_smccc_invoke(&regs, out_regs);

	donated_granules = out_regs->a1;
	if (WARN_ON(donated_granules > (size >> PAGE_SHIFT)))
		donated_granules = size >> PAGE_SHIFT;
	donated_size = donated_granules << PAGE_SHIFT;

	if (donated_granules == 0) {
		/* No pages used by the RMM */
		sro->addr_count++;
	} else {
		/* RMM kept the consumed prefix: record it, cache any tail. */
		phys = RMI_ADDR_RANGE_ADDR(sro->addr_list[sro->addr_count]);
		rmi_region_track(sro, phys, donated_size, sro->regs.a0, 0);
		if (donated_size < size)
			rmi_sro_cache_donated_tail(sro, phys + donated_size,
						   size - donated_size, state);
	}

	return 0;
}

/*
 * Satisfy a non-contiguous SRO donation by collecting matching cached ranges,
 * splitting oversized ranges, and filling any shortfall with fresh one-block
 * allocations. Submit the resulting descriptor list, track the consumed
 * prefix, and compact any unconsumed ranges back into the cache.
 */
static int rmi_sro_donate_noncontig(struct rmi_sro_state *sro,
				    unsigned long sro_handle,
				    unsigned long donatereq,
				    struct arm_smccc_1_2_regs *out_regs,
				    gfp_t gfp)
{
	unsigned long bsize = RMI_DONATE_BSIZE(donatereq);
	unsigned long block_size = RMI_ADDR_BSIZE_BYTES(bsize);
	unsigned long block_count = RMI_DONATE_COUNT(donatereq);
	unsigned long state = RMI_DONATE_STATE(donatereq);
	unsigned long blocks = 0;
	unsigned long list_count = 0;
	unsigned long capacity, donate_blocks;
	unsigned long addr_list_start = sro->addr_count;
	unsigned long donated_granules;
	unsigned long granules_per_block;
	unsigned long consumed_blocks;
	unsigned long partial_granules;
	unsigned long cache_pos;
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_OP_MEM_DONATE,
		sro_handle
	};

	/* CONDITIONAL donations are safely satisfied with delegated memory. */
	if (state == RMI_OP_MEM_CONDITIONAL)
		state = RMI_OP_MEM_DELEGATED;

	/*
	 * Reuse cached ranges with matching block size and state. Each Beta3
	 * address-range descriptor carries both properties; contiguity is a
	 * property of the donation request rather than of each list entry.
	 */
	for (unsigned long i = 0; i < addr_list_start && blocks < block_count; ) {
		unsigned long entry = sro->addr_list[i];
		unsigned long entry_count = RMI_ADDR_RANGE_COUNT(entry);
		unsigned long remaining = block_count - blocks;
		phys_addr_t phys = RMI_ADDR_RANGE_ADDR(entry);

		/*
		 * A non-contiguous donation can use any region whose base is
		 * aligned to the requested block size, but the region must still
		 * match the requested block size and memory state.
		 */
		if (!entry_count ||
		    !rmi_sro_cache_entry_matches(entry, bsize, state) ||
		    !IS_ALIGNED(phys, block_size)) {
			i++;
			continue;
		}

		/*
		 * This whole cached range fits in the remaining request. Move
		 * it into the suffix that will be passed to RMI_OP_MEM_DONATE.
		 */
		if (entry_count <= remaining) {
			addr_list_start--;
			swap(sro->addr_list[addr_list_start],
			     sro->addr_list[i]);
			blocks += entry_count;
			list_count++;
			continue;
		}

		/*
		 * The cached range is larger than the remaining request. If a
		 * spare slot exists, split off the requested prefix for the
		 * donation list and keep the leftover suffix cached.
		 */
		if (sro->addr_count < RMI_MAX_ADDR_LIST) {
			sro->addr_list[sro->addr_count] =
				RMI_ADDR_RANGE_DESC(phys, bsize, remaining, state);
			sro->addr_count++;

			phys += remaining * block_size;
			entry_count -= remaining;
			sro->addr_list[i] =
				RMI_ADDR_RANGE_DESC(phys, bsize, entry_count,
						    state);

			blocks += remaining;
			list_count++;
			continue;
		}

		i++;
	}

	if (WARN_ONCE(sro->addr_count > RMI_MAX_ADDR_LIST,
		      "RMI: SRO address list overflow %lu: %d\n",
		      sro->addr_count, -EOVERFLOW))
		return -EOVERFLOW;

	/*
	 * A non-contiguous donation may provide less memory than requested; the
	 * RMM consumes the prefix and asks for the remainder if it still needs
	 * more. Limit the list to the caller-owned cache instead of failing the
	 * SRO when the request is larger than the cached address list.
	 */
	capacity = RMI_MAX_ADDR_LIST - sro->addr_count;
	donate_blocks = min(block_count, blocks + capacity);
	if (!donate_blocks)
		return -ENOSPC;

	/*
	 * Fill any remaining donation shortfall with freshly allocated
	 * one-block ranges. These descriptors already match the requested size
	 * and state, so they can be appended directly to the donation suffix.
	 */
	while (blocks < donate_blocks) {
		unsigned long delegated_size = 0;
		unsigned long addr_range;
		phys_addr_t phys;
		void *virt;

		virt = alloc_pages_exact(block_size, gfp);
		if (!virt) {
			if (blocks)
				break;
			return -ENOMEM;
		}

		phys = virt_to_phys(virt);
		if (rmi_op_mem_needs_delegation(state)) {
			if (rmi_delegate_range(phys, block_size,
					       &delegated_size)) {
				rmi_free_failed_delegation(virt, block_size,
							   delegated_size);
				if (blocks)
					break;
				return -ENXIO;
			}
		}

		addr_range = RMI_ADDR_RANGE_DESC(phys, bsize, 1, state);
		sro->addr_list[sro->addr_count++] = addr_range;
		blocks++;
		list_count++;
	}

	/*
	 * X3 is the number of address-list entries, not the number of blocks
	 * covered by those entries. RMM reports consumption back in base
	 * granules, so convert that to requested block units below.
	 */
	regs.a2 = virt_to_phys(&sro->addr_list[addr_list_start]);
	regs.a3 = list_count;
	rmi_smccc_invoke(&regs, out_regs);

	donated_granules = out_regs->a1;
	granules_per_block = block_size >> PAGE_SHIFT;

	/*
	 * The RMM reports consumed memory in base granules, but the address
	 * list tracks ownership in block-sized ranges. Clamp first, then
	 * convert the consumed granules back to donated blocks.
	 */
	if (WARN_ON(donated_granules > blocks * granules_per_block))
		donated_granules = blocks * granules_per_block;

	consumed_blocks = donated_granules / granules_per_block;
	partial_granules = donated_granules % granules_per_block;
	cache_pos = addr_list_start;

	/*
	 * RMM consumes from the front of the donated block stream. Walk the
	 * submitted descriptors in order, drop fully consumed blocks, trim a
	 * partially consumed descriptor, and compact any untouched remainder
	 * back into the active cache.
	 */
	for (unsigned long i = 0; i < list_count; i++) {
		unsigned long entry = sro->addr_list[addr_list_start + i];
		unsigned long entry_count = RMI_ADDR_RANGE_COUNT(entry);
		phys_addr_t phys = RMI_ADDR_RANGE_ADDR(entry);

		if (consumed_blocks >= entry_count) {
			rmi_region_track(sro, phys, entry_count * block_size,
					 sro->regs.a0, 0);
			consumed_blocks -= entry_count;
			continue;
		}

		if (consumed_blocks) {
			rmi_region_track(sro, phys, consumed_blocks * block_size,
					 sro->regs.a0, 0);
			phys += consumed_blocks * block_size;
			entry_count -= consumed_blocks;
			consumed_blocks = 0;
		}

		/*
		 * Successful donation reports a multiple of the block size, but
		 * discard any non-conforming partial block defensively.
		 */
		if (partial_granules) {
			unsigned long donated_size =
				partial_granules << PAGE_SHIFT;

			rmi_region_track(sro, phys, donated_size, sro->regs.a0, 0);
			rmi_sro_free_donated_tail(phys + donated_size,
						  block_size - donated_size,
						  state);
			phys += block_size;
			entry_count--;
			partial_granules = 0;
		}

		if (!entry_count)
			continue;

		sro->addr_list[cache_pos] =
			RMI_ADDR_RANGE_DESC(phys, bsize, entry_count, state);
		cache_pos++;
	}

	sro->addr_count = cache_pos;

	return 0;
}

static int rmi_sro_donate(struct rmi_sro_state *sro,
			  unsigned long sro_handle,
			  unsigned long donatereq,
			  struct arm_smccc_1_2_regs *regs,
			  gfp_t gfp)
{
	unsigned long block_count = RMI_DONATE_COUNT(donatereq);
	unsigned long state = RMI_DONATE_STATE(donatereq);

	if (WARN_ONCE(!block_count || state > RMI_OP_MEM_CONDITIONAL ||
		      (donatereq & ~GENMASK(18, 0)),
		      "RMI: invalid donation request %#lx: %d\n",
		      donatereq, -EPROTO))
		return -EPROTO;

	if (RMI_DONATE_CONTIG(donatereq)) {
		return rmi_sro_donate_contig(sro, sro_handle, donatereq,
					     regs, gfp);
	} else {
		return rmi_sro_donate_noncontig(sro, sro_handle, donatereq,
						regs, gfp);
	}
}

static int rmi_sro_reclaim(struct rmi_sro_state *sro,
			   unsigned long sro_handle,
			   struct arm_smccc_1_2_regs *out_regs)
{
	unsigned long capacity;
	struct arm_smccc_1_2_regs regs;
	int ret;

	ret = rmi_sro_ensure_capacity(sro, 1);
	if (ret)
		return ret;

	capacity = RMI_MAX_ADDR_LIST - sro->addr_count;
	memset(&sro->addr_list[sro->addr_count], 0,
	       capacity * sizeof(sro->addr_list[0]));

	regs = (struct arm_smccc_1_2_regs){
		SMC_RMI_OP_MEM_RECLAIM,
		sro_handle,
		virt_to_phys(&sro->addr_list[sro->addr_count]),
		capacity
	};
	rmi_smccc_invoke(&regs, out_regs);

	if (RMI_RETURN_STATUS(out_regs->a0) != RMI_INCOMPLETE)
		return 0;

	if (WARN_ON_ONCE(out_regs->a1 > capacity))
		out_regs->a1 = capacity;

	for (unsigned long i = 0; i < out_regs->a1; i++) {
		unsigned long idx = sro->addr_count + i;
		unsigned long entry = sro->addr_list[idx];
		phys_addr_t phys = RMI_ADDR_RANGE_ADDR(entry);
		unsigned long range_count = RMI_ADDR_RANGE_COUNT(entry);
		unsigned long size;

		size = RMI_ADDR_BSIZE_BYTES(RMI_ADDR_RANGE_SIZE(entry)) *
		       range_count;

		/* The reclaimed range is host-owned again. */
		rmi_region_untrack(sro, phys, size);
	}

	sro->addr_count += out_regs->a1;

	return 0;
}

static void rmi_sro_continue(unsigned long sro_handle,
			     struct arm_smccc_1_2_regs *regs)
{
	*regs = (struct arm_smccc_1_2_regs){
		SMC_RMI_OP_CONTINUE, sro_handle, 0
	};
	rmi_smccc_invoke(regs, regs);
}

static bool rmi_sro_mem_xfer_needs_continue(unsigned long memreq,
					    const struct arm_smccc_1_2_regs *regs)
{
	unsigned long status = RMI_RETURN_STATUS(regs->a0);

	if (memreq == RMI_OP_MEM_REQ_NONE || status == RMI_INCOMPLETE)
		return false;

	/* A successful memory transfer always returns RMI_INCOMPLETE. */
	WARN_ON_ONCE(status == RMI_SUCCESS);

	return true;
}

void rmi_sro_free(struct rmi_sro_state *sro)
{
	if (!sro)
		return;

	for (unsigned long i = 0; i < sro->addr_count; i++) {
		unsigned long entry = sro->addr_list[i];

		rmi_sro_free_entry(entry);
	}

	sro->addr_count = 0;
}

/*
 * Cancel an SRO after the host cannot service its current request.
 * The handle must be released back to the RMM, otherwise the SRO context
 * table eventually saturates and subsequent initiations return RMI_BLOCKED.
 *
 * Per DEN0137 v2.0-bet3 §B4.3.2.5, a successful CANCEL never produces
 * further REQ_DONATE responses. Drive every REQ_RECLAIM/REQ_NONE response
 * until OP_CONTINUE returns a terminal status and invalidates the handle.
 */
static int rmi_sro_cancel(struct rmi_sro_state *sro, unsigned long sro_handle,
			  struct arm_smccc_1_2_regs *regs)
{
	*regs = (struct arm_smccc_1_2_regs){
		SMC_RMI_OP_CANCEL, sro_handle
	};
	rmi_smccc_invoke(regs, regs);

	if (WARN_ONCE(RMI_RETURN_STATUS(regs->a0) != RMI_INCOMPLETE,
		      "RMI: SRO cancel failed: 0x%lx err=%d\n",
		      regs->a0, -EPROTO))
		return -EPROTO;

	for (;;) {
		unsigned long memreq;
		int ret;

		if (RMI_RETURN_STATUS(regs->a0) != RMI_INCOMPLETE)
			return 0;

		memreq = RMI_RETURN_MEMREQ(regs->a0);
		switch (memreq) {
		case RMI_OP_MEM_REQ_NONE:
			rmi_sro_continue(sro_handle, regs);
			break;
		case RMI_OP_MEM_REQ_RECLAIM:
			ret = rmi_sro_reclaim(sro, sro_handle, regs);
			if (WARN_ONCE(ret, "RMI: SRO cancel reclaim failed: %d\n",
				      ret))
				return ret;

			if (rmi_sro_mem_xfer_needs_continue(memreq, regs))
				rmi_sro_continue(sro_handle, regs);
			break;
		case RMI_OP_MEM_REQ_DONATE:
		default:
			WARN_ONCE(1,
				  "RMI: unexpected memory request for FID %#lx: %d\n",
				  sro->regs.a0, -EPROTO);
			return -EPROTO;
		}
	}
}

/*
 * Drive an SRO command to completion. Does NOT free the SRO hot list - the
 * delegated remainder is left in place so the caller can reuse it across
 * commands and release it once when the SRO is no longer needed.
 */
long rmi_sro_execute(struct rmi_sro_state *sro, gfp_t gfp,
		     struct arm_smccc_1_2_regs *out_regs)
{
	unsigned long sro_handle;
	struct arm_smccc_1_2_regs regs;
	int host_error = 0;

	/* Memory-transferring SROs may wait for host memory. */
	might_sleep();

	rmi_smccc_invoke(&sro->regs, &regs);

	sro_handle = regs.a1;

	while (RMI_RETURN_STATUS(regs.a0) == RMI_INCOMPLETE) {
		bool can_cancel = RMI_RETURN_CAN_CANCEL(regs.a0);
		unsigned long memreq = RMI_RETURN_MEMREQ(regs.a0);
		int cancel_ret;
		int ret = 0;

		switch (memreq) {
		case RMI_OP_MEM_REQ_NONE:
			rmi_sro_continue(sro_handle, &regs);
			break;
		case RMI_OP_MEM_REQ_DONATE:
			ret = rmi_sro_donate(sro, sro_handle, regs.a2, &regs,
					     gfp);
			break;
		case RMI_OP_MEM_REQ_RECLAIM:
			ret = rmi_sro_reclaim(sro, sro_handle, &regs);
			break;
		default:
			WARN_ONCE(1,
				  "RMI: invalid memory request %lu for FID %#lx: %d\n",
				  memreq, sro->regs.a0, -EPROTO);
			ret = -EPROTO;
			break;
		}

		if (ret) {
			if (!can_cancel) {
				/*
				 * DEN0137 v2.0-bet3 §B4.3.2.5 requires
				 * RMI_OP_CONTINUE to invalidate a non-cancellable
				 * SRO handle.
				 */
				host_error = ret;
				rmi_sro_continue(sro_handle, &regs);
				continue;
			}

			/*
			 * Cancel the operation and process every response until
			 * OP_CONTINUE returns a terminal status and invalidates the
			 * handle. Preserve the host failure when cleanup succeeds.
			 */
			cancel_ret = rmi_sro_cancel(sro, sro_handle, &regs);
			if (cancel_ret)
				ret = cancel_ret;
			if (out_regs)
				*out_regs = regs;
			return ret;
		}

		/*
		 * A failed OP_MEM_{DONATE,RECLAIM} leaves the SRO handle
		 * valid. Resume so the RMM records the memory-transfer failure;
		 * the loop processes every subsequent response until the handle
		 * is released with the resumed command's result.
		 */
		if (rmi_sro_mem_xfer_needs_continue(memreq, &regs))
			rmi_sro_continue(sro_handle, &regs);
	}

	if (out_regs)
		*out_regs = regs;

	if (host_error)
		return host_error;

	return regs.a0;
}

/*
 * Cancel a no-transfer SRO after a protocol error. A command driven via
 * rmi_sro_execute_no_xfer() is one which DEN0137 v2.0-bet3 §B4.3.2
 * marks as NOT memory-transferring: such a command never legitimately
 * requests DONATE, and a successful CANCEL can never require RECLAIM.
 * If the RMM nonetheless requests a memory op, cancel the SRO if possible.
 * Without an address-list buffer, a non-cancellable SRO cannot be recovered
 * through the specified protocol, so warn and leak its handle.
 */
static int rmi_sro_cancel_no_xfer(unsigned long sro_handle,
				  struct arm_smccc_1_2_regs *regs)
{
	*regs = (struct arm_smccc_1_2_regs){
		SMC_RMI_OP_CANCEL, sro_handle
	};
	rmi_smccc_invoke(regs, regs);

	if (WARN_ONCE(RMI_RETURN_STATUS(regs->a0) != RMI_INCOMPLETE,
		      "RMI: no-xfer SRO cancel failed: 0x%lx err=%d\n",
		      regs->a0, -EPROTO))
		return -EPROTO;

	while (RMI_RETURN_STATUS(regs->a0) == RMI_INCOMPLETE) {
		unsigned long memreq = RMI_RETURN_MEMREQ(regs->a0);

		/*
		 * A memory op after cancelling a no-xfer SRO is an RMM
		 * protocol violation for which this path has no valid recovery.
		 */
		if (WARN_ONCE(memreq != RMI_OP_MEM_REQ_NONE,
			      "RMI: no-xfer SRO cancel returned memory op %lu; leaking handle: %d\n",
			      memreq, -EPROTO))
			return -EPROTO;

		rmi_sro_continue(sro_handle, regs);
	}

	return 0;
}

long rmi_sro_execute_no_xfer(struct arm_smccc_1_2_regs *regs)
{
	unsigned long fid = regs->a0;
	unsigned long sro_handle;

	rmi_smccc_invoke(regs, regs);
	sro_handle = regs->a1;

	while (RMI_RETURN_STATUS(regs->a0) == RMI_INCOMPLETE) {
		unsigned long memreq = RMI_RETURN_MEMREQ(regs->a0);

		/*
		 * A non-memory-transferring command must only ever continue
		 * (REQ_NONE). Any DONATE/RECLAIM request is a contract
		 * violation: attempt to cancel the SRO and fail.
		 */
		if (memreq != RMI_OP_MEM_REQ_NONE) {
			bool can_cancel = RMI_RETURN_CAN_CANCEL(regs->a0);
			int cancel_ret;

			WARN_ONCE(1,
				  "RMI: unexpected memreq %lu on no-xfer FID %#lx: %d\n",
				  memreq, fid, -EPROTO);
			if (!can_cancel) {
				/*
				 * A no-xfer SRO requesting a memory operation is
				 * an RMM protocol violation. RMI_OP_CONTINUE is not
				 * valid while result.mem selects a memory command,
				 * and this path cannot satisfy that command.
				 */
				WARN_ONCE(1,
					  "RMI: leaking non-cancellable no-xfer SRO handle: %d\n",
					  -EPROTO);
				return -EPROTO;
			}

			cancel_ret = rmi_sro_cancel_no_xfer(sro_handle, regs);
			if (cancel_ret)
				return cancel_ret;
			return -EPROTO;
		}

		rmi_sro_continue(sro_handle, regs);
	}

	return regs->a0;
}

static int rmi_check_version(void)
{
	struct arm_smccc_res res;
	unsigned short version_major, version_minor;
	unsigned long host_version = RMI_ABI_VERSION(RMI_ABI_MAJOR_VERSION,
						     RMI_ABI_MINOR_VERSION);
	unsigned long aa64pfr0 = read_sanitised_ftr_reg(SYS_ID_AA64PFR0_EL1);

	/* If RME isn't supported, then RMI can't be */
	if (cpuid_feature_extract_unsigned_field(aa64pfr0, ID_AA64PFR0_EL1_RME_SHIFT) == 0)
		return -ENXIO;

	rmi_smccc_invoke_v1_1(SMC_RMI_VERSION, host_version, &res);

	if (res.a0 == SMCCC_RET_NOT_SUPPORTED)
		return -ENXIO;

	version_major = RMI_ABI_VERSION_GET_MAJOR(res.a1);
	version_minor = RMI_ABI_VERSION_GET_MINOR(res.a1);

	if (res.a0 != RMI_SUCCESS) {
		unsigned short high_version_major, high_version_minor;

		high_version_major = RMI_ABI_VERSION_GET_MAJOR(res.a2);
		high_version_minor = RMI_ABI_VERSION_GET_MINOR(res.a2);

		pr_err("Unsupported RMI ABI (v%d.%d - v%d.%d) we want v%d.%d\n",
		       version_major, version_minor,
		       high_version_major, high_version_minor,
		       RMI_ABI_MAJOR_VERSION,
		       RMI_ABI_MINOR_VERSION);
		return -ENXIO;
	}

	pr_info("RMI ABI version %d.%d\n", version_major, version_minor);

	return 0;
}

int rmi_psmmu_activate(unsigned long psmmu_phys,
	       unsigned long psmmu_params_phys, unsigned long *rmi_ret)
{
	struct rmi_sro_state *sro __free(kfree) = kzalloc_obj(*sro);
	if (!sro)
		return -ENOMEM;

	sro->regs = (struct arm_smccc_1_2_regs){
		SMC_RMI_PSMMU_ACTIVATE, psmmu_phys, psmmu_params_phys
	};
	*rmi_ret = rmi_sro_execute(sro, GFP_KERNEL, NULL);
	rmi_sro_free(sro);
	return 0;
}

int rmi_psmmu_deactivate(unsigned long psmmu_phys, unsigned long *rmi_ret)
{
	struct rmi_sro_state *sro __free(kfree) = kzalloc_obj(*sro);
	if (!sro)
		return -ENOMEM;

	sro->regs = (struct arm_smccc_1_2_regs){
		SMC_RMI_PSMMU_DEACTIVATE, psmmu_phys
	};
	*rmi_ret = rmi_sro_execute(sro, GFP_KERNEL, NULL);
	rmi_sro_free(sro);
	return 0;
}

int rmi_psmmu_st_l2_create(unsigned long psmmu_phys,
		   unsigned long stream_id, unsigned long *rmi_ret)
{
	struct rmi_sro_state *sro __free(kfree) = kzalloc_obj(*sro);
	if (!sro)
		return -ENOMEM;

	sro->regs = (struct arm_smccc_1_2_regs){
		SMC_RMI_PSMMU_ST_L2_CREATE, psmmu_phys, stream_id
	};
	*rmi_ret = rmi_sro_execute(sro, GFP_KERNEL, NULL);
	rmi_sro_free(sro);
	return 0;
}

int rmi_psmmu_st_l2_destroy(unsigned long psmmu_phys,
		    unsigned long stream_id, unsigned long *rmi_ret)
{
	struct rmi_sro_state *sro __free(kfree) = kzalloc_obj(*sro);
	if (!sro)
		return -ENOMEM;

	sro->regs = (struct arm_smccc_1_2_regs){
		SMC_RMI_PSMMU_ST_L2_DESTROY, psmmu_phys, stream_id
	};
	*rmi_ret = rmi_sro_execute(sro, GFP_KERNEL, NULL);
	rmi_sro_free(sro);
	return 0;
}

static int rmi_read_features(void)
{
	for (int i = 0; i < RMI_FEAT_REG_COUNT; i++) {
		if (WARN_ON(rmi_features(i, &rmi_feat_reg_cache[i])))
			return -EINVAL;
	}

	return 0;
}

/*
 * RmiRmmConfig.rmi_granule_size encoding for this kernel's PAGE_SIZE.
 * The arm64 page shifts are 12/14/16 (4K/16K/64K), which map to the spec
 * encoding 0/1/2 as (PAGE_SHIFT - 12) / 2. Compile-time constant.
 */
#define RMI_PAGE_GRANULE_SIZE	((PAGE_SHIFT - 12) >> 1)

static int rmi_configure(struct rmi_sro_state *sro)
{
	struct rmm_config *config __free(free_page) = NULL;
	unsigned long ret;

	if (!(rmi_feat_reg(1) & BIT(RMI_PAGE_GRANULE_SIZE))) {
		pr_err("RMM does not support %luKB granules\n", PAGE_SIZE >> 10);
		return -ENXIO;
	}
	config = (struct rmm_config *)get_zeroed_page(GFP_KERNEL);
	if (!config)
		return -ENOMEM;

	config->rmi_granule_size = RMI_PAGE_GRANULE_SIZE;

	ret = rmi_rmm_config_set(virt_to_phys(config));
	if (ret) {
		pr_err("RMM config set failed\n");
		return -EINVAL;
	}

	/*
	 * Pre-populate the SRO hot list with one max-order buddy chunk of
	 * delegated granules before activating the RMM, so activation donates
	 * from a single contiguous allocation rather than many scattered
	 * per-donate allocs. That keeps the metadata the RMM consumes contiguous
	 * and the kexec reservation coalesced; the unconsumed remainder stays in
	 * the hot list and is reused by the GPT L1 creates that follow. Best-
	 * effort: the donate path falls back to fresh allocation on shortfall.
	 */
	rmi_sro_topup(sro, MAX_ORDER_NR_PAGES, MAX_ORDER_NR_PAGES);

	ret = rmi_rmm_activate(sro);
	if (ret) {
		pr_err("RMM activate failed\n");
		return -ENXIO;
	}

	return 0;
}

/*
 * For now we set the tracking_region_size to 0 for RMI_RMM_CONFIG_SET().
 * TODO: Support other tracking sizes (via Kconfig option).
 */
#ifdef CONFIG_PAGE_SIZE_4KB
#define RMM_GRANULE_TRACKING_SIZE	SZ_1G
#elif defined(CONFIG_PAGE_SIZE_16KB)
#define RMM_GRANULE_TRACKING_SIZE	SZ_32M
#elif defined(CONFIG_PAGE_SIZE_64KB)
#define RMM_GRANULE_TRACKING_SIZE	SZ_512M
#endif

#define RMI_TRACK_CATEGORY_ANY		ULONG_MAX

/* Make sure the area has the expected category and is tracked at FINE. */
static int rmi_init_memory_tracking(phys_addr_t start, phys_addr_t end,
				    unsigned long expected_category,
				    struct rmi_sro_state *sro)
{
	while (start < end) {
		unsigned long ret, category, state, next;
		phys_addr_t region_top;

		ret = rmi_granule_tracking_get(start, end, &category, &state, &next);
		if (ret != RMI_SUCCESS) {
			pr_err("RMI: tracking query failed for %pa: ret=0x%lx\n",
			       &start, ret);
			return -ENODEV;
		}
		if (next <= start || next > end) {
			pr_err("RMI: invalid tracking query cursor for %pa: next=0x%lx\n",
			       &start, next);
			return -ENODEV;
		}
		if (expected_category != RMI_TRACK_CATEGORY_ANY &&
		    category != expected_category) {
			pr_err("RMI: unexpected tracking category at %pa: category=%lu expected=%lu\n",
			       &start, category, expected_category);
			return -ENODEV;
		}
		if (state == RMI_TRACKING_FINE) {
			start = next;
			continue;
		}

		ret = rmi_granule_tracking_set(start, category,
					       RMI_TRACKING_FINE, sro);
		if (ret) {
			pr_err("RMI: tracking set failed for %pa: state=%lu ret=0x%lx\n",
			       &start, state, ret);
			return -ENODEV;
		}

		/* SET changes one tracking region; verify that exact region. */
		region_top = min_t(phys_addr_t, start + RMM_GRANULE_TRACKING_SIZE,
				   end);
		ret = rmi_granule_tracking_get(start, region_top, &category,
					       &state, &next);
		if (ret != RMI_SUCCESS) {
			pr_err("RMI: tracking verification query failed for %pa: ret=0x%lx\n",
			       &start, ret);
			return -ENODEV;
		}
		if (next != region_top ||
		    (expected_category != RMI_TRACK_CATEGORY_ANY &&
		     category != expected_category) ||
		    state != RMI_TRACKING_FINE) {
			pr_err("RMI: tracking verification failed for %pa: category=%lu state=%lu next=0x%lx\n",
			       &start, category, state, next);
			return -ENODEV;
		}

		start = next;
	}

	return 0;
}

static void rmi_teardown_memory_tracking(phys_addr_t start, phys_addr_t end,
					 struct rmi_sro_state *sro)
{
	while (start < end) {
		unsigned long ret, category, state, next;

		ret = rmi_granule_tracking_get(start, end, &category, &state,
					       &next);
		if (ret != RMI_SUCCESS) {
			pr_warn("RMI: tracking teardown query failed for %pa: ret=0x%lx\n",
				&start, ret);
			return;
		}
		if (next <= start || next > end) {
			pr_warn("RMI: invalid tracking teardown cursor for %pa: next=0x%lx\n",
				&start, next);
			return;
		}
		if (state == RMI_TRACKING_NONE ||
		    state == RMI_TRACKING_RESERVED) {
			start = next;
			continue;
		}

		ret = rmi_granule_tracking_set(start, category,
					       RMI_TRACKING_NONE, sro);
		if (ret) {
			pr_warn("RMI: tracking clear failed for %pa: state=%lu ret=0x%lx\n",
				&start, state, ret);
			return;
		}
		start += RMM_GRANULE_TRACKING_SIZE;
	}
}

static unsigned long rmi_l0gpt_size(void)
{
	return 1UL << (30 + FIELD_GET(RMI_FEATURE_REGISTER_1_L0GPTSZ,
				      rmi_feat_reg(1)));
}

/*
 * Size in bytes of the L1 GPT that describes one rmi_l0gpt_size() region.
 * Per DEN0137 v2.0-bet3 the GPT encodes a 4-bit GPI per granule, and the GPT
 * granule size matches the RMM granule (PAGE_SIZE, see rmi_configure()), so
 * the table needs (rmi_l0gpt_size() / PAGE_SIZE) granules * 4 bits, i.e.
 * (rmi_l0gpt_size() >> PAGE_SHIFT) / 2 bytes.
 */
static unsigned long rmi_l1gpt_size(void)
{
	return (rmi_l0gpt_size() >> PAGE_SHIFT) / 2;
}

/* One 32-bit DPT entry describes one RMM granule. */
static unsigned long rmi_l1dpt_size(void)
{
	return (RMI_DPT_L0_REGION_SIZE >> PAGE_SHIFT) * sizeof(u32);
}

static int rmi_init_dpt(struct rmi_sro_state *sro)
{
	unsigned long l1_pages = PFN_UP(rmi_l1dpt_size());
	struct memblock_region *r;
	phys_addr_t last_end = 0;
	int last_nid = NUMA_NO_NODE;
	long ret;

	if (!rmm_has_reg2_feature(RMI_FEATURE_REGISTER_2_ATS))
		return 0;

	ret = rmi_dpt_l0_create(sro);
	if (RMI_RETURN_STATUS(ret) != RMI_SUCCESS) {
		pr_err("RMI: DPT Level 0 create failed: 0x%lx\n", ret);
		return -ENXIO;
	}

	rmi_sro_free(sro);
	for_each_mem_region(r) {
		phys_addr_t start, end;
		int nid;

		if (memblock_is_nomap(r))
			continue;

		start = ALIGN_DOWN(PFN_PHYS(memblock_region_memory_base_pfn(r)),
				   RMI_DPT_L0_REGION_SIZE);
		end = ALIGN(PFN_PHYS(memblock_region_memory_end_pfn(r)),
			    RMI_DPT_L0_REGION_SIZE);
		if (start < last_end)
			start = last_end;
		if (start >= end)
			continue;
		last_end = end;

		nid = memblock_get_region_node(r);
		if (memblock_is_hotpluggable(r) || !numa_valid_node(nid))
			nid = NUMA_NO_NODE;
		if (nid != last_nid) {
			rmi_sro_free(sro);
			last_nid = nid;
		}

		while (start < end) {
			ret = rmi_sro_topup_node(sro, l1_pages, l1_pages, nid);
			if (ret)
				return ret;

			ret = rmi_dpt_l1_create(start, sro);
			if (RMI_RETURN_STATUS(ret) != RMI_SUCCESS) {
				pr_err("RMI: DPT Level 1 create failed for %pa: 0x%lx\n",
				       &start, ret);
				return -ENXIO;
			}
			start += RMI_DPT_L0_REGION_SIZE;
		}
	}

	return 0;
}

static int rmi_query_gpt_info(phys_addr_t base, phys_addr_t top,
			      phys_addr_t *out_top, unsigned long *state)
{
	unsigned long result_top, result_state;
	unsigned long l0gpt_sz = rmi_l0gpt_size();
	int ret;

	ret = rmi_gpt_info(base, top, &result_top, &result_state);
	if (ret != RMI_SUCCESS) {
		pr_err("RMI: GPT info failed for [%pa, %pa): 0x%x\n",
		       &base, &top, ret);
		return -ENXIO;
	}

	if (result_top <= base || result_top > top ||
	    !IS_ALIGNED(result_top, l0gpt_sz) ||
	    result_state > RMI_GPT_PAR_HOST_CREATED) {
		pr_err("RMI: invalid GPT info for [%pa, %pa): top=%#lx state=%#lx\n",
		       &base, &top, result_top, result_state);
		return -EPROTO;
	}

	*out_top = result_top;
	*state = result_state;

	return 0;
}

static int rmi_query_gpt_par(phys_addr_t addr, unsigned long l0gpt_sz,
			     unsigned long *state)
{
	phys_addr_t top;
	int ret;

	ret = rmi_query_gpt_info(addr, addr + l0gpt_sz, &top, state);
	if (ret)
		return ret;

	if (top != addr + l0gpt_sz)
		return -EPROTO;

	return 0;
}

/*
 * Create one host-allocated L1 GPT, including the explicit backfill flow from
 * DEN0137 v2.0-bet3 A2.3.9.3. If the first donated L1 GPT lies in another
 * host PAR which is not yet created, the RMM rejects the target CREATE and
 * reclaims the donation. Use that returned range to identify PAR_D, create
 * PAR_D, then retry PAR_T. The contiguous hot-list allocator keeps subsequent
 * donations in PAR_D, so the donor create is self-describing and the retry is
 * non-self-describing.
 */
static int rmi_create_gpt_l1(phys_addr_t target, unsigned long l0gpt_sz,
			     unsigned long l1_pages,
			     struct rmi_sro_state *sro)
{
	unsigned long donor_state, target_state;
	unsigned long entry, status;
	phys_addr_t donor;
	long ret;

	ret = rmi_gpt_l1_create(target, sro);
	if (ret < 0)
		return ret;

	status = RMI_RETURN_STATUS(ret);
	if (status == RMI_SUCCESS)
		return 0;
	if (status != RMI_ERROR_GPT)
		goto fail_target;

	/*
	 * RMI_ERROR_GPT can also mean that another caller created PAR_T.
	 * Re-read the architectural state before interpreting the reclaimed
	 * donation as a request for L1GPT backfill.
	 */
	ret = rmi_query_gpt_par(target, l0gpt_sz, &target_state);
	if (ret)
		return ret;
	if (target_state == RMI_GPT_PAR_HOST_CREATED)
		return 0;
	if (target_state != RMI_GPT_PAR_HOST_NOT_CREATED)
		return -EPROTO;

	/*
	 * A strict Beta3 RMM reclaimed the unsuccessful donation as the last
	 * hot-list entry. It must be the one contiguous, undelegated L1 GPT
	 * range requested by RMI_GPT_L1_CREATE.
	 */
	if (!sro->addr_count)
		return -EPROTO;
	entry = sro->addr_list[sro->addr_count - 1];
	if (RMI_ADDR_RANGE_SIZE(entry) != RMI_ADDR_RANGE_SIZE_PAGE ||
	    RMI_ADDR_RANGE_COUNT(entry) != l1_pages ||
	    RMI_ADDR_RANGE_STATE(entry) != RMI_OP_MEM_UNDELEGATED ||
	    !IS_ALIGNED(RMI_ADDR_RANGE_ADDR(entry), l1_pages << PAGE_SHIFT))
		return -EPROTO;

	donor = ALIGN_DOWN(RMI_ADDR_RANGE_ADDR(entry), l0gpt_sz);
	if (donor == target)
		return -EPROTO;

	/* Make the reclaimed range the donor CREATE's first exact match. */
	swap(sro->addr_list[0], sro->addr_list[sro->addr_count - 1]);

	ret = rmi_query_gpt_par(donor, l0gpt_sz, &donor_state);
	if (ret)
		return ret;

	if (donor_state == RMI_GPT_PAR_HOST_NOT_CREATED) {
		ret = rmi_gpt_l1_create(donor, sro);
		if (ret < 0)
			return ret;
		status = RMI_RETURN_STATUS(ret);
		if (status != RMI_SUCCESS) {
			/* Accept a concurrent successful backfill of PAR_D. */
			if (status != RMI_ERROR_GPT ||
			    rmi_query_gpt_par(donor, l0gpt_sz, &donor_state) ||
			    donor_state != RMI_GPT_PAR_HOST_CREATED) {
				pr_err("GPT Level1 backfill failed for %pa: 0x%lx\n",
				       &donor, status);
				return -ENXIO;
			}
		}
	} else if (donor_state != RMI_GPT_PAR_HOST_CREATED) {
		return -EPROTO;
	}

	ret = rmi_gpt_l1_create(target, sro);
	if (ret < 0)
		return ret;
	status = RMI_RETURN_STATUS(ret);
	if (status == RMI_SUCCESS)
		return 0;

	/* A racing caller may have completed PAR_T before the retry. */
	if (status == RMI_ERROR_GPT &&
	    !rmi_query_gpt_par(target, l0gpt_sz, &target_state) &&
	    target_state == RMI_GPT_PAR_HOST_CREATED)
		return 0;

fail_target:
	pr_err("GPT Level1 create failed for %pa: 0x%lx\n", &target, status);
	return -ENXIO;
}

/*
 * Create self-describing L1 GPTs for every physical address region represented
 * by the SRO address list before that memory is used as L1 GPT backing. Creating
 * an L1 GPT can consume, split, or reorder the cached descriptors, so restart
 * the walk after every successful creation. Cache the last completed target to
 * avoid repeated GPT_INFO calls for descriptors in the same L0 region.
 */
static int rmi_create_self_describing_gpt(struct rmi_sro_state *sro)
{
	static phys_addr_t cached_target = PHYS_ADDR_MAX;
	unsigned long l0gpt_sz = rmi_l0gpt_size();
	unsigned long l1_pages = PFN_UP(rmi_l1gpt_size());
	unsigned long i = 0;

	while (i < sro->addr_count) {
		unsigned long entry = sro->addr_list[i];
		unsigned long block_size;
		unsigned long range_size;
		unsigned long count;
		unsigned long state;
		phys_addr_t phys, end;
		phys_addr_t target;
		int ret;

		block_size = RMI_ADDR_BSIZE_BYTES(RMI_ADDR_RANGE_SIZE(entry));
		count = RMI_ADDR_RANGE_COUNT(entry);
		phys = RMI_ADDR_RANGE_ADDR(entry);
		if (!count || check_mul_overflow(block_size, count, &range_size))
			return -EPROTO;
		end = phys + range_size;

		target = ALIGN_DOWN(phys, l0gpt_sz);
		end = ALIGN(end, l0gpt_sz);
		while (target < end) {
			if (target == cached_target) {
				target += l0gpt_sz;
				continue;
			}

			ret = rmi_query_gpt_par(target, l0gpt_sz, &state);
			if (ret)
				return ret;

			if (state == RMI_GPT_PAR_HOST_CREATED) {
				cached_target = target;
				target += l0gpt_sz;
				continue;
			}
			if (state != RMI_GPT_PAR_HOST_NOT_CREATED)
				return -EPROTO;

			ret = rmi_create_gpt_l1(target, l0gpt_sz, l1_pages, sro);
			if (ret)
				return ret;

			cached_target = target;
			/* rmi_create_gpt_l1() may have changed the entire list. */
			i = 0;
			break;
		}

		if (target >= end)
			i++;
	}

	return 0;
}

static int rmi_init_metadata(struct rmi_sro_state *sro)
{
	unsigned long l0gpt_sz = rmi_l0gpt_size();
	unsigned long l1_pages = PFN_UP(rmi_l1gpt_size());
	unsigned long created_l1 = 0;
	unsigned long existing_l1 = 0;
	unsigned long non_host_l0 = 0;
	struct memblock_region *r;
	phys_addr_t last_end = 0;
	phys_addr_t start, end;
	int last_nid = NUMA_NO_NODE;
	int ret;

	/*
	 * Query the Beta3 GPT PAR state and create an L1 GPT only
	 * for host-allocated L0 blocks which do not already have one. Each
	 * GPT_L1_CREATE donates its own (SRO-decided) granule count, carved from a
	 * hot list which persists across each NUMA-node run. @last_end dedups L0
	 * blocks shared with or overlapped by an earlier region. Leave
	 * platform-owned blocks and existing host L1 GPTs untouched.
	 *
	 * DEN0137 v2.0-bet3 A2.3.9.1 requires L1 GPT creation to work before
	 * Granule tracking is configured, so do not inspect tracking state until
	 * every required host L1 GPT has been created.
	 */
	/* Discard activation leftovers before the NUMA-aware GPT sweep. */
	rmi_sro_free(sro);
	last_end = 0;
	for_each_mem_region(r) {
		phys_addr_t state_top;
		unsigned long state;
		int nid;

		if (memblock_is_nomap(r))
			continue;

		start = ALIGN_DOWN(PFN_PHYS(memblock_region_memory_base_pfn(r)),
				   l0gpt_sz);
		end = ALIGN(PFN_PHYS(memblock_region_memory_end_pfn(r)),
			    l0gpt_sz);

		if (start < last_end)
			start = last_end;
		if (start >= end)
			continue;
		last_end = end;

		state_top = start;
		nid = memblock_get_region_node(r);
		if (memblock_is_hotpluggable(r) || !numa_valid_node(nid))
			nid = NUMA_NO_NODE;

		do {
			if (start == state_top) {
				unsigned long nr_l0;

				ret = rmi_query_gpt_info(start, end, &state_top,
							 &state);
				if (ret)
					return ret;

				nr_l0 = (state_top - start) / l0gpt_sz;
				switch (state) {
				case RMI_GPT_PAR_RESERVED:
				case RMI_GPT_PAR_PLAT:
					non_host_l0 += nr_l0;
					start = state_top;
					continue;
				case RMI_GPT_PAR_HOST_CREATED:
					existing_l1 += nr_l0;
					start = state_top;
					continue;
				case RMI_GPT_PAR_HOST_NOT_CREATED:
					break;
				default:
					return -EPROTO;
				}

				/*
				 * Keep L1 GPT backing local to fixed memory. For
				 * hotpluggable memory, use the allocator's default
				 * node. Drop cached memory before changing nodes.
				 */
				if (nid != last_nid) {
					rmi_sro_free(sro);
					last_nid = nid;
				}
			}

			/* Keep two L1 GPT chunks for Beta3 backfill. */
			rmi_sro_topup_node(sro, MAX_ORDER_NR_PAGES,
					    2 * l1_pages, nid);

			ret = rmi_create_self_describing_gpt(sro);
			if (ret)
				return ret;

			ret = rmi_query_gpt_par(start, l0gpt_sz, &state);
			if (ret)
				return ret;
			if (state == RMI_GPT_PAR_HOST_NOT_CREATED) {
				ret = rmi_create_gpt_l1(start, l0gpt_sz,
							l1_pages, sro);
				if (ret)
					return ret;
			} else if (state != RMI_GPT_PAR_HOST_CREATED) {
				return -EPROTO;
			}
			created_l1++;
			start += l0gpt_sz;
		} while (start < end);
	}

	/*
	 * The current host implementation supports Realm memory only in
	 * fine-grained conventional tracking regions. Verify that prerequisite
	 * after GPT creation, since Beta3 explicitly makes the two management
	 * mechanisms independent. Skip PARs managed by the platform.
	 */
	last_end = 0;
	for_each_mem_region(r) {
		if (memblock_is_nomap(r))
			continue;

		start = ALIGN_DOWN(PFN_PHYS(memblock_region_memory_base_pfn(r)),
				   l0gpt_sz);
		end = ALIGN(PFN_PHYS(memblock_region_memory_end_pfn(r)),
			    l0gpt_sz);

		if (start < last_end)
			start = last_end;
		if (start >= end)
			continue;
		last_end = end;

		while (start < end) {
			phys_addr_t state_top;
			unsigned long state;

			ret = rmi_query_gpt_info(start, end, &state_top, &state);
			if (ret)
				return ret;

			if (state == RMI_GPT_PAR_HOST_NOT_CREATED ||
			    state == RMI_GPT_PAR_HOST_CREATED) {
				ret = rmi_init_memory_tracking(start, state_top,
						RMI_MEM_CATEGORY_CONVENTIONAL,
						sro);
				if (ret)
					return ret;
			}
			start = state_top;
		}
	}

	pr_info("RMI: GPT PARs created=%lu existing=%lu non-host=%lu\n",
		created_l1, existing_l1, non_host_l0);

	return 0;
}

static int rmi_init_device_gpt(struct rmi_sro_state *sro,
			       phys_addr_t start, phys_addr_t end)
{
	unsigned long l0gpt_sz = rmi_l0gpt_size();
	unsigned long l1_pages = PFN_UP(rmi_l1gpt_size());

	while (start < end) {
		unsigned long state;
		int ret;

		ret = rmi_query_gpt_par(start, l0gpt_sz, &state);
		if (ret)
			return ret;

		switch (state) {
		case RMI_GPT_PAR_RESERVED:
		case RMI_GPT_PAR_PLAT:
		case RMI_GPT_PAR_HOST_CREATED:
			start += l0gpt_sz;
			continue;
		case RMI_GPT_PAR_HOST_NOT_CREATED:
			break;
		default:
			return -EPROTO;
		}

		rmi_sro_topup_node(sro, MAX_ORDER_NR_PAGES, 2 * l1_pages,
				   NUMA_NO_NODE);

		ret = rmi_create_self_describing_gpt(sro);
		if (ret)
			return ret;

		ret = rmi_query_gpt_par(start, l0gpt_sz, &state);
		if (ret)
			return ret;
		if (state == RMI_GPT_PAR_HOST_NOT_CREATED) {
			ret = rmi_create_gpt_l1(start, l0gpt_sz, l1_pages, sro);
			if (ret)
				return ret;
		} else if (state != RMI_GPT_PAR_HOST_CREATED) {
			return -EPROTO;
		}
		start += l0gpt_sz;
	}

	return 0;
}

int rmi_init_device_tracking(phys_addr_t phys, unsigned long size)
{
	phys_addr_t start = ALIGN_DOWN(phys, RMM_GRANULE_TRACKING_SIZE);
	phys_addr_t end = ALIGN(phys + size, RMM_GRANULE_TRACKING_SIZE);
	int ret;

	mutex_lock(&rmi_sro_lock);
	ret = rmi_init_memory_tracking(start, end, RMI_TRACK_CATEGORY_ANY,
				       rmi_sro);
	rmi_sro_free(rmi_sro);
	mutex_unlock(&rmi_sro_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(rmi_init_device_tracking);

int rmi_init_device_gpt_range(phys_addr_t phys, unsigned long size)
{
	unsigned long l0gpt_sz = rmi_l0gpt_size();
	phys_addr_t start = ALIGN_DOWN(phys, l0gpt_sz);
	phys_addr_t end = ALIGN(phys + size, l0gpt_sz);
	int ret;

	mutex_lock(&rmi_sro_lock);
	ret = rmi_init_device_gpt(rmi_sro, start, end);
	rmi_sro_free(rmi_sro);
	mutex_unlock(&rmi_sro_lock);

	return ret;
}

/*
 * DEN0137 v2.0-bet3 allows VDEV and VSMMU object creation and destruction
 * to initiate a Stateful RMI Operation, so drive them through the SRO engine.
 */
static int rmi_sro_command(struct arm_smccc_1_2_regs regs,
			   unsigned long *rmi_ret)
{
	struct rmi_sro_state *sro __free(kfree) = kzalloc_obj(*sro);
	long ret;

	if (!sro)
		return -ENOMEM;

	sro->regs = regs;
	ret = rmi_sro_execute(sro, GFP_KERNEL, NULL);
	rmi_sro_free(sro);
	if (ret < 0)
		return ret;

	*rmi_ret = ret;
	return 0;
}

int rmi_vdev_create(unsigned long rd_phys, unsigned long pdev_phys,
		    unsigned long vdev_phys, unsigned long params_phys,
		    unsigned long *rmi_ret)
{
	return rmi_sro_command((struct arm_smccc_1_2_regs) {
			SMC_RMI_VDEV_CREATE, rd_phys, pdev_phys, vdev_phys,
			params_phys
		}, rmi_ret);
}
EXPORT_SYMBOL_GPL(rmi_vdev_create);

int rmi_vdev_destroy(unsigned long rd_phys, unsigned long pdev_phys,
		     unsigned long vdev_phys, unsigned long *rmi_ret)
{
	return rmi_sro_command((struct arm_smccc_1_2_regs) {
			SMC_RMI_VDEV_DESTROY, rd_phys, pdev_phys, vdev_phys
		}, rmi_ret);
}
EXPORT_SYMBOL_GPL(rmi_vdev_destroy);

int rmi_vsmmu_create(unsigned long rd_phys, unsigned long vsmmu_phys,
		     unsigned long params_phys, unsigned long *rmi_ret)
{
	return rmi_sro_command((struct arm_smccc_1_2_regs) {
			SMC_RMI_VSMMU_CREATE, rd_phys, vsmmu_phys, params_phys
		}, rmi_ret);
}
EXPORT_SYMBOL_GPL(rmi_vsmmu_create);

int rmi_vsmmu_destroy(unsigned long rd_phys, unsigned long vsmmu_phys,
		      unsigned long *rmi_ret)
{
	return rmi_sro_command((struct arm_smccc_1_2_regs) {
			SMC_RMI_VSMMU_DESTROY, rd_phys, vsmmu_phys
		}, rmi_ret);
}
EXPORT_SYMBOL_GPL(rmi_vsmmu_destroy);

int rmi_rtt_arch_dev_map(unsigned long rd_phys, unsigned long dev_phys,
			 unsigned long base, unsigned long top,
			 unsigned long *out_top, unsigned long *rmi_ret)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_RTT_ARCH_DEV_MAP, rd_phys, dev_phys, base, top
	};
	long ret;

	ret = rmi_sro_execute_no_xfer(&regs);
	if (ret < 0)
		return ret;

	*rmi_ret = ret;
	if (RMI_RETURN_STATUS(ret) == RMI_SUCCESS)
		*out_top = regs.a1;

	return 0;
}
EXPORT_SYMBOL_GPL(rmi_rtt_arch_dev_map);

int rmi_rtt_arch_dev_unmap(unsigned long rd_phys, unsigned long dev_phys,
			   unsigned long base, unsigned long top,
			   unsigned long *out_top, unsigned long *rmi_ret)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_RTT_ARCH_DEV_UNMAP, rd_phys, dev_phys, base, top
	};
	long ret;

	ret = rmi_sro_execute_no_xfer(&regs);
	if (ret < 0)
		return ret;

	*rmi_ret = ret;
	if (RMI_RETURN_STATUS(ret) == RMI_SUCCESS)
		*out_top = regs.a1;

	return 0;
}
EXPORT_SYMBOL_GPL(rmi_rtt_arch_dev_unmap);

bool is_rmi_available(void)
{
	return arm64_rmi_is_available;
}

/*
 * Destroy non-self-describing L1 GPTs first, reclaiming their backing memory
 * from the PARs which describe it. A second pass then destroys those
 * self-describing L1 GPTs after their dependent backing has been reclaimed.
 */
static void rmi_destroy_metadata(struct rmi_sro_state *sro)
{
	unsigned long slot = RMI_SMC_SLOT_IDX(SMC_RMI_GPT_L1_CREATE);
	unsigned long l0gpt_sz = rmi_l0gpt_size();

	for (unsigned int pass = 0; pass < 2; pass++) {
		for (;;) {
			MA_STATE(mas, &rmi_mt, 0, 0);
			phys_addr_t anchor = 0;
			bool found = false;
			void *entry;

			rcu_read_lock();
			mas_for_each(&mas, entry, ULONG_MAX) {
				unsigned long mark = xa_to_value(entry);
				bool self_desc;

				if (FIELD_GET(RMI_MT_TRACKID_MASK, mark) !=
				    RMI_TRACKID_GLOBAL)
					continue;
				if (FIELD_GET(RMI_MT_SLOT_MASK, mark) != slot)
					continue;

				anchor = mark & RMI_MT_IPA_MASK;
				self_desc = (ALIGN_DOWN(mas.index, l0gpt_sz) &
					     RMI_MT_IPA_MASK) == anchor;
				if ((pass == 0) == self_desc)
					continue;

				found = true;
				break;
			}
			rcu_read_unlock();

			if (!found)
				break;

			if (RMI_RETURN_STATUS(rmi_gpt_l1_destroy(anchor, sro)) !=
			    RMI_SUCCESS) {
				pr_warn("RMI: GPT L1 destroy failed for %pa\n",
					&anchor);
				break;
			}
		}
	}
}

static void rmi_destroy_dpt(struct rmi_sro_state *sro)
{
	struct memblock_region *r;
	phys_addr_t last_end = 0;

	if (!rmm_has_reg2_feature(RMI_FEATURE_REGISTER_2_ATS))
		return;

	for_each_mem_region(r) {
		phys_addr_t start, end;

		if (memblock_is_nomap(r))
			continue;

		start = ALIGN_DOWN(PFN_PHYS(memblock_region_memory_base_pfn(r)),
				   RMI_DPT_L0_REGION_SIZE);
		end = ALIGN(PFN_PHYS(memblock_region_memory_end_pfn(r)),
			    RMI_DPT_L0_REGION_SIZE);
		if (start < last_end)
			start = last_end;
		if (start >= end)
			continue;
		last_end = end;

		while (start < end) {
			if (RMI_RETURN_STATUS(rmi_dpt_l1_destroy(start, sro)) !=
			    RMI_SUCCESS) {
				pr_warn("RMI: DPT Level 1 destroy failed for %pa\n",
					&start);
				return;
			}
			start += RMI_DPT_L0_REGION_SIZE;
		}
	}

	if (RMI_RETURN_STATUS(rmi_dpt_l0_destroy(sro)) != RMI_SUCCESS)
		pr_warn("RMI: DPT Level 0 destroy failed\n");
}

static void rmi_destroy_tracking(struct rmi_sro_state *sro)
{
	unsigned int s2sz = FIELD_GET(RMI_FEATURE_REGISTER_0_S2SZ,
				      rmi_feat_reg(0));
	phys_addr_t pasz;

	if (!s2sz || s2sz >= BITS_PER_LONG)
		return;

	pasz = 1UL << s2sz;
	rmi_teardown_memory_tracking(0, pasz, sro);
}

/*
 * On the way into a kexec, fold away the L1 GPTs the RMM can release. This runs
 * in the reboot notifier chain (process context, before machine_shutdown()),
 * where the GPT_L1_DESTROY SRO is safe to call.
 *
 * Only act on a kexec (kexec_in_progress is set by kernel_kexec() just before
 * the reboot chain runs). A normal reboot/poweroff resets the firmware and
 * reinitialises the RMM, so explicit deactivation is unnecessary.
 */
static int rmi_reboot_notify(struct notifier_block *nb, unsigned long action,
			     void *data)
{
	if (kexec_in_progress && rmi_sro) {
		u64 remaining_bytes;
		long ret;

		mutex_lock(&rmi_sro_lock);
		rmi_destroy_dpt(rmi_sro);
		rmi_sro_free(rmi_sro);
		rmi_destroy_metadata(rmi_sro);
		rmi_sro_free(rmi_sro);
		rmi_destroy_tracking(rmi_sro);
		rmi_sro_free(rmi_sro);
		ret = rmi_rmm_deactivate(rmi_sro);
		remaining_bytes = rmi_region_owned_bytes(rmi_sro);
		mutex_unlock(&rmi_sro_lock);

		if (ret)
			pr_err("RMI: RMM deactivate failed: 0x%lx\n", ret);
		if (READ_ONCE(rmi_sro_donate_tracking_failed))
			pr_err("RMI: metadata ownership tracking is incomplete\n");
		if (remaining_bytes)
			pr_err("RMI: %llu KiB of metadata was not reclaimed\n",
			       remaining_bytes >> 10);
		else if (!ret)
			pr_info("RMI: RMM deactivated; all metadata reclaimed\n");

		/*
		 * A reboot notifier cannot veto the restart, so if any RMM-owned
		 * memory remains we must not let kexec proceed: the next kernel
		 * has no handoff for these reservations and would treat the
		 * still-owned granules as free RAM, corrupting live RMM state.
		 * Halt loudly instead of booting into a known-inconsistent map.
		 */
		if (ret || remaining_bytes ||
		    READ_ONCE(rmi_sro_donate_tracking_failed))
			panic("RMI: RMM memory still owned, unsafe to kexec\n");
	}
	return NOTIFY_DONE;
}

static struct notifier_block rmi_reboot_nb = {
	.notifier_call = rmi_reboot_notify,
};

static int __init arm64_init_rmi(void)
{
	u64 remaining_bytes;
	long deactivate_ret;
	int ret;

	/*
	 * A kdump/crash kernel runs inside the reserved crashkernel region and
	 * must not reconfigure the RMM or rebuild the GPTs: that state belongs
	 * to the crashed production kernel and is needed to capture the dump.
	 * Skip RMI/CCA bring-up entirely.
	 */
	if (is_kdump_kernel())
		return 0;

	/* Continue without realm support if we can't agree on a version */
	if (rmi_check_version())
		return 0;

	ret = rmi_read_features();
	if (ret)
		return 0;

	rmi_sro = kzalloc_obj(*rmi_sro, GFP_KERNEL);
	if (!rmi_sro)
		return -ENOMEM;

	/* Start tracking global SRO donations before activating the RMM. */
	register_reboot_notifier(&rmi_reboot_nb);

	/* Configure and activate the RMM, then build the GPT L1 tables. */
	ret = rmi_configure(rmi_sro);
	if (ret)
		goto out_free_sro;
	ret = rmi_init_metadata(rmi_sro);
	if (ret)
		goto out_undo_meta;

	ret = rmi_init_dpt(rmi_sro);
	if (ret)
		goto out_undo_dpt;

	arm64_rmi_is_available = true;
	pr_info("RMI configured\n");

	/*
	 * Drop the boot hot list (undelegate + free any leftover delegated
	 * granules) but keep the SRO struct allocated; the reboot notifier
	 * reuses it to tear down the L1 GPTs on a subsequent kexec.
	 */
	rmi_sro_free(rmi_sro);
	return 0;

out_undo_dpt:
	rmi_destroy_dpt(rmi_sro);
	rmi_sro_free(rmi_sro);
out_undo_meta:
	/*
	 * Beta3 permits L1 GPT destruction before tracking is configured. Undo
	 * any partial GPT setup, then return the RMM to INIT and reclaim every
	 * activation donation. Keep the notifier and tracking state only if the
	 * firmware fails to return all memory, so a later kexec can retry.
	 */
	rmi_destroy_metadata(rmi_sro);
	rmi_sro_free(rmi_sro);
	rmi_destroy_tracking(rmi_sro);
	rmi_sro_free(rmi_sro);
	deactivate_ret = rmi_rmm_deactivate(rmi_sro);
	remaining_bytes = rmi_region_owned_bytes(rmi_sro);
	if (deactivate_ret)
		pr_err("RMI: setup rollback deactivate failed: 0x%lx\n",
		       deactivate_ret);
	if (remaining_bytes)
		pr_err("RMI: setup rollback left %llu KiB owned by RMM\n",
		       remaining_bytes >> 10);
	if (deactivate_ret || remaining_bytes)
		goto out_free_sro;

	unregister_reboot_notifier(&rmi_reboot_nb);
	rmi_sro_free(rmi_sro);
	kfree(rmi_sro);
	rmi_sro = NULL;
	return 0;

out_free_sro:
	/* Keep ownership tracking alive if setup consumed RMM metadata. */
	rmi_sro_free(rmi_sro);
	return 0;
}
subsys_initcall(arm64_init_rmi);

/* Per-FID RMI SMC diagnostic counters exposed through debugfs. */
#define RMI_SMC_SLOT(_name)						\
	[RMI_SMC_SLOT_IDX(SMC_RMI_##_name)] = {				\
		.fid  = SMC_RMI_##_name,				\
		.name = #_name,						\
	}

struct rmi_smc_slot rmi_smc_slots[256] = {
	RMI_SMC_SLOT(VERSION),
	RMI_SMC_SLOT(FEATURES),
	RMI_SMC_SLOT(RMM_CONFIG_GET),
	RMI_SMC_SLOT(RMM_CONFIG_SET),
	RMI_SMC_SLOT(RMM_ACTIVATE),
	RMI_SMC_SLOT(RMM_DEACTIVATE),
	RMI_SMC_SLOT(RMM_STATE_GET),
	RMI_SMC_SLOT(GRANULE_TRACKING_GET),
	RMI_SMC_SLOT(GRANULE_TRACKING_SET),
	RMI_SMC_SLOT(GRANULE_RANGE_DELEGATE),
	RMI_SMC_SLOT(GRANULE_RANGE_UNDELEGATE),
	RMI_SMC_SLOT(GPT_INFO),
	RMI_SMC_SLOT(GPT_L1_CREATE),
	RMI_SMC_SLOT(GPT_L1_DESTROY),
	RMI_SMC_SLOT(REALM_ACTIVATE),
	RMI_SMC_SLOT(REALM_CREATE),
	RMI_SMC_SLOT(REALM_DESTROY),
	RMI_SMC_SLOT(REALM_TERMINATE),
	RMI_SMC_SLOT(REC_CREATE),
	RMI_SMC_SLOT(REC_DESTROY),
	RMI_SMC_SLOT(REC_ENTER),
	RMI_SMC_SLOT(RTT_CREATE),
	RMI_SMC_SLOT(RTT_DESTROY),
	RMI_SMC_SLOT(RTT_FOLD),
	RMI_SMC_SLOT(RTT_INIT_RIPAS),
	RMI_SMC_SLOT(RTT_SET_RIPAS),
	RMI_SMC_SLOT(RTT_READ_ENTRY),
	RMI_SMC_SLOT(RTT_SET_S2AP),
	RMI_SMC_SLOT(RTT_DATA_MAP_INIT),
	RMI_SMC_SLOT(RTT_DATA_MAP),
	RMI_SMC_SLOT(RTT_DATA_UNMAP),
	RMI_SMC_SLOT(RTT_UNPROT_MAP),
	RMI_SMC_SLOT(RTT_UNPROT_UNMAP),
	RMI_SMC_SLOT(RTT_AUX_CREATE),
	RMI_SMC_SLOT(RTT_AUX_DESTROY),
	RMI_SMC_SLOT(RTT_AUX_FOLD),
	RMI_SMC_SLOT(RTT_AUX_PROT_MAP),
	RMI_SMC_SLOT(RTT_AUX_PROT_UNMAP),
	RMI_SMC_SLOT(RTT_AUX_UNPROT_MAP),
	RMI_SMC_SLOT(RTT_AUX_UNPROT_UNMAP),
	RMI_SMC_SLOT(RTT_DEV_VALIDATE),
	RMI_SMC_SLOT(RTT_DEV_MAP),
	RMI_SMC_SLOT(RTT_DEV_UNMAP),
	RMI_SMC_SLOT(RTT_ARCH_DEV_MAP),
	RMI_SMC_SLOT(RTT_ARCH_DEV_UNMAP),
	RMI_SMC_SLOT(PSCI_COMPLETE),
	RMI_SMC_SLOT(OP_CONTINUE),
	RMI_SMC_SLOT(OP_CANCEL),
	RMI_SMC_SLOT(OP_MEM_DONATE),
	RMI_SMC_SLOT(OP_MEM_RECLAIM),
	RMI_SMC_SLOT(VSMMU_CREATE),
	RMI_SMC_SLOT(VSMMU_DESTROY),
	RMI_SMC_SLOT(VSMMU_FEATURES),
	RMI_SMC_SLOT(VSMMU_CMD_GET),
	RMI_SMC_SLOT(VSMMU_CMD_COMPLETE),
	RMI_SMC_SLOT(VSMMU_EVENT_HANDLE),
	RMI_SMC_SLOT(PSMMU_INFO),
	RMI_SMC_SLOT(PSMMU_IRQ_NOTIFY),
	RMI_SMC_SLOT(PSMMU_ACTIVATE),
	RMI_SMC_SLOT(PSMMU_DEACTIVATE),
	RMI_SMC_SLOT(PSMMU_ST_L2_CREATE),
	RMI_SMC_SLOT(PSMMU_ST_L2_DESTROY),
	RMI_SMC_SLOT(PSMMU_EVENT_CONSUME),
	RMI_SMC_SLOT(DPT_L0_CREATE),
	RMI_SMC_SLOT(DPT_L0_DESTROY),
	RMI_SMC_SLOT(DPT_L1_CREATE),
	RMI_SMC_SLOT(DPT_L1_DESTROY),
	RMI_SMC_SLOT(PDEV_ABORT),
	RMI_SMC_SLOT(PDEV_COMMUNICATE),
	RMI_SMC_SLOT(PDEV_CREATE),
	RMI_SMC_SLOT(PDEV_DESTROY),
	RMI_SMC_SLOT(PDEV_GET_STATE),
	RMI_SMC_SLOT(PDEV_STREAM_KEY_REFRESH),
	RMI_SMC_SLOT(PDEV_SET_PUBKEY),
	RMI_SMC_SLOT(PDEV_STOP),
	RMI_SMC_SLOT(PDEV_STREAM_CONNECT),
	RMI_SMC_SLOT(PDEV_STREAM_DISCONNECT),
	RMI_SMC_SLOT(PDEV_STREAM_COMPLETE),
	RMI_SMC_SLOT(PDEV_STREAM_KEY_PURGE),
	RMI_SMC_SLOT(PDEV_STREAM_INFO),
	RMI_SMC_SLOT(VDEV_ABORT),
	RMI_SMC_SLOT(VDEV_COMMUNICATE),
	RMI_SMC_SLOT(VDEV_CREATE),
	RMI_SMC_SLOT(VDEV_DESTROY),
	RMI_SMC_SLOT(VDEV_GET_STATE),
	RMI_SMC_SLOT(VDEV_UNLOCK),
	RMI_SMC_SLOT(VDEV_GET_INTERFACE_REPORT),
	RMI_SMC_SLOT(VDEV_GET_MEASUREMENTS),
	RMI_SMC_SLOT(VDEV_LOCK),
	RMI_SMC_SLOT(VDEV_START),
};

#undef RMI_SMC_SLOT

static int rmi_smc_slot_cmp_desc(const void *a, const void *b)
{
	const struct rmi_smc_slot *sa = a;
	const struct rmi_smc_slot *sb = b;
	long ca = atomic64_read(&sa->count[0]);
	long cb = atomic64_read(&sb->count[0]);

	if (ca > cb)
		return -1;
	if (ca < cb)
		return 1;
	return 0;
}

static int rmi_smc_counters_show(struct seq_file *m, void *v)
{
	struct rmi_smc_slot *snap;
	long total = 0, total_busy = 0;
	size_t i;

	snap = kmalloc_array(ARRAY_SIZE(rmi_smc_slots), sizeof(*snap),
			     GFP_KERNEL);
	if (!snap)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(rmi_smc_slots); i++) {
		snap[i].fid = rmi_smc_slots[i].fid;
		snap[i].name = rmi_smc_slots[i].name;
		atomic64_set(&snap[i].count[0],
			     atomic64_read(&rmi_smc_slots[i].count[0]));
		atomic64_set(&snap[i].count[1],
			     atomic64_read(&rmi_smc_slots[i].count[1]));
	}

	sort(snap, ARRAY_SIZE(rmi_smc_slots), sizeof(*snap),
	     rmi_smc_slot_cmp_desc, NULL);

	seq_printf(m, "%-10s  %-32s  %12s  %12s\n",
		   "FID", "NAME", "COUNT", "BUSY");
	for (i = 0; i < ARRAY_SIZE(rmi_smc_slots); i++) {
		long count = atomic64_read(&snap[i].count[0]);
		long busy = atomic64_read(&snap[i].count[1]);

		if (!count || !snap[i].fid)
			continue;
		seq_printf(m, "0x%08lx  %-32s  %12ld  %12ld\n",
			   snap[i].fid, snap[i].name, count, busy);
		total += count;
		total_busy += busy;
	}
	seq_printf(m, "%-10s  %-32s  %12ld  %12ld\n",
		   "", "TOTAL", total, total_busy);

	kfree(snap);
	return 0;
}

static int rmi_smc_counters_open(struct inode *inode, struct file *file)
{
	return single_open(file, rmi_smc_counters_show, NULL);
}

static ssize_t rmi_smc_counters_write(struct file *file,
				      const char __user *ubuf,
				      size_t len, loff_t *ppos)
{
	for (size_t i = 0; i < ARRAY_SIZE(rmi_smc_slots); i++) {
		atomic64_set(&rmi_smc_slots[i].count[0], 0);
		atomic64_set(&rmi_smc_slots[i].count[1], 0);
	}
	return len;
}

static const struct file_operations rmi_smc_counters_fops = {
	.owner		= THIS_MODULE,
	.open		= rmi_smc_counters_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= rmi_smc_counters_write,
};

#define RMI_MT_FILTER_TRACKID_MASK	GENMASK(14, 0)
#define RMI_MT_FILTER_TRACKID_VALID	BIT(15)
#define RMI_MT_FILTER_SLOT_MASK		GENMASK(23, 16)
#define RMI_MT_FILTER_SLOT_VALID		BIT(24)

/* Zero selects all Track IDs and RMI commands. */
static u32 rmi_mt_filter;

static bool rmi_mt_filter_match(unsigned long mark, u32 filter)
{
	if ((filter & RMI_MT_FILTER_TRACKID_VALID) &&
	    FIELD_GET(RMI_MT_TRACKID_MASK, mark) !=
	    FIELD_GET(RMI_MT_FILTER_TRACKID_MASK, filter))
		return false;

	if ((filter & RMI_MT_FILTER_SLOT_VALID) &&
	    FIELD_GET(RMI_MT_SLOT_MASK, mark) !=
	    FIELD_GET(RMI_MT_FILTER_SLOT_MASK, filter))
		return false;

	return true;
}

static int rmi_mt_show(struct seq_file *m, void *v)
{
	MA_STATE(mas, &rmi_mt, 0, 0);
	phys_addr_t run_base, run_end, run_limit;
	unsigned long run_mark, mark;
	unsigned long entry_index = 0;
	unsigned long range_count = 0;
	u64 total_pages = 0;
	u32 filter = READ_ONCE(rmi_mt_filter);
	void *entry;

	seq_printf(m, "%-16s  %-7s  %-14s  %-14s  %6s  %s\n",
		   "IDX+COUNT", "TRACKID", "PHYS", "IPA", "PAGES", "RMI_CMD");

	/* Coalesce matching adjacent entries without crossing PMD boundaries. */
	rcu_read_lock();
	entry = mas_find(&mas, ULONG_MAX);
	while (entry) {
		unsigned long first_index, run_entries;
		unsigned long slot;
		const char *name;
		char index[48];
		u16 trackid;
		u64 run_ipa;
		u64 pages;

		mark = xa_to_value(entry);
		trackid = FIELD_GET(RMI_MT_TRACKID_MASK, mark);
		if (!rmi_mt_filter_match(mark, filter)) {
			entry = mas_find(&mas, ULONG_MAX);
			continue;
		}

		run_base = mas.index;
		run_end = mas.last + 1;
		run_limit = ALIGN(run_base + 1, PMD_SIZE);
		run_mark = mark;
		run_ipa = run_mark & RMI_MT_IPA_MASK;
		first_index = ++entry_index;
		run_entries = 1;

		while ((entry = mas_find(&mas, ULONG_MAX)) != NULL) {
			u64 next_ipa;

			mark = xa_to_value(entry);
			if (!rmi_mt_filter_match(mark, filter))
				break;

			next_ipa = mark & RMI_MT_IPA_MASK;
			if (mas.index != run_end || mas.last >= run_limit ||
			    (mark & (RMI_MT_TRACKID_MASK | RMI_MT_SLOT_MASK)) !=
			    (run_mark &
			     (RMI_MT_TRACKID_MASK | RMI_MT_SLOT_MASK)) ||
			    ((run_ipa || next_ipa) &&
			     next_ipa != run_ipa + (run_end - run_base)))
				break;

			run_end = mas.last + 1;
			entry_index++;
			run_entries++;
		}

		scnprintf(index, sizeof(index), "0x%lx+%lu",
			  first_index, run_entries);
		pages = (run_end - run_base) >> PAGE_SHIFT;
		range_count++;
		total_pages += pages;
		slot = FIELD_GET(RMI_MT_SLOT_MASK, run_mark);
		name = rmi_smc_slots[slot].name;
		seq_printf(m,
			   "%-16s  0x%04x   0x%012llx  0x%012llx  %6llu  %s\n",
			   index, trackid, (u64)run_base, run_ipa, pages,
			   name ?: "UNKNOWN");
	}
	rcu_read_unlock();

	seq_printf(m, "\nTOTAL %lu ranges, %llu pages\n",
		   range_count, total_pages);
	return 0;
}

static int rmi_mt_open(struct inode *inode, struct file *file)
{
	return single_open(file, rmi_mt_show, NULL);
}

static int rmi_mt_slot_from_name(const char *name)
{
	for (unsigned int slot = 0; slot < ARRAY_SIZE(rmi_smc_slots); slot++) {
		if (rmi_smc_slots[slot].name &&
		    !strcmp(name, rmi_smc_slots[slot].name))
			return slot;
	}

	return -EINVAL;
}

/* Accept "<trackid>", "<RMI_CMD>", or "<trackid> <RMI_CMD>". */
static ssize_t rmi_mt_write(struct file *file, const char __user *ubuf,
			    size_t len, loff_t *ppos)
{
	char **argv __free(argv_free) = NULL;
	char buf[64], *command = NULL;
	u32 filter = 0;
	int trackid = -1;
	int slot = -1;
	int argc;
	int ret;

	if (!len)
		return -EINVAL;
	if (len >= sizeof(buf))
		return -E2BIG;
	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = '\0';

	argv = argv_split(GFP_KERNEL, buf, &argc);
	if (!argv)
		return -ENOMEM;
	if (argc < 1 || argc > 2)
		return -EINVAL;

	ret = kstrtoint(argv[0], 0, &trackid);
	if (!ret) {
		if (trackid < -1 || trackid > RMI_TRACKID_MAX)
			return -ERANGE;
		command = argc == 2 ? argv[1] : NULL;
	} else {
		if (argc != 1)
			return -EINVAL;
		command = argv[0];
	}

	if (command) {
		slot = rmi_mt_slot_from_name(command);
		if (slot < 0)
			return slot;
	}

	if (trackid >= 0)
		filter |= RMI_MT_FILTER_TRACKID_VALID |
			  FIELD_PREP(RMI_MT_FILTER_TRACKID_MASK, trackid);
	if (slot >= 0)
		filter |= RMI_MT_FILTER_SLOT_VALID |
			  FIELD_PREP(RMI_MT_FILTER_SLOT_MASK, slot);

	WRITE_ONCE(rmi_mt_filter, filter);
	return len;
}

static const struct file_operations rmi_mt_fops = {
	.owner		= THIS_MODULE,
	.open		= rmi_mt_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= rmi_mt_write,
};

static int __init rmi_debugfs_init(void)
{
	if (!is_rmi_available())
		return 0;

	debugfs_create_file("rmi_mt", 0600, NULL, NULL, &rmi_mt_fops);
	debugfs_create_file("rmi_smc_counters", 0600, NULL, NULL,
			    &rmi_smc_counters_fops);
	return 0;
}
late_initcall(rmi_debugfs_init);
