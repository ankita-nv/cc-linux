// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2026 ARM Ltd.
 */

#include <linux/arm-rmi-cmds.h>
#include <linux/cpufeature.h>
#include <linux/memblock.h>
#include <linux/processor.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <asm/memory.h>
#include <asm/pgtable-hwdef.h>

static bool arm64_rmi_is_available;

/* DEN0137 v2.0-bet3 defines feature registers 0 through 4. */
#define RMI_FEAT_REG_COUNT	5
static __ro_after_init unsigned long rmi_feat_reg_cache[RMI_FEAT_REG_COUNT];

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
		unsigned long out_top;

		ret = rmi_granule_range_delegate(phys, top, &out_top);
		if (ret != RMI_SUCCESS)
			return ret;

		if (WARN_ONCE(out_top <= phys || out_top > top,
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
EXPORT_SYMBOL_GPL(rmi_delegate_range);

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
		unsigned long out_top;

		ret = rmi_granule_range_undelegate(phys, top, &out_top);
		if (ret != RMI_SUCCESS)
			return ret;

		if (WARN_ONCE(out_top <= phys || out_top > top,
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
EXPORT_SYMBOL_GPL(rmi_undelegate_range);

int free_delegated_page(phys_addr_t phys)
{
	if (WARN_ON(rmi_undelegate_page(phys))) {
		/* Undelegate failed: leak the page */
		return -EBUSY;
	}

	free_page((unsigned long)phys_to_virt(phys));

	return 0;
}
EXPORT_SYMBOL_GPL(free_delegated_page);

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

static bool rmi_op_mem_needs_delegation(unsigned long flags)
{
	return RMI_OP_MEM_FLAGS_STATE(flags) != RMI_OP_MEM_UNDELEGATED;
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
	do {
		arm_smccc_1_2_invoke(&regs, regs_out);
		status = RMI_RETURN_STATUS(regs_out->a0);
		if (status == RMI_BUSY)
			cpu_relax();
	} while (status == RMI_BUSY);
}

static void rmi_sro_free_entry(unsigned long entry, unsigned long flags)
{
	unsigned long addr = RMI_ADDR_RANGE_ADDR(entry);
	unsigned long bsize = RMI_OP_MEM_FLAGS_BSIZE(flags);
	unsigned long count = RMI_ADDR_RANGE_COUNT(entry);
	unsigned long size = RMI_ADDR_BSIZE_BYTES(bsize) * count;
	long ret;

	if (rmi_op_mem_needs_delegation(flags)) {
		unsigned long undelegated_size = 0;

		ret = rmi_undelegate_range(addr, size, &undelegated_size);
		if (WARN_ONCE(ret != RMI_SUCCESS,
			      "RMI: failed SRO entry undelegate: %ld\n", ret)) {
			/* Leak the still-delegated tail. */
			if (undelegated_size)
				free_pages_exact(phys_to_virt(addr),
						 undelegated_size);
			return;
		}
	}
	free_pages_exact(phys_to_virt(addr), size);
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
		rmi_sro_free_entry(sro->addr_list[sro->addr_count],
				   sro->addr_flags[sro->addr_count]);
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
				      unsigned long flags)
{
	unsigned long undelegated_size = 0;
	unsigned long off;
	long ret;

	if (rmi_op_mem_needs_delegation(flags)) {
		ret = rmi_undelegate_range(phys, size, &undelegated_size);
		if (WARN_ONCE(ret != RMI_SUCCESS,
			      "RMI: failed donated tail undelegate: %ld\n", ret)) {
			for (off = 0; off < undelegated_size; off += PAGE_SIZE)
				__free_page(phys_to_page(phys + off));
			return;
		}
	}

	for (off = 0; off < size; off += PAGE_SIZE)
		__free_page(phys_to_page(phys + off));
}

static unsigned long rmi_sro_cache_entry_flags(unsigned long flags,
					       phys_addr_t phys,
					       unsigned long count)
{
	unsigned long entry_flags;
	unsigned long block_size;

	entry_flags = flags & ~RMI_OP_MEM_FLAGS_CONTIG_MASK;
	block_size = RMI_ADDR_BSIZE_BYTES(RMI_OP_MEM_FLAGS_BSIZE(entry_flags));
	if (!block_size)
		return entry_flags;

	if (is_power_of_2(count) && IS_ALIGNED(phys, block_size * count))
		entry_flags |= RMI_OP_MEM_FLAGS_CONTIG_MASK;

	return entry_flags;
}

static bool rmi_sro_cache_entry_matches(unsigned long entry_flags,
					unsigned long flags)
{
	unsigned long mask = ~RMI_OP_MEM_FLAGS_CONTIG_MASK;

	return (entry_flags & mask) == (flags & mask);
}

/*
 * Preserve a host-owned tail left behind after a partial donation. The original
 * descriptor now covers memory with mixed ownership, so cache the remainder as
 * PAGE-sized descriptors and free only the part that does not fit.
 */
static void rmi_sro_cache_donated_tail(struct rmi_sro_state *sro,
				       phys_addr_t phys, unsigned long size,
				       unsigned long flags)
{
	unsigned long max_count = FIELD_MAX(RMI_ADDR_RANGE_COUNT_MASK);
	unsigned long nr_pages = size >> PAGE_SHIFT;
	unsigned long tail_flags;

	tail_flags = flags & ~RMI_OP_MEM_FLAGS_BSIZE_MASK;
	tail_flags |= FIELD_PREP(RMI_OP_MEM_FLAGS_BSIZE_MASK,
				 RMI_ADDR_RANGE_SIZE_PAGE);

	while (nr_pages && (sro->addr_count < RMI_MAX_ADDR_LIST)) {
		unsigned long count = min(nr_pages, max_count);

		sro->addr_list[sro->addr_count] =
			RMI_ADDR_RANGE_DESC(phys, count);
		sro->addr_flags[sro->addr_count] =
			rmi_sro_cache_entry_flags(tail_flags, phys, count);
		sro->addr_count++;

		phys += count << PAGE_SHIFT;
		nr_pages -= count;
	}

	if (nr_pages)
		rmi_sro_free_donated_tail(phys, nr_pages << PAGE_SHIFT, flags);
}

static int rmi_sro_donate_contig(struct rmi_sro_state *sro,
				 unsigned long sro_handle,
				 unsigned long donatereq,
				 struct arm_smccc_1_2_regs *out_regs,
				 gfp_t gfp)
{
	unsigned long flags = RMI_DONATE_FLAGS(donatereq);
	unsigned long block_count = RMI_DONATE_COUNT(donatereq);
	unsigned long size;
	unsigned long addr_range;
	unsigned long donated_granules;
	unsigned long donated_size;
	unsigned long delegated_size = 0;
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

	size = RMI_ADDR_BSIZE_BYTES(RMI_DONATE_BSIZE(donatereq)) * block_count;

	for (int i = 0; i < sro->addr_count; i++) {
		unsigned long entry = sro->addr_list[i];

		/*
		 * Contiguous donation requires the base address to be
		 * aligned to the total donation size per DEN0137 v2.0-bet3.
		 * The fresh-alloc path below honours this via
		 * alloc_pages_exact(size), but cached entries may have come
		 * from RMI_OP_MEM_RECLAIM and the RMM is free to return them at
		 * any alignment. Reusing a misaligned entry would trip
		 * RMI_ERROR_INPUT and tear down the SRO context, so skip such
		 * entries and fall through to a fresh
		 * allocation instead.
		 */
		if (sro->addr_flags[i] == flags &&
		    RMI_ADDR_RANGE_COUNT(entry) == block_count &&
		    IS_ALIGNED(RMI_ADDR_RANGE_ADDR(entry), size)) {
			sro->addr_count--;
			swap(sro->addr_list[sro->addr_count],
			     sro->addr_list[i]);
			swap(sro->addr_flags[sro->addr_count],
			     sro->addr_flags[i]);

			goto out;
		}
	}

	ret = rmi_sro_ensure_capacity(sro, 1);
	if (ret)
		return ret;

	virt = alloc_pages_exact(size, gfp);
	if (!virt)
		return -ENOMEM;
	phys = virt_to_phys(virt);

	if (rmi_op_mem_needs_delegation(flags)) {
		if (rmi_delegate_range(phys, size, &delegated_size)) {
			rmi_free_failed_delegation(virt, size, delegated_size);
			return -ENXIO;
		}
	}

	addr_range = RMI_ADDR_RANGE_DESC(phys, block_count);
	sro->addr_list[sro->addr_count] = addr_range;
	sro->addr_flags[sro->addr_count] = flags;

out:
	regs.a2 = virt_to_phys(&sro->addr_list[sro->addr_count]);
	regs.a3 = 1;
	regs.a4 = flags;
	rmi_smccc_invoke(&regs, out_regs);

	donated_granules = out_regs->a1;
	donated_size = donated_granules << PAGE_SHIFT;

	if (donated_granules == 0) {
		/* No pages used by the RMM */
		sro->addr_count++;
	} else if (donated_size < size) {
		/* Not all granules used by the RMM. */
		phys = RMI_ADDR_RANGE_ADDR(sro->addr_list[sro->addr_count]);
		rmi_sro_cache_donated_tail(sro, phys + donated_size,
					   size - donated_size, flags);
	}

	return 0;
}

static int rmi_sro_donate_noncontig(struct rmi_sro_state *sro,
				    unsigned long sro_handle,
				    unsigned long donatereq,
				    struct arm_smccc_1_2_regs *out_regs,
				    gfp_t gfp)
{
	unsigned long flags = RMI_DONATE_FLAGS(donatereq);
	unsigned long block_size =
		RMI_ADDR_BSIZE_BYTES(RMI_DONATE_BSIZE(donatereq));
	unsigned long block_count = RMI_DONATE_COUNT(donatereq);
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

	/*
	 * Reuse cached ranges with matching block size and state. The cached
	 * CONTIG bit is only a local descriptor property, so ignore it here:
	 * X4 carries the non-contiguous requirement for this donation.
	 */
	for (unsigned long i = 0; i < addr_list_start && blocks < block_count; ) {
		unsigned long entry = sro->addr_list[i];
		unsigned long entry_flags = sro->addr_flags[i];
		unsigned long entry_count = RMI_ADDR_RANGE_COUNT(entry);
		unsigned long remaining = block_count - blocks;
		phys_addr_t phys = RMI_ADDR_RANGE_ADDR(entry);

		/*
		 * A non-contiguous donation can use any region whose base is
		 * aligned to the requested block size, but the region must still
		 * match the requested block size and memory state.
		 */
		if (!entry_count ||
		    !rmi_sro_cache_entry_matches(entry_flags, flags) ||
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
			swap(sro->addr_flags[addr_list_start],
			     sro->addr_flags[i]);
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
				RMI_ADDR_RANGE_DESC(phys, remaining);
			sro->addr_flags[sro->addr_count] =
				rmi_sro_cache_entry_flags(entry_flags, phys,
							  remaining);
			sro->addr_count++;

			phys += remaining * block_size;
			entry_count -= remaining;
			sro->addr_list[i] =
				RMI_ADDR_RANGE_DESC(phys, entry_count);
			sro->addr_flags[i] =
				rmi_sro_cache_entry_flags(entry_flags, phys,
							  entry_count);

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
	 * one-block ranges. These entries already match the requested flags,
	 * so they can be appended directly to the donation suffix.
	 */
	while (blocks < donate_blocks) {
		unsigned long delegated_size = 0;
		unsigned long addr_range;
		void *virt = alloc_pages_exact(block_size, gfp);
		phys_addr_t phys;

		if (!virt) {
			if (blocks)
				break;
			return -ENOMEM;
		}

		phys = virt_to_phys(virt);

		if (rmi_op_mem_needs_delegation(flags)) {
			if (rmi_delegate_range(phys, block_size,
					       &delegated_size)) {
				rmi_free_failed_delegation(virt, block_size,
							   delegated_size);
				if (blocks)
					break;
				return -ENXIO;
			}
		}

		addr_range = RMI_ADDR_RANGE_DESC(phys, 1);
		sro->addr_list[sro->addr_count++] = addr_range;
		sro->addr_flags[sro->addr_count - 1] = flags;
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
	regs.a4 = flags;
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
		unsigned long entry_flags = sro->addr_flags[addr_list_start + i];
		unsigned long entry_count = RMI_ADDR_RANGE_COUNT(entry);
		phys_addr_t phys = RMI_ADDR_RANGE_ADDR(entry);

		if (consumed_blocks >= entry_count) {
			consumed_blocks -= entry_count;
			continue;
		}

		if (consumed_blocks) {
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

			rmi_sro_free_donated_tail(phys + donated_size,
						  block_size - donated_size,
						  entry_flags);
			phys += block_size;
			entry_count--;
			partial_granules = 0;
		}

		if (!entry_count)
			continue;

		sro->addr_list[cache_pos] =
			RMI_ADDR_RANGE_DESC(phys, entry_count);
		sro->addr_flags[cache_pos] =
			rmi_sro_cache_entry_flags(entry_flags, phys, entry_count);
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

	if (WARN_ONCE(!block_count, "RMI: zero donation count: %d\n",
		      -EPROTO))
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

	for (unsigned long i = 0; i < out_regs->a1; i++)
		sro->addr_flags[sro->addr_count + i] =
			out_regs->a2 & RMI_OP_MEM_FLAGS_MASK;

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
	for (int i = 0; i < sro->addr_count; i++) {
		unsigned long entry = sro->addr_list[i];
		unsigned long flags = sro->addr_flags[i];

		rmi_sro_free_entry(entry, flags);
	}

	sro->addr_count = 0;
}
EXPORT_SYMBOL_GPL(rmi_sro_free);

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

static unsigned long __rmi_sro_execute(struct rmi_sro_state *sro,
				       gfp_t gfp,
				       struct arm_smccc_1_2_regs *out_regs)
{
	unsigned long sro_handle;
	struct arm_smccc_1_2_regs regs;
	struct arm_smccc_1_2_regs *regs_in = &sro->regs;
	int host_error = 0;

	/* Memory-transferring SROs may wait for host memory. */
	might_sleep();

	rmi_smccc_invoke(regs_in, &regs);

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

	return host_error ? host_error : regs.a0;
}

unsigned long rmi_sro_execute(struct rmi_sro_state *sro, gfp_t gfp)
{
	return __rmi_sro_execute(sro, gfp, NULL);
}
EXPORT_SYMBOL_GPL(rmi_sro_execute);

unsigned long rmi_sro_execute_cmd(struct rmi_sro_state *sro,
				  const struct arm_smccc_1_2_regs *regs,
				  gfp_t gfp,
				  struct arm_smccc_1_2_regs *out_regs)
{
	unsigned long ret;

	*sro = (struct rmi_sro_state){ .regs = *regs };
	ret = __rmi_sro_execute(sro, gfp, out_regs);
	rmi_sro_free(sro);

	return ret;
}
EXPORT_SYMBOL_GPL(rmi_sro_execute_cmd);

unsigned long rmi_sro_execute_cmd_alloc(const struct arm_smccc_1_2_regs *regs,
					gfp_t gfp,
					struct arm_smccc_1_2_regs *out_regs)
{
	unsigned long ret;
	struct rmi_sro_state *sro;

	sro = kmalloc_obj(*sro, gfp);
	if (!sro)
		return -ENOMEM;

	ret = rmi_sro_execute_cmd(sro, regs, gfp, out_regs);
	kfree(sro);
	return ret;
}
EXPORT_SYMBOL_GPL(rmi_sro_execute_cmd_alloc);

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

unsigned long rmi_sro_execute_no_xfer(struct arm_smccc_1_2_regs *regs)
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
EXPORT_SYMBOL_GPL(rmi_sro_execute_no_xfer);

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

	arm_smccc_1_1_invoke(SMC_RMI_VERSION, host_version, &res);

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

static int rmi_read_features(void)
{
	/* Negotiating a compatible version makes these registers mandatory. */
	for (int i = 0; i < RMI_FEAT_REG_COUNT; i++) {
		if (WARN_ON(rmi_features(i, &rmi_feat_reg_cache[i])))
			return -EINVAL;
	}

	return 0;
}

static int rmi_configure(void)
{
	unsigned long granule_feature;
	unsigned long granule_size;
	struct rmm_config *config;
	struct rmi_sro_state *sro;
	long rmi_ret;
	int ret = 0;

	config = (struct rmm_config *)get_zeroed_page(GFP_KERNEL);
	if (!config)
		return -ENOMEM;

	sro = kmalloc_obj(*sro, GFP_KERNEL);
	if (!sro) {
		ret = -ENOMEM;
		goto out_free_config;
	}

	switch (PAGE_SIZE) {
	case SZ_4K:
		granule_size = RMI_GRANULE_SIZE_4KB;
		granule_feature = RMI_FEATURE_REGISTER_1_RMI_GRAN_SZ_4KB;
		break;
	case SZ_16K:
		granule_size = RMI_GRANULE_SIZE_16KB;
		granule_feature = RMI_FEATURE_REGISTER_1_RMI_GRAN_SZ_16KB;
		break;
	case SZ_64K:
		granule_size = RMI_GRANULE_SIZE_64KB;
		granule_feature = RMI_FEATURE_REGISTER_1_RMI_GRAN_SZ_64KB;
		break;
	default:
		BUILD_BUG();
	}

	if (!(rmi_feat_reg(1) & granule_feature)) {
		pr_err("RMM does not support %luKB granules\n", PAGE_SIZE >> 10);
		ret = -ENXIO;
		goto out_free_sro;
	}

	config->rmi_granule_size = granule_size;
	config->tracking_region_size = 0;

	rmi_ret = rmi_rmm_config_set(virt_to_phys(config));
	if (rmi_ret) {
		pr_err("RMM config set failed\n");
		ret = -EINVAL;
		goto out_free_sro;
	}

	rmi_ret = rmi_rmm_activate(sro);
	if (rmi_ret) {
		pr_err("RMM activate failed\n");
		ret = rmi_ret < 0 ? rmi_ret : -ENXIO;
	}

out_free_sro:
	kfree(sro);
out_free_config:
	free_page((unsigned long)config);
	return ret;
}

/*
 * Make sure the area is tracked by RMM at FINE granularity.
 * We do not support changing the tracking yet.
 */
static int rmi_verify_memory_tracking(phys_addr_t start, phys_addr_t end)
{
	while (start < end) {
		unsigned long ret, category, state, next;

		ret = rmi_granule_tracking_get(start, end, &category, &state, &next);
		if (ret != RMI_SUCCESS ||
		    state != RMI_TRACKING_FINE ||
		    category != RMI_MEM_CATEGORY_CONVENTIONAL) {
			/* TODO: Set granule tracking in this case */
			pr_err("Granule tracking for region isn't fine/conventional: %llx",
			       start);
			return -ENODEV;
		}
		start = next;
	}

	return 0;
}

static unsigned long rmi_l0gpt_size(void)
{
	return 1UL << (30 + FIELD_GET(RMI_FEATURE_REGISTER_1_L0GPTSZ,
				      rmi_feat_reg(1)));
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

static int rmi_verify_host_memory_tracking(phys_addr_t start, phys_addr_t end)
{
	unsigned long l0gpt_sz = rmi_l0gpt_size();

	start = ALIGN_DOWN(start, l0gpt_sz);
	end = ALIGN(end, l0gpt_sz);

	while (start < end) {
		phys_addr_t state_top;
		unsigned long state;
		int ret;

		ret = rmi_query_gpt_info(start, end, &state_top, &state);
		if (ret)
			return ret;

		if (state == RMI_GPT_PAR_HOST_NOT_CREATED ||
		    state == RMI_GPT_PAR_HOST_CREATED) {
			ret = rmi_verify_memory_tracking(start, state_top);
			if (ret)
				return ret;
		}

		start = state_top;
	}

	return 0;
}

static int rmi_create_gpts(phys_addr_t start, phys_addr_t end)
{
	struct rmi_sro_state *sro;
	unsigned long l0gpt_sz = rmi_l0gpt_size();
	int ret = 0;

	sro = kmalloc_obj(*sro, GFP_KERNEL);
	if (!sro)
		return -ENOMEM;

	start = ALIGN_DOWN(start, l0gpt_sz);
	end = ALIGN(end, l0gpt_sz);

	while (start < end) {
		phys_addr_t state_top;
		unsigned long state;

		ret = rmi_query_gpt_info(start, end, &state_top, &state);
		if (ret)
			break;

		switch (state) {
		case RMI_GPT_PAR_RESERVED:
		case RMI_GPT_PAR_PLAT:
		case RMI_GPT_PAR_HOST_CREATED:
			start = state_top;
			continue;
		case RMI_GPT_PAR_HOST_NOT_CREATED:
			break;
		default:
			ret = -EPROTO;
			goto out;
		}

		while (start < state_top) {
			long rmi_ret;

			rmi_ret = rmi_gpt_l1_create(start, sro, GFP_KERNEL);
			if (rmi_ret < 0) {
				ret = rmi_ret;
				goto out;
			}
			if (RMI_RETURN_STATUS(rmi_ret) != RMI_SUCCESS) {
				pr_err("RMI: GPT L1 create failed for %pa: 0x%lx\n",
				       &start, rmi_ret);
				ret = -ENXIO;
				goto out;
			}
			start += l0gpt_sz;
		}
	}

out:
	kfree(sro);
	return ret;
}

static int rmi_init_metadata(void)
{
	phys_addr_t start, end;
	const struct memblock_region *r;

	/*
	 * DEN0137 v2.0-bet3 requires L1 GPT creation to be independent of
	 * Granule tracking. Create every required host L1 GPT before checking
	 * that host memory uses fine-grained conventional tracking.
	 */
	for_each_mem_region(r) {
		int ret;

		/* Firmware-reserved NOMAP regions are not usable system RAM. */
		if (memblock_is_nomap(r))
			continue;

		start = memblock_region_memory_base_pfn(r) << PAGE_SHIFT;
		end = memblock_region_memory_end_pfn(r) << PAGE_SHIFT;
		ret = rmi_create_gpts(start, end);
		if (ret)
			return ret;
	}

	/*
	 * The current host implementation supports Realm memory only in
	 * fine-grained conventional tracking regions. Validate that prerequisite
	 * only after all required GPTs have been created.
	 */
	for_each_mem_region(r) {
		int ret;

		if (memblock_is_nomap(r))
			continue;

		start = memblock_region_memory_base_pfn(r) << PAGE_SHIFT;
		end = memblock_region_memory_end_pfn(r) << PAGE_SHIFT;
		ret = rmi_verify_host_memory_tracking(start, end);
		if (ret)
			return ret;
	}

	return 0;
}

bool is_rmi_available(void)
{
	return arm64_rmi_is_available;
}

static int __init arm64_init_rmi(void)
{
	int ret;

	/* Continue without realm support if we can't agree on a version */
	ret = rmi_check_version();
	if (ret)
		return ret;

	ret = rmi_read_features();
	if (ret)
		return ret;

	ret = rmi_configure();
	if (ret)
		return ret;

	ret = rmi_init_metadata();
	if (ret)
		return ret;

	arm64_rmi_is_available = true;
	pr_info("RMI configured\n");

	return 0;
}
subsys_initcall(arm64_init_rmi);
