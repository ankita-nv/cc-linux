// SPDX-License-Identifier: GPL-2.0-only
/*
 * Debug helper used to dump the stage-2 pagetables of the system and their
 * associated permissions.
 *
 * Copyright (C) Google, 2024
 * Author: Sebastian Ene <sebastianene@google.com>
 */
#include <linux/debugfs.h>
#include <linux/kvm_host.h>
#include <linux/seq_file.h>
#include <linux/sizes.h>

#include <asm/cpufeature.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/pgtable.h>
#include <asm/pgtable-hwdef.h>
#include <asm/ptdump.h>
#include <asm/rmi_cmds.h>

#define MARKERS_LEN		2
#define KVM_PGTABLE_MAX_LEVELS	(KVM_PGTABLE_LAST_LEVEL + 1)
#define S2FNAMESZ		sizeof("0x0123456789abcdef-0x0123456789abcdef-s2-disabled")

/*
 * Bound the Realm stage-2 dump's mmu_lock read-side hold: drop and re-acquire
 * the lock (and reschedule) after this many RMI_RTT_READ_ENTRY calls. Bounding
 * by read count rather than IPA span keeps the hold uniform regardless of how
 * densely the window is mapped (a 4K-mapped 2MB table is 512 reads).
 */
#define KVM_REALM_PTDUMP_READS_PER_LOCK	1024

/*
 * single_open() seeds a one-page seq buffer and, on overflow, frees it,
 * doubles the size and re-invokes ->show() from scratch. For a Realm that
 * re-runs the whole RMI walk, repeating thousands of RMI_RTT_READ_ENTRY SMCs
 * per retry. Pre-size the buffer so a typical dump completes in a single pass;
 * a larger dump still falls back to the grow-and-retry path (correct, slower).
 */
#define KVM_REALM_PTDUMP_BUF_SIZE	SZ_2M

/*
 * Descriptors per RTT (table) granule = granule size / 8-byte descriptor:
 * 512 at 4K, 2048 at 16K, 8192 at 64K. Bounds the entries of any single table
 * (so a leaf run within one table never exceeds this) and the fan-out per
 * level; used to size the concatenated root.
 */
#define KVM_REALM_PTRS_PER_RTT		(1UL << (PAGE_SHIFT - 3))

struct kvm_ptdump_guest_state {
	struct kvm_s2_mmu	*mmu;
	struct ptdump_pg_state	parser_state;
	struct addr_marker	ipa_marker[MARKERS_LEN];
	struct ptdump_pg_level	level[KVM_PGTABLE_MAX_LEVELS];
};

static const struct ptdump_prot_bits stage2_pte_bits[] = {
	{
		.mask	= PTE_VALID,
		.val	= PTE_VALID,
		.set	= " ",
		.clear	= "F",
	},
	{
		.mask	= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R,
		.val	= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R,
		.set	= "R",
		.clear	= " ",
	},
	{
		.mask	= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W,
		.val	= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W,
		.set	= "W",
		.clear	= " ",
	},
	{
		.mask	= KVM_PTE_LEAF_ATTR_HI_S2_XN,
		.val	= 0b00UL << __bf_shf(KVM_PTE_LEAF_ATTR_HI_S2_XN),
		.set	= "px ux ",
	},
	{
		.mask	= KVM_PTE_LEAF_ATTR_HI_S2_XN,
		.val	= 0b01UL << __bf_shf(KVM_PTE_LEAF_ATTR_HI_S2_XN),
		.set	= "PXNux ",
	},
	{
		.mask	= KVM_PTE_LEAF_ATTR_HI_S2_XN,
		.val	= 0b10UL << __bf_shf(KVM_PTE_LEAF_ATTR_HI_S2_XN),
		.set	= "PXNUXN",
	},
	{
		.mask	= KVM_PTE_LEAF_ATTR_HI_S2_XN,
		.val	= 0b11UL << __bf_shf(KVM_PTE_LEAF_ATTR_HI_S2_XN),
		.set	= "px UXN",
	},
	{
		.mask	= KVM_PTE_LEAF_ATTR_LO_S2_AF,
		.val	= KVM_PTE_LEAF_ATTR_LO_S2_AF,
		.set	= "AF",
		.clear	= "  ",
	},
	{
		.mask	= PMD_TYPE_MASK,
		.val	= PMD_TYPE_SECT,
		.set	= "BLK",
		.clear	= "   ",
	},
};

static int kvm_ptdump_visitor(const struct kvm_pgtable_visit_ctx *ctx,
			      enum kvm_pgtable_walk_flags visit)
{
	struct ptdump_pg_state *st = ctx->arg;
	struct ptdump_state *pt_st = &st->ptdump;

	note_page(pt_st, ctx->addr, ctx->level, ctx->old);

	return 0;
}

static int kvm_ptdump_build_levels(struct ptdump_pg_level *level, u32 start_lvl)
{
	u32 i;
	u64 mask;

	if (WARN_ON_ONCE(start_lvl >= KVM_PGTABLE_LAST_LEVEL))
		return -EINVAL;

	mask = 0;
	for (i = 0; i < ARRAY_SIZE(stage2_pte_bits); i++)
		mask |= stage2_pte_bits[i].mask;

	for (i = start_lvl; i < KVM_PGTABLE_MAX_LEVELS; i++) {
		snprintf(level[i].name, sizeof(level[i].name), "%u", i);

		level[i].num	= ARRAY_SIZE(stage2_pte_bits);
		level[i].bits	= stage2_pte_bits;
		level[i].mask	= mask;
	}

	return 0;
}

static struct kvm_ptdump_guest_state *kvm_ptdump_parser_create(struct kvm_s2_mmu *mmu)
{
	struct kvm_ptdump_guest_state *st;
	struct kvm_pgtable *pgtable = mmu->pgt;
	int ret;

	st = kzalloc_obj(struct kvm_ptdump_guest_state, GFP_KERNEL_ACCOUNT);
	if (!st)
		return ERR_PTR(-ENOMEM);

	ret = kvm_ptdump_build_levels(&st->level[0], pgtable->start_level);
	if (ret) {
		kfree(st);
		return ERR_PTR(ret);
	}

	st->ipa_marker[0].name		= "Guest IPA";
	st->ipa_marker[1].start_address = ULONG_MAX;

	st->mmu				= mmu;
	return st;
}

static unsigned long kvm_realm_rtt_mapsize(int level)
{
	if (WARN_ON(level > KVM_PGTABLE_LAST_LEVEL))
		return PAGE_SIZE;

	return 1UL << ARM64_HW_PGTABLE_LEVEL_SHIFT(level);
}

static const char *rmi_ripas_str(int ripas)
{
	switch (ripas) {
	case RMI_EMPTY:		return "empty";
	case RMI_RAM:		return "ram";
	case RMI_DESTROYED:	return "destroyed";
	case RMI_DEV:		return "dev";
	default:		return "?";
	}
}

static const char *rmi_rtte_state_str(int state)
{
	switch (state) {
	case RMI_UNASSIGNED:		return "unassigned";
	case RMI_ASSIGNED:		return "assigned";
	case RMI_TABLE:			return "table";
	case RMI_ASSIGNED_DEV:		return "assigned-dev";
	case RMI_AUX_DESTROYED:		return "aux-destroyed";
	case RMI_ASSIGNED_VSMMU:	return "assigned-vsmmu";
	default:			return "?";
	}
}

/*
 * At a terminal entry, DATA, NARCH_DEV and ARCH_DEV carry a PA. DEN0137
 * v2.0-bet3 only defines RIPAS for VOID and DATA; AUX_DESTROYED has neither.
 */
static bool rmi_rtte_state_is_mapping(int state)
{
	return state == RMI_ASSIGNED || state == RMI_ASSIGNED_DEV ||
	       state == RMI_ASSIGNED_VSMMU;
}

static bool rmi_rtte_state_has_ripas(int state)
{
	return state == RMI_UNASSIGNED || state == RMI_ASSIGNED;
}

static void kvm_realm_fmt_size(char *buf, size_t len, unsigned long sz)
{
	if (sz >> 30)
		snprintf(buf, len, "%luG", sz >> 30);
	else if (sz >> 20)
		snprintf(buf, len, "%luM", sz >> 20);
	else
		snprintf(buf, len, "%luK", sz >> 10);
}

/*
 * Format a run's extent (size * count) using the coarsest binary unit it is
 * exactly aligned to (T/G/M/K) - so a full table reads "2M"/"1G" while a
 * partial run keeps its precise K/M value.
 */
static void kvm_realm_fmt_extent(char *buf, size_t len, unsigned long size,
				 unsigned long count)
{
	unsigned long ext = size * count;

	if (IS_ALIGNED(ext, SZ_1T))
		snprintf(buf, len, "%luT", ext >> 40);
	else if (IS_ALIGNED(ext, SZ_1G))
		snprintf(buf, len, "%luG", ext >> 30);
	else if (IS_ALIGNED(ext, SZ_1M))
		snprintf(buf, len, "%luM", ext >> 20);
	else
		snprintf(buf, len, "%luK", ext >> 10);
}

/* Sum a per-leaf-level byte array. */
static unsigned long kvm_realm_sum(const unsigned long *bytes, int start_level)
{
	unsigned long total = 0;
	int l;

	for (l = start_level; l <= KVM_PGTABLE_LAST_LEVEL; l++)
		total += bytes[l];

	return total;
}

/*
 * Print "<n> x 4K + <n> x 2M + ..." for the per-level byte array, deriving the
 * leaf count at each level as bytes / mapping-size (smallest size first).
 */
static void kvm_realm_print_counts(struct seq_file *s,
				   const unsigned long *bytes, int start_level)
{
	char buf[8];
	bool first = true;
	int l;

	for (l = KVM_PGTABLE_LAST_LEVEL; l >= start_level; l--) {
		unsigned long n = bytes[l] / kvm_realm_rtt_mapsize(l);

		if (n == 0UL)
			continue;
		kvm_realm_fmt_size(buf, sizeof(buf), kvm_realm_rtt_mapsize(l));
		seq_printf(s, "%s%lu x %s", first ? "" : " + ", n, buf);
		first = false;
	}
	if (first)
		seq_puts(s, "none");
}

/*
 * A run of consecutive leaf entries sharing the same attributes. PA-backed
 * entries are only merged while their PA is physically contiguous (a constant
 * +/- size stride, ascending or descending); a discontiguity ends the run, so
 * scattered entries are emitted exactly, one row each, with their own PA.
 * @tbl[l] holds the RTT granule referenced by the level-l walk-path entry
 * (i.e. the next-level, L(l+1), table), emitted as the "L<l+1>" columns; a run
 * never spans a table so these are constant across it.
 */
struct realm_pt_run {
	bool		active;
	bool		shared;
	int		level;
	int		state;
	int		ripas;
	unsigned long	ipa;
	unsigned long	size;
	unsigned long	count;
	phys_addr_t	pa_first;
	phys_addr_t	pa_last;
	phys_addr_t	tbl[KVM_PGTABLE_MAX_LEVELS];
	s64		pa_step;
};

/* Running totals for the trailing summary. */
struct realm_pt_stats {
	unsigned long	tbl[KVM_PGTABLE_MAX_LEVELS];		/* L(l+1) tables */
	/* [shared?][level] DATA/MAPPED_NS bytes, per leaf level */
	unsigned long	assigned[2][KVM_PGTABLE_MAX_LEVELS];
	/* protected bytes with an architecturally reported RIPAS */
	unsigned long	ripas[RMI_DEV + 1];
	unsigned long	reads;					/* RMI_RTT reads */
};

/*
 * Trailing summary: how much memory the Realm has.
 *   Private/Shared: assigned (backed) byte total + per-size count breakdown
 *   Ripas:          protected VOID/DATA bytes per reported RIPAS state
 */
static void kvm_realm_print_summary(struct seq_file *s,
				    const struct realm_pt_stats *stats,
				    int start_level)
{
	unsigned long p_asg = kvm_realm_sum(stats->assigned[0], start_level);
	unsigned long s_asg = kvm_realm_sum(stats->assigned[1], start_level);
	bool first = true;
	int i;

	seq_printf(s, "\nPrivate:   assigned 0x%lx Bytes (", p_asg);
	kvm_realm_print_counts(s, stats->assigned[0], start_level);
	seq_puts(s, ")\n");

	seq_printf(s, "Shared:    assigned 0x%lx Bytes (", s_asg);
	kvm_realm_print_counts(s, stats->assigned[1], start_level);
	seq_puts(s, ")\n");

	seq_puts(s, "Ripas:    ");
	for (i = RMI_EMPTY; i <= RMI_DEV; i++) {
		if (!stats->ripas[i])
			continue;
		seq_printf(s, "%s %s 0x%lx Bytes", first ? "" : ",",
			   rmi_ripas_str(i), stats->ripas[i]);
		first = false;
	}
	seq_puts(s, first ? " none\n" : "\n");
}

static void realm_pt_flush(struct seq_file *s, struct realm_pt_run *r,
			   int ia_digits, int pa_digits, int start_level)
{
	char szbuf[8], extbuf[8], pabuf[40], ipabuf[20];
	bool has_ripas, is_mapping;
	int l;

	if (!r->active)
		return;

	has_ripas = !r->shared && rmi_rtte_state_has_ripas(r->state);
	is_mapping = rmi_rtte_state_is_mapping(r->state);

	kvm_realm_fmt_size(szbuf, sizeof(szbuf), r->size);
	kvm_realm_fmt_extent(extbuf, sizeof(extbuf), r->size, r->count);

	if (!is_mapping)
		strscpy(pabuf, "-", sizeof(pabuf));
	else
		snprintf(pabuf, sizeof(pabuf), "0x%0*llx", pa_digits,
			 (u64)r->pa_first);

	snprintf(ipabuf, sizeof(ipabuf), "0x%0*lx", ia_digits, r->ipa);

	seq_printf(s, "%-*s %-*s %-8s %4s %6lu %7s  %-14s %-9s",
		   ia_digits + 2, ipabuf, pa_digits + 2, pabuf,
		   r->shared ? "shared" : "private", szbuf, r->count, extbuf,
		   rmi_rtte_state_str(r->state),
		   has_ripas ? rmi_ripas_str(r->ripas) : "-");

	/*
	 * RTT granule referenced at each level on the walk path; only levels
	 * the Realm actually uses (start_level .. leaf) get a column.
	 */
	for (l = start_level; l < KVM_PGTABLE_LAST_LEVEL; l++) {
		char tb[20];

		if (l < r->level)
			snprintf(tb, sizeof(tb), "0x%0*llx", pa_digits,
				 (u64)r->tbl[l]);
		else
			strscpy(tb, "-", sizeof(tb));
		seq_printf(s, " %-*s", pa_digits + 2, tb);
	}
	seq_putc(s, '\n');

	r->active = false;
}

/*
 * Dump a Realm's stage-2 by walking it over RMI. KVM cannot read the RTTs
 * directly, so for each IPA we query the deepest reachable entry with
 * RMI_RTT_READ_ENTRY at KVM_PGTABLE_LAST_LEVEL: the RMM reports the level its
 * walk stopped at (walk_level), the RTTE state, the descriptor and - for
 * protected IPAs - the RIPAS. Advancing by the block size at walk_level visits
 * each leaf once and skips unmapped regions in a single call.
 *
 * Each output row is a leaf (or block); the next-level RTT granule referenced
 * by each walk-path entry is appended as the "L<l+1>" columns (re-read per
 * level and memoised), so a block at level l shows "-" there (no deeper RTT).
 * The root RTT granule is the stage-2 base (mmu->pgd_phys), shown in the header.
 *
 * Consecutive leaf entries with identical attributes are coalesced into a
 * single range (see struct realm_pt_run) to keep the output - and the seq_file
 * buffer - small; an attribute change or crossing into a new table flushes the
 * run (so the L<n> columns stay constant across a run).
 *
 * Both IPA halves are covered: protected [0, 2^(ia_bits-1)) and unprotected/
 * shared [2^(ia_bits-1), 2^ia_bits). Assigned leaves and any protected range
 * with a non-EMPTY RIPAS (e.g. RAM reserved but not yet backed, or DESTROYED),
 * and AUX_DESTROYED entries are printed; unmapped EMPTY space is skipped.
 * Realm page contents are not host-accessible by design.
 *
 * The dump takes the read side of mmu_lock because it does not modify RTT
 * state. Other read-side fault handlers may update mappings concurrently, so
 * this is a best-effort view. Drop and re-acquire the lock every
 * KVM_REALM_PTDUMP_READS_PER_LOCK RMI reads to bound writer latency and provide
 * a reschedule point. The run and table memo persist across the gap so
 * coalescing and each table's single print are unaffected.
 */
static int kvm_realm_stage2_ptdump(struct kvm *kvm, struct seq_file *s)
{
	struct kvm_s2_mmu *mmu = &kvm->arch.mmu;
	struct realm *realm = &kvm->arch.realm;
	unsigned long tbl_base[KVM_PGTABLE_MAX_LEVELS];
	phys_addr_t tbl_gran[KVM_PGTABLE_MAX_LEVELS] = { };
	struct realm_pt_stats stats = { };
	struct realm_pt_run run = { };
	unsigned long ipa, ipa_end, shared_bit, root_tbls;
	int start_level, ia_digits, pa_digits;
	int l, ret = 0, rtt_reads = 0;
	phys_addr_t rd;

	if (!realm->rd || !mmu->pgt) {
		seq_puts(s, "Realm not created\n");
		return 0;
	}

	rd = virt_to_phys(realm->rd);
	start_level = mmu->pgt->start_level;
	ipa_end = BIT(realm->ia_bits);
	shared_bit = BIT(realm->ia_bits - 1);
	/*
	 * Hex-digit counts for the "0x.." tokens: the IPA column is sized to
	 * the Realm's IPA space, the PA and L<n> columns to the running
	 * kernel's PA width (PHYS_MASK_SHIFT, which accounts for LPA2). The
	 * column width adds 2 for the "0x" prefix.
	 */
	ia_digits = DIV_ROUND_UP(realm->ia_bits, 4);
	pa_digits = DIV_ROUND_UP(PHYS_MASK_SHIFT, 4);

	for (l = 0; l < KVM_PGTABLE_MAX_LEVELS; l++)
		tbl_base[l] = ~0UL;

	seq_printf(s, "%-*s %-*s %-8s %4s %6s %7s  %-14s %-9s",
		   ia_digits + 2, "IPA", pa_digits + 2, "PA", "TYPE", "SIZE",
		   "COUNT", "EXTENT", "STATE", "RIPAS");
	for (l = start_level; l < KVM_PGTABLE_LAST_LEVEL; l++) {
		char lbl[8];

		/* Column shows the next-level RTT the level-l entry points to. */
		snprintf(lbl, sizeof(lbl), "L%d", l + 1);
		seq_printf(s, " %-*s", pa_digits + 2, lbl);
	}
	seq_putc(s, '\n');

	read_lock(&kvm->mmu_lock);
	for (ipa = 0; ipa < ipa_end && !ret;) {
		struct rtt_entry leaf;
		unsigned long leaf_size;
		phys_addr_t pa;
		bool has_ripas, is_mapping, ns;
		int ripas, wl, rc;

		rc = rmi_rtt_read_entry(rd, ipa, KVM_PGTABLE_LAST_LEVEL, &leaf);
		rtt_reads++;
		stats.reads++;
		if (RMI_RETURN_STATUS(rc) != RMI_SUCCESS) {
			realm_pt_flush(s, &run, ia_digits, pa_digits, start_level);
			seq_printf(s, "0x%lx  RTT_READ_ENTRY failed (0x%x)\n",
				   ipa, rc);
			ret = -ENXIO;
			break;
		}

		wl = leaf.walk_level;
		leaf_size = kvm_realm_rtt_mapsize(wl);
		if (WARN_ON_ONCE(!leaf_size)) {
			ret = -EINVAL;
			break;
		}
		ns = !!(ipa & shared_bit);
		is_mapping = rmi_rtte_state_is_mapping(leaf.state);
		has_ripas = rmi_rtte_state_has_ripas(leaf.state);
		ripas = has_ripas ? leaf.ripas : -1;

		/*
		 * Record the RTT granule for each walk-path table not seen yet
		 * (memoised per level). A new table on the path changes the
		 * L<n> columns, so flush the open run.
		 */
		for (l = start_level; l < wl; l++) {
			unsigned long tsize = kvm_realm_rtt_mapsize(l);
			unsigned long base = ALIGN_DOWN(ipa, tsize);
			struct rtt_entry tbl;
			int k;

			if (tbl_base[l] == base)
				continue;
			tbl_base[l] = base;
			for (k = l + 1; k < KVM_PGTABLE_MAX_LEVELS; k++) {
				tbl_base[k] = ~0UL;
				tbl_gran[k] = 0;
			}

			rc = rmi_rtt_read_entry(rd, ipa, l, &tbl);
			rtt_reads++;
			stats.reads++;
			if (RMI_RETURN_STATUS(rc) != RMI_SUCCESS)
				continue;

			realm_pt_flush(s, &run, ia_digits, pa_digits, start_level);
			tbl_gran[l] = kvm_pte_to_phys(tbl.desc);
			stats.tbl[l]++;
		}

		/* Coalesce terminal entries (leaf or reserved hole). */
		if (is_mapping || leaf.state == RMI_AUX_DESTROYED ||
		    (!ns && leaf.state == RMI_UNASSIGNED &&
		     ripas != RMI_EMPTY)) {
			/* IPA span of the leaf's own RTT table. */
			unsigned long tblspan = leaf_size * KVM_REALM_PTRS_PER_RTT;
			bool same;

			pa = is_mapping ? kvm_pte_to_phys(leaf.desc) : 0;

			if (!ns && has_ripas && ((unsigned int)ripas <= RMI_DEV))
				stats.ripas[ripas] += leaf_size;
			if (leaf.state == RMI_ASSIGNED)
				stats.assigned[ns][wl] += leaf_size;

			/*
			 * Confine a run to a single RTT table so COUNT never
			 * exceeds KVM_REALM_PTRS_PER_RTT. Sub-root leaves are
			 * already bounded by the per-table flush above; this
			 * also bounds root-level block runs, which have no
			 * parent table on the walk to break them.
			 */
			same = run.active &&
			       (run.shared == ns) &&
			       (run.level == wl) &&
			       (run.size == leaf_size) &&
			       (run.state == leaf.state) &&
			       (run.ripas == ripas) &&
			       (run.ipa + run.count * run.size == ipa) &&
			       (ALIGN_DOWN(ipa, tblspan) == ALIGN_DOWN(run.ipa, tblspan));

			/*
			 * Only merge PA-backed entries whose PA stride is exactly
			 * +/- the mapping size (physically contiguous); otherwise
			 * break so the entry is emitted exactly.
			 */
			if (same && is_mapping) {
				s64 step = (s64)pa - (s64)run.pa_last;

				if (run.count == 1) {
					if ((step == (s64)leaf_size) ||
					    (step == -(s64)leaf_size))
						run.pa_step = step;
					else
						same = false;
				} else if (step != run.pa_step) {
					same = false;
				}
			}

			if (same) {
				run.pa_last = pa;
				run.count++;
			} else {
				realm_pt_flush(s, &run, ia_digits, pa_digits, start_level);
				run.active = true;
				run.shared = ns;
				run.level = wl;
				run.state = leaf.state;
				run.ripas = ripas;
				run.ipa = ipa;
				run.size = leaf_size;
				run.count = 1;
				run.pa_first = pa;
				run.pa_last = pa;
				memcpy(run.tbl, tbl_gran, sizeof(run.tbl));
			}
		} else {
			/* Unmapped EMPTY gap ends any open run. */
			realm_pt_flush(s, &run, ia_digits, pa_digits, start_level);
		}

		ipa = ALIGN_DOWN(ipa, leaf_size) + leaf_size;

		/*
		 * Bound the read-side lock hold to ~N RMI reads: drop the lock
		 * and reschedule at this entry boundary, then continue.
		 * cond_resched() must run with mmu_lock released.
		 */
		if (rtt_reads >= KVM_REALM_PTDUMP_READS_PER_LOCK) {
			read_unlock(&kvm->mmu_lock);
			cond_resched();
			read_lock(&kvm->mmu_lock);
			rtt_reads = 0;
		}
	}
	read_unlock(&kvm->mmu_lock);

	realm_pt_flush(s, &run, ia_digits, pa_digits, start_level);

	kvm_realm_print_summary(s, &stats, start_level);
	/*
	 * Per-level RTT granule counts: the root at start_level (a contiguous
	 * run of concatenated tables that spans the whole IPA - one table per
	 * KVM_REALM_PTRS_PER_RTT start-level entries, min one), then each lower
	 * level's tables as discovered on the walk (stats.tbl[l] is the count of
	 * L(l+1) tables). L1/L2 only appear on realms whose start_level is low
	 * enough to use them.
	 */
	seq_puts(s, "RTT tables:");
	root_tbls = (BIT(realm->ia_bits) >>
		     ARM64_HW_PGTABLE_LEVEL_SHIFT(start_level)) /
		    KVM_REALM_PTRS_PER_RTT;
	seq_printf(s, " L%d=%lu", start_level, root_tbls ? root_tbls : 1UL);
	for (l = start_level; l < KVM_PGTABLE_LAST_LEVEL; l++)
		seq_printf(s, " L%d=%lu", l + 1, stats.tbl[l]);
	seq_printf(s, ",   RMI_RTT reads: %lu\n", stats.reads);
	seq_printf(s, "Realm: root_rtt=0x%llx start_level=%d ia_bits=%u\n",
		   (u64)mmu->pgd_phys, start_level, realm->ia_bits);

	return ret;
}

static int kvm_ptdump_guest_show(struct seq_file *m, void *unused)
{
	int ret;
	struct kvm_ptdump_guest_state *st = m->private;
	struct kvm_s2_mmu *mmu = st->mmu;
	struct kvm *kvm = kvm_s2_mmu_to_kvm(mmu);
	struct kvm_pgtable_walker walker = (struct kvm_pgtable_walker) {
		.cb	= kvm_ptdump_visitor,
		.arg	= &st->parser_state,
		.flags	= KVM_PGTABLE_WALK_LEAF,
	};

	/*
	 * The host stage-2 is empty for Realms; the live mappings are held in
	 * the RMM's RTTs, so query them over RMI instead. That walk manages
	 * mmu_lock itself in read-side batches rather than holding it throughout.
	 */
	if (kvm_is_realm(kvm))
		return kvm_realm_stage2_ptdump(kvm, m);

	guard(write_lock)(&kvm->mmu_lock);
	st->parser_state = (struct ptdump_pg_state) {
		.marker		= &st->ipa_marker[0],
		.end_address	= BIT(mmu->pgt->ia_bits),
		.level		= -1,
		.pg_level	= &st->level[0],
		.seq		= m,
	};

	ret = kvm_pgtable_walk(mmu->pgt, 0, BIT(mmu->pgt->ia_bits), &walker);
	if (ret)
		return ret;
	note_page_flush(&st->parser_state.ptdump);

	return 0;
}

static int kvm_ptdump_guest_open(struct inode *m, struct file *file)
{
	struct kvm_s2_mmu *mmu = m->i_private;
	struct kvm *kvm = kvm_s2_mmu_to_kvm(mmu);
	struct kvm_ptdump_guest_state *st;
	int ret;

	if (!kvm_get_kvm_safe(kvm))
		return -ENOENT;

	st = kvm_ptdump_parser_create(mmu);
	if (IS_ERR(st)) {
		ret = PTR_ERR(st);
		goto err_with_kvm_ref;
	}

	/*
	 * The Realm dump issues an RMI SMC per entry and is re-run on every
	 * seq buffer overflow, so pre-size the buffer to keep it single-pass.
	 * The normal stage-2 walk is SMC-free, so the default is fine there.
	 */
	if (kvm_is_realm(kvm))
		ret = single_open_size(file, kvm_ptdump_guest_show, st,
				       KVM_REALM_PTDUMP_BUF_SIZE);
	else
		ret = single_open(file, kvm_ptdump_guest_show, st);
	if (!ret)
		return 0;

	kfree(st);
err_with_kvm_ref:
	kvm_put_kvm(kvm);
	return ret;
}

static int kvm_ptdump_guest_close(struct inode *m, struct file *file)
{
	struct kvm *kvm = kvm_s2_mmu_to_kvm(m->i_private);
	void *st = ((struct seq_file *)file->private_data)->private;

	kfree(st);
	kvm_put_kvm(kvm);

	return single_release(m, file);
}

static const struct file_operations kvm_ptdump_guest_fops = {
	.open		= kvm_ptdump_guest_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= kvm_ptdump_guest_close,
};

static int kvm_pgtable_range_show(struct seq_file *m, void *unused)
{
	struct kvm_pgtable *pgtable = m->private;

	seq_printf(m, "%2u\n", pgtable->ia_bits);
	return 0;
}

static int kvm_pgtable_levels_show(struct seq_file *m, void *unused)
{
	struct kvm_pgtable *pgtable = m->private;

	seq_printf(m, "%1d\n", KVM_PGTABLE_MAX_LEVELS - pgtable->start_level);
	return 0;
}

static int kvm_pgtable_debugfs_open(struct inode *m, struct file *file,
				    int (*show)(struct seq_file *, void *))
{
	struct kvm_s2_mmu *mmu = m->i_private;
	struct kvm *kvm = kvm_s2_mmu_to_kvm(mmu);
	struct kvm_pgtable *pgtable;
	int ret;

	if (!kvm_get_kvm_safe(kvm))
		return -ENOENT;

	pgtable = mmu->pgt;

	ret = single_open(file, show, pgtable);
	if (ret < 0)
		kvm_put_kvm(kvm);
	return ret;
}

static int kvm_pgtable_range_open(struct inode *m, struct file *file)
{
	return kvm_pgtable_debugfs_open(m, file, kvm_pgtable_range_show);
}

static int kvm_pgtable_levels_open(struct inode *m, struct file *file)
{
	return kvm_pgtable_debugfs_open(m, file, kvm_pgtable_levels_show);
}

static int kvm_pgtable_debugfs_close(struct inode *m, struct file *file)
{
	struct kvm *kvm = kvm_s2_mmu_to_kvm(m->i_private);

	kvm_put_kvm(kvm);
	return single_release(m, file);
}

static const struct file_operations kvm_pgtable_range_fops = {
	.open		= kvm_pgtable_range_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= kvm_pgtable_debugfs_close,
};

static const struct file_operations kvm_pgtable_levels_fops = {
	.open		= kvm_pgtable_levels_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= kvm_pgtable_debugfs_close,
};

void kvm_nested_s2_ptdump_create_debugfs(struct kvm_s2_mmu *mmu)
{
	struct dentry *dent;
	char file_name[S2FNAMESZ];

	snprintf(file_name, sizeof(file_name), "0x%016llx-0x%016llx-s2-%sabled",
		 mmu->tlb_vttbr,
		 mmu->tlb_vtcr,
		 mmu->nested_stage2_enabled ? "en" : "dis");

	dent = debugfs_create_file(file_name, 0400,
				   mmu->arch->debugfs_nv_dentry, mmu,
				   &kvm_ptdump_guest_fops);

	mmu->shadow_pt_debugfs_dentry = dent;
}

void kvm_nested_s2_ptdump_remove_debugfs(struct kvm_s2_mmu *mmu)
{
	debugfs_remove(mmu->shadow_pt_debugfs_dentry);
}

void kvm_s2_ptdump_create_debugfs(struct kvm *kvm)
{
	debugfs_create_file("stage2_page_tables", 0400, kvm->debugfs_dentry,
			    &kvm->arch.mmu, &kvm_ptdump_guest_fops);
	debugfs_create_file("ipa_range", 0400, kvm->debugfs_dentry,
			    &kvm->arch.mmu, &kvm_pgtable_range_fops);
	debugfs_create_file("stage2_levels", 0400, kvm->debugfs_dentry,
			    &kvm->arch.mmu, &kvm_pgtable_levels_fops);
	if (cpus_have_final_cap(ARM64_HAS_NESTED_VIRT))
		kvm->arch.debugfs_nv_dentry = debugfs_create_dir("nested", kvm->debugfs_dentry);
}
