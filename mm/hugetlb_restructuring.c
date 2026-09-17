// SPDX-License-Identifier: GPL-2.0-only
/*
 * Code to support runtime HugeTLB folio restructuring.
 */

#include <linux/mm.h>
#include <linux/dax.h>
#include <linux/shmem_fs.h>
#include <linux/hugetlb.h>
#include <linux/hugetlb_cgroup.h>
#include <linux/hugetlb_restructuring.h>
#include <linux/llist.h>
#include <linux/workqueue.h>
#include <linux/xarray.h>

#include "hugetlb_vmemmap.h"
#include "internal.h"

static DEFINE_XARRAY(hugetlb_restructuring_metadata);

struct hugetlb_restructuring_metadata {
	struct hugepage_subpool *spool;
	struct hugetlb_cgroup *h_cg;
	struct hugetlb_cgroup *h_cg_rsvd;
	unsigned long base_pfn;
	unsigned long nr_pages_waiting_to_be_merged;
	u8 page_order;
	bool hugetlb_cma;
};

static struct hugetlb_restructuring_metadata *
__hugetlb_restructuring_metadata_get(unsigned long pfn)
{
	lockdep_assert_held(&hugetlb_lock);

	return xa_load(&hugetlb_restructuring_metadata, pfn);
}

static bool hugetlb_restructuring_metadata_valid(
	struct hugetlb_restructuring_metadata *metadata)
{
	unsigned long nr_pages;

	lockdep_assert_held(&hugetlb_lock);

	if (!metadata || metadata->page_order >= BITS_PER_LONG ||
	    !hugetlb_order_to_hstate(metadata->page_order))
		return false;

	nr_pages = 1UL << metadata->page_order;
	return IS_ALIGNED(metadata->base_pfn, nr_pages);
}

static void __hugetlb_restructuring_metadata_initialize(
	struct hugetlb_restructuring_metadata *metadata, struct folio *folio)
{
	lockdep_assert_held(&hugetlb_lock);

	metadata->base_pfn = folio_pfn(folio);
	metadata->page_order = folio_order(folio);
	metadata->spool = hugetlb_folio_subpool(folio);
	metadata->h_cg = hugetlb_cgroup_from_folio(folio);
	metadata->h_cg_rsvd = hugetlb_cgroup_from_folio_rsvd(folio);
	metadata->hugetlb_cma = folio_test_hugetlb_cma(folio);
	metadata->nr_pages_waiting_to_be_merged = 0;
}

static bool __hugetlb_restructuring_metadata_range_empty(
	struct hugetlb_restructuring_metadata *metadata)
{
	unsigned long index = metadata->base_pfn;
	unsigned long nr_pages = 1UL << metadata->page_order;
	unsigned long last;

	lockdep_assert_held(&hugetlb_lock);

	if (metadata->base_pfn > ULONG_MAX - (nr_pages - 1))
		return false;
	last = metadata->base_pfn + nr_pages - 1;

	return !xa_find(&hugetlb_restructuring_metadata, &index, last,
			XA_PRESENT);
}

static bool __hugetlb_restructuring_metadata_apply(
	struct folio *folio, struct hugetlb_restructuring_metadata *metadata)
{
	lockdep_assert_held(&hugetlb_lock);

	if (!hugetlb_restructuring_metadata_valid(metadata) ||
	    !folio_test_hugetlb(folio) ||
	    folio_pfn(folio) != metadata->base_pfn ||
	    folio_order(folio) != metadata->page_order)
		return false;

	hugetlb_set_folio_subpool(folio, metadata->spool);
	set_hugetlb_cgroup(folio, metadata->h_cg);
	set_hugetlb_cgroup_rsvd(folio, metadata->h_cg_rsvd);
	if (metadata->hugetlb_cma)
		folio_set_hugetlb_cma(folio);
	else
		folio_clear_hugetlb_cma(folio);

	return true;
}

static bool hugetlb_restructuring_metadata_restore(struct folio *folio)
{
	struct hugetlb_restructuring_metadata *metadata;
	void *erased;
	bool restored = false;

	spin_lock_irq(&hugetlb_lock);
	metadata = __hugetlb_restructuring_metadata_get(folio_pfn(folio));
	if (!__hugetlb_restructuring_metadata_apply(folio, metadata))
		goto out_unlock;

	erased = xa_erase(&hugetlb_restructuring_metadata, metadata->base_pfn);
	if (WARN_ON_ONCE(erased != metadata))
		goto out_unlock;
	restored = true;

out_unlock:
	spin_unlock_irq(&hugetlb_lock);
	if (restored)
		kfree(metadata);

	return restored;
}

int hugetlb_restructuring_metadata_store(struct folio *folio)
{
	XA_STATE(xas, &hugetlb_restructuring_metadata, folio_pfn(folio));
	struct hugetlb_restructuring_metadata *metadata;
	int ret;

	metadata = kmalloc(sizeof(*metadata), GFP_KERNEL);
	if (!metadata)
		return -ENOMEM;

	for (;;) {
		spin_lock_irq(&hugetlb_lock);
		if (!folio_test_hugetlb(folio) ||
		    folio_order(folio) >= BITS_PER_LONG ||
		    !hugetlb_order_to_hstate(folio_order(folio))) {
			ret = -EINVAL;
			goto out_unlock;
		}

		__hugetlb_restructuring_metadata_initialize(metadata, folio);
		if (!__hugetlb_restructuring_metadata_range_empty(metadata)) {
			ret = -EEXIST;
			goto out_unlock;
		}

		xas_set_order(&xas, metadata->base_pfn, metadata->page_order);
		xas_lock(&xas);
		xas_store(&xas, metadata);
		ret = xas_error(&xas);
		xas_unlock(&xas);

out_unlock:
		spin_unlock_irq(&hugetlb_lock);

		/* Allocate outside hugetlb_lock, then revalidate before retrying. */
		if (ret != -ENOMEM || !xas_nomem(&xas, GFP_KERNEL))
			break;
	}

	xas_destroy(&xas);
	if (ret)
		kfree(metadata);

	return ret;
}
EXPORT_SYMBOL_FOR_MODULES(hugetlb_restructuring_metadata_store, "kvm");

void hugetlb_restructuring_metadata_abort(struct folio *folio)
{
	struct hugetlb_restructuring_metadata *metadata;
	void *erased = NULL;

	spin_lock_irq(&hugetlb_lock);
	metadata = __hugetlb_restructuring_metadata_get(folio_pfn(folio));
	if (hugetlb_restructuring_metadata_valid(metadata) &&
	    folio_test_hugetlb(folio) &&
	    folio_pfn(folio) == metadata->base_pfn &&
	    folio_order(folio) == metadata->page_order &&
	    __hugetlb_restructuring_metadata_apply(folio, metadata))
		erased = xa_erase(&hugetlb_restructuring_metadata,
				  metadata->base_pfn);
	spin_unlock_irq(&hugetlb_lock);

	if (WARN_ON_ONCE(erased != metadata))
		return;
	kfree(metadata);
}
EXPORT_SYMBOL_FOR_MODULES(hugetlb_restructuring_metadata_abort, "kvm");

static bool hugetlb_restructuring_metadata_order(struct folio *folio,
						  unsigned long *base_pfn,
						  u8 *page_order)
{
	struct hugetlb_restructuring_metadata *metadata;
	unsigned long pfn = folio_pfn(folio);
	unsigned long nr_pages;
	bool found = false;

	spin_lock_irq(&hugetlb_lock);
	metadata = __hugetlb_restructuring_metadata_get(pfn);
	if (!hugetlb_restructuring_metadata_valid(metadata))
		goto out_unlock;

	nr_pages = 1UL << metadata->page_order;
	if (pfn < metadata->base_pfn ||
	    pfn - metadata->base_pfn >= nr_pages)
		goto out_unlock;

	*base_pfn = metadata->base_pfn;
	*page_order = metadata->page_order;
	found = true;

out_unlock:
	spin_unlock_irq(&hugetlb_lock);
	return found;
}

bool hugetlb_restructuring_cgroup_get(struct folio *folio,
				     struct hugetlb_cgroup **h_cg,
				     unsigned long *nr_pages)
{
	struct hugetlb_restructuring_metadata *metadata;

	lockdep_assert_held(&hugetlb_lock);

	metadata = __hugetlb_restructuring_metadata_get(folio_pfn(folio));
	if (!hugetlb_restructuring_metadata_valid(metadata))
		return false;

	*h_cg = metadata->h_cg;
	*nr_pages = 1UL << metadata->page_order;
	return true;
}

void hugetlb_restructuring_cgroup_set(struct folio *folio,
				     struct hugetlb_cgroup *h_cg)
{
	struct hugetlb_restructuring_metadata *metadata;

	lockdep_assert_held(&hugetlb_lock);

	metadata = __hugetlb_restructuring_metadata_get(folio_pfn(folio));
	if (WARN_ON_ONCE(!hugetlb_restructuring_metadata_valid(metadata)))
		return;

	metadata->h_cg = h_cg;
	if (folio_test_hugetlb(folio) &&
	    folio_pfn(folio) == metadata->base_pfn &&
	    folio_order(folio) == metadata->page_order)
		set_hugetlb_cgroup(folio, h_cg);
}

static bool hugetlb_restructuring_metadata_matches(struct folio *folio,
						     u8 original_order)
{
	struct hugetlb_restructuring_metadata *metadata;
	bool matches;

	spin_lock_irq(&hugetlb_lock);
	metadata = __hugetlb_restructuring_metadata_get(folio_pfn(folio));
	matches = hugetlb_restructuring_metadata_valid(metadata) &&
		  metadata->base_pfn == folio_pfn(folio) &&
		  metadata->page_order == original_order;
	spin_unlock_irq(&hugetlb_lock);

	return matches;
}

static int hugetlb_restructuring_freeze_folio(struct folio *folio)
{
	const int filemap_refcount = folio_nr_pages(folio);

	if (!folio_ref_freeze(folio, filemap_refcount))
		return -EAGAIN;

	return 0;
}

static void hugetlb_restructuring_unfreeze_folio(struct folio *folio)
{
	const int filemap_refcount = folio_nr_pages(folio);

	folio_ref_unfreeze(folio, filemap_refcount);
}

static bool hugetlb_restructuring_set_hugetlb_and_apply(struct folio *folio)
{
	struct hugetlb_restructuring_metadata *metadata;
	bool applied;

	spin_lock_irq(&hugetlb_lock);
	metadata = __hugetlb_restructuring_metadata_get(folio_pfn(folio));
	if (WARN_ON_ONCE(folio_has_type(folio) ||
			 !hugetlb_restructuring_metadata_valid(metadata) ||
			 metadata->base_pfn != folio_pfn(folio) ||
			 metadata->page_order != folio_order(folio))) {
		applied = false;
		goto out_unlock;
	}

	__folio_set_hugetlb(folio);
	applied = __hugetlb_restructuring_metadata_apply(folio, metadata);
	WARN_ON_ONCE(!applied);

out_unlock:
	spin_unlock_irq(&hugetlb_lock);
	return applied;
}

static int hugetlb_restructuring_clear_hugetlb(struct folio *folio)
{
	int ret = 0;

	spin_lock_irq(&hugetlb_lock);
	if (folio_test_hugetlb(folio))
		__folio_clear_hugetlb(folio);
	else
		ret = -EAGAIN;
	spin_unlock_irq(&hugetlb_lock);

	return ret;
}

static struct folio *hugetlb_restructuring_lookup_folio(
	struct address_space *mapping, pgoff_t index)
{
	struct folio *folio;

	folio = filemap_get_folio(mapping, index);
	if (IS_ERR(folio))
		return folio;

	if (folio->mapping != mapping) {
		folio_put(folio);
		return ERR_PTR(-EAGAIN);
	}

	if (folio_contain_hwpoisoned_page(folio)) {
		folio_put(folio);
		return ERR_PTR(-EHWPOISON);
	}

	/*
	 * The caller holds invalidate_lock exclusively, so the filemap reference
	 * keeps the folio stable after dropping this temporary reference.  Any
	 * lockless reference acquired after this point is detected by ref-freeze.
	 */
	folio_put(folio);
	return folio;
}

static bool hugetlb_restructuring_xas_matches(struct xa_state *xas,
					      pgoff_t index,
					      struct folio *folio,
					      u8 order)
{
	void *entry;

	xas_set_order(xas, index, 0);
	entry = xas_load(xas);
	if (xas_error(xas) || entry != folio)
		return false;

	return xas_get_order(xas) == order;
}

static u8 hugetlb_restructuring_next_split_order(u8 current_order,
						 u8 to_order)
{
	u8 boundary_order, next_order;

	boundary_order = ((current_order - 1) / XA_CHUNK_SHIFT) *
			 XA_CHUNK_SHIFT;
	next_order = max(to_order, boundary_order);

	/* Keep PMD as a stage so partial restructuring remains resumable. */
	if (PTRS_PER_PMD > 1 && current_order > PMD_ORDER &&
	    next_order < PMD_ORDER)
		next_order = PMD_ORDER;

	return next_order;
}

static void __merge_folio_to_order(struct folio *folio, unsigned int to_order)
{
	struct address_space *mapping = folio->mapping;

	prep_compound_page(folio_page(folio, 0), to_order);

	folio->mapping = mapping;
}

static void hugetlb_restructuring_merge_folios(struct folio **children,
		unsigned long nr_children, u8 current_order, u8 to_order,
		bool large_rmappable)
{
	unsigned long i;

	/*
	 * prep_compound_page() assumes freshly allocated base pages.  Undo the
	 * per-folio state installed by __split_folio_to_order() before making
	 * each interior child head a tail of the new folio.
	 */
	for (i = 0; i < nr_children; i++) {
		struct folio *child = children[i];

		if (current_order) {
			child->_flags_1 &= ~PAGE_FLAGS_SECOND;
#ifdef NR_PAGES_IN_LARGE_FOLIO
			child->_nr_pages = 0;
#endif
			if (i)
				ClearPageCompound(&child->page);
		}

		if (i) {
			child->flags.f &= ~PAGE_FLAGS_CHECK_AT_PREP;
#ifdef CONFIG_MEMCG
			child->memcg_data = 0;
#endif
		}
	}

	__merge_folio_to_order(children[0], to_order);
	if (large_rmappable)
		folio_set_large_rmappable(children[0]);
}

static void hugetlb_restructuring_prepare_uptodate(struct folio **children,
						    unsigned long nr_children)
{
	bool any_uptodate = false;
	unsigned long i;

	for (i = 0; i < nr_children; i++)
		any_uptodate |= folio_test_uptodate(children[i]);
	if (!any_uptodate)
		return;

	/*
	 * A merged folio has one uptodate bit.  Preserve initialized children
	 * and zero only untouched children before representing the entire range
	 * as uptodate.
	 */
	for (i = 0; i < nr_children; i++) {
		if (folio_test_uptodate(children[i]))
			continue;
		folio_zero_user(children[i], 0);
		folio_mark_uptodate(children[i]);
	}
}

static int hugetlb_restructuring_split_one(struct address_space *mapping,
					   pgoff_t index,
					   struct folio *folio,
					   u8 current_order,
					   u8 to_order)
{
	XA_STATE(xas, &mapping->i_pages, index);
	unsigned long nr_children, i;
	struct hstate *h = NULL;
	bool restore_vmemmap;
	bool hugetlb_cleared = false;
	int ret;

	if (WARN_ON_ONCE(current_order <= to_order ||
			 current_order - to_order > XA_CHUNK_SHIFT))
		return -EINVAL;

	nr_children = 1UL << (current_order - to_order);
	restore_vmemmap = folio_test_hugetlb(folio);
	if (restore_vmemmap) {
		h = hugetlb_order_to_hstate(current_order);
		if (WARN_ON_ONCE(!h))
			return -EINVAL;
	}

	mapping_set_update(&xas, mapping);
	xas_set_order(&xas, index, to_order);
	xas_split_alloc(&xas, folio, current_order, GFP_KERNEL);
	ret = xas_error(&xas);
	if (ret)
		goto out_destroy;

	ret = hugetlb_restructuring_freeze_folio(folio);
	if (ret)
		goto out_destroy;

	/* Avoid expensive vmemmap work if the mapping changed unexpectedly. */
	xas_lock_irq(&xas);
	if (!hugetlb_restructuring_xas_matches(&xas, index, folio,
					       current_order))
		ret = -EAGAIN;
	xas_unlock_irq(&xas);
	if (ret)
		goto out_unfreeze;
	if (folio_contain_hwpoisoned_page(folio)) {
		ret = -EHWPOISON;
		goto out_unfreeze;
	}

	/*
	 * Restore an optimized HugeTLB vmemmap before clearing the HugeTLB page
	 * type.  This may sleep, but the folio is frozen and no XArray lock is
	 * held.
	 */
	if (restore_vmemmap) {
		ret = hugetlb_vmemmap_restore_folio(h, folio);
		if (ret)
			goto out_unfreeze;
		if (folio_contain_hwpoisoned_page(folio)) {
			ret = -EHWPOISON;
			goto out_unfreeze;
		}

		ret = hugetlb_restructuring_clear_hugetlb(folio);
		if (ret)
			goto out_unfreeze;
		hugetlb_cleared = true;
	}

	/*
	 * Publish at most one new XArray level.  Newly allocated nodes were
	 * initialized before taking xa_lock, and a horizontal split touches at
	 * most XA_CHUNK_SIZE slots.
	 */
	xas_lock_irq(&xas);
	if (!hugetlb_restructuring_xas_matches(&xas, index, folio,
					       current_order)) {
		ret = -EAGAIN;
		xas_unlock_irq(&xas);
		goto out_unfreeze;
	}
	xas_set_order(&xas, index, to_order);
	xas_split(&xas, folio, current_order);
	xas_unlock_irq(&xas);

	/* The potentially long struct page walk must not run under xa_lock. */
	__split_folio_to_order(folio, current_order, to_order);
	if (to_order)
		folio_set_large_rmappable(folio);

	/*
	 * Replace at most XA_CHUNK_SIZE entries while all resulting folios are
	 * still frozen.  Any lockless lookup of a stale entry retries.
	 */
	xas_lock_irq(&xas);
	for (i = 0; i < nr_children; i++) {
		pgoff_t child_index = index + (i << to_order);
		struct folio *child =
			(struct folio *)folio_page(folio, i << to_order);

		WARN_ON_ONCE(child->mapping != mapping);
		WARN_ON_ONCE(child->index != child_index);
		WARN_ON_ONCE(folio_order(child) != to_order);
		WARN_ON_ONCE(!hugetlb_restructuring_xas_matches(
					&xas, child_index, folio, to_order));

		xas_set_order(&xas, child_index, to_order);
		xas_store(&xas, child);
		WARN_ON_ONCE(xas_error(&xas));
	}
	xas_unlock_irq(&xas);

	for (i = 0; i < nr_children; i++) {
		struct folio *child =
			(struct folio *)folio_page(folio, i << to_order);

		hugetlb_restructuring_unfreeze_folio(child);
	}

	xas_destroy(&xas);
	return 0;

out_unfreeze:
	if (hugetlb_cleared &&
	    WARN_ON_ONCE(!hugetlb_restructuring_set_hugetlb_and_apply(folio)))
		ret = -EINVAL;
	hugetlb_restructuring_unfreeze_folio(folio);
out_destroy:
	xas_destroy(&xas);
	return ret;
}

static int hugetlb_restructuring_split_range(struct address_space *mapping,
					     pgoff_t start, u8 original_order,
					     u8 from_order, u8 to_order)
{
	pgoff_t end = start + (1UL << from_order);
	u8 current_order = from_order;

	while (current_order > to_order) {
		u8 next_order = hugetlb_restructuring_next_split_order(
			current_order, to_order);
		pgoff_t index;

		for (index = start; index < end;
		     index += 1UL << current_order) {
			struct folio *folio;
			u8 actual_order;
			int ret;

			folio = hugetlb_restructuring_lookup_folio(mapping, index);
			if (IS_ERR(folio))
				return PTR_ERR(folio);

			actual_order = folio_order(folio);
			if (folio->index != index || actual_order > current_order)
				return -EINVAL;
			if (actual_order == original_order) {
				if (!folio_test_hugetlb(folio))
					return -EINVAL;
			} else if (folio_has_type(folio)) {
				return -EINVAL;
			}

			/* A previous attempt may have completed this stage. */
			if (actual_order < current_order) {
				if (actual_order > next_order)
					return -EINVAL;
				cond_resched();
				continue;
			}

			ret = hugetlb_restructuring_split_one(mapping, index,
							 folio, current_order,
							 next_order);
			if (ret)
				return ret;

			cond_resched();
		}

		current_order = next_order;
	}

	return 0;
}

static u8 hugetlb_restructuring_next_merge_order(u8 current_order,
						 u8 to_order)
{
	u8 boundary_order, next_order;

	boundary_order = (current_order / XA_CHUNK_SHIFT + 1) *
			 XA_CHUNK_SHIFT;
	next_order = min(to_order, boundary_order);

	/* Keep PMD as a stage so partial restructuring remains resumable. */
	if (PTRS_PER_PMD > 1 && current_order < PMD_ORDER &&
	    next_order > PMD_ORDER)
		next_order = PMD_ORDER;

	return next_order;
}

static int hugetlb_restructuring_merge_one(struct address_space *mapping,
					   pgoff_t index, u8 current_order,
					   u8 to_order, u8 original_order)
{
	struct folio *children[XA_CHUNK_SIZE];
	XA_STATE(xas, &mapping->i_pages, index);
	unsigned long nr_children, nr_frozen = 0, i;
	unsigned long first_pfn = 0;
	struct hstate *h = NULL;
	int ret = 0;

	if (WARN_ON_ONCE(current_order >= to_order ||
			 to_order - current_order > XA_CHUNK_SHIFT))
		return -EINVAL;
	if (to_order == original_order) {
		h = hugetlb_order_to_hstate(to_order);
		if (WARN_ON_ONCE(!h))
			return -EINVAL;
	}

	nr_children = 1UL << (to_order - current_order);
	for (i = 0; i < nr_children; i++) {
		pgoff_t child_index = index + (i << current_order);
		struct folio *child;

		child = hugetlb_restructuring_lookup_folio(mapping, child_index);
		if (IS_ERR(child))
			return PTR_ERR(child);
		if (!i)
			first_pfn = folio_pfn(child);
		if (child->mapping != mapping || child->index != child_index ||
		    folio_order(child) != current_order ||
		    folio_pfn(child) != first_pfn + (i << current_order) ||
		    folio_test_large(child) != !!current_order ||
		    folio_has_type(child))
			return -EINVAL;
		if (folio_mapped(child) || folio_test_lru(child))
			return -EBUSY;
		if (current_order > 1 &&
		    !list_empty(&child->_deferred_list))
			return -EINVAL;

		children[i] = child;
	}
	if (to_order == original_order &&
	    !hugetlb_restructuring_metadata_matches(children[0],
						      original_order))
		return -EINVAL;

	for (i = 0; i < nr_children; i++) {
		ret = hugetlb_restructuring_freeze_folio(children[i]);
		if (ret)
			goto out_unfreeze;
		nr_frozen++;
	}
#ifdef CONFIG_MEMCG
	for (i = 1; i < nr_children; i++) {
		if (children[i]->memcg_data != children[0]->memcg_data) {
			ret = -EINVAL;
			goto out_unfreeze;
		}
	}
#endif
	for (i = 0; i < nr_children; i++) {
		if (folio_contain_hwpoisoned_page(children[i])) {
			ret = -EHWPOISON;
			goto out_unfreeze;
		}
	}
	hugetlb_restructuring_prepare_uptodate(children, nr_children);

	mapping_set_update(&xas, mapping);
	xas_lock_irq(&xas);
	for (i = 0; i < nr_children; i++) {
		pgoff_t child_index = index + (i << current_order);

		if (!hugetlb_restructuring_xas_matches(&xas, child_index,
							 children[i],
							 current_order)) {
			ret = -EAGAIN;
			goto out_unlock;
		}
	}

	/* Collapsing one level touches at most XA_CHUNK_SIZE nodes or slots. */
	xas_set_order(&xas, index, to_order);
	xas_store(&xas, children[0]);
	ret = xas_error(&xas);
out_unlock:
	xas_unlock_irq(&xas);
	if (ret)
		goto out_unfreeze;

	/* Readers can only see the frozen first child until the merge is done. */
	hugetlb_restructuring_merge_folios(children, nr_children,
					      current_order, to_order,
					      to_order != original_order);
	if (to_order == original_order) {
		if (!hugetlb_restructuring_set_hugetlb_and_apply(children[0]))
			ret = -EINVAL;
		else
			hugetlb_vmemmap_optimize_folio(h, children[0]);
	}

	hugetlb_restructuring_unfreeze_folio(children[0]);
	return ret;

out_unfreeze:
	while (nr_frozen) {
		nr_frozen--;
		hugetlb_restructuring_unfreeze_folio(children[nr_frozen]);
	}
	return ret;
}

static int hugetlb_restructuring_merge_range(struct address_space *mapping,
					     pgoff_t start, u8 original_order,
					     u8 to_order)
{
	pgoff_t end = start + (1UL << to_order);
	u8 current_order = 0;

	while (current_order < to_order) {
		u8 next_order = hugetlb_restructuring_next_merge_order(
			current_order, to_order);
		pgoff_t index;

		for (index = start; index < end;) {
			struct folio *folio;
			pgoff_t folio_end;
			u8 actual_order;
			int ret;

			folio = hugetlb_restructuring_lookup_folio(mapping, index);
			if (IS_ERR(folio))
				return PTR_ERR(folio);

			actual_order = folio_order(folio);
			folio_end = folio->index + folio_nr_pages(folio);
			if (folio_end < folio->index)
				return -EINVAL;
			if (actual_order == original_order) {
				if (!folio_test_hugetlb(folio))
					return -EINVAL;
			} else if (folio_has_type(folio)) {
				return -EINVAL;
			}

			/* A previous attempt may already have merged this range. */
			if (actual_order >= next_order) {
				if (folio->index > index ||
				    folio_end < index + (1UL << next_order))
					return -EINVAL;
				index = min(folio_end, end);
				cond_resched();
				continue;
			}

			if (actual_order != current_order || folio->index != index)
				return -EINVAL;

			ret = hugetlb_restructuring_merge_one(mapping, index,
							 current_order,
							 next_order,
							 original_order);
			if (ret)
				return ret;

			index += 1UL << next_order;
			cond_resched();
		}

		current_order = next_order;
	}

	return 0;
}

/*
 * Restructure an aligned range within the original HugeTLB allocation.
 * Splits cap every folio in the range at @target_order, while merges ensure
 * the complete range is covered by a single folio of at least @target_order.
 */
int hugetlb_restructuring_restructure_folio(struct folio *folio,
					    pgoff_t start, u8 range_order,
					    u8 target_order)
{
	struct address_space *mapping = folio->mapping;
	unsigned long base_pfn, pfn_offset;
	unsigned long nr_pages, range_pages;
	pgoff_t original_start, original_end, folio_end, range_end;
	unsigned int current_order;
	u8 original_order;

	if (!mapping)
		return -EINVAL;

	lockdep_assert_held_write(&mapping->invalidate_lock);

	if (!hugetlb_restructuring_metadata_order(folio, &base_pfn,
						  &original_order))
		return -EINVAL;

	if (target_order > range_order || range_order > original_order)
		return -EINVAL;

	if (folio_contain_hwpoisoned_page(folio))
		return -EHWPOISON;

	nr_pages = 1UL << original_order;
	original_start = round_down(folio->index, nr_pages);
	original_end = original_start + nr_pages;
	if (original_end < original_start)
		return -EINVAL;

	folio_end = folio->index + folio_nr_pages(folio);
	if (folio_end < folio->index || folio_end > original_end ||
	    !in_range(start, folio->index, folio_nr_pages(folio)))
		return -EINVAL;

	if (!in_range(folio_pfn(folio), base_pfn, nr_pages))
		return -EINVAL;

	pfn_offset = folio_pfn(folio) - base_pfn;
	if (folio->index - original_start != pfn_offset)
		return -EINVAL;

	/* Only the original-order folio retains the HugeTLB type. */
	current_order = folio_order(folio);
	if (current_order > original_order)
		return -EINVAL;

	if (current_order == original_order) {
		if (!folio_test_hugetlb(folio))
			return -EINVAL;
	} else if (folio_has_type(folio)) {
		return -EINVAL;
	}

	range_pages = 1UL << range_order;
	range_end = start + range_pages;
	if (!IS_ALIGNED(start, range_pages) || range_end < start ||
	    range_end > original_end)
		return -EINVAL;

	if (target_order == range_order && range_end <= folio_end)
		return 0;

	if (target_order < range_order)
		return hugetlb_restructuring_split_range(mapping, start,
							 original_order,
							 range_order,
							 target_order);

	return hugetlb_restructuring_merge_range(mapping, start, original_order,
						 target_order);
}
EXPORT_SYMBOL_FOR_MODULES(hugetlb_restructuring_restructure_folio, "kvm");

static int hugetlb_restructuring_cleanup_account(
	struct folio *folio, unsigned long *base_pfn, u8 *original_order)
{
	struct hugetlb_restructuring_metadata *metadata;
	unsigned long pfn = folio_pfn(folio);
	unsigned long offset, nr_pages, total_pages;
	unsigned int order = folio_order(folio);
	int ret = -EINVAL;

	spin_lock_irq(&hugetlb_lock);
	metadata = __hugetlb_restructuring_metadata_get(pfn);
	if (!hugetlb_restructuring_metadata_valid(metadata) ||
	    !folio_test_hugetlb_split(folio) ||
	    folio_ref_count(folio) || folio->mapping ||
	    order >= metadata->page_order || order >= BITS_PER_LONG ||
	    folio_test_large(folio) != !!order)
		goto out_unlock;

	total_pages = 1UL << metadata->page_order;
	nr_pages = 1UL << order;
	if (pfn < metadata->base_pfn)
		goto out_unlock;
	offset = pfn - metadata->base_pfn;
	if (!IS_ALIGNED(pfn, nr_pages) || offset >= total_pages ||
	    nr_pages > total_pages - offset ||
	    metadata->nr_pages_waiting_to_be_merged >
		total_pages - nr_pages)
		goto out_unlock;

	metadata->nr_pages_waiting_to_be_merged += nr_pages;
	if (metadata->nr_pages_waiting_to_be_merged == total_pages) {
		*base_pfn = metadata->base_pfn;
		*original_order = metadata->page_order;
		ret = 1;
	} else {
		ret = 0;
	}

out_unlock:
	spin_unlock_irq(&hugetlb_lock);
	WARN_ON_ONCE(ret < 0);
	return ret;
}

static bool hugetlb_restructuring_cleanup_validate(unsigned long base_pfn,
						     u8 original_order)
{
	unsigned long offset = 0;
	unsigned long total_pages = 1UL << original_order;
#ifdef CONFIG_MEMCG
	unsigned long memcg_data = pfn_folio(base_pfn)->memcg_data;
#endif

	while (offset < total_pages) {
		struct page *page = pfn_to_page(base_pfn + offset);
		struct folio *folio;
		unsigned long nr_pages;
		unsigned int order;

		if (PageTail(page))
			return false;
		folio = page_folio(page);
		order = folio_order(folio);
		if (order >= original_order || order >= BITS_PER_LONG)
			return false;

		nr_pages = 1UL << order;
		if (folio_pfn(folio) != base_pfn + offset ||
		    !IS_ALIGNED(base_pfn + offset, nr_pages) ||
		    nr_pages > total_pages - offset ||
		    folio_test_large(folio) != !!order ||
		    folio_ref_count(folio) || folio->mapping ||
		    !folio_test_hugetlb_split(folio) ||
		    folio_test_lru(folio) || folio_test_locked(folio) ||
		    folio_test_writeback(folio) || folio_test_dirty(folio) ||
		    folio_test_uptodate(folio) || folio_has_private(folio) ||
		    folio_contain_hwpoisoned_page(folio))
			return false;
		if (order > 1 && !list_empty(&folio->_deferred_list))
			return false;
#ifdef CONFIG_MEMCG
		if (folio->memcg_data != memcg_data)
			return false;
#endif

		offset += nr_pages;
		if (!(offset & (XA_CHUNK_SIZE - 1)))
			cond_resched();
	}

	return offset == total_pages;
}

static bool hugetlb_restructuring_cleanup_merge_one(unsigned long base_pfn,
						      unsigned long offset,
						      u8 current_order,
						      u8 to_order,
						      u8 original_order)
{
	struct folio *children[XA_CHUNK_SIZE];
	unsigned long nr_children, i;

	if (to_order <= current_order ||
	    to_order - current_order > XA_CHUNK_SHIFT)
		return false;

	nr_children = 1UL << (to_order - current_order);
	for (i = 0; i < nr_children; i++) {
		unsigned long child_pfn = base_pfn + offset +
					  (i << current_order);
		struct page *page = pfn_to_page(child_pfn);
		struct folio *child;

		if (PageTail(page))
			return false;
		child = page_folio(page);
		if (folio_pfn(child) != child_pfn ||
		    folio_order(child) != current_order ||
		    folio_ref_count(child) || child->mapping ||
		    !folio_test_hugetlb_split(child))
			return false;
		children[i] = child;
	}

	spin_lock_irq(&hugetlb_lock);
	for (i = 0; i < nr_children; i++) {
		if (WARN_ON_ONCE(!folio_test_hugetlb_split(children[i]))) {
			spin_unlock_irq(&hugetlb_lock);
			return false;
		}
	}
	for (i = 1; i < nr_children; i++)
		__folio_clear_hugetlb_split(children[i]);
	spin_unlock_irq(&hugetlb_lock);

	hugetlb_restructuring_merge_folios(children, nr_children,
					      current_order, to_order,
					      to_order != original_order);
	return true;
}

static bool hugetlb_restructuring_cleanup_merge(unsigned long base_pfn,
						  u8 original_order)
{
	unsigned long total_pages = 1UL << original_order;
	u8 current_order = 0;

	while (current_order < original_order) {
		u8 next_order = hugetlb_restructuring_next_merge_order(
			current_order, original_order);
		unsigned long offset = 0;

		while (offset < total_pages) {
			struct page *page = pfn_to_page(base_pfn + offset);
			struct folio *folio;
			unsigned int actual_order;

			if (PageTail(page))
				return false;
			folio = page_folio(page);
			actual_order = folio_order(folio);
			if (!folio_test_hugetlb_split(folio))
				return false;
			if (actual_order > next_order) {
				offset += folio_nr_pages(folio);
				continue;
			}
			if (actual_order == next_order) {
				offset += 1UL << next_order;
				continue;
			}
			if (actual_order != current_order ||
			    !hugetlb_restructuring_cleanup_merge_one(
					base_pfn, offset, current_order,
					next_order, original_order))
				return false;

			offset += 1UL << next_order;
			cond_resched();
		}

		current_order = next_order;
	}

	return folio_order(pfn_folio(base_pfn)) == original_order;
}

static bool hugetlb_restructuring_cleanup_finish(struct folio *folio,
						   unsigned long base_pfn,
						   u8 original_order)
{
	struct hugetlb_restructuring_metadata *metadata;
	unsigned long total_pages = 1UL << original_order;
	void *erased = NULL;
	bool finished = false;

	spin_lock_irq(&hugetlb_lock);
	metadata = __hugetlb_restructuring_metadata_get(base_pfn);
	if (!hugetlb_restructuring_metadata_valid(metadata) ||
	    metadata->base_pfn != base_pfn ||
	    metadata->page_order != original_order ||
	    metadata->nr_pages_waiting_to_be_merged != total_pages ||
	    folio_pfn(folio) != base_pfn ||
	    folio_order(folio) != original_order ||
	    !folio_test_hugetlb_split(folio))
		goto out_unlock;

	__folio_clear_hugetlb_split(folio);
	__folio_set_hugetlb(folio);
	if (!__hugetlb_restructuring_metadata_apply(folio, metadata))
		goto out_unlock;

	erased = xa_erase(&hugetlb_restructuring_metadata, base_pfn);
	if (erased == metadata)
		finished = true;

out_unlock:
	if (!finished) {
		/* Keep a failed reconstruction out of both HugeTLB and buddy. */
		if (folio_test_hugetlb(folio))
			__folio_clear_hugetlb(folio);
		/* A zero refcount keeps page_type stable outside hugetlb_lock. */
		if (data_race(folio->page.page_type) == UINT_MAX)
			__folio_set_hugetlb_split(folio);
	}
	spin_unlock_irq(&hugetlb_lock);
	if (WARN_ON_ONCE(!finished))
		return false;

	kfree(metadata);
	return true;
}

static void hugetlb_restructuring_cleanup_folio(struct folio *folio)
{
	unsigned long base_pfn;
	struct folio *first_folio;
	struct hstate *h;
	u8 original_order;
	int ret;

	ret = hugetlb_restructuring_cleanup_account(folio, &base_pfn,
						     &original_order);
	if (ret <= 0)
		return;

	if (WARN_ON_ONCE(!hugetlb_restructuring_cleanup_validate(
					base_pfn, original_order))) {
		/* Poison or corrupt topology is quarantined instead of reused. */
		return;
	}

	if (WARN_ON_ONCE(!hugetlb_restructuring_cleanup_merge(
					base_pfn, original_order)))
		return;
	first_folio = pfn_folio(base_pfn);
	if (!hugetlb_restructuring_cleanup_finish(first_folio, base_pfn,
						  original_order))
		return;

	h = hugetlb_order_to_hstate(original_order);
	hugetlb_vmemmap_optimize_folio(h, first_folio);
	__folio_put(first_folio);
}

static LLIST_HEAD(hugetlb_restructuring_cleanup_list);
static void hugetlb_restructuring_cleanup_workfn(struct work_struct *work);
static DECLARE_WORK(hugetlb_restructuring_cleanup_work,
			    hugetlb_restructuring_cleanup_workfn);
static struct workqueue_struct *hugetlb_restructuring_wq __ro_after_init;

static int __init hugetlb_restructuring_init(void)
{
	hugetlb_restructuring_wq = alloc_workqueue("hugetlb_restructuring",
						   WQ_MEM_RECLAIM | WQ_UNBOUND, 0);
	if (!hugetlb_restructuring_wq)
		return -ENOMEM;

	return 0;
}
subsys_initcall(hugetlb_restructuring_init);

static void hugetlb_restructuring_cleanup_workfn(struct work_struct *work)
{
	struct llist_node *node;

	while ((node = llist_del_all(&hugetlb_restructuring_cleanup_list))) {
		while (node) {
			struct llist_node *next = node->next;
			struct folio *folio;

			folio = container_of((struct address_space **)node,
					     struct folio, mapping);
			folio->mapping = NULL;
			hugetlb_restructuring_cleanup_folio(folio);
			node = next;
		}
	}
}

static void hugetlb_restructuring_defer_cleanup(struct folio *folio)
{
	struct llist_node *node;

	/* Reuse folio->mapping after the folio has left the page cache. */
	BUILD_BUG_ON(sizeof(folio->mapping) != sizeof(struct llist_node));
	if (WARN_ON_ONCE(folio->mapping))
		return;
	node = (struct llist_node *)&folio->mapping;

	if (llist_add(node, &hugetlb_restructuring_cleanup_list))
		queue_work(hugetlb_restructuring_wq,
			   &hugetlb_restructuring_cleanup_work);
}

static bool hugetlb_restructuring_mark_folio(struct folio *folio)
{
	struct hugetlb_restructuring_metadata *metadata;
	unsigned long pfn = folio_pfn(folio);
	unsigned long offset, nr_pages, total_pages;
	unsigned int order = folio_order(folio);
	bool marked = false;

	spin_lock_irq(&hugetlb_lock);
	metadata = __hugetlb_restructuring_metadata_get(pfn);
	if (!hugetlb_restructuring_metadata_valid(metadata) ||
	    order >= metadata->page_order || order >= BITS_PER_LONG ||
	    folio_test_large(folio) != !!order || folio_has_type(folio) ||
	    folio->mapping || folio_mapped(folio))
		goto out_unlock;

	total_pages = 1UL << metadata->page_order;
	nr_pages = 1UL << order;
	if (pfn < metadata->base_pfn)
		goto out_unlock;
	offset = pfn - metadata->base_pfn;
	if (!IS_ALIGNED(pfn, nr_pages) || offset >= total_pages ||
	    nr_pages > total_pages - offset)
		goto out_unlock;

	__folio_set_hugetlb_split(folio);
	marked = true;

out_unlock:
	spin_unlock_irq(&hugetlb_lock);
	return marked;
}

static void hugetlb_restructuring_quarantine_folio(struct folio *folio)
{
	spin_lock_irq(&hugetlb_lock);
	if (folio_test_hugetlb(folio))
		__folio_clear_hugetlb(folio);
	/* The unmapped folio cannot acquire a mapcount after final removal. */
	if (data_race(folio->page.page_type) == UINT_MAX)
		__folio_set_hugetlb_split(folio);
	spin_unlock_irq(&hugetlb_lock);
}

void hugetlb_split_handle_folio_put(struct folio *folio)
{
	if (WARN_ON_ONCE(!folio_test_hugetlb_split(folio) ||
			 folio_ref_count(folio)))
		return;

	/* folio_put() may run in interrupt context; merge in process context. */
	hugetlb_restructuring_defer_cleanup(folio);
}

void hugetlb_restructuring_free_folio(struct folio *folio)
{
	unsigned long base_pfn;
	u8 original_order;

	if (!hugetlb_restructuring_metadata_order(folio, &base_pfn,
						  &original_order))
		goto quarantine;

	if (folio_order(folio) == original_order) {
		if (folio_pfn(folio) == base_pfn &&
		    hugetlb_restructuring_metadata_restore(folio))
			return;
		goto quarantine;
	}

	if (hugetlb_restructuring_mark_folio(folio))
		return;

quarantine:
	WARN_ON_ONCE(1);
	hugetlb_restructuring_quarantine_folio(folio);
}
EXPORT_SYMBOL_FOR_MODULES(hugetlb_restructuring_free_folio, "kvm");
