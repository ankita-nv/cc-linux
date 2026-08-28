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
#include <linux/workqueue.h>
#include <linux/xarray.h>

#include "hugetlb_vmemmap.h"
#include "internal.h"

static DEFINE_XARRAY(hugetlb_restructuring_metadata);

static void hugetlb_restructuring_metadata_initialize(
	struct hugetlb_restructuring_metadata *metadata, struct folio *folio)
{
	metadata->page_order = folio_order(folio);
	metadata->spool = hugetlb_folio_subpool(folio);
	metadata->h_cg = hugetlb_cgroup_from_folio(folio);
	metadata->h_cg_rsvd = hugetlb_cgroup_from_folio_rsvd(folio);
	metadata->hugetlb_cma = folio_test_hugetlb_cma(folio);
	atomic_set(&metadata->nr_pages_waiting_to_be_merged, 0);
}

static void __hugetlb_restructuring_metadata_restore(
	struct folio *folio, struct hugetlb_restructuring_metadata *metadata)
{
	WARN_ON(!folio_test_hugetlb(folio));
	WARN_ON(folio_order(folio) != metadata->page_order);

	hugetlb_set_folio_subpool(folio, metadata->spool);
	set_hugetlb_cgroup(folio, metadata->h_cg);
	set_hugetlb_cgroup_rsvd(folio, metadata->h_cg_rsvd);
	if (metadata->hugetlb_cma)
		folio_set_hugetlb_cma(folio);
	else
		folio_clear_hugetlb_cma(folio);
}

static int hugetlb_restructuring_metadata_register(
	unsigned long pfn, struct hugetlb_restructuring_metadata *metadata)
{
	u8 order = metadata->page_order;
	void *entry;

	entry = xa_store_order(&hugetlb_restructuring_metadata, pfn, order,
			       metadata, GFP_KERNEL);

	WARN(entry, "Unexpected duplicate metadata registered");
	if (xa_is_err(entry))
		return xa_err(entry);

	return 0;
}

int hugetlb_restructuring_metadata_store(struct folio *folio)
{
	struct hugetlb_restructuring_metadata *metadata;

	metadata = kmalloc(sizeof(*metadata), GFP_KERNEL);
	if (!metadata)
		return -ENOMEM;

	hugetlb_restructuring_metadata_initialize(metadata, folio);
	return hugetlb_restructuring_metadata_register(folio_pfn(folio), metadata);
}
EXPORT_SYMBOL_FOR_MODULES(hugetlb_restructuring_metadata_store, "kvm");

void hugetlb_restructuring_metadata_restore(struct folio *folio)
{
	struct hugetlb_restructuring_metadata *metadata;
	unsigned long pfn = folio_pfn(folio);

	metadata = xa_erase(&hugetlb_restructuring_metadata, pfn);
	__hugetlb_restructuring_metadata_restore(folio, metadata);

	kfree(metadata);
}
EXPORT_SYMBOL_FOR_MODULES(hugetlb_restructuring_metadata_restore, "kvm");

struct hugetlb_restructuring_metadata *
hugetlb_restructuring_metadata_get(unsigned long pfn)
{
	return xa_load(&hugetlb_restructuring_metadata, pfn);
}
EXPORT_SYMBOL_FOR_MODULES(hugetlb_restructuring_metadata_get, "kvm");

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

static void hugetlb_restructuring_set_hugetlb(struct folio *folio)
{
	spin_lock_irq(&hugetlb_lock);
	__folio_set_hugetlb(folio);
	spin_unlock_irq(&hugetlb_lock);
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
	u8 boundary_order;

	boundary_order = ((current_order - 1) / XA_CHUNK_SHIFT) *
			 XA_CHUNK_SHIFT;
	return max(to_order, boundary_order);
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

static int merge_unreferenced_folio(struct folio *first_folio, u8 to_order)
{
	struct hstate *h;

	WARN_ON_ONCE(!IS_ALIGNED(first_folio->index, 1 << to_order));

	__merge_folio_to_order(first_folio, to_order);

	hugetlb_restructuring_set_hugetlb(first_folio);
	h = hugetlb_order_to_hstate(folio_order(first_folio));
	hugetlb_vmemmap_optimize_folio(h, first_folio);

	return 0;
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
	if (hugetlb_cleared)
		hugetlb_restructuring_set_hugetlb(folio);
	hugetlb_restructuring_unfreeze_folio(folio);
out_destroy:
	xas_destroy(&xas);
	return ret;
}

static int hugetlb_restructuring_split_range(struct address_space *mapping,
					     pgoff_t start, u8 original_order,
					     u8 to_order)
{
	pgoff_t end = start + (1UL << original_order);
	u8 current_order = original_order;

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
	u8 boundary_order;

	boundary_order = (current_order / XA_CHUNK_SHIFT + 1) *
			 XA_CHUNK_SHIFT;
	return min(to_order, boundary_order);
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
		    folio_has_type(child) || folio_mapped(child) ||
		    folio_test_lru(child))
			return -EINVAL;
		if (current_order > 1 &&
		    !list_empty(&child->_deferred_list))
			return -EINVAL;

		children[i] = child;
	}

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
		hugetlb_restructuring_set_hugetlb(children[0]);
		hugetlb_vmemmap_optimize_folio(h, children[0]);
	}

	hugetlb_restructuring_unfreeze_folio(children[0]);
	return 0;

out_unfreeze:
	while (nr_frozen) {
		nr_frozen--;
		hugetlb_restructuring_unfreeze_folio(children[nr_frozen]);
	}
	return ret;
}

static int hugetlb_restructuring_merge_range(struct address_space *mapping,
					     pgoff_t start, u8 original_order,
					     u8 from_order)
{
	pgoff_t end = start + (1UL << original_order);
	u8 current_order = from_order;

	while (current_order < original_order) {
		u8 next_order = hugetlb_restructuring_next_merge_order(
			current_order, original_order);
		pgoff_t index;

		for (index = start; index < end;
		     index += 1UL << next_order) {
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

			cond_resched();
		}

		current_order = next_order;
	}

	return 0;
}

int hugetlb_restructuring_restructure_folio(struct folio *folio, u8 to_order)
{
	struct hugetlb_restructuring_metadata *metadata;
	struct address_space *mapping = folio->mapping;
	unsigned long nr_pages;
	pgoff_t start;
	u8 original_order;

	if (!mapping)
		return -EINVAL;

	lockdep_assert_held_write(&mapping->invalidate_lock);

	metadata = hugetlb_restructuring_metadata_get(folio_pfn(folio));
	if (!metadata)
		return -EINVAL;

	original_order = metadata->page_order;
	if (original_order >= BITS_PER_LONG ||
	    !hugetlb_order_to_hstate(original_order))
		return -EINVAL;

	/* The conversion interface only needs fully split or original order. */
	if (to_order != 0 && to_order != original_order)
		return -EINVAL;

	if (folio_contain_hwpoisoned_page(folio))
		return -EHWPOISON;

	nr_pages = 1UL << original_order;
	start = round_down(folio->index, nr_pages);
	if (start + nr_pages < start)
		return -EINVAL;

	if (to_order == 0)
		return hugetlb_restructuring_split_range(mapping, start,
							 original_order, 0);

	return hugetlb_restructuring_merge_range(mapping, start,
						 original_order, 0);
}

EXPORT_SYMBOL_FOR_MODULES(hugetlb_restructuring_restructure_folio, "kvm");

static struct folio *maybe_merge_unreferenced_folio(struct folio *folio)
{
	struct hugetlb_restructuring_metadata *metadata;
	size_t nr_pages_waiting_to_be_merged;
	unsigned long first_folio_pfn;
	struct folio *first_folio;
	size_t original_nr_pages;
	u8 original_order;
	int ret;

	unsigned long pfn = folio_pfn(folio);
	metadata = hugetlb_restructuring_metadata_get(pfn);
	original_order = metadata->page_order;
	original_nr_pages = 1 << original_order;

	nr_pages_waiting_to_be_merged = atomic_add_return(
		folio_nr_pages(folio), &metadata->nr_pages_waiting_to_be_merged);
	if (nr_pages_waiting_to_be_merged < original_nr_pages)
		return NULL;

	first_folio_pfn = round_down(pfn, original_nr_pages);
	first_folio = pfn_folio(first_folio_pfn);

	ret = merge_unreferenced_folio(first_folio, original_order);
	if (ret) {
		WARN_ONCE(ret, "Error merging unreferenced folio.");
		return ERR_PTR(ret);
	}

	return first_folio;
}

static void hugetlb_restructuring_cleanup_folio(struct folio *folio)
{
	struct folio *merged_folio = maybe_merge_unreferenced_folio(folio);

	if (!IS_ERR_OR_NULL(merged_folio)) {
		hugetlb_restructuring_metadata_restore(merged_folio);
		__folio_put(merged_folio);
	}
}

struct workqueue_struct *hugetlb_restructuring_wq __ro_after_init;
static struct work_struct hugetlb_restructuring_cleanup_work;
static LLIST_HEAD(hugetlb_restructuring_cleanup_list);

static void hugetlb_restructuring_cleanup_workfn(struct work_struct *work)
{
	struct llist_node *node = llist_del_all(&hugetlb_restructuring_cleanup_list);

	while (node) {
		struct folio *folio;

		folio = container_of((struct address_space **)node,
				     struct folio, mapping);

		node = node->next;
		folio->mapping = NULL;

		hugetlb_restructuring_cleanup_folio(folio);
	}
}

static int __init hugetlb_restructuring_init(void)
{
	INIT_WORK(&hugetlb_restructuring_cleanup_work, hugetlb_restructuring_cleanup_workfn);

	hugetlb_restructuring_wq = alloc_workqueue("hugetlb_restructuring",
						   WQ_MEM_RECLAIM | WQ_UNBOUND, 0);
	if (!hugetlb_restructuring_wq)
		return -ENOMEM;

	return 0;
}
subsys_initcall(hugetlb_restructuring_init);

static void hugetlb_restructuring_mark_folio(struct folio *folio)
{
	/*
	 * Clear HugeTLB page type (if it is set) temporarily to make way for
	 * guestmem_hugetlb page type.
	 */
	__folio_clear_hugetlb(folio);
	__folio_set_hugetlb_split(folio);
}

static void hugetlb_restructuring_unmark_folio(struct folio *folio)
{
	__folio_clear_hugetlb_split(folio);

	/* Restore invariant ahead of merging later. */
	if (folio_order(folio) > 0)
		__folio_set_hugetlb(folio);
}

static void hugetlb_restructuring_defer_cleanup(struct folio *folio)
{
	struct llist_node *node;

	/*
	 * Reuse the folio->mapping pointer as a struct llist_node, since
	 * folio->mapping is NULL at this point.
	 */
	BUILD_BUG_ON(sizeof(folio->mapping) != sizeof(struct llist_node));
	node = (struct llist_node *)&folio->mapping;

	/*
	 * Only schedule work if list is previously empty. Otherwise,
	 * schedule_work() had been called but the workfn hasn't retrieved the
	 * list yet.
	 */
	if (llist_add(node, &hugetlb_restructuring_cleanup_list))
		queue_work(hugetlb_restructuring_wq, &hugetlb_restructuring_cleanup_work);
}

void hugetlb_split_handle_folio_put(struct folio *folio)
{
	hugetlb_restructuring_unmark_folio(folio);

	/*
	 * folio_put() can be called in interrupt context, hence do the work
	 * outside of interrupt context
	 */
	hugetlb_restructuring_defer_cleanup(folio);
}

void hugetlb_restructuring_free_folio(struct folio *folio)
{
	struct hugetlb_restructuring_metadata *metadata;
	unsigned long pfn = folio_pfn(folio);

	metadata = hugetlb_restructuring_metadata_get(pfn);

	if (folio_order(folio) == metadata->page_order)
		hugetlb_restructuring_metadata_restore(folio);
	else
		hugetlb_restructuring_mark_folio(folio);
}
