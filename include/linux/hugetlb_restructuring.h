#ifndef _LINUX_HUGETLB_RESTRUCTURING_H
#define _LINUX_HUGETLB_RESTRUCTURING_H

#include <linux/errno.h>
#include <linux/types.h>

struct folio;
struct hugetlb_cgroup;

#ifdef CONFIG_HUGETLB_RESTRUCTURING

int hugetlb_restructuring_metadata_store(struct folio *folio);
void hugetlb_restructuring_metadata_abort(struct folio *folio);

int hugetlb_restructuring_restructure_folio(struct folio *folio, u8 to_order);
void hugetlb_split_handle_folio_put(struct folio *folio);
void hugetlb_restructuring_free_folio(struct folio *folio);

bool hugetlb_restructuring_cgroup_get(struct folio *folio,
				     struct hugetlb_cgroup **h_cg,
				     unsigned long *nr_pages);
void hugetlb_restructuring_cgroup_set(struct folio *folio,
				     struct hugetlb_cgroup *h_cg);

#else

static inline int hugetlb_restructuring_metadata_store(struct folio *folio)
{
	return -EOPNOTSUPP;
}

static inline void hugetlb_restructuring_metadata_abort(struct folio *folio)
{
}

static inline int hugetlb_restructuring_restructure_folio(struct folio *folio,
						   u8 to_order)
{
	return -EOPNOTSUPP;
}

static inline void hugetlb_split_handle_folio_put(struct folio *folio)
{
}

static inline void hugetlb_restructuring_free_folio(struct folio *folio)
{
}

static inline bool
hugetlb_restructuring_cgroup_get(struct folio *folio,
				struct hugetlb_cgroup **h_cg,
				unsigned long *nr_pages)
{
	return false;
}

static inline void
hugetlb_restructuring_cgroup_set(struct folio *folio,
				struct hugetlb_cgroup *h_cg)
{
}

#endif /* CONFIG_HUGETLB_RESTRUCTURING */

#endif  /* _LINUX_HUGETLB_RESTRUCTURING_H */
