#ifndef __KVM_GUEST_MEMFD_HUGETLB_H__
#define __KVM_GUEST_MEMFD_HUGETLB_H__

#include <linux/err.h>
#include <linux/mm_types.h>
#include <linux/types.h>

#ifdef CONFIG_KVM_GUEST_MEMFD_HUGETLB

#include <linux/hugetlb_restructuring.h>

bool gmem_hugetlb_valid_order(u8 order);
int gmem_hugetlb_init(struct inode *inode, u64 flags, size_t size,
		      u8 page_order);
void gmem_hugetlb_teardown(struct inode *inode, u8 page_order, u64 flags);
struct folio *gmem_hugetlb_alloc_folio(void *priv, u8 page_order,
				       struct mempolicy *mpol);

static inline void gmem_hugetlb_free_folio(struct folio *folio)
{
	hugetlb_restructuring_free_folio(folio);
}

int gmem_hugetlb_restructure_folio(struct address_space *mapping,
				   pgoff_t index, u8 to_order);

#else

static inline bool gmem_hugetlb_valid_order(u8 order)
{
	return false;
}

static inline int gmem_hugetlb_init(struct inode *inode, u64 flags,
				    size_t size, u8 page_order)
{
	return 0;
}

static inline void gmem_hugetlb_teardown(struct inode *inode, u8 page_order,
					 u64 flags)
{
}

static inline struct folio *gmem_hugetlb_alloc_folio(
		void *priv, u8 page_order, struct mempolicy *mpol)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void gmem_hugetlb_free_folio(struct folio *folio) {}

static inline int gmem_hugetlb_restructure_folio(struct address_space *mapping,
						 pgoff_t index, u8 to_order)
{
	WARN_ONCE(true, "Unexpected call to gmem_hugetlb_restructure_folio().");
	return -EOPNOTSUPP;
}

#endif /* CONFIG_KVM_GUEST_MEMFD_HUGETLB */

#endif
