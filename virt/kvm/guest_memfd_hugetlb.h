#ifndef __KVM_GUEST_MEMFD_HUGETLB_H__
#define __KVM_GUEST_MEMFD_HUGETLB_H__

#include <linux/mm_types.h>
#include <linux/types.h>

#ifdef CONFIG_KVM_GUEST_MEMFD_HUGETLB

bool gmem_hugetlb_valid_order(u8 order);
int gmem_hugetlb_init(struct inode *inode, u64 flags, size_t size,
		      u8 page_order);

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

#endif /* CONFIG_KVM_GUEST_MEMFD_HUGETLB */

#endif
