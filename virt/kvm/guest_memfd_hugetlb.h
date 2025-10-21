#ifndef __KVM_GUEST_MEMFD_HUGETLB_H__
#define __KVM_GUEST_MEMFD_HUGETLB_H__

#include <linux/types.h>

#ifdef CONFIG_KVM_GUEST_MEMFD_HUGETLB

bool gmem_hugetlb_valid_order(u8 order);

#else

static inline bool gmem_hugetlb_valid_order(u8 order)
{
	return false;
}

#endif /* CONFIG_KVM_GUEST_MEMFD_HUGETLB */

#endif
