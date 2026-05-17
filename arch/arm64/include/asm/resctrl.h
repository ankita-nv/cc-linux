/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_RESCTRL_H
#define _ASM_ARM64_RESCTRL_H

#include <linux/arm_mpam.h>

struct rdt_domain_hdr *resctrl_arch_find_domain(struct list_head *domain_list,
						int id);

#endif /* _ASM_ARM64_RESCTRL_H */
