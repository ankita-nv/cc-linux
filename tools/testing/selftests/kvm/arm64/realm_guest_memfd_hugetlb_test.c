// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test HugeTLB-backed guest_memfd conversion for Arm CCA Realms.
 *
 * Realm guest_memfd mappings start private.  Shared memory is exposed by
 * converting ranges through the guest_memfd file descriptor; INIT_SHARED is
 * intentionally not used because it is unsupported for Realms.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/falloc.h>
#include <linux/kvm.h>
#include <linux/sizes.h>
#include <sys/mman.h>
#include <unistd.h>

#include "kvm_syscalls.h"
#include "kvm_util.h"
#include "test_util.h"

#define REALM_IPA_BITS	40
#define TEST_GPA	SZ_4G
#define TEST_SLOT	1

static bool is_target_hugetlb_order(u8 order)
{
	size_t size = (size_t)getpagesize() << order;

	return size == SZ_2M || size == SZ_1G;
}

static bool hugepage_pool_unavailable(int error)
{
	return error == ENOMEM || error == ENOSPC || error == EDQUOT;
}

static int create_realm_vm(int kvm_fd)
{
	unsigned long type = KVM_VM_TYPE_ARM_REALM |
			     KVM_VM_TYPE_ARM_IPA_SIZE(REALM_IPA_BITS);
	int vm_fd;

	vm_fd = __kvm_ioctl(kvm_fd, KVM_CREATE_VM, (void *)type);
	TEST_ASSERT(vm_fd >= 0, KVM_IOCTL_ERROR(KVM_CREATE_VM, vm_fd));

	return vm_fd;
}

static void bind_guest_memfd(int vm_fd, int gmem_fd, void *mem, size_t size)
{
	struct kvm_userspace_memory_region2 region = {
		.slot = TEST_SLOT,
		.flags = KVM_MEM_GUEST_MEMFD,
		.guest_phys_addr = TEST_GPA,
		.memory_size = size,
		.userspace_addr = (uintptr_t)mem,
		.guest_memfd = gmem_fd,
		.guest_memfd_offset = 0,
	};
	int ret;

	ret = __kvm_ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION2, &region);
	TEST_ASSERT(ret == 0, KVM_IOCTL_ERROR(KVM_SET_USER_MEMORY_REGION2, ret));
}

static void unbind_guest_memfd(int vm_fd)
{
	struct kvm_userspace_memory_region2 region = {
		.slot = TEST_SLOT,
	};
	int ret;

	ret = __kvm_ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION2, &region);
	TEST_ASSERT(ret == 0, KVM_IOCTL_ERROR(KVM_SET_USER_MEMORY_REGION2, ret));
}

static bool test_hugetlb_order(int vm_fd, u8 order)
{
	const size_t base_page_size = getpagesize();
	const size_t hugepage_size = base_page_size << order;
	struct kvm_create_guest_memfd create = {
		.size = hugepage_size,
		.flags = GUEST_MEMFD_FLAG_MMAP | GUEST_MEMFD_FLAG_HUGETLB,
		.page_order = order,
	};
	char *mem;
	int gmem_fd;
	int ret;

	gmem_fd = __kvm_ioctl(vm_fd, KVM_CREATE_GUEST_MEMFD, &create);
	if (gmem_fd < 0 && hugepage_pool_unavailable(errno))
		return false;
	TEST_ASSERT(gmem_fd >= 0, KVM_IOCTL_ERROR(KVM_CREATE_GUEST_MEMFD,
						    gmem_fd));

	/*
	 * Fault the HugeTLB folio in explicitly.  This separates a missing
	 * hugepage pool from failures in the conversion path under test.
	 */
	ret = fallocate(gmem_fd, FALLOC_FL_KEEP_SIZE, 0, hugepage_size);
	if (ret && hugepage_pool_unavailable(errno)) {
		close(gmem_fd);
		return false;
	}
	TEST_ASSERT(ret == 0, __KVM_SYSCALL_ERROR("fallocate()", ret));

	mem = kvm_mmap(hugepage_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		       gmem_fd);

	bind_guest_memfd(vm_fd, gmem_fd, mem, hugepage_size);

	/* A Realm guest_memfd is initially private and inaccessible to host. */
	TEST_EXPECT_SIGBUS(READ_ONCE(mem[0]));

	/*
	 * Share one base page.  The adjacent page must remain private even
	 * though both started in the same HugeTLB folio.
	 */
	gmem_set_shared(gmem_fd, 0, base_page_size);
	TEST_ASSERT_EQ(READ_ONCE(mem[0]), 0);
	WRITE_ONCE(mem[0], 0x5a);
	TEST_EXPECT_SIGBUS(READ_ONCE(mem[base_page_size]));

	/* Convert back to private, then share again and verify data survived. */
	gmem_set_private(gmem_fd, 0, base_page_size);
	TEST_EXPECT_SIGBUS(READ_ONCE(mem[0]));
	gmem_set_shared(gmem_fd, 0, base_page_size);
	TEST_ASSERT_EQ(READ_ONCE(mem[0]), 0x5a);

	/* Leave the guest_memfd fully private and mergeable at teardown. */
	gmem_set_private(gmem_fd, 0, base_page_size);
	TEST_EXPECT_SIGBUS(READ_ONCE(mem[0]));

	unbind_guest_memfd(vm_fd);
	kvm_munmap(mem, hugepage_size);
	close(gmem_fd);

	return true;
}

int main(void)
{
	const u64 required_flags = GUEST_MEMFD_FLAG_MMAP |
				   GUEST_MEMFD_FLAG_HUGETLB;
	u64 realm_flags, realm_attrs;
	unsigned int nr_orders = 0;
	int cap, kvm_fd, vm_fd;
	u8 order;

	TEST_REQUIRE(kvm_check_cap(KVM_CAP_ARM_RMI));
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_ARM_VM_IPA_SIZE) >= REALM_IPA_BITS);
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_USER_MEMORY2));
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_GUEST_MEMFD));

	kvm_fd = open_path_or_exit(KVM_DEV_PATH, O_RDWR);
	vm_fd = create_realm_vm(kvm_fd);

	cap = __kvm_ioctl(vm_fd, KVM_CHECK_EXTENSION,
			  (void *)KVM_CAP_GUEST_MEMFD_FLAGS);
	TEST_ASSERT(cap >= 0, KVM_IOCTL_ERROR(KVM_CHECK_EXTENSION, cap));
	realm_flags = cap;
	TEST_REQUIRE((realm_flags & required_flags) == required_flags);
	TEST_ASSERT(!(realm_flags & GUEST_MEMFD_FLAG_INIT_SHARED),
		    "Realm unexpectedly supports GUEST_MEMFD_FLAG_INIT_SHARED");

	cap = __kvm_ioctl(vm_fd, KVM_CHECK_EXTENSION,
			  (void *)KVM_CAP_GUEST_MEMFD_MEMORY_ATTRIBUTES);
	TEST_ASSERT(cap >= 0, KVM_IOCTL_ERROR(KVM_CHECK_EXTENSION, cap));
	realm_attrs = cap;
	TEST_REQUIRE(realm_attrs & KVM_MEMORY_ATTRIBUTE_PRIVATE);

	for_each_valid_hugetlb_page_order(order) {
		if (is_target_hugetlb_order(order))
			nr_orders++;
	}
	if (!nr_orders)
		ksft_exit_skip("No 2M or 1G HugeTLB hstate is available\n");

	ksft_print_header();
	ksft_set_plan(nr_orders);

	for_each_valid_hugetlb_page_order(order) {
		size_t hugepage_size;

		if (!is_target_hugetlb_order(order))
			continue;

		hugepage_size = (size_t)getpagesize() << order;
		if (!test_hugetlb_order(vm_fd, order)) {
			ksft_test_result_skip("No free/reservable %zu-byte HugeTLB page\n",
					      hugepage_size);
			continue;
		}

		ksft_test_result_pass("Realm guest_memfd HugeTLB order %u (%zu bytes)\n",
				      order, hugepage_size);
	}

	close(vm_fd);
	close(kvm_fd);
	ksft_finished();
}
