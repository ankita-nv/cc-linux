// SPDX-License-Identifier: GPL-2.0-only
/*
 * Physically contiguous RAM block device for platform backdoor loading.
 *
 * Usage:
 *
 *     modprobe bdram
 *     echo 67108864 > /sys/module/bdram/parameters/size_bytes
 *     cat /sys/block/bdram0/physical_range
 *     blockdev --flushbufs /dev/bdram0
 *     echo 1 > /sys/block/bdram0/flush_cache
 *
 *     # Perform and complete the platform backdoor load.
 *
 *     echo 1 > /sys/block/bdram0/invalidate_cache
 *     blockdev --flushbufs /dev/bdram0
 *     blockdev --rereadpt /dev/bdram0
 *
 * The device and its partitions must be closed before destroying it:
 *
 *     echo 0 > /sys/module/bdram/parameters/size_bytes
 *
 * The device can also be created while loading the module:
 *
 *     modprobe bdram size_bytes=67108864
 */

#include <linux/bio.h>
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/libnvdimm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/numa.h>

#define BDRAM_NAME	"bdram"
#define BDRAM_DISK_NAME	"bdram0"
#define BDRAM_MINORS	16

struct bdram_device {
	struct gendisk *disk;
	struct page *pages;
	void *virt_addr;
	phys_addr_t phys_addr;
	size_t size;
	unsigned long nr_pages;
	int major;
};

static struct bdram_device bdram;
static unsigned long size_bytes;
static bool initialized;
static bool transitioning;
static bool destroying;
static unsigned int active_users;
static DEFINE_MUTEX(bdram_lock);

static int bdram_get(struct gendisk *disk)
{
	int rc = 0;

	mutex_lock(&bdram_lock);
	if (destroying || bdram.disk != disk)
		rc = -ENODEV;
	else
		active_users++;
	mutex_unlock(&bdram_lock);
	return rc;
}

static void bdram_put(void)
{
	mutex_lock(&bdram_lock);
	WARN_ON_ONCE(!active_users);
	if (active_users)
		active_users--;
	mutex_unlock(&bdram_lock);
}

static void bdram_zero(struct bdram_device *bram,
		       sector_t sector, unsigned int bytes)
{
	memset(bram->virt_addr + (sector << SECTOR_SHIFT), 0, bytes);
}

static void bdram_submit_bio(struct bio *bio)
{
	struct bdram_device *bram = bio->bi_bdev->bd_disk->private_data;
	sector_t sector = bio->bi_iter.bi_sector;
	struct bio_vec bvec;
	struct bvec_iter iter;
	void *buffer;
	size_t offset;

	if (bio_end_sector(bio) > get_capacity(bram->disk)) {
		bio_io_error(bio);
		return;
	}

	switch (bio_op(bio)) {
	case REQ_OP_FLUSH:
		break;
	case REQ_OP_DISCARD:
	case REQ_OP_WRITE_ZEROES:
		bdram_zero(bram, sector, bio->bi_iter.bi_size);
		break;
	case REQ_OP_READ:
	case REQ_OP_WRITE:
		bio_for_each_segment(bvec, bio, iter) {
			offset = sector << SECTOR_SHIFT;
			buffer = bvec_kmap_local(&bvec);
			if (op_is_write(bio_op(bio)))
				memcpy(bram->virt_addr + offset, buffer,
				       bvec.bv_len);
			else
				memcpy(buffer, bram->virt_addr + offset,
				       bvec.bv_len);
			kunmap_local(buffer);
			sector += bvec.bv_len >> SECTOR_SHIFT;
		}
		break;
	default:
		bio->bi_status = BLK_STS_NOTSUPP;
		break;
	}

	bio_endio(bio);
}

static int bdram_open(struct gendisk *disk, blk_mode_t mode)
{
	return bdram_get(disk);
}

static void bdram_release(struct gendisk *disk)
{
	bdram_put();
}

static const struct block_device_operations bdram_fops = {
	.owner		= THIS_MODULE,
	.open		= bdram_open,
	.release	= bdram_release,
	.submit_bio	= bdram_submit_bio,
};

/*
 * /sys/block/bdram0/physical_range
 *
 * Report the physical start address and size in bytes for the backdoor
 * loader. Both values are hexadecimal.
 */
static ssize_t physical_range_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct gendisk *disk = dev_to_disk(dev);
	struct bdram_device *bram = disk->private_data;
	phys_addr_t phys_addr;
	size_t size;
	ssize_t len;

	mutex_lock(&bdram_lock);
	if (destroying || bram->disk != disk) {
		mutex_unlock(&bdram_lock);
		return -ENODEV;
	}
	phys_addr = bram->phys_addr;
	size = bram->size;
	mutex_unlock(&bdram_lock);

	len = sysfs_emit(buf, "%-18s %s\n", "start", "size");
	len += sysfs_emit_at(buf, len, "%pa %#zx\n", &phys_addr, size);
	return len;
}
static DEVICE_ATTR_RO(physical_range);

static ssize_t bdram_cache_store(struct device *dev, const char *buf,
				 size_t len, bool invalidate)
{
	struct gendisk *disk = dev_to_disk(dev);
	struct bdram_device *bram = disk->private_data;
	unsigned int memflags;
	bool trigger;
	int rc;

	rc = kstrtobool(buf, &trigger);
	if (rc)
		return rc;
	if (!trigger)
		return -EINVAL;
	rc = bdram_get(disk);
	if (rc)
		return rc;

	mutex_lock(&disk->open_mutex);
	if (disk_openers(disk)) {
		rc = -EBUSY;
		goto out_unlock;
	}

	memflags = blk_mq_freeze_queue(disk->queue);
	if (invalidate)
		arch_invalidate_pmem(bram->virt_addr, bram->size);
	else
		arch_wb_cache_pmem(bram->virt_addr, bram->size);
	blk_mq_unfreeze_queue(disk->queue, memflags);
	rc = len;

out_unlock:
	mutex_unlock(&disk->open_mutex);
	bdram_put();
	return rc;
}

/*
 * /sys/block/bdram0/flush_cache
 *
 * Write 1 before the backdoor load starts. Userspace must first flush the
 * block cache. This cleans dirty CPU cache lines to the backing memory so
 * they cannot overwrite data subsequently loaded through the backdoor.
 */
static ssize_t flush_cache_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t len)
{
	return bdram_cache_store(dev, buf, len, false);
}
static DEVICE_ATTR_WO(flush_cache);

/*
 * /sys/block/bdram0/invalidate_cache
 *
 * Write 1 after the backdoor load completes. The device must not be open or
 * mounted. Block-device page-cache invalidation remains a userspace step.
 */
static ssize_t invalidate_cache_store(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf, size_t len)
{
	return bdram_cache_store(dev, buf, len, true);
}
static DEVICE_ATTR_WO(invalidate_cache);

static struct attribute *bdram_attributes[] = {
	&dev_attr_physical_range.attr,
	&dev_attr_flush_cache.attr,
	&dev_attr_invalidate_cache.attr,
	NULL,
};

static const struct attribute_group bdram_attribute_group = {
	.attrs = bdram_attributes,
};

static const struct attribute_group *bdram_attribute_groups[] = {
	&bdram_attribute_group,
	NULL,
};

static int bdram_create(unsigned long requested_size_bytes)
{
	struct bdram_device *bram = &bdram;
	struct queue_limits lim;
	unsigned long i;
	int rc;

	lim = (struct queue_limits) {
		.logical_block_size		= SECTOR_SIZE,
		.physical_block_size		= PAGE_SIZE,
		.max_hw_sectors			= UINT_MAX,
		.max_hw_discard_sectors		= UINT_MAX,
		.max_write_zeroes_sectors	= UINT_MAX,
		.max_discard_segments		= 1,
		.discard_granularity		= PAGE_SIZE,
		.features			= BLK_FEAT_SYNCHRONOUS,
	};

	if (!requested_size_bytes ||
	    !IS_ALIGNED(requested_size_bytes, SECTOR_SIZE))
		return -EINVAL;
	bram->size = requested_size_bytes;
	bram->nr_pages = bram->size >> PAGE_SHIFT;
	if (bram->size & ~PAGE_MASK)
		bram->nr_pages++;

	bram->pages = alloc_contig_pages(bram->nr_pages, GFP_KERNEL,
					 first_online_node, NULL);
	if (!bram->pages)
		return -ENOMEM;

	for (i = 0; i < bram->nr_pages; i++) {
		clear_highpage(bram->pages + i);
		cond_resched();
	}
	bram->virt_addr = page_address(bram->pages);
	bram->phys_addr = page_to_phys(bram->pages);
	arch_wb_cache_pmem(bram->virt_addr, bram->size);

	bram->major = register_blkdev(0, BDRAM_NAME);
	if (bram->major < 0) {
		rc = bram->major;
		goto out_free_pages;
	}

	bram->disk = blk_alloc_disk(&lim, NUMA_NO_NODE);
	if (IS_ERR(bram->disk)) {
		rc = PTR_ERR(bram->disk);
		goto out_unregister_blkdev;
	}

	bram->disk->major = bram->major;
	bram->disk->first_minor = 0;
	bram->disk->minors = BDRAM_MINORS;
	bram->disk->fops = &bdram_fops;
	bram->disk->private_data = bram;
	strscpy(bram->disk->disk_name, BDRAM_DISK_NAME,
		DISK_NAME_LEN);
	set_capacity(bram->disk, bram->size >> SECTOR_SHIFT);

	rc = device_add_disk(NULL, bram->disk,
			     bdram_attribute_groups);
	if (rc)
		goto out_put_disk;

	pr_info("%s: %zu bytes (%#zx) at %pa\n", BDRAM_DISK_NAME,
		bram->size, bram->size, &bram->phys_addr);
	return 0;

out_put_disk:
	put_disk(bram->disk);
out_unregister_blkdev:
	unregister_blkdev(bram->major, BDRAM_NAME);
out_free_pages:
	free_contig_range(page_to_pfn(bram->pages), bram->nr_pages);
	return rc;
}

static int bdram_destroy(void)
{
	struct bdram_device *bram = &bdram;
	struct gendisk *disk = bram->disk;

	mutex_lock(&disk->open_mutex);
	if (disk_openers(disk)) {
		mutex_unlock(&disk->open_mutex);
		return -EBUSY;
	}
	mutex_unlock(&disk->open_mutex);

	del_gendisk(disk);
	put_disk(disk);
	unregister_blkdev(bram->major, BDRAM_NAME);
	free_contig_range(page_to_pfn(bram->pages), bram->nr_pages);
	bram->disk = NULL;
	bram->pages = NULL;
	bram->virt_addr = NULL;
	bram->size = 0;
	bram->nr_pages = 0;
	bram->major = 0;
	return 0;
}

static int bdram_change_size(unsigned long requested_size_bytes)
{
	int rc = 0;

	mutex_lock(&bdram_lock);
	if (transitioning) {
		rc = -EBUSY;
		goto out_unlock;
	}
	if (requested_size_bytes == size_bytes)
		goto out_unlock;

	if (size_bytes && requested_size_bytes) {
		rc = -EBUSY;
		goto out_unlock;
	}
	if (!requested_size_bytes && active_users) {
		rc = -EBUSY;
		goto out_unlock;
	}

	transitioning = true;
	destroying = !requested_size_bytes;
	mutex_unlock(&bdram_lock);

	if (requested_size_bytes)
		rc = bdram_create(requested_size_bytes);
	else
		rc = bdram_destroy();

	mutex_lock(&bdram_lock);
	if (!rc)
		size_bytes = requested_size_bytes;
	destroying = false;
	transitioning = false;
out_unlock:
	mutex_unlock(&bdram_lock);
	return rc;
}

static int bdram_set_size(const char *val,
			  const struct kernel_param *kp)
{
	unsigned long requested_size_bytes;
	int rc;

	rc = kstrtoul(val, 0, &requested_size_bytes);
	if (rc)
		return rc;
	if (requested_size_bytes &&
	    !IS_ALIGNED(requested_size_bytes, SECTOR_SIZE))
		return -EINVAL;
	if (!initialized) {
		size_bytes = requested_size_bytes;
		return 0;
	}

	return bdram_change_size(requested_size_bytes);
}

static const struct kernel_param_ops bdram_size_ops = {
	.set = bdram_set_size,
	.get = param_get_ulong,
};

module_param_cb(size_bytes, &bdram_size_ops, &size_bytes, 0644);
MODULE_PARM_DESC(size_bytes,
		 "Block device size in bytes (0 destroys it)");

static int __init bdram_init(void)
{
	unsigned long requested_size_bytes;

	mutex_lock(&bdram_lock);
	initialized = true;
	requested_size_bytes = size_bytes;
	size_bytes = 0;
	mutex_unlock(&bdram_lock);

	if (requested_size_bytes)
		return bdram_change_size(requested_size_bytes);
	return 0;
}

static void __exit bdram_exit(void)
{
	mutex_lock(&bdram_lock);
	initialized = false;
	if (!size_bytes) {
		mutex_unlock(&bdram_lock);
		return;
	}
	destroying = true;
	mutex_unlock(&bdram_lock);

	WARN_ON_ONCE(bdram_destroy());
}

module_init(bdram_init);
module_exit(bdram_exit);

MODULE_AUTHOR("Shanker Donthineni <sdonthineni@nvidia.com>");
MODULE_DESCRIPTION("Physically contiguous RAM block device");
MODULE_LICENSE("GPL");
