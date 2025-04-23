// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/blkdev.h>
#include <linux/dax.h>
#include <linux/vmalloc.h>
#include <linux/pfn_t.h>
#include <linux/parser.h>

#include "cache_dev.h"

static void cache_dev_dax_exit(struct pcache_cache_dev *cache_dev)
{
	if (cache_dev->dax_dev)
		fs_put_dax(cache_dev->dax_dev, cache_dev);

	if (cache_dev->bdev_file)
		fput(cache_dev->bdev_file);
}

static int cache_dev_dax_notify_failure(struct dax_device *dax_dev, u64 offset,
				  u64 len, int mf_flags)
{

	pr_err("%s: dax_dev %llx offset %llx len %lld mf_flags %x\n",
	       __func__, (u64)dax_dev, (u64)offset, (u64)len, mf_flags);

	return -EOPNOTSUPP;
}

const struct dax_holder_operations cache_dev_dax_holder_ops = {
	.notify_failure		= cache_dev_dax_notify_failure,
};

static int cache_dev_dax_init(struct pcache_cache_dev *cache_dev, char *path)
{
	struct dax_device *dax_dev = NULL;
	struct file *bdev_file = NULL;
	struct block_device *bdev;
	long total_pages, mapped_pages;
	u64 bdev_size, start_off = 0;
	struct page **pages = NULL;
	void *vaddr = NULL;
	int ret, id;
	pfn_t pfn;
	long i = 0;

	/* Open block device */
	bdev_file = bdev_file_open_by_path(path, BLK_OPEN_READ | BLK_OPEN_WRITE, cache_dev, NULL);
	if (IS_ERR(bdev_file)) {
		ret = PTR_ERR(bdev_file);
		pcache_err("failed to open bdev %s, err=%d\n", path, ret);
		goto err;
	}

	/* Get block device structure */
	bdev = file_bdev(bdev_file);
	if (!bdev) {
		ret = -EINVAL;
		pcache_err("failed to get bdev from file\n");
		goto fput;
	}

	/* Get total device size */
	bdev_size = bdev_nr_bytes(bdev);
	if (bdev_size == 0) {
		ret = -ENODEV;
		pcache_err("device %s has zero size\n", path);
		goto fput;
	}

	/* Convert device size to total pages */
	total_pages = bdev_size >> PAGE_SHIFT;

	/* Get the DAX device */
	dax_dev = fs_dax_get_by_bdev(bdev, &start_off, cache_dev, &cache_dev_dax_holder_ops);
	if (IS_ERR(dax_dev)) {
		ret = PTR_ERR(dax_dev);
		pcache_err("failed to get dax_dev from bdev, err=%d\n", ret);
		goto fput;
	}

	/* Lock DAX access */
	id = dax_read_lock();

	/* Try to access the entire device memory */
	mapped_pages = dax_direct_access(dax_dev, 0, total_pages, DAX_ACCESS, &vaddr, &pfn);
	if (mapped_pages < 0) {
		pcache_err("dax_direct_access failed, err=%ld\n", mapped_pages);
		ret = mapped_pages;
		goto unlock;
	}

	if (!pfn_t_has_page(pfn)) {
		pcache_err("pfn_t does not have a valid page mapping\n");
		ret = -EOPNOTSUPP;
		goto unlock;
	}

	/* If all pages are mapped in one go, use direct mapping */
	if (mapped_pages == total_pages) {
		cache_dev->sb_addr = (struct pcache_sb *)vaddr;
	} else {
		/* Use vmap() to create a contiguous mapping */
		long chunk_size;

		pcache_debug("partial mapping, using vmap\n");

		pages = vmalloc_array(total_pages, sizeof(struct page *));
		if (!pages) {
			ret = -ENOMEM;
			goto unlock;
		}

		i = 0;
		do {
			/* Access each page range in DAX */
			chunk_size = dax_direct_access(dax_dev, i, total_pages - i, DAX_ACCESS, NULL, &pfn);
			if (chunk_size <= 0) {
				ret = chunk_size ? chunk_size : -EINVAL;
				goto vfree;
			}

			if (!pfn_t_has_page(pfn)) {
				ret = -EOPNOTSUPP;
				goto vfree;
			}

			/* Store pages in the array for vmap */
			while (chunk_size-- && i < total_pages) {
				pages[i++] = pfn_t_to_page(pfn);
				pfn.val++;
				if (!(i & 15))
					cond_resched();
			}
		} while (i < total_pages);

		/* Map all pages into a contiguous virtual address */
		vaddr = vmap(pages, total_pages, VM_MAP, PAGE_KERNEL);
		if (!vaddr) {
			pcache_err("vmap failed");
			ret = -ENOMEM;
			goto vfree;
		}

		vfree(pages);
		cache_dev->sb_addr = (struct pcache_sb *)vaddr;
	}

	/* Unlock and store references */
	dax_read_unlock(id);

	cache_dev->bdev_file = bdev_file;
	cache_dev->dax_dev = dax_dev;
	cache_dev->bdev = bdev;

	return 0;

vfree:
	vfree(pages);
unlock:
	dax_read_unlock(id);
	fs_put_dax(dax_dev, cache_dev);
fput:
	fput(bdev_file);
err:
	return ret;
}

void cache_dev_flush(struct pcache_cache_dev *cache_dev, void *pos, u32 size)
{
	dax_flush(cache_dev->dax_dev, pos, size);
}

void cache_dev_zero_range(struct pcache_cache_dev *cache_dev, void *pos, u32 size)
{
	memset(pos, 0, size);
	cache_dev_flush(cache_dev, pos, size);
}

static int cache_dev_format(struct pcache_cache_dev *cache_dev)
{
	struct pcache_sb *sb = cache_dev->sb_addr;
	u64 nr_segs;
	u64 cache_dev_size;
	u64 magic;
	u16 flags = 0;

	magic = le64_to_cpu(sb->magic);
	if (magic)
		return -EEXIST;

	cache_dev_size = bdev_nr_bytes(file_bdev(cache_dev->bdev_file));
	if (cache_dev_size < PCACHE_CACHE_DEV_SIZE_MIN) {
		pcache_err("dax device is too small, required at least %u",
				PCACHE_CACHE_DEV_SIZE_MIN);
		return -ENOSPC;
	}

	nr_segs = (cache_dev_size - PCACHE_SEGMENTS_OFF) / ((PCACHE_SEG_SIZE));

	sb->version = cpu_to_le16(PCACHE_VERSION);

#if defined(__BYTE_ORDER) ? (__BIG_ENDIAN == __BYTE_ORDER) : defined(__BIG_ENDIAN)
	flags |= PCACHE_SB_F_BIGENDIAN;
#endif
	sb->flags = cpu_to_le16(flags);

	sb->magic = cpu_to_le64(PCACHE_MAGIC);
	sb->seg_num = cpu_to_le16(nr_segs);

	sb->crc = cpu_to_le32(crc32(0, (void *)sb + 4, PCACHE_SB_SIZE - 4));

	return 0;
}

static int sb_validate(struct pcache_cache_dev *cache_dev)
{
	struct pcache_sb *sb = cache_dev->sb_addr;
	u16 flags;

	if (le64_to_cpu(sb->magic) != PCACHE_MAGIC) {
		pcache_err("unexpected magic: %llx\n",
				le64_to_cpu(sb->magic));
		return -EINVAL;
	}

	flags = le16_to_cpu(sb->flags);

#if defined(__BYTE_ORDER) ? (__BIG_ENDIAN == __BYTE_ORDER) : defined(__BIG_ENDIAN)
	if (!(flags & PCACHE_SB_F_BIGENDIAN)) {
		pcache_err("cache_dev is not big endian\n");
		return -EINVAL;
	}
#else
	if (flags & PCACHE_SB_F_BIGENDIAN) {
		pcache_err("cache_dev is big endian\n");
		return -EINVAL;
	}
#endif
	return 0;
}

static int __cache_dev_init(struct pcache_cache_dev *cache_dev)
{
	struct pcache_sb *sb;
	struct device *dev;
	int ret;

	ret = sb_validate(cache_dev);
	if (ret)
		goto err;

	sb = cache_dev->sb_addr;
	cache_dev->seg_num = le64_to_cpu(sb->seg_num);

	cache_dev->seg_bitmap = bitmap_zalloc(cache_dev->seg_num, GFP_KERNEL);
	if (!cache_dev->seg_bitmap)
		goto err;

	return 0;

free_bitmap:
	bitmap_free(cache_dev->seg_bitmap);
err:
	return ret;
}

static void __cache_dev_exit(struct pcache_cache_dev *cache_dev)
{
	bitmap_free(cache_dev->seg_bitmap);
}

int cache_dev_exit(struct pcache_cache_dev *cache_dev)
{
	__cache_dev_exit(cache_dev);
	cache_dev_dax_exit(cache_dev);

	return 0;
}

int cache_dev_init(struct pcache_cache_dev *cache_dev, char *cache_dev_path, char *backing_dev_path)
{
	int ret;

	ret = cache_dev_dax_init(cache_dev, cache_dev_path);
	if (ret)
		goto cache_dev_free;

	ret = cache_dev_format(cache_dev);
	if (ret < 0)
		goto dax_release;

	ret = __cache_dev_init(cache_dev);
	if (ret)
		goto dax_release;

	return 0;
dax_release:
	cache_dev_dax_exit(cache_dev);
cache_dev_free:

	return ret;
}

int cache_dev_get_empty_segment_id(struct pcache_cache_dev *cache_dev, u32 *seg_id)
{
	int ret;

	mutex_lock(&cache_dev->seg_lock);
	*seg_id = find_next_zero_bit(cache_dev->seg_bitmap, cache_dev->seg_num, 0);
	if (*seg_id == cache_dev->seg_num) {
		ret = -ENOSPC;
		goto unlock;
	}

	set_bit(*seg_id, cache_dev->seg_bitmap);
	ret = 0;
unlock:
	mutex_unlock(&cache_dev->seg_lock);
	return ret;
}
