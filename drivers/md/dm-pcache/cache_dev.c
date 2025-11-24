// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/blkdev.h>
#include <linux/dax.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/vmalloc.h>
#include <linux/parser.h>

#include "cache_dev.h"
#include "backing_dev.h"
#include "cache.h"
#include "dm_pcache.h"

#include "../../dax/dax-private.h"

static void cache_dev_dax_exit(struct pcache_cache_dev *cache_dev)
{
	if (cache_dev->use_vmap)
		vunmap(cache_dev->mapping);
}

static int build_vmap(struct dax_device *dax_dev, long total_pages, void **vaddr)
{
	struct page **pages;
	long i = 0, chunk;
	unsigned long pfn;
	int ret;

	pages = vmalloc_array(total_pages, sizeof(struct page *));
	if (!pages)
		return -ENOMEM;

	do {
		chunk = dax_direct_access(dax_dev, i, total_pages - i,
					  DAX_ACCESS, NULL, &pfn);
		if (chunk <= 0) {
			ret = chunk ? chunk : -EINVAL;
			goto out_free;
		}

		if (!pfn_valid(pfn)) {
			ret = -EOPNOTSUPP;
			goto out_free;
		}

		while (chunk-- && i < total_pages) {
			pages[i++] = pfn_to_page(pfn);
			pfn++;
			if (!(i & 15))
				cond_resched();
		}
	} while (i < total_pages);

	*vaddr = vmap(pages, total_pages, VM_MAP, PAGE_KERNEL);
	if (!*vaddr) {
		ret = -ENOMEM;
		goto out_free;
	}

	ret = 0;

out_free:
	vfree(pages);
	return ret;
}

static int cache_dax_notify_failure(struct dax_device *dax_dev, u64 offset,
			u64 len, int mf_flags)
{
	pr_err("dm-pcache: %s offset=%lld len=%llu flags=%x\n", __func__,
	       offset, len, mf_flags);

	return 0;
}

static const struct dax_holder_operations cache_dax_holder_ops = {
	.notify_failure		= cache_dax_notify_failure,
};

static int lookup_daxdev(const char *pathname, dev_t *devno)
{
	struct inode *inode;
	struct path path;
	int err;

	if (!pathname || !*pathname)
		return -EINVAL;

	err = kern_path(pathname, LOOKUP_FOLLOW, &path);
	if (err)
		return err;

	inode = d_backing_inode(path.dentry);
	if (!S_ISCHR(inode->i_mode)) {
		err = -EINVAL;
		goto out_path_put;
	}

	 /* if it's dax, i_rdev is struct dax_device */
	*devno = inode->i_rdev;

out_path_put:
	path_put(&path);
	return err;
}

static u64 dev_dax_size(struct dax_device *dax_dev)
{
	struct dev_dax *dev_dax = dax_get_private(dax_dev);
	u64 size = 0;
	int i;

	for (i = 0; i < dev_dax->nr_range; i++)
		size += range_len(&dev_dax->ranges[i].range);

	return size;
}

const char *cache_dev_name(struct pcache_cache_dev *cache_dev)
{
	if (cache_dev->use_char_dev)
		return cache_dev->name;

	return cache_dev->dm_dev->name;
}

int cache_dev_open_daxdev(struct pcache_cache_dev *cache_dev, char *path)
{
	int ret;
	dev_t daxdevno;

	ret = lookup_daxdev(path, &daxdevno);
	if (ret)
		return ret;

	cache_dev->dax_dev = dax_dev_get(daxdevno);
	if (!cache_dev->dax_dev) {
		pr_warn("%s: device %s not found or not dax\n",
		       __func__, path);
		return -ENODEV;
	}

	ret = fs_dax_get(cache_dev->dax_dev, cache_dev, &cache_dax_holder_ops);
	if (ret) {
		pr_err("%s: fs_dax_get(%lld) failed\n", __func__, (u64)daxdevno);
		return -EBUSY;
	}

	cache_dev->use_char_dev = true;
	cache_dev->size = dev_dax_size(cache_dev->dax_dev);
	format_dev_t(cache_dev->name, daxdevno);

	return 0;
}

void cache_dev_close_daxdev(struct pcache_cache_dev *cache_dev)
{
	fs_put_dax(cache_dev->dax_dev, cache_dev);
}

static struct dax_device *get_dax_dev(struct pcache_cache_dev *cache_dev)
{
	if (cache_dev->use_char_dev)
		return cache_dev->dax_dev;

	return cache_dev->dm_dev->dax_dev;
}

static u64 get_dax_size(struct pcache_cache_dev *cache_dev)
{
	if (cache_dev->use_char_dev)
		return cache_dev->size;

	return  bdev_nr_bytes(cache_dev->dm_dev->bdev);
}

static int cache_dev_dax_init(struct pcache_cache_dev *cache_dev)
{
	struct dm_pcache	*pcache = CACHE_DEV_TO_PCACHE(cache_dev);
	struct dax_device	*dax_dev;
	long			total_pages, mapped_pages;
	u64			dax_size;
	void			*vaddr;
	int			ret;
	int			id;
	unsigned long		pfn;

	dax_dev	= get_dax_dev(cache_dev);
	/* total size check */
	dax_size = get_dax_size(cache_dev);
	if (dax_size < PCACHE_CACHE_DEV_SIZE_MIN) {
		pcache_dev_err(pcache, "dax device is too small, required at least %llu",
				PCACHE_CACHE_DEV_SIZE_MIN);
		ret = -ENOSPC;
		goto out;
	}

	total_pages = dax_size >> PAGE_SHIFT;
	/* attempt: direct-map the whole range */
	id = dax_read_lock();
	mapped_pages = dax_direct_access(dax_dev, 0, total_pages,
					 DAX_ACCESS, &vaddr, &pfn);
	if (mapped_pages < 0) {
		pcache_dev_err(pcache, "dax_direct_access failed: %ld\n", mapped_pages);
		ret = mapped_pages;
		goto unlock;
	}

	if (!pfn_valid(pfn)) {
		ret = -EOPNOTSUPP;
		goto unlock;
	}

	if (mapped_pages == total_pages) {
		/* success: contiguous direct mapping */
		cache_dev->mapping = vaddr;
	} else {
		/* need vmap fallback */
		ret = build_vmap(dax_dev, total_pages, &vaddr);
		if (ret) {
			pcache_dev_err(pcache, "vmap fallback failed: %d\n", ret);
			goto unlock;
		}

		cache_dev->mapping	= vaddr;
		cache_dev->use_vmap	= true;
	}
	dax_read_unlock(id);

	return 0;
unlock:
	dax_read_unlock(id);
out:
	return ret;
}

void cache_dev_zero_range(struct pcache_cache_dev *cache_dev, void *pos, u32 size)
{
	memset(pos, 0, size);
	dax_flush(get_dax_dev(cache_dev), pos, size);
}

static int sb_read(struct pcache_cache_dev *cache_dev, struct pcache_sb *sb)
{
	struct pcache_sb *sb_addr = CACHE_DEV_SB(cache_dev);

	if (copy_mc_to_kernel(sb, sb_addr, sizeof(struct pcache_sb)))
		return -EIO;

	return 0;
}

static void sb_write(struct pcache_cache_dev *cache_dev, struct pcache_sb *sb)
{
	struct pcache_sb *sb_addr = CACHE_DEV_SB(cache_dev);

	memcpy_flushcache(sb_addr, sb, sizeof(struct pcache_sb));
	pmem_wmb();
}

static int sb_init(struct pcache_cache_dev *cache_dev, struct pcache_sb *sb)
{
	struct dm_pcache *pcache = CACHE_DEV_TO_PCACHE(cache_dev);
	u64 nr_segs;
	u64 cache_dev_size;
	u64 magic;
	u32 flags = 0;

	magic = le64_to_cpu(sb->magic);
	if (magic)
		return -EEXIST;

	cache_dev_size = get_dax_size(cache_dev);
	if (cache_dev_size < PCACHE_CACHE_DEV_SIZE_MIN) {
		pcache_dev_err(pcache, "dax device is too small, required at least %llu",
				PCACHE_CACHE_DEV_SIZE_MIN);
		return -ENOSPC;
	}

	nr_segs = (cache_dev_size - PCACHE_SEGMENTS_OFF) / ((PCACHE_SEG_SIZE));

#if defined(__BYTE_ORDER) ? (__BIG_ENDIAN == __BYTE_ORDER) : defined(__BIG_ENDIAN)
	flags |= PCACHE_SB_F_BIGENDIAN;
#endif
	sb->flags = cpu_to_le32(flags);
	sb->magic = cpu_to_le64(PCACHE_MAGIC);
	sb->seg_num = cpu_to_le32(nr_segs);
	sb->crc = cpu_to_le32(crc32c(PCACHE_CRC_SEED, (void *)(sb) + 4, sizeof(struct pcache_sb) - 4));

	cache_dev_zero_range(cache_dev, CACHE_DEV_CACHE_INFO(cache_dev),
			     PCACHE_CACHE_INFO_SIZE * PCACHE_META_INDEX_MAX +
			     PCACHE_CACHE_CTRL_SIZE);

	return 0;
}

static int sb_validate(struct pcache_cache_dev *cache_dev, struct pcache_sb *sb)
{
	struct dm_pcache *pcache = CACHE_DEV_TO_PCACHE(cache_dev);
	u32 flags;
	u32 crc;

	if (le64_to_cpu(sb->magic) != PCACHE_MAGIC) {
		pcache_dev_err(pcache, "unexpected magic: %llx\n",
				le64_to_cpu(sb->magic));
		return -EINVAL;
	}

	crc = crc32c(PCACHE_CRC_SEED, (void *)(sb) + 4, sizeof(struct pcache_sb) - 4);
	if (crc != le32_to_cpu(sb->crc)) {
		pcache_dev_err(pcache, "corrupted sb: %u, expected: %u\n", crc, le32_to_cpu(sb->crc));
		return -EINVAL;
	}

	flags = le32_to_cpu(sb->flags);
#if defined(__BYTE_ORDER) ? (__BIG_ENDIAN == __BYTE_ORDER) : defined(__BIG_ENDIAN)
	if (!(flags & PCACHE_SB_F_BIGENDIAN)) {
		pcache_dev_err(pcache, "cache_dev is not big endian\n");
		return -EINVAL;
	}
#else
	if (flags & PCACHE_SB_F_BIGENDIAN) {
		pcache_dev_err(pcache, "cache_dev is big endian\n");
		return -EINVAL;
	}
#endif
	return 0;
}

static int cache_dev_init(struct pcache_cache_dev *cache_dev, u32 seg_num)
{
	cache_dev->seg_num = seg_num;
	cache_dev->seg_bitmap = kvcalloc(BITS_TO_LONGS(cache_dev->seg_num), sizeof(unsigned long), GFP_KERNEL);
	if (!cache_dev->seg_bitmap)
		return -ENOMEM;

	return 0;
}

static void cache_dev_exit(struct pcache_cache_dev *cache_dev)
{
	kvfree(cache_dev->seg_bitmap);
}

void cache_dev_stop(struct dm_pcache *pcache)
{
	struct pcache_cache_dev *cache_dev = &pcache->cache_dev;

	cache_dev_exit(cache_dev);
	cache_dev_dax_exit(cache_dev);
}

int cache_dev_start(struct dm_pcache *pcache)
{
	struct pcache_cache_dev *cache_dev = &pcache->cache_dev;
	struct pcache_sb sb;
	bool format = false;
	int ret;

	mutex_init(&cache_dev->seg_lock);

	ret = cache_dev_dax_init(cache_dev);
	if (ret) {
		pcache_dev_err(pcache, "failed to init cache_dev via dax way: %d.", ret);
		goto err;
	}

	ret = sb_read(cache_dev, &sb);
	if (ret)
		goto dax_release;

	if (le64_to_cpu(sb.magic) == 0) {
		format = true;
		ret = sb_init(cache_dev, &sb);
		if (ret < 0)
			goto dax_release;
	}

	ret = sb_validate(cache_dev, &sb);
	if (ret)
		goto dax_release;

	cache_dev->sb_flags = le32_to_cpu(sb.flags);
	ret = cache_dev_init(cache_dev, le32_to_cpu(sb.seg_num));
	if (ret)
		goto dax_release;

	if (format)
		sb_write(cache_dev, &sb);

	return 0;

dax_release:
	cache_dev_dax_exit(cache_dev);
err:
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

	__set_bit(*seg_id, cache_dev->seg_bitmap);
	ret = 0;
unlock:
	mutex_unlock(&cache_dev->seg_lock);
	return ret;
}
