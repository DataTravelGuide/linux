/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _PCACHE_CACHE_DEV_H
#define _PCACHE_CACHE_DEV_H

#include <linux/device.h>

#include "pcache_internal.h"

/*
 * PCACHE SB flags configured during formatting
 *
 * The PCACHE_SB_F_xxx flags define registration requirements based on cache_dev
 * formatting. For a machine to register a cache_dev:
 * - PCACHE_SB_F_BIGENDIAN: Requires a big-endian machine.
 */
#define PCACHE_SB_F_BIGENDIAN			(1 << 0)

struct pcache_sb {
	__le32 crc;
	__le16 version;
	__le16 flags;
	__le64 magic;

	__le16 seg_num;
};

struct pcache_cache_dev {
	u16				seg_num;
	struct pcache_sb		*sb_addr;

	struct dax_device		*dax_dev;
	struct file			*bdev_file;
	struct block_device		*bdev;

	struct mutex			seg_lock;
	unsigned long			*seg_bitmap;
};

struct dm_pcache;
int cache_dev_stop(struct dm_pcache *pcache);
int cache_dev_start(struct dm_pcache *pcache, const char *cache_dev_path);

void cache_dev_flush(struct pcache_cache_dev *cache_dev, void *pos, u32 size);
void cache_dev_zero_range(struct pcache_cache_dev *cache_dev, void *pos, u32 size);

int cache_dev_get_empty_segment_id(struct pcache_cache_dev *cache_dev, u32 *seg_id);

#endif /* _PCACHE_CACHE_DEV_H */
