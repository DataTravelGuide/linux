/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _PCACHE_CACHE_DEV_H
#define _PCACHE_CACHE_DEV_H

#include <linux/device.h>
#include <linux/device-mapper.h>

#include "pcache_internal.h"

#define PCACHE_MAGIC				0x65B05EFA96C596EFULL
#define PCACHE_VERSION				1

#define PCACHE_SB_OFF				(4 * PCACHE_KB)
#define PCACHE_SB_SIZE				(4 * PCACHE_KB)

#define PCACHE_CACHE_INFO_OFF			(PCACHE_SB_OFF + PCACHE_SB_SIZE)
#define PCACHE_CACHE_INFO_SIZE			(4 * PCACHE_KB)

#define PCACHE_CACHE_CTRL_OFF			(PCACHE_CACHE_INFO_OFF + (PCACHE_CACHE_INFO_SIZE * PCACHE_META_INDEX_MAX))
#define PCACHE_CACHE_CTRL_SIZE			(4 * PCACHE_KB)

#define PCACHE_SEGMENTS_OFF			(PCACHE_CACHE_CTRL_OFF + PCACHE_CACHE_CTRL_SIZE)
#define PCACHE_SEG_INFO_SIZE			(4 * PCACHE_KB)

#define PCACHE_CACHE_DEV_SIZE_MIN		(512 * PCACHE_MB)	 /* 512 MB */
#define PCACHE_SEG_SIZE				(16 * PCACHE_MB)		/* Size of each PCACHE segment (16 MB) */

#define CACHE_DEV_SB(cache_dev)			((struct pcache_sb *)(cache_dev->mapping + PCACHE_SB_OFF))
#define CACHE_DEV_CACHE_INFO(cache_dev)		((void *)cache_dev->mapping + PCACHE_CACHE_INFO_OFF)
#define CACHE_DEV_CACHE_CTRL(cache_dev)		((void *)cache_dev->mapping + PCACHE_CACHE_CTRL_OFF)
#define CACHE_DEV_SEGMENTS(cache_dev)		((void *)cache_dev->mapping + PCACHE_SEGMENTS_OFF)
#define CACHE_DEV_SEGMENT(cache_dev, id)	((void *)CACHE_DEV_SEGMENTS(cache_dev) + (u64)id * PCACHE_SEG_SIZE)

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
	void				*mapping;

	struct file			*bdev_file;
	struct block_device		*bdev;
	struct dm_dev			*dm_dev;

	struct mutex			seg_lock;
	unsigned long			*seg_bitmap;
};

struct dm_pcache;
int cache_dev_start(struct dm_pcache *pcache, const char *cache_dev_path);
void cache_dev_stop(struct dm_pcache *pcache);

void cache_dev_flush(struct pcache_cache_dev *cache_dev, void *pos, u32 size);
void cache_dev_zero_range(struct pcache_cache_dev *cache_dev, void *pos, u32 size);

int cache_dev_get_empty_segment_id(struct pcache_cache_dev *cache_dev, u32 *seg_id);

#endif /* _PCACHE_CACHE_DEV_H */
