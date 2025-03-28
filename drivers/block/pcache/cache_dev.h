/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _PCACHE_CACHE_DEV_H
#define _PCACHE_CACHE_DEV_H

#include <linux/device.h>

#include "pcache_internal.h"
#include "meta_segment.h"

#define cache_dev_err(cache_dev, fmt, ...)						\
	pcache_err("cache_dev%u: " fmt,							\
		 cache_dev->id, ##__VA_ARGS__)
#define cache_dev_info(cache_dev, fmt, ...)						\
	pcache_info("cache_dev%u: " fmt,						\
		 cache_dev->id, ##__VA_ARGS__)
#define cache_dev_debug(cache_dev, fmt, ...)						\
	pcache_debug("cache_dev%u: " fmt,						\
		 cache_dev->id, ##__VA_ARGS__)

/*
 * PCACHE SB flags configured during formatting
 *
 * The PCACHE_SB_F_xxx flags define registration requirements based on cache_dev
 * formatting. For a machine to register a cache_dev:
 * - PCACHE_SB_F_BIGENDIAN: Requires a big-endian machine.
 * - PCACHE_SB_F_CACHE_DATA_CRC: Requires PCACHE_CACHE_DATA_CRC enabled.
 */
#define PCACHE_SB_F_BIGENDIAN			(1 << 0)
#define PCACHE_SB_F_CACHE_DATA_CRC		(1 << 1)

struct pcache_sb {
	__le32 crc;
	__le64 magic;
	__le16 version;
	__le16 flags;

	__le16 seg_num;
};

struct pcache_cache_dev {
	u16				id;
	u16				seg_num;
	struct pcache_sb		*sb_addr;
	struct device			device;
	struct mutex			lock;
	struct mutex			adm_lock;
	struct list_head		backing_devs;

	char				path[PCACHE_PATH_LEN];
	struct dax_device		*dax_dev;
	struct file			*bdev_file;
	struct block_device		*bdev;

	struct mutex			seg_lock;
	unsigned long			*seg_bitmap;

	struct pcache_meta_segment	*backing_info_seg;
};

struct pcache_cache_dev_register_options {
	char path[PCACHE_PATH_LEN];
	u16 format:1;
	u16 force:1;
	u16 unused:14;
};

struct pcache_backing_dev;
int cache_dev_register(struct pcache_cache_dev_register_options *opts);
int cache_dev_unregister(u32 cache_dev_id);

void cache_dev_flush(struct pcache_cache_dev *cache_dev, void *pos, u32 size);
void cache_dev_zero_range(struct pcache_cache_dev *cache_dev, void *pos, u32 size);

int cache_dev_find_backing_info(struct pcache_cache_dev *cache_dev,
				struct pcache_backing_dev *backing_dev, bool *new_backing);

int cache_dev_add_backing(struct pcache_cache_dev *cache_dev, struct pcache_backing_dev *backing_dev);
struct pcache_backing_dev *cache_dev_fetch_backing(struct pcache_cache_dev *cache_dev, u32 backing_dev_id);
int cache_dev_get_empty_segment_id(struct pcache_cache_dev *cache_dev, u32 *seg_id);

extern const struct bus_type pcache_bus_type;
extern struct device pcache_root_dev;

#endif /* _PCACHE_CACHE_DEV_H */
