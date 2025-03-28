/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _PCACHE_META_SEGMENT_H
#define _PCACHE_META_SEGMENT_H

#include <linux/bio.h>

#include "pcache_internal.h"
#include "cache_dev.h"
#include "segment.h"

struct pcache_cache_dev;
struct pcache_backing_dev_info;

struct pcache_meta_segment_info {
	struct pcache_segment_info	seg_info;
	u32 meta_size;
	u32 meta_num;
};

struct pcache_meta_segment {
	struct pcache_segment	segment;

	struct pcache_cache_dev *cache_dev;

	struct pcache_meta_segment_info meta_seg_info;
	struct mutex info_lock;

	struct pcache_meta_segment *next_meta_seg;
};

static inline void *meta_seg_meta(struct pcache_meta_segment *meta_seg, u32 meta_id)
{
	void *data = meta_seg->segment.data;

	return (data + meta_id * meta_seg->meta_seg_info.meta_size * PCACHE_META_INDEX_MAX);
}

#define pcache_meta_seg_for_each_meta(meta_seg, i, meta)	\
	for (i = 0;						\
	     i < meta_seg->meta_seg_info.meta_num &&		\
	     ((meta = meta_seg_meta(meta_seg, i)) || true);	\
	     i++)

struct pcache_meta_segment *pcache_meta_seg_alloc(struct pcache_cache_dev *cache_dev, u32 seg_id, u32 meta_size);
void pcache_meta_seg_free(struct pcache_meta_segment *meta_seg);
#endif /* _PCACHE_META_SEGMENT_H */
