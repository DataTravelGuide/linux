// SPDX-License-Identifier: GPL-2.0-or-later
#include "cache_dev.h"
#include "cache.h"
#include "backing_dev.h"
#include "meta_segment.h"

static void meta_seg_info_write(struct pcache_meta_segment *meta_seg)
{
	struct pcache_meta_segment_info *info_addr;

	mutex_lock(&meta_seg->info_lock);
	meta_seg->meta_seg_info.seg_info.header.seq++;

	info_addr = CACHE_DEV_SEGMENT(meta_seg->cache_dev, meta_seg->meta_seg_info.seg_info.seg_id);
	info_addr = pcache_meta_find_oldest(&info_addr->seg_info.header, PCACHE_SEG_INFO_SIZE);

	memcpy(info_addr, &meta_seg->meta_seg_info, sizeof(struct pcache_meta_segment_info));
	info_addr->seg_info.header.crc = pcache_meta_crc(&info_addr->seg_info.header, PCACHE_SEG_INFO_SIZE);

	cache_dev_flush(meta_seg->cache_dev, info_addr, PCACHE_SEG_INFO_SIZE);
	mutex_unlock(&meta_seg->info_lock);
}

static void meta_seg_init(struct pcache_cache_dev *cache_dev, struct pcache_meta_segment *meta_seg, u32 seg_id, u32 meta_size)
{
	struct pcache_segment_init_options seg_opts = { 0 };

	meta_seg->cache_dev = cache_dev;
	mutex_init(&meta_seg->info_lock);

	seg_opts.type = PCACHES_TYPE_META;
	seg_opts.state = PCACHE_SEGMENT_STATE_RUNNING;
	seg_opts.seg_id = seg_id;
	seg_opts.data_off = PCACHE_SEG_INFO_SIZE * PCACHE_META_INDEX_MAX;
	seg_opts.seg_info = &meta_seg->meta_seg_info.seg_info;

	pcache_segment_init(cache_dev, &meta_seg->segment, &seg_opts);

	meta_seg->meta_seg_info.meta_size = meta_size;
	meta_seg->meta_seg_info.meta_num = meta_seg->segment.data_size / (meta_size * PCACHE_META_INDEX_MAX);

	meta_seg_info_write(meta_seg);
}

struct pcache_meta_segment *pcache_meta_seg_alloc(struct pcache_cache_dev *cache_dev, u32 seg_id, u32 meta_size)
{
	struct pcache_meta_segment *meta_seg;

	meta_seg = kzalloc(sizeof(struct pcache_meta_segment), GFP_KERNEL);
	if (!meta_seg)
		return NULL;

	meta_seg_init(cache_dev, meta_seg, seg_id, meta_size);

	return meta_seg;
}

void pcache_meta_seg_free(struct pcache_meta_segment *meta_seg)
{
	kfree(meta_seg);
}
