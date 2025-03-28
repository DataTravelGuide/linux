// SPDX-License-Identifier: GPL-2.0-or-later

#include "cache_dev.h"
#include "cache.h"
#include "backing_dev.h"

static void cache_seg_info_write(struct pcache_cache_segment *cache_seg)
{
	mutex_lock(&cache_seg->info_lock);
	pcache_segment_info_write(cache_seg->cache->backing_dev->cache_dev,
			&cache_seg->cache_seg_info.segment_info,
			cache_seg->segment.seg_info->seg_id);
	mutex_unlock(&cache_seg->info_lock);
}

static int cache_seg_info_load(struct pcache_cache_segment *cache_seg)
{
	struct pcache_segment_info *cache_seg_info;
	int ret = 0;

	mutex_lock(&cache_seg->info_lock);
	cache_seg_info = pcache_segment_info_read(cache_seg->cache->backing_dev->cache_dev,
						cache_seg->segment.seg_info->seg_id);
	if (!cache_seg_info) {
		pr_err("can't read segment info of segment: %u\n",
			      cache_seg->segment.seg_info->seg_id);
		ret = -EIO;
		goto out;
	}
	memcpy(&cache_seg->cache_seg_info, cache_seg_info, sizeof(struct pcache_cache_seg_info));
out:
	mutex_unlock(&cache_seg->info_lock);
	return ret;
}

static void cache_seg_ctrl_load(struct pcache_cache_segment *cache_seg)
{
	struct pcache_cache_seg_ctrl *cache_seg_ctrl = cache_seg->cache_seg_ctrl;
	struct pcache_cache_seg_gen *cache_seg_gen;

	mutex_lock(&cache_seg->ctrl_lock);
	cache_seg_gen = pcache_meta_find_latest(&cache_seg_ctrl->gen->header,
					     sizeof(struct pcache_cache_seg_gen));
	if (!cache_seg_gen) {
		cache_seg->gen = 0;
		goto out;
	}

	cache_seg->gen = cache_seg_gen->gen;
out:
	mutex_unlock(&cache_seg->ctrl_lock);
}

static void cache_seg_ctrl_write(struct pcache_cache_segment *cache_seg)
{
	struct pcache_cache_seg_ctrl *cache_seg_ctrl = cache_seg->cache_seg_ctrl;
	struct pcache_cache_seg_gen *cache_seg_gen;

	mutex_lock(&cache_seg->ctrl_lock);
	cache_seg_gen = pcache_meta_find_oldest(&cache_seg_ctrl->gen->header,
					     sizeof(struct pcache_cache_seg_gen));
	BUG_ON(!cache_seg_gen);
	cache_seg_gen->gen = cache_seg->gen;
	cache_seg_gen->header.seq = pcache_meta_get_next_seq(&cache_seg_ctrl->gen->header,
							  sizeof(struct pcache_cache_seg_gen));
	cache_seg_gen->header.crc = pcache_meta_crc(&cache_seg_gen->header,
						 sizeof(struct pcache_cache_seg_gen));
	mutex_unlock(&cache_seg->ctrl_lock);

	cache_dev_flush(cache_seg->cache->backing_dev->cache_dev, cache_seg_gen, sizeof(struct pcache_cache_seg_gen));
}

static int cache_seg_meta_load(struct pcache_cache_segment *cache_seg)
{
	int ret;

	ret = cache_seg_info_load(cache_seg);
	if (ret)
		goto err;

	cache_seg_ctrl_load(cache_seg);

	return 0;
err:
	return ret;
}

/**
 * cache_seg_set_next_seg - Sets the ID of the next segment
 * @cache_seg: Pointer to the cache segment structure.
 * @seg_id: The segment ID to set as the next segment.
 *
 * A pcache_cache allocates multiple cache segments, which are linked together
 * through next_seg. When loading a pcache_cache, the first cache segment can
 * be found using cache->seg_id, which allows access to all the cache segments.
 */
void cache_seg_set_next_seg(struct pcache_cache_segment *cache_seg, u32 seg_id)
{
	cache_seg->cache_seg_info.segment_info.flags |= PCACHE_SEG_INFO_FLAGS_HAS_NEXT;
	cache_seg->cache_seg_info.segment_info.next_seg = seg_id;
	cache_seg_info_write(cache_seg);
}

int cache_seg_init(struct pcache_cache *cache, u32 seg_id, u32 cache_seg_id,
		   bool new_cache)
{
	struct pcache_cache_dev *cache_dev = cache->backing_dev->cache_dev;
	struct pcache_cache_segment *cache_seg = &cache->segments[cache_seg_id];
	struct pcache_segment_init_options seg_options = { 0 };
	struct pcache_segment *segment = &cache_seg->segment;
	int ret;

	cache_seg->cache = cache;
	cache_seg->cache_seg_id = cache_seg_id;
	spin_lock_init(&cache_seg->gen_lock);
	atomic_set(&cache_seg->refs, 0);
	mutex_init(&cache_seg->info_lock);
	mutex_init(&cache_seg->ctrl_lock);

	/* init pcache_segment */
	seg_options.type = PCACHE_SEGMENT_TYPE_DATA;
	seg_options.data_off = PCACHE_CACHE_SEG_CTRL_OFF + PCACHE_CACHE_SEG_CTRL_SIZE;
	seg_options.seg_id = seg_id;
	seg_options.seg_info = &cache_seg->cache_seg_info.segment_info;
	pcache_segment_init(cache_dev, segment, &seg_options);

	cache_seg->cache_seg_ctrl = CACHE_DEV_SEGMENT(cache_dev, seg_id) + PCACHE_CACHE_SEG_CTRL_OFF;
	/* init cache->cache_ctrl */
	if (cache_seg_is_ctrl_seg(cache_seg_id))
		cache->cache_ctrl = (struct pcache_cache_ctrl *)cache_seg->cache_seg_ctrl;

	if (new_cache) {
		cache_seg->cache_seg_info.segment_info.type = PCACHE_SEGMENT_TYPE_DATA;
		cache_seg->cache_seg_info.segment_info.state = PCACHE_SEGMENT_STATE_RUNNING;
		cache_seg->cache_seg_info.segment_info.flags = 0;
		cache_seg_info_write(cache_seg);

		/* clear outdated kset in segment */
		memcpy_flushcache(segment->data, &pcache_empty_kset, sizeof(struct pcache_cache_kset_onmedia));
	} else {
		ret = cache_seg_meta_load(cache_seg);
		if (ret)
			goto err;
	}

	atomic_set(&cache_seg->state, pcache_cache_seg_state_running);

	return 0;
err:
	return ret;
}

void cache_seg_destroy(struct pcache_cache_segment *cache_seg)
{
	/* clear cache segment ctrl */
	cache_dev_zero_range(cache_seg->cache->backing_dev->cache_dev, cache_seg->cache_seg_ctrl,
			PCACHE_CACHE_SEG_CTRL_SIZE);

	clear_bit(cache_seg->segment.seg_info->seg_id, cache_seg->cache->backing_dev->cache_dev->seg_bitmap);
}

#define PCACHE_WAIT_NEW_CACHE_INTERVAL	100
#define PCACHE_WAIT_NEW_CACHE_COUNT	100

/**
 * get_cache_segment - Retrieves a free cache segment from the cache.
 * @cache: Pointer to the cache structure.
 *
 * This function attempts to find a free cache segment that can be used.
 * It locks the segment map and checks for the next available segment ID.
 * If no segment is available, it waits for a predefined interval and retries.
 * If a free segment is found, it initializes it and returns a pointer to the
 * cache segment structure. Returns NULL if no segments are available after
 * waiting for a specified count.
 */
struct pcache_cache_segment *get_cache_segment(struct pcache_cache *cache)
{
	struct pcache_cache_segment *cache_seg;
	u32 seg_id;
	u32 wait_count = 0;

again:
	spin_lock(&cache->seg_map_lock);
	seg_id = find_next_zero_bit(cache->seg_map, cache->n_segs, cache->last_cache_seg);
	if (seg_id == cache->n_segs) {
		spin_unlock(&cache->seg_map_lock);
		/* reset the hint of ->last_cache_seg and retry */
		if (cache->last_cache_seg) {
			cache->last_cache_seg = 0;
			goto again;
		}

		if (++wait_count >= PCACHE_WAIT_NEW_CACHE_COUNT)
			return NULL;

		udelay(PCACHE_WAIT_NEW_CACHE_INTERVAL);
		goto again;
	}

	/*
	 * found an available cache_seg, mark it used in seg_map
	 * and update the search hint ->last_cache_seg
	 */
	set_bit(seg_id, cache->seg_map);
	cache->last_cache_seg = seg_id;
	spin_unlock(&cache->seg_map_lock);

	cache_seg = &cache->segments[seg_id];
	cache_seg->cache_seg_id = seg_id;

	return cache_seg;
}

static void cache_seg_gen_increase(struct pcache_cache_segment *cache_seg)
{
	spin_lock(&cache_seg->gen_lock);
	cache_seg->gen++;
	spin_unlock(&cache_seg->gen_lock);

	cache_seg_ctrl_write(cache_seg);
}

void cache_seg_get(struct pcache_cache_segment *cache_seg)
{
	atomic_inc(&cache_seg->refs);
}

static void cache_seg_invalidate(struct pcache_cache_segment *cache_seg)
{
	struct pcache_cache *cache;

	cache = cache_seg->cache;
	cache_seg_gen_increase(cache_seg);

	spin_lock(&cache->seg_map_lock);
	clear_bit(cache_seg->cache_seg_id, cache->seg_map);
	spin_unlock(&cache->seg_map_lock);

	/* clean_work will clean the bad key in key_tree*/
	queue_work(cache->backing_dev->task_wq, &cache->clean_work);
}

void cache_seg_put(struct pcache_cache_segment *cache_seg)
{
	if (atomic_dec_and_test(&cache_seg->refs))
		cache_seg_invalidate(cache_seg);
}
