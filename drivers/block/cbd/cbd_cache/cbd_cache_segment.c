// SPDX-License-Identifier: GPL-2.0-or-later

#include "cbd_cache_internal.h"

/**
 * cache_seg_info_write - Writes cache_seg_info of the cache segment.
 * @cache_seg: Pointer to the cache segment structure.
 *
 * This function locks the `info_lock` to ensure thread-safe access to `cache_seg_info`,
 * calls `cbdt_segment_info_write` to write the cache segment's cache_seg_info to storage,
 * and updates the cache_seg_info index (`info_index`) for tracking changes.
 */
static void cache_seg_info_write(struct cbd_cache_segment *cache_seg)
{
	mutex_lock(&cache_seg->info_lock);
	cbdt_segment_info_write(cache_seg->cache->cbdt, &cache_seg->cache_seg_info,
				sizeof(struct cbd_cache_seg_info), cache_seg->segment.seg_id,
				cache_seg->info_index);
	cache_seg->info_index = (cache_seg->info_index + 1) % CBDT_META_INDEX_MAX;
	mutex_unlock(&cache_seg->info_lock);
}

/**
 * cache_seg_info_load - Loads cache_seg_info for a cache segment.
 * @cache_seg: Pointer to the cache segment structure.
 *
 * Locks `info_lock`, reads segment cache_seg_info using `cbdt_segment_info_read`, and stores 
 * it in `cache_seg_info`. If cache_seg_info cannot be read, logs an error and returns -EIO.
 * Returns 0 on success or -EIO if reading fails.
 */
static int cache_seg_info_load(struct cbd_cache_segment *cache_seg)
{
	struct cbd_segment_info *cache_seg_info;
	int ret = 0;

	mutex_lock(&cache_seg->info_lock);
	cache_seg_info = cbdt_segment_info_read(cache_seg->cache->cbdt,
						cache_seg->segment.seg_id,
						&cache_seg->info_index);
	if (!cache_seg_info) {
		cbd_cache_err(cache_seg->cache, "can't read segment info of segment: %u\n",
			      cache_seg->segment.seg_id);
		ret = -EIO;
		goto out;
	}
	memcpy(&cache_seg->cache_seg_info, cache_seg_info, sizeof(struct cbd_cache_seg_info));
out:
	mutex_unlock(&cache_seg->info_lock);
	return ret;
}

/**
 * cache_seg_ctrl_load - Loads control information for the cache segment.
 * @cache_seg: Pointer to the cache segment structure.
 *
 * Locks `ctrl_lock` to safely read the control structure (`cache_seg_ctrl`).
 * Finds the latest generation information using `cbd_meta_find_latest` and updates 
 * `cache_seg->gen` with the generation number. Sets `gen` to 0 if no valid entry exists.
 */
static void cache_seg_ctrl_load(struct cbd_cache_segment *cache_seg)
{
	struct cbd_cache_seg_ctrl *cache_seg_ctrl = cache_seg->cache_seg_ctrl;
	struct cbd_cache_seg_gen *cache_seg_gen;

	mutex_lock(&cache_seg->ctrl_lock);
	cache_seg_gen = cbd_meta_find_latest(&cache_seg_ctrl->gen->header,
					     sizeof(struct cbd_cache_seg_gen),
					     NULL);
	if (!cache_seg_gen) {
		cache_seg->gen = 0;
		goto out;
	}

	cache_seg->gen = cache_seg_gen->gen;
out:
	mutex_unlock(&cache_seg->ctrl_lock);
}

/**
 * cache_seg_ctrl_write - Writes control information for the cache segment.
 * @cache_seg: Pointer to the cache segment structure.
 *
 * Locks `ctrl_lock`, finds the oldest control entry using `cbd_meta_find_oldest`, 
 * and updates its generation data with the current segment generation number.
 * Also calculates and updates the CRC for integrity.
 * Triggers a BUG if no oldest entry is found (should not happen).
 */
static void cache_seg_ctrl_write(struct cbd_cache_segment *cache_seg)
{
	struct cbd_cache_seg_ctrl *cache_seg_ctrl = cache_seg->cache_seg_ctrl;
	struct cbd_cache_seg_gen *cache_seg_gen;

	mutex_lock(&cache_seg->ctrl_lock);
	cache_seg_gen = cbd_meta_find_oldest(&cache_seg_ctrl->gen->header,
					     sizeof(struct cbd_cache_seg_gen));
	BUG_ON(!cache_seg_gen);
	cache_seg_gen->gen = cache_seg->gen;
	cache_seg_gen->header.seq = cbd_meta_get_next_seq(&cache_seg_ctrl->gen->header,
							  sizeof(struct cbd_cache_seg_gen));
	cache_seg_gen->header.crc = cbd_meta_crc(&cache_seg_gen->header,
						 sizeof(struct cbd_cache_seg_gen));
	mutex_unlock(&cache_seg->ctrl_lock);
}

/**
 * cache_seg_meta_load - Loads cache_seg_info and control data for the cache segment.
 * @cache_seg: Pointer to the cache segment structure.
 *
 * Calls `cache_seg_info_load` to load segment cache_seg_info, and if successful, 
 * calls `cache_seg_ctrl_load` to load control information. Returns 0 on success,
 * otherwise returns the error code from `cache_seg_info_load`.
 */
static int cache_seg_meta_load(struct cbd_cache_segment *cache_seg)
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
 * This function updates the flags to indicate that there is a next segment 
 * and sets the ID of the next segment in the segment information structure.
 * Finally, it writes the updated cache segment information to storage.
 *
 * A cbd_cache allocates multiple cache segments, which are linked together
 * through next_seg. When loading a cbd_cache, the first cache segment can
 * be found using cache->seg_id, which allows access to all the cache segments.
 */
void cache_seg_set_next_seg(struct cbd_cache_segment *cache_seg, u32 seg_id)
{
	cache_seg->cache_seg_info.segment_info.flags |= CBD_SEG_INFO_FLAGS_HAS_NEXT;
	cache_seg->cache_seg_info.segment_info.next_seg = seg_id;
	cache_seg_info_write(cache_seg);
}

/**
 * cbd_cache_seg_sanitize_pos - Validates the position within the segment.
 * @pos: Pointer to the segment position structure.
 *
 * This function checks if the offset (`off`) in the segment position 
 * does not exceed the data size of the segment.
 */
static void cbd_cache_seg_sanitize_pos(struct cbd_seg_pos *pos)
{
	BUG_ON(pos->off > pos->segment->data_size);
}

static struct cbd_seg_ops cbd_cache_seg_ops = {
	.sanitize_pos = cbd_cache_seg_sanitize_pos
};

/**
 * cache_seg_init - Initializes a cache segment.
 * @cache: Pointer to the cache structure.
 * @seg_id: The segment ID to initialize, this is the id of cbd segment.
 * @cache_seg_id: The ID of the cache segment, this is the index id in cache->segments[]
 * @new_cache: Boolean indicating if this is a new cache segment.
 *
 * This function initializes the cache segment structure, including 
 * setting up locks, reference counters, and segment options. If 
 * it's a new cache segment, it initializes its state and flags; 
 * otherwise, it attempts to load existing metadata.
 *
 * Returns 0 on success or an error code on failure.
 */
int cache_seg_init(struct cbd_cache *cache, u32 seg_id, u32 cache_seg_id,
		   bool new_cache)
{
	struct cbd_transport *cbdt = cache->cbdt;
	struct cbd_cache_segment *cache_seg = &cache->segments[cache_seg_id];
	struct cbds_init_options seg_options = { 0 };
	struct cbd_segment *segment = &cache_seg->segment;
	int ret;

	cache_seg->cache = cache;
	cache_seg->cache_seg_id = cache_seg_id;
	spin_lock_init(&cache_seg->gen_lock);
	atomic_set(&cache_seg->refs, 0);
	cache_seg->info_index = 0;
	mutex_init(&cache_seg->info_lock);
	mutex_init(&cache_seg->ctrl_lock);

	/* init cbd_segment */
	seg_options.type = cbds_type_cache;
	seg_options.data_off = CBDT_CACHE_SEG_CTRL_OFF + CBDT_CACHE_SEG_CTRL_SIZE;
	seg_options.seg_ops = &cbd_cache_seg_ops;
	seg_options.seg_id = seg_id;
	cbd_segment_init(cbdt, segment, &seg_options);

	cache_seg->cache_seg_ctrl = (void *)segment->data + CBDT_CACHE_SEG_CTRL_OFF;

	if (new_cache) {
		cache_seg->cache_seg_info.segment_info.type = cbds_type_cache;
		cache_seg->cache_seg_info.segment_info.state = cbd_segment_state_running;
		cache_seg->cache_seg_info.segment_info.flags = 0;

		cache_seg->cache_seg_info.backend_id = cache->cache_id;
		cache_seg_info_write(cache_seg);
	} else {
		ret = cache_seg_meta_load(cache_seg);
		if (ret)
			goto err;
	}

	return 0;
err:
	return ret;
}

/**
 * cache_seg_destroy - Cleans up and clears the cache segment.
 * @cache_seg: Pointer to the cache segment structure.
 *
 * This function clears the segment information to release resources 
 * and prepares the segment for cleanup. It should be called when 
 * the cache segment is no longer needed. This function should only
 * be called by owner backend.
 */
void cache_seg_destroy(struct cbd_cache_segment *cache_seg)
{
	/* clear cache segment ctrl */
	cbdt_zero_range(cache_seg->cache->cbdt, cache_seg->cache_seg_ctrl,
			CBDT_CACHE_SEG_CTRL_SIZE);

	/* clear cbd segment infomation */
	cbd_segment_info_clear(&cache_seg->segment);
}

#define CBD_WAIT_NEW_CACHE_INTERVAL	100 /* usecs */
#define CBD_WAIT_NEW_CACHE_COUNT	100

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
struct cbd_cache_segment *get_cache_segment(struct cbd_cache *cache)
{
	struct cbd_cache_segment *cache_seg;
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

		if (++wait_count >= CBD_WAIT_NEW_CACHE_COUNT)
			return NULL;

		udelay(CBD_WAIT_NEW_CACHE_INTERVAL);
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

	/* Zero out the memory region for the segment data */
	cbdt_zero_range(cache->cbdt, cache_seg->segment.data, cache_seg->segment.data_size);

	return cache_seg;
}

/**
 * cache_seg_gen_increase - Increases the generation counter for a cache segment.
 * @cache_seg: Pointer to the cache segment structure.
 *
 * This function locks the generation lock, increments the generation counter 
 * of the specified cache segment, and writes the updated control information 
 * to the cache segment. It ensures that generation updates are synchronized.
 */
static void cache_seg_gen_increase(struct cbd_cache_segment *cache_seg)
{
	spin_lock(&cache_seg->gen_lock);
	cache_seg->gen++;
	spin_unlock(&cache_seg->gen_lock);

	cache_seg_ctrl_write(cache_seg);
}

/**
 * cache_seg_get - Increases the reference count for a cache segment.
 * @cache_seg: Pointer to the cache segment structure.
 *
 * This function increments the reference count of the specified cache segment.
 * It indicates that the segment is in use and prevents it from being invalidated.
 */
void cache_seg_get(struct cbd_cache_segment *cache_seg)
{
	atomic_inc(&cache_seg->refs);
}

/**
 * cache_seg_invalidate - Invalidates a cache segment, marking it as no longer in use.
 * @cache_seg: Pointer to the cache segment structure.
 *
 * This function increments the generation counter for the segment, clears its 
 * bit from the segment map, and queues a work item for cache cleaning.
 */
static void cache_seg_invalidate(struct cbd_cache_segment *cache_seg)
{
	struct cbd_cache *cache;

	cache = cache_seg->cache;
	cache_seg_gen_increase(cache_seg);

	spin_lock(&cache->seg_map_lock);
	clear_bit(cache_seg->cache_seg_id, cache->seg_map);
	spin_unlock(&cache->seg_map_lock);

	/* clean_work will clean the bad key in key_tree*/
	queue_work(cache->cache_wq, &cache->clean_work);
}

/**
 * cache_seg_put - Decreases the reference count for a cache segment.
 * @cache_seg: Pointer to the cache segment structure.
 *
 * This function atomically decrements the reference count for the specified 
 * cache segment. If the reference count reaches zero, it invalidates the 
 * segment, marking it as no longer in use.
 */
void cache_seg_put(struct cbd_cache_segment *cache_seg)
{
	if (atomic_dec_and_test(&cache_seg->refs))
		cache_seg_invalidate(cache_seg);
}
