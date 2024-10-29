// SPDX-License-Identifier: GPL-2.0-or-later

#include "cbd_cache_internal.h"

/**
 * cache_key_gc - Releases the reference of a cache key segment.
 * @cache: Pointer to the cbd_cache structure.
 * @key: Pointer to the cache key to be garbage collected.
 *
 * This function decrements the reference count of the cache segment
 * associated with the given key. If the reference count drops to zero,
 * the segment may be invalidated and reused.
 */
static void cache_key_gc(struct cbd_cache *cache, struct cbd_cache_key *key)
{
	cache_seg_put(key->cache_pos.cache_seg);
}

/**
 * need_gc - Determines if garbage collection is needed for the cache.
 * @cache: Pointer to the cbd_cache structure.
 *
 * This function checks if garbage collection is necessary based on the
 * current state of the cache, including the position of the dirty tail,
 * the integrity of the key segment on media, and the percentage of used
 * segments compared to the configured threshold.
 *
 * Return: true if garbage collection is needed, false otherwise.
 */
static bool need_gc(struct cbd_cache *cache)
{
	struct cbd_cache_kset_onmedia *kset_onmedia;
	void *dirty_addr, *key_addr;
	u32 segs_used, segs_gc_threshold;
	int ret;

	/* Refresh dirty_tail position; it may be updated by writeback on the block device side */
	ret = cache_decode_dirty_tail(cache);
	if (ret) {
		cbd_cache_debug(cache, "failed to decode dirty_tail\n");
		return false;
	}

	/* Get addresses for dirty and key tail; wait for writeback to complete for the key before executing GC */
	dirty_addr = cache_pos_addr(&cache->dirty_tail);
	key_addr = cache_pos_addr(&cache->key_tail);
	if (dirty_addr == key_addr) {
		cbd_cache_debug(cache, "key tail is equal to dirty tail.\n");
		return false;
	}

	/* Check if kset_onmedia is corrupted */
	kset_onmedia = (struct cbd_cache_kset_onmedia *)key_addr;
	if (kset_onmedia->magic != CBD_KSET_MAGIC) {
		cbd_cache_debug(cache, "gc error: magic is not as expected. key_tail: %u:%u magic: %llx, expected: %llx\n",
					cache->key_tail.cache_seg->cache_seg_id, cache->key_tail.seg_off,
					kset_onmedia->magic, CBD_KSET_MAGIC);
		return false;
	}

	/* Verify the CRC of the kset_onmedia */
	if (kset_onmedia->crc != cache_kset_crc(kset_onmedia)) {
		cbd_cache_debug(cache, "gc error: crc is not as expected. crc: %x, expected: %x\n",
					cache_kset_crc(kset_onmedia), kset_onmedia->crc);
		return false;
	}

	/*
	 * Load gc_percent and check GC threshold. gc_percent can be modified
	 * via sysfs in metadata, so we need to load the latest cache_info here.
	 */
	cache_info_load(cache);
	segs_used = bitmap_weight(cache->seg_map, cache->n_segs);
	segs_gc_threshold = cache->n_segs * cache->cache_info->gc_percent / 100;
	if (segs_used < segs_gc_threshold) {
		cbd_cache_debug(cache, "segs_used: %u, segs_gc_threshold: %u\n", segs_used, segs_gc_threshold);
		return false;
	}

	return true;
}

/**
 * last_kset_gc - Advances the garbage collection for the last kset.
 * @cache: Pointer to the cbd_cache structure.
 * @kset_onmedia: Pointer to the kset_onmedia structure for the last kset.
 *
 * This function updates the key tail to point to the next segment
 * specified in the kset_onmedia. It clears the segment from the segment map
 * only if the dirty tail has moved beyond the current segment.
 *
 * Return: 0 on success, -EAGAIN if the dirty tail has not moved.
 */
static int last_kset_gc(struct cbd_cache *cache, struct cbd_cache_kset_onmedia *kset_onmedia)
{
	struct cbd_cache_segment *cur_seg, *next_seg;

	/* Don't move to the next segment if dirty_tail has not moved */
	if (cache->dirty_tail.cache_seg == cache->key_tail.cache_seg)
		return -EAGAIN;

	cur_seg = cache->key_tail.cache_seg;

	/* Update key tail to the next segment specified in kset_onmedia */
	next_seg = &cache->segments[kset_onmedia->next_cache_seg_id];
	cache->key_tail.cache_seg = next_seg;
	cache->key_tail.seg_off = 0;
	cache_encode_key_tail(cache);

	cbd_cache_debug(cache, "gc advance kset seg: %u\n", cur_seg->cache_seg_id);

	/* Clear the current segment from the segment map */
	spin_lock(&cache->seg_map_lock);
	clear_bit(cur_seg->cache_seg_id, cache->seg_map);
	spin_unlock(&cache->seg_map_lock);

	return 0;
}

/**
 * cbd_cache_gc_fn - Main function for garbage collection of cache keys.
 * @work: Pointer to the work_struct that contains the gc_work.
 *
 * This function checks if garbage collection is needed and processes
 * each kset_onmedia in the cache. It handles the last kset specially
 * and performs garbage collection on each key in a kset.
 */
void cbd_cache_gc_fn(struct work_struct *work)
{
	struct cbd_cache *cache = container_of(work, struct cbd_cache, gc_work.work);
	struct cbd_cache_kset_onmedia *kset_onmedia;
	struct cbd_cache_key_onmedia *key_onmedia;
	struct cbd_cache_key *key;
	int ret;
	int i;

	while (true) {
		/* Check if garbage collection is needed */
		if (!need_gc(cache))
			break;

		kset_onmedia = (struct cbd_cache_kset_onmedia *)cache_pos_addr(&cache->key_tail);

		/* Handle the last kset differently */
		if (kset_onmedia->flags & CBD_KSET_FLAGS_LAST) {
			ret = last_kset_gc(cache, kset_onmedia);
			if (ret)
				break;
			continue;
		}

		/* Perform garbage collection on each key_onmedia in the kset_onmedia */
		for (i = 0; i < kset_onmedia->key_num; i++) {
			struct cbd_cache_key key_tmp = { 0 };

			key_onmedia = &kset_onmedia->data[i];

			key = &key_tmp;
			cache_key_init(cache, key);

			cache_key_decode(key_onmedia, key);
			cache_key_gc(cache, key);
		}

		/* Advance the key tail position after processing all keys */
		cache_pos_advance(&cache->key_tail, get_kset_onmedia_size(kset_onmedia));
		cache_encode_key_tail(cache);
	}

	/* Requeue the garbage collection work after the defined interval */
	queue_delayed_work(cache->cache_wq, &cache->gc_work, CBD_CACHE_GC_INTERVAL);
}
