// SPDX-License-Identifier: GPL-2.0-or-later

#include "cache.h"
#include "backing_dev.h"

/**
 * cache_key_gc - Releases the reference of a cache key segment.
 * @cache: Pointer to the pcache_cache structure.
 * @key: Pointer to the cache key to be garbage collected.
 *
 * This function decrements the reference count of the cache segment
 * associated with the given key. If the reference count drops to zero,
 * the segment may be invalidated and reused.
 */
static void cache_key_gc(struct pcache_cache *cache, struct pcache_cache_key *key)
{
	cache_seg_put(key->cache_pos.cache_seg);
}

/**
 * need_gc - Determines if garbage collection is needed for the cache.
 * @cache: Pointer to the pcache_cache structure.
 *
 * This function checks if garbage collection is necessary based on the
 * current state of the cache, including the position of the dirty tail,
 * the integrity of the key segment on media, and the percentage of used
 * segments compared to the configured threshold.
 *
 * Return: true if garbage collection is needed, false otherwise.
 */
static bool need_gc(struct pcache_cache *cache)
{
	struct pcache_cache_kset_onmedia *kset_onmedia;
	void *dirty_addr, *key_addr;
	u32 segs_used, segs_gc_threshold;

	dirty_addr = cache_pos_addr(&cache->dirty_tail);
	key_addr = cache_pos_addr(&cache->key_tail);
	if (dirty_addr == key_addr) {
		backing_dev_debug(cache->backing_dev, "key tail is equal to dirty tail: %u:%u\n",
				cache->dirty_tail.cache_seg->cache_seg_id,
				cache->dirty_tail.seg_off);
		return false;
	}

	/* Check if kset_onmedia is corrupted */
	kset_onmedia = (struct pcache_cache_kset_onmedia *)key_addr;
	if (kset_onmedia->magic != PCACHE_KSET_MAGIC) {
		backing_dev_debug(cache->backing_dev, "gc error: magic is not as expected. key_tail: %u:%u magic: %llx, expected: %llx\n",
					cache->key_tail.cache_seg->cache_seg_id, cache->key_tail.seg_off,
					kset_onmedia->magic, PCACHE_KSET_MAGIC);
		return false;
	}

	/* Verify the CRC of the kset_onmedia */
	if (kset_onmedia->crc != cache_kset_crc(kset_onmedia)) {
		backing_dev_debug(cache->backing_dev, "gc error: crc is not as expected. crc: %x, expected: %x\n",
					cache_kset_crc(kset_onmedia), kset_onmedia->crc);
		return false;
	}

	segs_used = bitmap_weight(cache->seg_map, cache->n_segs);
	segs_gc_threshold = cache->n_segs * cache->cache_info->gc_percent / 100;
	if (segs_used < segs_gc_threshold) {
		backing_dev_debug(cache->backing_dev, "segs_used: %u, segs_gc_threshold: %u\n", segs_used, segs_gc_threshold);
		return false;
	}

	return true;
}

/**
 * last_kset_gc - Advances the garbage collection for the last kset.
 * @cache: Pointer to the pcache_cache structure.
 * @kset_onmedia: Pointer to the kset_onmedia structure for the last kset.
 */
static int last_kset_gc(struct pcache_cache *cache, struct pcache_cache_kset_onmedia *kset_onmedia)
{
	struct pcache_cache_segment *cur_seg, *next_seg;

	/* Don't move to the next segment if dirty_tail has not moved */
	if (cache->dirty_tail.cache_seg == cache->key_tail.cache_seg)
		return -EAGAIN;

	cur_seg = cache->key_tail.cache_seg;

	next_seg = &cache->segments[kset_onmedia->next_cache_seg_id];
	cache->key_tail.cache_seg = next_seg;
	cache->key_tail.seg_off = 0;
	cache_encode_key_tail(cache);

	backing_dev_debug(cache->backing_dev, "gc advance kset seg: %u\n", cur_seg->cache_seg_id);

	spin_lock(&cache->seg_map_lock);
	clear_bit(cur_seg->cache_seg_id, cache->seg_map);
	spin_unlock(&cache->seg_map_lock);

	return 0;
}

void pcache_cache_gc_fn(struct work_struct *work)
{
	struct pcache_cache *cache = container_of(work, struct pcache_cache, gc_work.work);
	struct pcache_cache_kset_onmedia *kset_onmedia;
	struct pcache_cache_key_onmedia *key_onmedia;
	struct pcache_cache_key *key;
	int ret;
	int i;

	while (true) {
		if (!need_gc(cache))
			break;

		kset_onmedia = (struct pcache_cache_kset_onmedia *)cache_pos_addr(&cache->key_tail);

		if (kset_onmedia->flags & PCACHE_KSET_FLAGS_LAST) {
			ret = last_kset_gc(cache, kset_onmedia);
			if (ret)
				break;
			continue;
		}

		for (i = 0; i < kset_onmedia->key_num; i++) {
			struct pcache_cache_key key_tmp = { 0 };

			key_onmedia = &kset_onmedia->data[i];

			key = &key_tmp;
			cache_key_init(&cache->req_key_tree, key);

			ret = cache_key_decode(cache, key_onmedia, key);
			if (ret) {
				backing_dev_err(cache->backing_dev, "failed to decode cache key in gc\n");
				break;
			}

			cache_key_gc(cache, key);
		}

		backing_dev_debug(cache->backing_dev, "gc advance: %u:%u %u\n",
			cache->key_tail.cache_seg->cache_seg_id,
			cache->key_tail.seg_off,
			get_kset_onmedia_size(kset_onmedia));

		cache_pos_advance(&cache->key_tail, get_kset_onmedia_size(kset_onmedia));
		cache_encode_key_tail(cache);
	}

	queue_delayed_work(cache->backing_dev->task_wq, &cache->gc_work, PCACHE_CACHE_GC_INTERVAL);
}
