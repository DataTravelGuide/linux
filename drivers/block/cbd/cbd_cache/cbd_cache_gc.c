// SPDX-License-Identifier: GPL-2.0-or-later

#include "../cbd_internal.h"
#include "cbd_cache_internal.h"

static void cache_key_gc(struct cbd_cache *cache, struct cbd_cache_key *key)
{
	struct cbd_cache_segment *cache_seg = key->cache_pos.cache_seg;

	//cbd_cache_err(cache, "gc %u\n", cache_seg->cache_seg_id);
	cache_seg_put(cache_seg);
}

/* gc */
static bool need_gc(struct cbd_cache *cache)
{
	void *dirty_addr, *key_addr;
	int ret;

	ret = cache_decode_dirty_tail(cache);
	if (ret) {
		cbd_cache_err(cache, "failed to decode dirty_tail\n");
		return false;
	}

	dirty_addr = cache_pos_addr(&cache->dirty_tail);
	key_addr = cache_pos_addr(&cache->key_tail);

	if (dirty_addr == key_addr) {
		//cbd_cache_err(cache, "dirty_tail == key_tail\n");
		return false;
	}

	//cbd_cache_err(cache, "weight: %u, %u\n", bitmap_weight(cache->seg_map, cache->n_segs), (cache->n_segs * cache->cache_info->gc_percent / 100));

	if (bitmap_weight(cache->seg_map, cache->n_segs) < (cache->n_segs * cache->cache_info->gc_percent / 100))
		return false;


	return true;
}

void cbd_cache_gc_fn(struct work_struct *work)
{
	struct cbd_cache *cache = container_of(work, struct cbd_cache, gc_work.work);
	struct cbd_cache_pos *pos;
	struct cbd_cache_kset_onmedia *kset_onmedia;
	struct cbd_cache_key_onmedia *key_onmedia;
	struct cbd_cache_key *key = NULL;
	void *addr;
	int ret;
	int i;

	while (true) {
		if (cache->state == cbd_cache_state_stopping)
			return;

		if (!need_gc(cache)) {
			queue_delayed_work(cache->cache_wq, &cache->gc_work, CBD_CACHE_GC_INTERVAL);
			return;
		}

		pos = &cache->key_tail;
		addr = cache_pos_addr(pos);
		kset_onmedia = (struct cbd_cache_kset_onmedia *)addr;
		if (kset_onmedia->magic != CBD_KSET_MAGIC) {
			cbd_cache_err(cache, "gc error magic is not expected. key_tail: %u:%u magic: %llx, expected: %llx\n",
						pos->cache_seg->cache_seg_id, pos->seg_off, kset_onmedia->magic, CBD_KSET_MAGIC);
			queue_delayed_work(cache->cache_wq, &cache->gc_work, CBD_CACHE_GC_INTERVAL);
			return;
		}

		if (kset_onmedia->crc != cache_kset_crc(kset_onmedia)) {
			cbd_cache_err(cache, "gc error crc is not expected. crc: %x, expected: %x\n",
						cache_kset_crc(kset_onmedia), kset_onmedia->crc);
			queue_delayed_work(cache->cache_wq, &cache->gc_work, CBD_CACHE_GC_INTERVAL);
			return;
		}

		if (kset_onmedia->flags & CBD_KSET_FLAGS_LAST) {
			struct cbd_cache_segment *cur_seg, *next_seg;

			ret = cache_decode_dirty_tail(cache);
			if (ret)
				continue;

			/* dont move next segment if dirty_tail has not move */
			if (cache->dirty_tail.cache_seg == pos->cache_seg)
				continue;
			cur_seg = pos->cache_seg;
			next_seg = &cache->segments[kset_onmedia->next_cache_seg_id];
			pos->cache_seg = next_seg;
			pos->seg_off = 0;
			cache_encode_key_tail(cache);
			cbd_cache_err(cache, "gc kset seg: %u\n", cur_seg->cache_seg_id);

			spin_lock(&cache->seg_map_lock);
			clear_bit(cur_seg->cache_seg_id, cache->seg_map);
			spin_unlock(&cache->seg_map_lock);
			continue;
		}

		for (i = 0; i < kset_onmedia->key_num; i++) {
			key_onmedia = &kset_onmedia->data[i];

			key = cache_key_alloc(cache);
			if (!key) {
				cbd_cache_err(cache, "gc error failed to alloc key\n");
				queue_delayed_work(cache->cache_wq, &cache->gc_work, CBD_CACHE_GC_INTERVAL);
				return;
			}

			cache_key_decode(key_onmedia, key);
			cache_key_gc(cache, key);
			cache_key_put(key);
		}

		cache_pos_advance(pos, get_kset_onmedia_size(kset_onmedia));
		cache_encode_key_tail(cache);
	}
}

