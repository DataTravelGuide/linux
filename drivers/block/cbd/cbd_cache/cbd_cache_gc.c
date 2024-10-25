// SPDX-License-Identifier: GPL-2.0-or-later

#include "../cbd_internal.h"
#include "cbd_cache_internal.h"

static void cache_key_gc(struct cbd_cache *cache, struct cbd_cache_key *key)
{
	cache_seg_put(key->cache_pos.cache_seg);
}

static bool need_gc(struct cbd_cache *cache)
{
	struct cbd_cache_kset_onmedia *kset_onmedia;
	void *dirty_addr, *key_addr;
	u32 segs_used, segs_gc_threshold;
	int ret;

	/* refresh dirty_tail pos, it could be updated by writeback on blkdev side */
	ret = cache_decode_dirty_tail(cache);
	if (ret) {
		cbd_cache_err(cache, "failed to decode dirty_tail\n");
		return false;
	}

	dirty_addr = cache_pos_addr(&cache->dirty_tail);
	key_addr = cache_pos_addr(&cache->key_tail);

	if (dirty_addr == key_addr) {
		cbd_cache_debug(cache, "key tail is equal with dirty tail.\n");
		return false;
	}

	/* kset_onmedia corrupted? */
	kset_onmedia = (struct cbd_cache_kset_onmedia *)key_addr;
	if (kset_onmedia->magic != CBD_KSET_MAGIC) {
		cbd_cache_err(cache, "gc error magic is not expected. key_tail: %u:%u magic: %llx, expected: %llx\n",
					cache->key_tail.cache_seg->cache_seg_id, cache->key_tail.seg_off,
					kset_onmedia->magic, CBD_KSET_MAGIC);
		return false;
	}

	if (kset_onmedia->crc != cache_kset_crc(kset_onmedia)) {
		cbd_cache_err(cache, "gc error crc is not expected. crc: %x, expected: %x\n",
					cache_kset_crc(kset_onmedia), kset_onmedia->crc);
		return false;
	}

	/* gc threshold */
	segs_used = bitmap_weight(cache->seg_map, cache->n_segs);
	segs_gc_threshold = cache->n_segs * cache->cache_info->gc_percent / 100;
	if (segs_used < segs_gc_threshold)
		return false;

	return true;
}

static int last_kset_gc(struct cbd_cache *cache, struct cbd_cache_kset_onmedia *kset_onmedia)
{
	struct cbd_cache_segment *cur_seg, *next_seg;

	/* dont move next segment if dirty_tail has not move */
	if (cache->dirty_tail.cache_seg == cache->key_tail.cache_seg)
		return -EAGAIN;

	cur_seg = cache->key_tail.cache_seg;

	next_seg = &cache->segments[kset_onmedia->next_cache_seg_id];
	cache->key_tail.cache_seg = next_seg;
	cache->key_tail.seg_off = 0;
	cache_encode_key_tail(cache);

	cbd_cache_debug(cache, "gc advance kset seg: %u\n", cur_seg->cache_seg_id);
	spin_lock(&cache->seg_map_lock);
	clear_bit(cur_seg->cache_seg_id, cache->seg_map);
	spin_unlock(&cache->seg_map_lock);

	return 0;
}

void cbd_cache_gc_fn(struct work_struct *work)
{
	struct cbd_cache *cache = container_of(work, struct cbd_cache, gc_work.work);
	struct cbd_cache_kset_onmedia *kset_onmedia;
	struct cbd_cache_key_onmedia *key_onmedia;
	struct cbd_cache_key *key;
	int ret;
	int i;

	while (true) {
		if (!need_gc(cache))
			break;

		kset_onmedia = (struct cbd_cache_kset_onmedia *)cache_pos_addr(&cache->key_tail);

		if (kset_onmedia->flags & CBD_KSET_FLAGS_LAST) {
			ret = last_kset_gc(cache, kset_onmedia);
			if (ret)
				break;
			continue;
		}

		/* gc each key_onmedia in kset_onmedia */
		for (i = 0; i < kset_onmedia->key_num; i++) {
			struct cbd_cache_key key_tmp = { 0 };

			key_onmedia = &kset_onmedia->data[i];

			key = &key_tmp;
			cache_key_init(cache, key);

			cache_key_decode(key_onmedia, key);
			cache_key_gc(cache, key);
		}

		cache_pos_advance(&cache->key_tail, get_kset_onmedia_size(kset_onmedia));
		cache_encode_key_tail(cache);
	}

	queue_delayed_work(cache->cache_wq, &cache->gc_work, CBD_CACHE_GC_INTERVAL);
}
