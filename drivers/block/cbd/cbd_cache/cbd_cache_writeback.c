// SPDX-License-Identifier: GPL-2.0-or-later

#include "../cbd_internal.h"
#include "cbd_cache_internal.h"

void cache_writeback_exit(struct cbd_cache *cache)
{
	cache_flush(cache);

	while (!cache_clean(cache))
		schedule_timeout(HZ);

	cancel_delayed_work_sync(&cache->writeback_work);
	bioset_exit(cache->bioset);
	kfree(cache->bioset);
}

int cache_writeback_init(struct cbd_cache *cache)
{
	int ret;

	cache->bioset = kzalloc(sizeof(*cache->bioset), GFP_KERNEL);
	if (!cache->bioset) {
		ret = -ENOMEM;
		goto err;
	}

	ret = bioset_init(cache->bioset, 256, 0, BIOSET_NEED_BVECS);
	if (ret) {
		kfree(cache->bioset);
		cache->bioset = NULL;
		goto err;
	}

	queue_delayed_work(cache->cache_wq, &cache->writeback_work, 0);

	return 0;

err:
	return ret;
}

static int cache_key_writeback(struct cbd_cache *cache, struct cbd_cache_key *key)
{
	struct cbd_cache_pos *pos;
	void *addr;
	ssize_t written;
	u32 seg_remain;
	u64 off;

	if (cache_key_clean(key))
		return 0;

	pos = &key->cache_pos;

	seg_remain = cache_seg_remain(pos);
	/* all data in one key should be int the same segment */
	BUG_ON(seg_remain < key->len);

	addr = cache_pos_addr(pos);
	off = key->off;
	/* Here write is in sync way, because it should consider
	 * the sequence of overwrites. E.g, K1 writes A at 0-4K,
	 * K2 after K1 writes B to 0-4K, we have to ensure K1
	 * to be written back before K2.
	 */
	written = kernel_write(cache->bdev_file, addr, key->len, &off);
	if (written != key->len)
		return -EIO;

	return 0;
}

static int cache_kset_writeback(struct cbd_cache *cache,
		struct cbd_cache_kset_onmedia *kset_onmedia)
{
	struct cbd_cache_key_onmedia *key_onmedia;
	struct cbd_cache_key *key;
	int ret;
	u32 i;

	for (i = 0; i < kset_onmedia->key_num; i++) {
		key_onmedia = &kset_onmedia->data[i];

		key = cache_key_alloc(cache);
		if (!key) {
			cbd_cache_err(cache, "writeback error failed to alloc key\n");
			return -ENOMEM;
		}

		cache_key_decode(key_onmedia, key);
		ret = cache_key_writeback(cache, key);
		cache_key_put(key);

		if (ret) {
			cbd_cache_err(cache, "writeback error: %d\n", ret);
			return ret;
		}
	}

	vfs_fsync(cache->bdev_file, 1);

	return 0;
}

static void last_kset_handle(struct cbd_cache *cache,
		struct cbd_cache_kset_onmedia *last_kset_onmedia)
{
	struct cbd_cache_segment *next_seg;

	cbd_cache_debug(cache, "last kset, next: %u\n", last_kset_onmedia->next_cache_seg_id);

	next_seg = &cache->segments[last_kset_onmedia->next_cache_seg_id];

	/* update dirty_tail pos */
	cache->dirty_tail.cache_seg = next_seg;
	cache->dirty_tail.seg_off = 0;

	cache_encode_dirty_tail(cache);
}

#ifdef CONFIG_CBD_CRC
static int kset_data_verify(struct cbd_cache *cache,
		struct cbd_cache_kset_onmedia *kset_onmedia)
{
	u32 i;

	for (i = 0; i < kset_onmedia->key_num; i++) {
		struct cbd_cache_key key_tmp = { 0 };
		struct cbd_cache_key *key;
		struct cbd_cache_key_onmedia *key_onmedia;

		key = &key_tmp;
		kref_init(&key->ref);
		key->cache = cache;
		INIT_LIST_HEAD(&key->list_node);

		key_onmedia = &kset_onmedia->data[i];
		cache_key_decode(key_onmedia, key);

		if (key->data_crc != cache_key_data_crc(key)) {
			cbd_cache_debug(cache, "key: %llu:%u data crc(%x) is not expected(%x), wait for data ready.\n",
					key->off, key->len, cache_key_data_crc(key), key->data_crc);
			return -EIO;
		}
	}

	return 0;
}
#endif

void cache_writeback_fn(struct work_struct *work)
{
	struct cbd_cache *cache = container_of(work, struct cbd_cache, writeback_work.work);
	struct cbd_cache_kset_onmedia *kset_onmedia;
	int ret = 0;
	void *addr;

	while (true) {
		if (cache_clean(cache))
			break;

		/* get kset_onmedia from dirty_tail position */
		addr = cache_pos_addr(&cache->dirty_tail);
		kset_onmedia = (struct cbd_cache_kset_onmedia *)addr;

		if (kset_onmedia->flags & CBD_KSET_FLAGS_LAST) {
			last_kset_handle(cache, kset_onmedia);
			continue;
		}

#ifdef CONFIG_CBD_CRC
		/* check the data crc */
		ret = kset_data_verify(cache, kset_onmedia);
		if (ret)
			break;
#endif
		ret = cache_kset_writeback(cache, kset_onmedia);
		if (ret)
			break;

		//cbd_cache_err(cache, "writeback advance: %u:%u %u\n", pos->cache_seg->cache_seg_id, pos->seg_off, get_kset_onmedia_size(kset_onmedia));
		cache_pos_advance(&cache->dirty_tail, get_kset_onmedia_size(kset_onmedia));
		cache_encode_dirty_tail(cache);
	}

	queue_delayed_work(cache->cache_wq, &cache->writeback_work, CBD_CACHE_WRITEBACK_INTERVAL);
}
