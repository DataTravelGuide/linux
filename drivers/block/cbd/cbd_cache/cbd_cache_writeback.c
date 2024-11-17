// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/bio.h>

#include "cbd_cache_internal.h"

static inline bool is_cache_clean(struct cbd_cache *cache)
{
	struct cbd_cache_kset_onmedia *kset_onmedia;
	struct cbd_cache_pos *pos;
	void *addr;

	pos = &cache->dirty_tail;
	addr = cache_pos_addr(pos);
	kset_onmedia = (struct cbd_cache_kset_onmedia *)addr;

	/* Check if the magic number matches the expected value */
	if (kset_onmedia->magic != CBD_KSET_MAGIC) {
		cbd_cache_debug(cache, "dirty_tail: %u:%u magic: %llx, not expected: %llx\n",
				pos->cache_seg->cache_seg_id, pos->seg_off,
				kset_onmedia->magic, CBD_KSET_MAGIC);
		return true;
	}

	/* Verify the CRC checksum for data integrity */
	if (kset_onmedia->crc != cache_kset_crc(kset_onmedia)) {
		cbd_cache_debug(cache, "dirty_tail: %u:%u crc: %x, not expected: %x\n",
				pos->cache_seg->cache_seg_id, pos->seg_off,
				cache_kset_crc(kset_onmedia), kset_onmedia->crc);
		return true;
	}

	return false;
}

void cache_writeback_exit(struct cbd_cache *cache)
{
	cache_flush(cache);

	while (!is_cache_clean(cache))
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

	/* Queue delayed work to start writeback handling */
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
	BUG_ON(seg_remain < key->len);

	addr = cache_pos_addr(pos);
	off = key->off;

	/* Perform synchronous writeback to maintain overwrite sequence.
	 * Ensures data consistency by writing in order. For instance, if K1 writes
	 * data to the range 0-4K and then K2 writes to the same range, K1's write
	 * must complete before K2's.
	 *
	 * Note: We defer flushing data immediately after each key's writeback.
	 * Instead, a `sync` operation is issued once the entire kset (group of keys)
	 * has completed writeback, ensuring all data from the kset is safely persisted
	 * to disk while reducing the overhead of frequent flushes.
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

	/* Iterate through all keys in the kset and write each back to storage */
	for (i = 0; i < kset_onmedia->key_num; i++) {
		struct cbd_cache_key key_tmp = { 0 };

		key_onmedia = &kset_onmedia->data[i];

		key = &key_tmp;
		cache_key_init(NULL, key);

		ret = cache_key_decode(cache, key_onmedia, key);
		if (ret) {
			cbd_cache_err(cache, "failed to decode key: %llu:%u in writeback.",
					key->off, key->len);
			return ret;
		}

		ret = cache_key_writeback(cache, key);
		if (ret) {
			cbd_cache_err(cache, "writeback error: %d\n", ret);
			return ret;
		}
	}

	/* Sync the entire kset's data to disk to ensure durability */
	vfs_fsync(cache->bdev_file, 1);

	return 0;
}

static void last_kset_writeback(struct cbd_cache *cache,
		struct cbd_cache_kset_onmedia *last_kset_onmedia)
{
	struct cbd_cache_segment *next_seg;

	cbd_cache_debug(cache, "last kset, next: %u\n", last_kset_onmedia->next_cache_seg_id);

	next_seg = &cache->segments[last_kset_onmedia->next_cache_seg_id];

	cache->dirty_tail.cache_seg = next_seg;
	cache->dirty_tail.seg_off = 0;
	cache_encode_dirty_tail(cache);
}

void cache_writeback_fn(struct work_struct *work)
{
	struct cbd_cache *cache = container_of(work, struct cbd_cache, writeback_work.work);
	struct cbd_cache_kset_onmedia *kset_onmedia;
	int ret = 0;
	void *addr;

	/* Loop until all dirty data is written back and the cache is clean */
	while (true) {
		if (is_cache_clean(cache))
			break;

		addr = cache_pos_addr(&cache->dirty_tail);
		kset_onmedia = (struct cbd_cache_kset_onmedia *)addr;

		if (kset_onmedia->flags & CBD_KSET_FLAGS_LAST) {
			last_kset_writeback(cache, kset_onmedia);
			continue;
		}

		ret = cache_kset_writeback(cache, kset_onmedia);
		if (ret)
			break;

		cbd_cache_debug(cache, "writeback advance: %u:%u %u\n",
			cache->dirty_tail.cache_seg->cache_seg_id,
			cache->dirty_tail.seg_off,
			get_kset_onmedia_size(kset_onmedia));

		cache_pos_advance(&cache->dirty_tail, get_kset_onmedia_size(kset_onmedia));

		cache_encode_dirty_tail(cache);
	}

	queue_delayed_work(cache->cache_wq, &cache->writeback_work, CBD_CACHE_WRITEBACK_INTERVAL);
}
