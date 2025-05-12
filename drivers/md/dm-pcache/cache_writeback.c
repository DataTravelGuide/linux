// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/bio.h>

#include "cache.h"
#include "backing_dev.h"

static inline bool is_cache_clean(struct pcache_cache *cache)
{
	struct pcache_cache_kset_onmedia *kset_onmedia;
	struct pcache_cache_pos *pos;
	void *addr;

	pos = &cache->dirty_tail;
	addr = cache_pos_addr(pos);
	kset_onmedia = (struct pcache_cache_kset_onmedia *)addr;

	/* Check if the magic number matches the expected value */
	if (kset_onmedia->magic != PCACHE_KSET_MAGIC) {
		pcache_debug("dirty_tail: %u:%u magic: %llx, not expected: %llx\n",
				pos->cache_seg->cache_seg_id, pos->seg_off,
				kset_onmedia->magic, PCACHE_KSET_MAGIC);
		return true;
	}

	/* Verify the CRC checksum for data integrity */
	if (kset_onmedia->crc != cache_kset_crc(kset_onmedia)) {
		pcache_debug("dirty_tail: %u:%u crc: %x, not expected: %x\n",
				pos->cache_seg->cache_seg_id, pos->seg_off,
				cache_kset_crc(kset_onmedia), kset_onmedia->crc);
		return true;
	}

	return false;
}

void cache_writeback_exit(struct pcache_cache *cache)
{
	cache_flush(cache);

	while (!is_cache_clean(cache))
		schedule_timeout(HZ);

	cancel_delayed_work_sync(&cache->writeback_work);
	cache_tree_exit(&cache->writeback_key_tree);
}

int cache_writeback_init(struct pcache_cache *cache)
{
	int ret;

	ret = cache_tree_init(cache, &cache->writeback_key_tree, 1);
	if (ret)
		goto err;

	/* Queue delayed work to start writeback handling */
	queue_delayed_work(cache_get_wq(cache), &cache->writeback_work, 0);

	return 0;
err:
	return ret;
}

static int cache_key_writeback(struct pcache_cache *cache, struct pcache_cache_key *key)
{
	struct pcache_cache_pos *pos;
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

static int cache_wb_tree_writeback(struct pcache_cache *cache)
{
	struct pcache_cache_tree *cache_tree = &cache->writeback_key_tree;
	struct pcache_cache_subtree *cache_subtree;
	struct rb_node *node;
	struct pcache_cache_key *key;
	int ret;
	u32 i;

	for (i = 0; i < cache_tree->n_subtrees; i++) {
		cache_subtree = &cache_tree->subtrees[i];

		node = rb_first(&cache_subtree->root);
		while (node) {
			key = CACHE_KEY(node);
			node = rb_next(node);

			ret = cache_key_writeback(cache, key);
			if (ret) {
				pcache_err("writeback error: %d\n", ret);
				return ret;
			}

			cache_key_delete(key);
		}
	}

	/* Sync the entire kset's data to disk to ensure durability */
	vfs_fsync(cache->bdev_file, 1);

	return 0;
}

static int cache_kset_insert_tree(struct pcache_cache *cache, struct pcache_cache_kset_onmedia *kset_onmedia)
{
	struct pcache_cache_key_onmedia *key_onmedia;
	struct pcache_cache_key *key;
	int ret;
	u32 i;

	/* Iterate through all keys in the kset and write each back to storage */
	for (i = 0; i < kset_onmedia->key_num; i++) {
		key_onmedia = &kset_onmedia->data[i];

		key = cache_key_alloc(&cache->writeback_key_tree);
		if (!key)
			return -ENOMEM;

		ret = cache_key_decode(cache, key_onmedia, key);
		if (ret) {
			cache_key_delete(key);
			return ret;
		}

		ret = cache_key_insert(&cache->writeback_key_tree, key, true);
		if (ret) {
			cache_key_delete(key);
			return ret;
		}
	}

	return 0;
}

static void last_kset_writeback(struct pcache_cache *cache,
		struct pcache_cache_kset_onmedia *last_kset_onmedia)
{
	struct pcache_cache_segment *next_seg;

	pcache_debug("last kset, next: %u\n", last_kset_onmedia->next_cache_seg_id);

	next_seg = &cache->segments[last_kset_onmedia->next_cache_seg_id];

	cache->dirty_tail.cache_seg = next_seg;
	cache->dirty_tail.seg_off = 0;
	cache_encode_dirty_tail(cache);
}

void cache_writeback_fn(struct work_struct *work)
{
	struct pcache_cache *cache = container_of(work, struct pcache_cache, writeback_work.work);
	struct pcache_cache_kset_onmedia *kset_onmedia;
	int ret = 0;
	void *addr;

	/* Loop until all dirty data is written back and the cache is clean */
	while (true) {
		if (is_cache_clean(cache))
			break;

		addr = cache_pos_addr(&cache->dirty_tail);
		kset_onmedia = (struct pcache_cache_kset_onmedia *)addr;

		if (kset_onmedia->flags & PCACHE_KSET_FLAGS_LAST) {
			last_kset_writeback(cache, kset_onmedia);
			continue;
		}

		ret = cache_kset_insert_tree(cache, kset_onmedia);
		if (ret)
			break;

		ret = cache_wb_tree_writeback(cache);
		if (ret)
			break;

		pcache_debug("writeback advance: %u:%u %u\n",
			cache->dirty_tail.cache_seg->cache_seg_id,
			cache->dirty_tail.seg_off,
			get_kset_onmedia_size(kset_onmedia));

		cache_pos_advance(&cache->dirty_tail, get_kset_onmedia_size(kset_onmedia));

		cache_encode_dirty_tail(cache);
	}

	queue_delayed_work(cache_get_wq(cache), &cache->writeback_work, PCACHE_CACHE_WRITEBACK_INTERVAL);
}
