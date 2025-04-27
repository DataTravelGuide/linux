// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/blk_types.h>

#include "cache.h"
#include "backing_dev.h"
#include "dm_pcache.h"

static void cache_info_write(struct pcache_cache *cache)
{
	struct pcache_cache_info *cache_info = &cache->cache_info;
	struct pcache_cache_info *cache_info_addr;

	cache_info->header.seq++;
	cache_info_addr = pcache_meta_find_oldest(&cache->cache_info_addr->header, PCACHE_CACHE_INFO_SIZE);

	memcpy(cache_info_addr, cache_info, sizeof(struct pcache_cache_info));

	cache_info_addr->header.crc = pcache_meta_crc(&cache_info_addr->header, PCACHE_CACHE_INFO_SIZE);
	cache_dev_flush(cache->backing_dev->cache_dev, cache_info_addr, PCACHE_CACHE_INFO_SIZE);
}

static void cache_info_init(struct pcache_cache *cache);
static void cache_info_load(struct pcache_cache *cache)
{
	struct pcache_cache_info *cache_info_addr;

	cache_info_addr = pcache_meta_find_latest(&cache->cache_info_addr->header, PCACHE_CACHE_INFO_SIZE);

	if (!cache_info_addr)
		cache_info_init(cache);
	else
		memcpy(&cache->cache_info, cache_info_addr, sizeof(struct pcache_cache_info));
}

void cache_pos_encode(struct pcache_cache *cache,
			     struct pcache_cache_pos_onmedia *pos_onmedia,
			     struct pcache_cache_pos *pos)
{
	struct pcache_cache_pos_onmedia *oldest;

	oldest = pcache_meta_find_oldest(&pos_onmedia->header, sizeof(struct pcache_cache_pos_onmedia));
	BUG_ON(!oldest);

	oldest->cache_seg_id = pos->cache_seg->cache_seg_id;
	oldest->seg_off = pos->seg_off;
	oldest->header.seq = pcache_meta_get_next_seq(&pos_onmedia->header, sizeof(struct pcache_cache_pos_onmedia));
	oldest->header.crc = cache_pos_onmedia_crc(oldest);
	cache_dev_flush(cache->backing_dev->cache_dev, oldest, sizeof(struct pcache_cache_pos_onmedia));
}

int cache_pos_decode(struct pcache_cache *cache,
			    struct pcache_cache_pos_onmedia *pos_onmedia,
			    struct pcache_cache_pos *pos)
{
	struct pcache_cache_pos_onmedia *latest;

	latest = pcache_meta_find_latest(&pos_onmedia->header, sizeof(struct pcache_cache_pos_onmedia));
	if (!latest)
		return -EIO;

	pos->cache_seg = &cache->segments[latest->cache_seg_id];
	pos->seg_off = latest->seg_off;

	return 0;
}

static void cache_info_set_seg_id(struct pcache_cache *cache, u32 seg_id)
{
	cache->cache_info.seg_id = seg_id;
}

static struct pcache_cache *cache_alloc(struct pcache_backing_dev *backing_dev)
{
	struct pcache_cache *cache;

	cache = kzalloc(sizeof(struct pcache_cache), GFP_KERNEL);
	if (!cache)
		goto err;

	cache->segments = kvzalloc(sizeof(struct pcache_cache_segment) * backing_dev->cache_segs, GFP_KERNEL);
	if (!cache->segments)
		goto free_cache;

	cache->seg_map = bitmap_zalloc(backing_dev->cache_segs, GFP_KERNEL);
	if (!cache->seg_map)
		goto free_segments;

	cache->req_cache = KMEM_CACHE(pcache_backing_dev_req, 0);
	if (!cache->req_cache)
		goto free_bitmap;

	cache->backing_dev = backing_dev;
	cache->n_segs = backing_dev->cache_segs;
	spin_lock_init(&cache->seg_map_lock);
	spin_lock_init(&cache->key_head_lock);

	mutex_init(&cache->key_tail_lock);
	mutex_init(&cache->dirty_tail_lock);

	INIT_DELAYED_WORK(&cache->writeback_work, cache_writeback_fn);
	INIT_DELAYED_WORK(&cache->gc_work, pcache_cache_gc_fn);
	INIT_WORK(&cache->clean_work, clean_fn);

	return cache;

free_bitmap:
	bitmap_free(cache->seg_map);
free_segments:
	kvfree(cache->segments);
free_cache:
	kfree(cache);
err:
	return NULL;
}

static void cache_free(struct pcache_cache *cache)
{
	kmem_cache_destroy(cache->req_cache);
	bitmap_free(cache->seg_map);
	kvfree(cache->segments);
	kvfree(cache);
}

static void cache_info_init(struct pcache_cache *cache)
{
	struct pcache_backing_dev *backing_dev = cache->backing_dev;
	struct pcache_cache_info *cache_info = &cache->cache_info;

	cache_info->n_segs = backing_dev->cache_dev->seg_num;
	pr_err("init n_segs: %u", cache_info->n_segs);
	cache_info->gc_percent = PCACHE_CACHE_GC_PERCENT_DEFAULT;
	cache_info->flags |= PCACHE_CACHE_FLAGS_DATA_CRC;
}

static int cache_tail_init(struct pcache_cache *cache, bool new_cache)
{
	int ret;

	if (new_cache) {
		set_bit(0, cache->seg_map);

		cache->key_head.cache_seg = &cache->segments[0];
		cache->key_head.seg_off = 0;
		cache_pos_copy(&cache->key_tail, &cache->key_head);
		cache_pos_copy(&cache->dirty_tail, &cache->key_head);

		cache_encode_dirty_tail(cache);
		cache_encode_key_tail(cache);
	} else {
		if (cache_decode_key_tail(cache) || cache_decode_dirty_tail(cache)) {
			pcache_err("Corrupted key tail or dirty tail.\n");
			ret = -EIO;
			goto err;
		}
	}
	return 0;
err:
	return ret;
}

static void cache_segs_destroy(struct pcache_cache *cache)
{
	u32 i;

	for (i = 0; i < cache->n_segs; i++)
		cache_seg_destroy(&cache->segments[i]);
}

static int get_seg_id(struct pcache_cache *cache,
		      struct pcache_cache_segment *prev_cache_seg,
		      bool new_cache, u32 *seg_id)
{
	struct pcache_backing_dev *backing_dev = cache->backing_dev;
	struct pcache_cache_dev *cache_dev = backing_dev->cache_dev;
	int ret;

	if (new_cache) {
		ret = cache_dev_get_empty_segment_id(cache_dev, seg_id);
		if (ret) {
			pcache_err("no available segment\n");
			goto err;
		}

		if (prev_cache_seg)
			cache_seg_set_next_seg(prev_cache_seg, *seg_id);
		else
			cache_info_set_seg_id(cache, *seg_id);
	} else {
		if (prev_cache_seg) {
			struct pcache_segment_info *prev_seg_info;

			prev_seg_info = &prev_cache_seg->cache_seg_info.segment_info;
			if (!segment_info_has_next(prev_seg_info)) {
				ret = -EFAULT;
				goto err;
			}
			*seg_id = prev_cache_seg->cache_seg_info.segment_info.next_seg;
		} else {
			*seg_id = cache->cache_info.seg_id;
		}
	}
	return 0;
err:
	return ret;
}

static int cache_segs_init(struct pcache_cache *cache, bool new_cache)
{
	struct pcache_cache_segment *prev_cache_seg = NULL;
	struct pcache_cache_info *cache_info = &cache->cache_info;
	u32 seg_id;
	int ret;
	u32 i;

	for (i = 0; i < cache_info->n_segs; i++) {
		ret = get_seg_id(cache, prev_cache_seg, new_cache, &seg_id);
		if (ret)
			goto segments_destroy;

		ret = cache_seg_init(cache, seg_id, i, new_cache);
		if (ret)
			goto segments_destroy;

		prev_cache_seg = &cache->segments[i];
	}
	return 0;

segments_destroy:
	cache_segs_destroy(cache);

	return ret;
}

static int cache_init_req_keys(struct pcache_cache *cache, u32 n_paral)
{
	u32 n_subtrees;
	int ret;
	u32 i, cpu;

	/* Calculate number of cache trees based on the device size */
	n_subtrees = DIV_ROUND_UP(cache->dev_size << SECTOR_SHIFT, PCACHE_CACHE_SUBTREE_SIZE);
	ret = cache_tree_init(cache, &cache->req_key_tree, n_subtrees);
	if (ret)
		goto err;

	/* Set the number of ksets based on n_paral, often corresponding to blkdev multiqueue count */
	cache->n_ksets = n_paral;
	cache->ksets = kcalloc(cache->n_ksets, PCACHE_KSET_SIZE, GFP_KERNEL);
	if (!cache->ksets) {
		ret = -ENOMEM;
		goto req_tree_exit;
	}

	/*
	 * Initialize each kset with a spinlock and delayed work for flushing.
	 * Each kset is associated with one queue to ensure independent handling
	 * of cache keys across multiple queues, maximizing multiqueue concurrency.
	 */
	for (i = 0; i < cache->n_ksets; i++) {
		struct pcache_cache_kset *kset = get_kset(cache, i);

		kset->cache = cache;
		spin_lock_init(&kset->kset_lock);
		INIT_DELAYED_WORK(&kset->flush_work, kset_flush_fn);
	}

	cache->data_heads = alloc_percpu(struct pcache_cache_data_head);
	if (!cache->data_heads) {
		ret = -ENOMEM;
		goto free_kset;
	}

	for_each_possible_cpu(cpu) {
		struct pcache_cache_data_head *h =
			per_cpu_ptr(cache->data_heads, cpu);
		h->head_pos.cache_seg = NULL;
	}

	/*
	 * Replay persisted cache keys using cache_replay.
	 * This function loads and replays cache keys from previously stored
	 * ksets, allowing the cache to restore its state after a restart.
	 */
	ret = cache_replay(cache);
	if (ret) {
		pcache_err("failed to replay keys\n");
		goto free_heads;
	}

	return 0;

free_heads:
	free_percpu(cache->data_heads);
free_kset:
	kfree(cache->ksets);
req_tree_exit:
	cache_tree_exit(&cache->req_key_tree);
err:
	return ret;
}

static void cache_destroy_req_keys(struct pcache_cache *cache)
{
	u32 i;

	for (i = 0; i < cache->n_ksets; i++) {
		struct pcache_cache_kset *kset = get_kset(cache, i);

		cancel_delayed_work_sync(&kset->flush_work);
	}

	free_percpu(cache->data_heads);
	kfree(cache->ksets);
	cache_tree_exit(&cache->req_key_tree);
}

struct pcache_cache *pcache_cache_alloc(struct dm_pcache *pcache)
{
	struct pcache_backing_dev *backing_dev = &pcache->backing_dev;
	struct pcache_cache *cache;
	bool new_cache = true;
	int ret;

	cache = cache_alloc(backing_dev);
	if (!cache)
		return NULL;

	cache->cache_info_addr = CACHE_DEV_CACHE_INFO(backing_dev->cache_dev);
	backing_dev->cache = cache;
	cache->bdev_file = backing_dev->bdev_file;
	cache->dev_size = backing_dev->dev_size;
	cache->state = PCACHE_CACHE_STATE_RUNNING;

	cache_info_load(cache);

	new_cache = !(cache->cache_info.flags & PCACHE_CACHE_FLAGS_INIT_DONE);

	ret = cache_segs_init(cache, new_cache);
	if (ret)
		goto free_cache;

	ret = cache_tail_init(cache, new_cache);
	if (ret)
		goto segs_destroy;

	ret = cache_init_req_keys(cache, num_online_cpus());
	if (ret)
		goto segs_destroy;

	ret = cache_writeback_init(cache);
	if (ret)
		goto destroy_keys;

	cache->cache_info.flags |= PCACHE_CACHE_FLAGS_INIT_DONE;
	cache_info_write(cache);
	queue_delayed_work(cache->backing_dev->task_wq, &cache->gc_work, 0);

	return cache;

destroy_keys:
	cache_destroy_req_keys(cache);
segs_destroy:
	cache_segs_destroy(cache);
free_cache:
	cache_free(cache);

	return NULL;
}

void pcache_cache_destroy(struct pcache_cache *cache)
{
	cache->state = PCACHE_CACHE_STATE_STOPPING;
	cache_flush(cache);

	cancel_delayed_work_sync(&cache->gc_work);
	flush_work(&cache->clean_work);

	cache_writeback_exit(cache);

	if (cache->req_key_tree.n_subtrees)
		cache_destroy_req_keys(cache);

	cache_segs_destroy(cache);
	cache_free(cache);
}
