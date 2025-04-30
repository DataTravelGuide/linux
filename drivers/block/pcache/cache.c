// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/blk_types.h>

#include "logic_dev.h"
#include "cache.h"
#include "backing_dev.h"

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
	cache->cache_info->seg_id = seg_id;
	backing_dev_info_write(cache->backing_dev);
}

static struct pcache_cache *cache_alloc(struct pcache_backing_dev *backing_dev)
{
	struct pcache_cache *cache;

	cache = kvzalloc(struct_size(cache, segments, backing_dev->cache_segs), GFP_KERNEL);
	if (!cache)
		goto err;

	cache->seg_map = bitmap_zalloc(backing_dev->cache_segs, GFP_KERNEL);
	if (!cache->seg_map)
		goto free_cache;

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
free_cache:
	kvfree(cache);
err:
	return NULL;
}

static void cache_free(struct pcache_cache *cache)
{
	kmem_cache_destroy(cache->req_cache);
	bitmap_free(cache->seg_map);
	kvfree(cache);
}

static void pcache_cache_info_init(struct pcache_cache_opts *opts)
{
	struct pcache_cache_info *cache_info = opts->cache_info;

	cache_info->n_segs = opts->n_segs;
	cache_info->gc_percent = PCACHE_CACHE_GC_PERCENT_DEFAULT;
	if (opts->data_crc)
		cache_info->flags |= PCACHE_CACHE_FLAGS_DATA_CRC;
}

static int cache_validate(struct pcache_backing_dev *backing_dev,
			  struct pcache_cache_opts *opts)
{
	struct pcache_cache_info *cache_info;
	int ret = -EINVAL;

	if (opts->n_paral > PCACHE_CACHE_PARAL_MAX) {
		backing_dev_err(backing_dev, "n_paral too large (max %u).\n",
			 PCACHE_CACHE_PARAL_MAX);
		goto err;
	}

	if (opts->new_cache)
		pcache_cache_info_init(opts);

	cache_info = opts->cache_info;

	/*
	 * Check if the number of segments required for the specified n_paral
	 * exceeds the available segments in the cache. If so, report an error.
	 */
	if (opts->n_paral * PCACHE_CACHE_SEGS_EACH_PARAL > cache_info->n_segs) {
		backing_dev_err(backing_dev, "n_paral %u requires cache size (%llu), more than current (%llu).",
				opts->n_paral, opts->n_paral * PCACHE_CACHE_SEGS_EACH_PARAL * (u64)PCACHE_SEG_SIZE,
				cache_info->n_segs * (u64)PCACHE_SEG_SIZE);
		goto err;
	}

	if (cache_info->n_segs > backing_dev->cache_dev->seg_num) {
		backing_dev_err(backing_dev, "too large cache_segs: %u, segment_num: %u\n",
				cache_info->n_segs, backing_dev->cache_dev->seg_num);
		goto err;
	}

	if (cache_info->n_segs > PCACHE_CACHE_SEGS_MAX) {
		backing_dev_err(backing_dev, "cache_segs: %u larger than PCACHE_CACHE_SEGS_MAX: %u\n",
				cache_info->n_segs, PCACHE_CACHE_SEGS_MAX);
		goto err;
	}

	return 0;

err:
	return ret;
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
			backing_dev_err(cache->backing_dev, "Corrupted key tail or dirty tail.\n");
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
			backing_dev_err(backing_dev, "no available segment\n");
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
			*seg_id = cache->cache_info->seg_id;
		}
	}
	return 0;
err:
	return ret;
}

static int cache_segs_init(struct pcache_cache *cache, bool new_cache)
{
	struct pcache_cache_segment *prev_cache_seg = NULL;
	struct pcache_cache_info *cache_info = cache->cache_info;
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
	u32 i;

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

	cache->n_heads = n_paral;
	cache->data_heads = kcalloc(cache->n_heads, sizeof(struct pcache_cache_data_head), GFP_KERNEL);
	if (!cache->data_heads) {
		ret = -ENOMEM;
		goto free_kset;
	}

	for (i = 0; i < cache->n_heads; i++) {
		struct pcache_cache_data_head *data_head = &cache->data_heads[i];

		spin_lock_init(&data_head->data_head_lock);
	}

	/*
	 * Replay persisted cache keys using cache_replay.
	 * This function loads and replays cache keys from previously stored
	 * ksets, allowing the cache to restore its state after a restart.
	 */
	ret = cache_replay(cache);
	if (ret) {
		backing_dev_err(cache->backing_dev, "failed to replay keys\n");
		goto free_heads;
	}

	return 0;

free_heads:
	kfree(cache->data_heads);
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

	kfree(cache->data_heads);
	kfree(cache->ksets);
	cache_tree_exit(&cache->req_key_tree);
}

struct pcache_cache *pcache_cache_alloc(struct pcache_backing_dev *backing_dev,
				  struct pcache_cache_opts *opts)
{
	struct pcache_cache *cache;
	int ret;

	ret = cache_validate(backing_dev, opts);
	if (ret)
		return NULL;

	cache = cache_alloc(backing_dev);
	if (!cache)
		return NULL;

	cache->bdev_file = opts->bdev_file;
	cache->dev_size = opts->dev_size;
	cache->cache_info = opts->cache_info;
	cache->state = PCACHE_CACHE_STATE_RUNNING;

	ret = cache_segs_init(cache, opts->new_cache);
	if (ret)
		goto free_cache;

	ret = cache_tail_init(cache, opts->new_cache);
	if (ret)
		goto segs_destroy;

	ret = cache_init_req_keys(cache, opts->n_paral);
	if (ret)
		goto segs_destroy;

	ret = cache_writeback_init(cache);
	if (ret)
		goto destroy_keys;

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
