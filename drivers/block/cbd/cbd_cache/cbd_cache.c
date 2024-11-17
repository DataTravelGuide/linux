// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/blk_types.h>

#include "../cbd_backend.h"
#include "cbd_cache_internal.h"

void cbd_cache_info_init(struct cbd_cache_info *cache_info, u32 cache_segs)
{
	cache_info->n_segs = cache_segs;
	cache_info->gc_percent = CBD_CACHE_GC_PERCENT_DEFAULT;
}

static void cache_segs_destroy(struct cbd_cache *cache)
{
	u32 i;

	if (!cache->owner)
		return;

	for (i = 0; i < cache->n_segs; i++)
		cache_seg_destroy(&cache->segments[i]);
}

static void cache_info_set_seg_id(struct cbd_cache *cache, u32 seg_id)
{
	cache->cache_info->seg_id = seg_id;
	cache_info_write(cache);
}

/*
 * get_seg_id - Retrieve the segment ID for cache initialization
 * @cache: Pointer to the cache structure
 * @prev_cache_seg: Pointer to the previous cache segment in the sequence
 * @new_cache: Flag indicating if this is a new cache initialization
 * @seg_id: Pointer to store the retrieved or allocated segment ID
 *
 * For a new cache, this function allocates a new segment ID,
 * and links it with the previous segment in the chain.
 *
 * If reloading an existing cache, it retrieves the segment ID based on the
 * segment chain, using the previous segment information to maintain continuity.
 */
static int get_seg_id(struct cbd_cache *cache,
		      struct cbd_cache_segment *prev_cache_seg,
		      bool new_cache, u32 *seg_id)
{
	struct cbd_transport *cbdt = cache->cbdt;
	int ret;

	if (new_cache) {
		ret = cbdt_get_empty_segment_id(cbdt, seg_id);
		if (ret) {
			cbd_cache_err(cache, "no available segment\n");
			goto err;
		}

		if (prev_cache_seg)
			cache_seg_set_next_seg(prev_cache_seg, *seg_id);
		else
			cache_info_set_seg_id(cache, *seg_id);
	} else {
		if (prev_cache_seg) {
			struct cbd_segment_info *prev_seg_info;

			prev_seg_info = &prev_cache_seg->cache_seg_info.segment_info;
			if (!cbd_segment_info_has_next(prev_seg_info)) {
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

static int cache_segs_init(struct cbd_cache *cache, bool new_cache)
{
	struct cbd_cache_segment *prev_cache_seg = NULL;
	struct cbd_cache_info *cache_info = cache->cache_info;
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

static void used_segs_update_work_fn(struct work_struct *work)
{
	struct cbd_cache *cache = container_of(work, struct cbd_cache, used_segs_update_work);
	struct cbd_cache_used_segs *used_segs;

	used_segs = cbd_meta_find_oldest(&cache->cache_ctrl->used_segs->header, sizeof(struct cbd_cache_used_segs));

	used_segs->header.seq = cbd_meta_get_next_seq(&used_segs->header, sizeof(struct cbd_cache_used_segs));
	used_segs->used_segs = bitmap_weight(cache->seg_map, cache->n_segs);
	used_segs->header.crc = cbd_meta_crc(&used_segs->header, sizeof(struct cbd_cache_used_segs));

	cbdt_flush(cache->cbdt, used_segs, sizeof(struct cbd_cache_used_segs));
}

static struct cbd_cache *cache_alloc(struct cbd_transport *cbdt, struct cbd_cache_info *cache_info)
{
	struct cbd_cache *cache;

	cache = kvzalloc(struct_size(cache, segments, cache_info->n_segs), GFP_KERNEL);
	if (!cache)
		goto err;

	cache->seg_map = bitmap_zalloc(cache_info->n_segs, GFP_KERNEL);
	if (!cache->seg_map)
		goto free_cache;

	cache->req_cache = KMEM_CACHE(cbd_request, 0);
	if (!cache->req_cache)
		goto free_bitmap;

	cache->cache_wq = alloc_workqueue("cbdt%d-c%u",  WQ_UNBOUND | WQ_MEM_RECLAIM,
					0, cbdt->id, cache->cache_id);
	if (!cache->cache_wq)
		goto free_req_cache;

	cache->cbdt = cbdt;
	cache->cache_info = cache_info;
	cache->n_segs = cache_info->n_segs;
	spin_lock_init(&cache->seg_map_lock);
	spin_lock_init(&cache->key_head_lock);
	spin_lock_init(&cache->miss_read_reqs_lock);
	INIT_LIST_HEAD(&cache->miss_read_reqs);

	mutex_init(&cache->key_tail_lock);
	mutex_init(&cache->dirty_tail_lock);

	INIT_DELAYED_WORK(&cache->writeback_work, cache_writeback_fn);
	INIT_DELAYED_WORK(&cache->gc_work, cbd_cache_gc_fn);
	INIT_WORK(&cache->clean_work, clean_fn);
	INIT_WORK(&cache->miss_read_end_work, miss_read_end_work_fn);
	INIT_WORK(&cache->used_segs_update_work, used_segs_update_work_fn);

	return cache;

free_req_cache:
	kmem_cache_destroy(cache->req_cache);
free_bitmap:
	bitmap_free(cache->seg_map);
free_cache:
	kvfree(cache);
err:
	return NULL;
}

static void cache_free(struct cbd_cache *cache)
{
	drain_workqueue(cache->cache_wq);
	destroy_workqueue(cache->cache_wq);
	kmem_cache_destroy(cache->req_cache);
	bitmap_free(cache->seg_map);
	kvfree(cache);
}

static int cache_init_req_keys(struct cbd_cache *cache, u32 n_paral)
{
	u32 n_subtrees;
	int ret;
	u32 i;

	/* Calculate number of cache trees based on the device size */
	n_subtrees = DIV_ROUND_UP(cache->dev_size << SECTOR_SHIFT, CBD_CACHE_SUBTREE_SIZE);
	ret = cache_tree_init(cache, &cache->req_key_tree, n_subtrees);
	if (ret)
		goto err;

	/* Set the number of ksets based on n_paral, often corresponding to blkdev multiqueue count */
	cache->n_ksets = n_paral;
	cache->ksets = kcalloc(cache->n_ksets, CBD_KSET_SIZE, GFP_KERNEL);
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
		struct cbd_cache_kset *kset = get_kset(cache, i);

		kset->cache = cache;
		spin_lock_init(&kset->kset_lock);
		INIT_DELAYED_WORK(&kset->flush_work, kset_flush_fn);
	}

	cache->n_heads = n_paral;
	cache->data_heads = kcalloc(cache->n_heads, sizeof(struct cbd_cache_data_head), GFP_KERNEL);
	if (!cache->data_heads) {
		ret = -ENOMEM;
		goto free_kset;
	}

	for (i = 0; i < cache->n_heads; i++) {
		struct cbd_cache_data_head *data_head = &cache->data_heads[i];

		spin_lock_init(&data_head->data_head_lock);
	}

	/*
	 * Replay persisted cache keys using cache_replay.
	 * This function loads and replays cache keys from previously stored
	 * ksets, allowing the cache to restore its state after a restart.
	 */
	ret = cache_replay(cache);
	if (ret) {
		cbd_cache_err(cache, "failed to replay keys\n");
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

static void cache_destroy_req_keys(struct cbd_cache *cache)
{
	u32 i;

	for (i = 0; i < cache->n_ksets; i++) {
		struct cbd_cache_kset *kset = get_kset(cache, i);

		cancel_delayed_work_sync(&kset->flush_work);
	}

	kfree(cache->data_heads);
	kfree(cache->ksets);
	cache_tree_exit(&cache->req_key_tree);
}

static int __cache_info_load(struct cbd_transport *cbdt,
			      struct cbd_cache_info *cache_info,
			      u32 cache_id);
static int cache_validate(struct cbd_transport *cbdt,
			  struct cbd_cache_opts *opts)
{
	struct cbd_cache_info *cache_info;
	int ret = -EINVAL;

	if (opts->n_paral > CBD_CACHE_PARAL_MAX) {
		cbdt_err(cbdt, "n_paral too large (max %u).\n",
			 CBD_CACHE_PARAL_MAX);
		goto err;
	}

	/*
	 * For a new cache, ensure an owner backend is specified
	 * and initialize cache information with the specified number of segments.
	 */
	if (opts->new_cache) {
		if (!opts->owner) {
			cbdt_err(cbdt, "owner is needed for new cache.\n");
			goto err;
		}

		cbd_cache_info_init(opts->cache_info, opts->n_segs);
	} else {
		/* Load cache information from storage for existing cache */
		ret = __cache_info_load(cbdt, opts->cache_info, opts->cache_id);
		if (ret)
			goto err;
	}

	cache_info = opts->cache_info;

	/*
	 * Check if the number of segments required for the specified n_paral
	 * exceeds the available segments in the cache. If so, report an error.
	 */
	if (opts->n_paral * CBD_CACHE_SEGS_EACH_PARAL > cache_info->n_segs) {
		cbdt_err(cbdt, "n_paral %u requires cache size (%llu), more than current (%llu).",
				opts->n_paral, opts->n_paral * CBD_CACHE_SEGS_EACH_PARAL * (u64)CBDT_SEG_SIZE,
				cache_info->n_segs * (u64)CBDT_SEG_SIZE);
		goto err;
	}

	if (cache_info->n_segs > cbdt->transport_info.segment_num) {
		cbdt_err(cbdt, "too large cache_segs: %u, segment_num: %u\n",
				cache_info->n_segs, cbdt->transport_info.segment_num);
		goto err;
	}

	if (cache_info->n_segs > CBD_CACHE_SEGS_MAX) {
		cbdt_err(cbdt, "cache_segs: %u larger than CBD_CACHE_SEGS_MAX: %u\n",
				cache_info->n_segs, CBD_CACHE_SEGS_MAX);
		goto err;
	}

	return 0;

err:
	return ret;
}

static int cache_tail_init(struct cbd_cache *cache, bool new_cache)
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
			cbd_cache_err(cache, "Corrupted key tail or dirty tail.\n");
			ret = -EIO;
			goto err;
		}
	}
	return 0;
err:
	return ret;
}

struct cbd_cache *cbd_cache_alloc(struct cbd_transport *cbdt,
				  struct cbd_cache_opts *opts)
{
	struct cbd_cache *cache;
	int ret;

	ret = cache_validate(cbdt, opts);
	if (ret)
		return NULL;

	cache = cache_alloc(cbdt, opts->cache_info);
	if (!cache)
		return NULL;

	cache->bdev_file = opts->bdev_file;
	cache->dev_size = opts->dev_size;
	cache->cache_id = opts->cache_id;
	cache->owner = opts->owner;
	cache->state = CBD_CACHE_STATE_RUNNING;

	ret = cache_segs_init(cache, opts->new_cache);
	if (ret)
		goto free_cache;

	ret = cache_tail_init(cache, opts->new_cache);
	if (ret)
		goto segs_destroy;

	if (opts->init_req_keys) {
		ret = cache_init_req_keys(cache, opts->n_paral);
		if (ret)
			goto segs_destroy;
	}

	if (opts->start_writeback) {
		cache->start_writeback = 1;
		ret = cache_writeback_init(cache);
		if (ret)
			goto destroy_keys;
	}

	if (opts->start_gc) {
		cache->start_gc = 1;
		queue_delayed_work(cache->cache_wq, &cache->gc_work, 0);
	}

	return cache;

destroy_keys:
	cache_destroy_req_keys(cache);
segs_destroy:
	cache_segs_destroy(cache);
free_cache:
	cache_free(cache);

	return NULL;
}

void cbd_cache_destroy(struct cbd_cache *cache)
{
	cache->state = CBD_CACHE_STATE_STOPPING;

	flush_work(&cache->miss_read_end_work);
	cache_flush(cache);

	if (cache->start_gc) {
		cancel_delayed_work_sync(&cache->gc_work);
		flush_work(&cache->clean_work);
	}

	if (cache->start_writeback)
		cache_writeback_exit(cache);

	if (cache->req_key_tree.n_subtrees)
		cache_destroy_req_keys(cache);

	flush_work(&cache->used_segs_update_work);

	cache_segs_destroy(cache);
	cache_free(cache);
}

/*
 * cache_info_write - Write cache information to backend
 * @cache: Pointer to the cache structure
 *
 * This function writes the cache's metadata to the backend. Only the owner
 * backend of the cache is permitted to perform this operation. It asserts
 * that the cache has an owner backend.
 */
void cache_info_write(struct cbd_cache *cache)
{
	struct cbd_backend *backend = cache->owner;

	/* Ensure only owner backend is allowed to write */
	BUG_ON(!backend);

	cbd_backend_info_write(backend);
}

static int __cache_info_load(struct cbd_transport *cbdt,
			      struct cbd_cache_info *cache_info,
			      u32 cache_id)
{
	struct cbd_backend_info *backend_info;

	backend_info = cbdt_backend_info_read(cbdt, cache_id);
	if (!backend_info)
		return -ENOENT;

	memcpy(cache_info, &backend_info->cache_info, sizeof(struct cbd_cache_info));

	return 0;
}

int cache_info_load(struct cbd_cache *cache)
{
	return __cache_info_load(cache->cbdt, cache->cache_info, cache->cache_id);
}

u32 cache_info_used_segs(struct cbd_transport *cbdt, struct cbd_cache_info *cache_info)
{
	struct cbd_cache_used_segs *latest_used_segs;
	struct cbd_cache_ctrl *cache_ctrl;
	void *seg_info;

	seg_info = cbdt_get_segment_info(cbdt, cache_info->seg_id);
	cache_ctrl = (seg_info + CBDT_CACHE_SEG_CTRL_OFF);

	latest_used_segs = cbd_meta_find_latest(&cache_ctrl->used_segs->header,
						sizeof(struct cbd_cache_used_segs));
	if (!latest_used_segs)
		return 0;

	return latest_used_segs->used_segs;
}
