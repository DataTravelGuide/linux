// SPDX-License-Identifier: GPL-2.0-or-later

#include "../cbd_internal.h"
#include "cbd_cache_internal.h"


/* sysfs for cache */
static ssize_t cache_segs_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_backend *backend;

	backend = container_of(dev, struct cbd_backend, cache_dev);

	return sprintf(buf, "%u\n", backend->cbd_cache->cache_info->n_segs);
}

static DEVICE_ATTR(cache_segs, 0400, cache_segs_show, NULL);

static ssize_t gc_percent_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_backend *backend;

	backend = container_of(dev, struct cbd_backend, cache_dev);

	return sprintf(buf, "%u\n", backend->cbd_cache->cache_info->gc_percent);
}

static ssize_t gc_percent_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf,
				size_t size)
{
	struct cbd_backend *backend;
	unsigned long val;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	backend = container_of(dev, struct cbd_backend, cache_dev);
	ret = kstrtoul(buf, 10, &val);
	if (ret)
		return ret;

	if (val < CBD_CACHE_GC_PERCENT_MIN ||
			val > CBD_CACHE_GC_PERCENT_MAX)
		return -EINVAL;

	backend->cbd_cache->cache_info->gc_percent = val;

	cache_info_write(backend->cbd_cache);

	return size;
}

static DEVICE_ATTR(gc_percent, 0600, gc_percent_show, gc_percent_store);

static struct attribute *cbd_cache_attrs[] = {
	&dev_attr_cache_segs.attr,
	&dev_attr_gc_percent.attr,
	NULL
};

static struct attribute_group cbd_cache_attr_group = {
	.attrs = cbd_cache_attrs,
};

static const struct attribute_group *cbd_cache_attr_groups[] = {
	&cbd_cache_attr_group,
	NULL
};

static void cbd_cache_release(struct device *dev)
{
}

const struct device_type cbd_cache_type = {
	.name		= "cbd_cache",
	.groups		= cbd_cache_attr_groups,
	.release	= cbd_cache_release,
};

static void cache_info_init(struct cbd_cache_info *cache_info, u32 cache_segs)
{
	cache_info->n_segs = cache_segs;
	cache_info->gc_percent = CBD_CACHE_GC_PERCENT_DEFAULT;
}

static void cache_segs_destroy(struct cbd_cache *cache)
{
	u32 i;

	for (i = 0; i < cache->n_segs; i++)
		cache_seg_exit(&cache->segments[i]);
}

static void cache_info_set_seg_id(struct cbd_cache *cache, u32 seg_id)
{
	cache->cache_info->seg_id = seg_id;
	cache_info_write(cache);
}

static int cache_segs_init(struct cbd_cache *cache, bool new_cache)
{
	struct cbd_cache_segment *prev_cache_seg = NULL;
	struct cbd_cache_info *cache_info = cache->cache_info;
	struct cbd_transport *cbdt = cache->cbdt;
	u32 seg_id;
	int ret;
	u32 i;

	for (i = 0; i < cache_info->n_segs; i++) {
		if (new_cache) {
			ret = cbdt_get_empty_segment_id(cbdt, &seg_id);
			if (ret) {
				cbd_cache_err(cache, "no available segment\n");
				goto segments_destroy;
			}

			if (prev_cache_seg) {
				cache_seg_set_next_seg(prev_cache_seg, seg_id);
			} else {
				cache_info_set_seg_id(cache, seg_id);
			}

		} else {
			if (prev_cache_seg) {
				if (!(prev_cache_seg->cache_seg_info.segment_info.flags & CBD_SEG_INFO_FLAGS_HAS_NEXT)) {
					cbd_cache_err(cache, "flags: %llu, !prev_seg_info->flags & CBD_SEG_INFO_FLAGS_HAS_NEXT\n", prev_cache_seg->cache_seg_info.segment_info.flags);
					ret = -EFAULT;
					goto segments_destroy;
				}
				seg_id = prev_cache_seg->cache_seg_info.segment_info.next_seg;
			} else {
				seg_id = cache_info->seg_id;
			}
		}

		prev_cache_seg = &cache->segments[i];
		pr_err("cache_seg_init: %u, seg_id: %u\n", i, seg_id);
		if (cache_seg_is_meta_seg(i))
			cache->cache_ctrl = (void *)cbdt_get_segment_info(cbdt, seg_id) + CBDT_CACHE_SEG_CTRL_OFF;
		ret = cache_seg_init(cache, seg_id, i, new_cache);
		if (ret)
			goto segments_destroy;
	}

	if (new_cache) {
		/* get first segment for key */
		set_bit(0, cache->seg_map);

		cache->key_head.cache_seg = &cache->segments[0];
		cache->key_head.seg_off = 0;
		cache_pos_copy(&cache->key_tail, &cache->key_head);
		cache_pos_copy(&cache->dirty_tail, &cache->key_head);

		cache_encode_dirty_tail(cache);
		cache_encode_key_tail(cache);
	} else {
		pr_err("read key_tail \n");
		if (cache_decode_key_tail(cache) || cache_decode_dirty_tail(cache)) {
			cbd_cache_err(cache, "Corrupted key tail or dirty tail.\n");
			ret = -EIO;
			goto segments_destroy;
		}
	}

	return 0;

segments_destroy:
	cbd_cache_err(cache, "segments_destroy\n");
	cache_segs_destroy(cache);

	return ret;
}

static struct cbd_cache *cache_alloc(struct cbd_transport *cbdt, struct cbd_cache_info *cache_info)
{
	struct cbd_cache *cache;

	cache = kzalloc(struct_size(cache, segments, cache_info->n_segs), GFP_KERNEL);
	if (!cache) {
		cbdt_err(cbdt, "failed to alloc cache\n");
		goto err;
	}

	cache->seg_map = bitmap_zalloc(cache_info->n_segs, GFP_KERNEL);
	if (!cache->seg_map) {
		cbdt_err(cbdt, "failed to alloc bitmap\n");
		goto free_cache;
	}

	cache->key_cache = KMEM_CACHE(cbd_cache_key, 0);
	if (!cache->key_cache) {
		cbdt_err(cbdt, "failed to alloc key_cache\n");
		goto free_bitmap;
	}

	cache->req_cache = KMEM_CACHE(cbd_request, 0);
	if (!cache->req_cache) {
		cbdt_err(cbdt, "failed to alloc req_cache\n");
		goto free_key_cache;
	}

	cache->cache_wq = alloc_workqueue("cbdt%d-c%u",  WQ_UNBOUND | WQ_MEM_RECLAIM,
					0, cbdt->id, cache->cache_id);
	if (!cache->cache_wq) {
		cbdt_err(cbdt, "failed to alloc cache_wq\n");
		goto free_req_cache;
	}

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

	return cache;

free_req_cache:
	kmem_cache_destroy(cache->req_cache);
free_key_cache:
	kmem_cache_destroy(cache->key_cache);
free_bitmap:
	bitmap_free(cache->seg_map);
free_cache:
	kfree(cache);
err:
	return NULL;
}

static void cache_free(struct cbd_cache *cache)
{
	drain_workqueue(cache->cache_wq);
	destroy_workqueue(cache->cache_wq);
	kmem_cache_destroy(cache->req_cache);
	kmem_cache_destroy(cache->key_cache);
	bitmap_free(cache->seg_map);
	kfree(cache);
}

static int cache_init_keys(struct cbd_cache *cache, u32 n_paral)
{
	int ret;
	u32 i;

	cache->n_trees = DIV_ROUND_UP(cache->dev_size << SECTOR_SHIFT, CBD_CACHE_TREE_SIZE);
	cache->cache_trees = kvcalloc(cache->n_trees, sizeof(struct cbd_cache_tree), GFP_KERNEL);
	if (!cache->cache_trees) {
		ret = -ENOMEM;
		goto err;
	}

	for (i = 0; i < cache->n_trees; i++) {
		struct cbd_cache_tree *cache_tree;

		cache_tree = &cache->cache_trees[i];
		cache_tree->root = RB_ROOT;
		spin_lock_init(&cache_tree->tree_lock);
	}

	cache->n_ksets = n_paral;
	cache->ksets = kcalloc(cache->n_ksets, CBD_KSET_SIZE, GFP_KERNEL);
	if (!cache->ksets) {
		ret = -ENOMEM;
		goto free_trees;
	}

	for (i = 0; i < cache->n_ksets; i++) {
		struct cbd_cache_kset *kset;

		kset = get_kset(cache, i);

		kset->cache = cache;
		spin_lock_init(&kset->kset_lock);
		INIT_DELAYED_WORK(&kset->flush_work, kset_flush_fn);
	}

	/* Init caceh->data_heads */
	cache->n_heads = n_paral;
	cache->data_heads = kcalloc(cache->n_heads, sizeof(struct cbd_cache_data_head), GFP_KERNEL);
	if (!cache->data_heads) {
		ret = -ENOMEM;
		goto free_kset;
	}

	for (i = 0; i < cache->n_heads; i++) {
		struct cbd_cache_data_head *data_head;

		data_head = &cache->data_heads[i];
		spin_lock_init(&data_head->data_head_lock);
	}

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
free_trees:
	kvfree(cache->cache_trees);
err:
	return ret;
}

static void cache_destroy_keys(struct cbd_cache *cache)
{
	u32 i;

	for (i = 0; i < cache->n_trees; i++) {
		struct cbd_cache_tree *cache_tree;
		struct rb_node *node;
		struct cbd_cache_key *key;

		cache_tree = &cache->cache_trees[i];

		spin_lock(&cache_tree->tree_lock);
		node = rb_first(&cache_tree->root);
		while (node) {
			key = CACHE_KEY(node);
			node = rb_next(node);

			cache_key_delete(key);
		}
		spin_unlock(&cache_tree->tree_lock);
	}

	for (i = 0; i < cache->n_ksets; i++) {
		struct cbd_cache_kset *kset;

		kset = get_kset(cache, i);
		cancel_delayed_work_sync(&kset->flush_work);
	}

	kfree(cache->data_heads);
	kfree(cache->ksets);
	kvfree(cache->cache_trees);
}

static int cache_validate(struct cbd_transport *cbdt,
			  struct cbd_cache_opts *opts)
{
	struct cbd_cache_info *cache_info;

	if (opts->n_paral > CBD_CACHE_PARAL_MAX) {
		cbdt_err(cbdt, "n_paral too large (max %u).\n",
			 CBD_CACHE_PARAL_MAX);
		goto err;
	}

	if (opts->new_cache) {
		if (!opts->backend) {
			cbdt_err(cbdt, "backend is needed for new cache.\n");
			goto err;
		}

		cache_info_init(opts->cache_info, opts->n_segs);
	} else {
		struct cbd_backend_info *backend_info;

		backend_info = cbdt_backend_info_read(cbdt, opts->cache_id, NULL);
		memcpy(opts->cache_info, &backend_info->cache_info, sizeof(struct cbd_cache_info));
	}

	cache_info = opts->cache_info;

	if (opts->n_paral * CBD_CACHE_SEGS_EACH_PARAL > cache_info->n_segs) {
		cbdt_err(cbdt, "n_paral %u requires cache size (%llu), more than current (%llu).",
				opts->n_paral, opts->n_paral * CBD_CACHE_SEGS_EACH_PARAL * (u64)CBDT_SEG_SIZE,
				cache_info->n_segs * (u64)CBDT_SEG_SIZE);
		goto err;
	}

	return 0;
err:
	return -EINVAL;
}

struct cbd_cache *cbd_cache_alloc(struct cbd_transport *cbdt,
				  struct cbd_cache_opts *opts)
{
	struct cbd_segment_info *prev_seg_info = NULL;
	struct cbd_cache *cache;
	u32 seg_id;
	u32 backend_id;
	int ret;
	int i;

	/* options validate */
	ret = cache_validate(cbdt, opts);
	if (ret)
		return NULL;

	/* allocations */
	cache = cache_alloc(cbdt, opts->cache_info);
	if (!cache)
		return NULL;

	cache->bdev_file = opts->bdev_file;
	cache->dev_size = opts->dev_size;
	cache->cache_id = opts->cache_id;
	cache->backend = opts->backend;

	cache->state = cbd_cache_state_running;

	/* init cache segments */
	ret = cache_segs_init(cache, opts->new_cache);
	if (ret)
		goto free_cache;

	/* init cache keys and do cache replay */
	if (opts->init_keys) {
		ret = cache_init_keys(cache, opts->n_paral);
		if (ret)
			goto segs_destroy;
	}

	/* start writeback */
	if (opts->start_writeback) {
		cache->start_writeback = 1;
		ret = cache_writeback_init(cache);
		if (ret)
			goto destroy_keys;
	}

	/* start gc */
	if (opts->start_gc) {
		cache->start_gc = 1;
		queue_delayed_work(cache->cache_wq, &cache->gc_work, 0);
	}

	return cache;

destroy_keys:
	cbd_cache_err(cache, "destroy_keys\n");
	cache_destroy_keys(cache);
segs_destroy:
	cbd_cache_err(cache, "destroy_segs\n");
	cache_segs_destroy(cache);
free_cache:
	cbd_cache_err(cache, "error \n");
	cache_free(cache);

	return NULL;
}

void cbd_cache_destroy(struct cbd_cache *cache)
{
	int i;

	cache->state = cbd_cache_state_stopping;

	flush_work(&cache->miss_read_end_work);
	cache_flush(cache);

	if (cache->start_gc) {
		cancel_delayed_work_sync(&cache->gc_work);
		flush_work(&cache->clean_work);
	}

	if (cache->start_writeback)
		cache_writeback_exit(cache);

	if (cache->n_trees)
		cache_destroy_keys(cache);

	cache_segs_destroy(cache);
	cache_free(cache);
}

void cache_info_write(struct cbd_cache *cache)
{
	struct cbd_backend *backend = cache->backend;

	BUG_ON(!backend);

	cbd_backend_info_write(backend);
}
