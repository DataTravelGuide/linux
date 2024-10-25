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

/* debug functions */
#ifdef CONFIG_CBD_DEBUG
static void dump_seg_map(struct cbd_cache *cache)
{
	int i;

	cbd_cache_debug(cache, "start seg map dump");
	for (i = 0; i < cache->n_segs; i++)
		cbd_cache_debug(cache, "seg: %u, %u", i, test_bit(i, cache->seg_map));
	cbd_cache_debug(cache, "end seg map dump");
}

static void dump_cache(struct cbd_cache *cache)
{
	struct cbd_cache_key *key;
	struct rb_node *node;
	int i;

	cbd_cache_debug(cache, "start cache tree dump");

	for (i = 0; i < cache->n_trees; i++) {
		struct cbd_cache_tree *cache_tree;

		cache_tree = &cache->cache_trees[i];
		node = rb_first(&cache_tree->root);
		while (node) {
			key = CACHE_KEY(node);
			node = rb_next(node);

			if (cache_key_empty(key))
				continue;

			cbd_cache_debug(cache, "key: %p gen: %llu key->off: %llu, len: %u, cache: %p segid: %u, seg_off: %u\n",
					key, key->seg_gen, key->off, key->len, cache_pos_addr(&key->cache_pos),
					key->cache_pos.cache_seg->cache_seg_id, key->cache_pos.seg_off);
		}
	}
	cbd_cache_debug(cache, "end cache tree dump");
}

#endif /* CONFIG_CBD_DEBUG */

#define CBD_CACHE_WRITEBACK_INTERVAL	(10 * HZ)
#define CBD_CACHE_GC_INTERVAL	(10 * HZ)

static void cache_key_gc(struct cbd_cache *cache, struct cbd_cache_key *key)
{
	struct cbd_cache_segment *cache_seg = key->cache_pos.cache_seg;

	//cbd_cache_err(cache, "gc %u\n", cache_seg->cache_seg_id);
	cache_seg_put(cache_seg);
}

static u32 cache_pos_onmedia_crc(struct cbd_cache_pos_onmedia *pos_om)
{
	return crc32(0, (void *)pos_om + 4, sizeof(*pos_om) - 4);
}

static void cache_pos_encode(struct cbd_cache *cache,
			     struct cbd_cache_pos_onmedia *pos_onmedia,
			     struct cbd_cache_pos *pos,
			     char *debug)
{
	struct cbd_cache_pos_onmedia *oldest;

	oldest = cbd_meta_find_oldest(&pos_onmedia->header, sizeof(struct cbd_cache_pos_onmedia));

	BUG_ON(!oldest);

	oldest->header.seq = cbd_meta_get_next_seq(&pos_onmedia->header, sizeof(struct cbd_cache_pos_onmedia));

	//cbd_cache_err(cache, "%s oldest: %p set seq: %llu seg_id: %u\n", debug, oldest, oldest->seq, pos->cache_seg->cache_seg_id);
	oldest->cache_seg_id = pos->cache_seg->cache_seg_id;
	//cbd_cache_err(cache, "%s finish set seg_off: %u\n", debug, pos->seg_off);
	oldest->seg_off = pos->seg_off;

	oldest->header.crc = cache_pos_onmedia_crc(oldest);

	//dax_flush(cache->cbdt->dax_dev, oldest, sizeof(*oldest));
	//cbd_cache_err(cache, "%s dax_flush oldest seq: %llu , crc: %u\n", debug, oldest->seq, oldest->crc);
}

static int cache_pos_decode(struct cbd_cache *cache,
		            struct cbd_cache_pos_onmedia *pos_onmedia,
			    struct cbd_cache_pos *pos)
{
	struct cbd_cache_pos_onmedia *latest;

	latest = cbd_meta_find_latest(&pos_onmedia->header, sizeof(struct cbd_cache_pos_onmedia), NULL);
	if (!latest)
		return -EIO;

	//cbd_cache_err(cache, "read pos: %u:%u\n", newest_pos->cache_seg_id, newest_pos->seg_off);
	pos->cache_seg = &cache->segments[latest->cache_seg_id];
	pos->seg_off = latest->seg_off;

	return 0;
}

static void cache_encode_key_tail(struct cbd_cache *cache)
{
	//pr_err("update key tail\n");
	mutex_lock(&cache->key_tail_lock);
	cache_pos_encode(cache, cache->cache_ctrl->key_tail_pos, &cache->key_tail, "key_tail");
	mutex_unlock(&cache->key_tail_lock);
}

static int cache_decode_key_tail(struct cbd_cache *cache)
{
	int ret;

	mutex_lock(&cache->key_tail_lock);
	ret = cache_pos_decode(cache, cache->cache_ctrl->key_tail_pos, &cache->key_tail);
	mutex_unlock(&cache->key_tail_lock);

	return ret;
}

static void cache_encode_dirty_tail(struct cbd_cache *cache)
{
	//pr_err("update dirty tail\n");
	mutex_lock(&cache->dirty_tail_lock);
	cache_pos_encode(cache, cache->cache_ctrl->dirty_tail_pos, &cache->dirty_tail, "dirty tail");
	mutex_unlock(&cache->dirty_tail_lock);
}

static int cache_decode_dirty_tail(struct cbd_cache *cache)
{
	int ret;

	mutex_lock(&cache->dirty_tail_lock);
	ret = cache_pos_decode(cache, cache->cache_ctrl->dirty_tail_pos, &cache->dirty_tail);
	mutex_unlock(&cache->dirty_tail_lock);

	return ret;
}

/* Writeback */
static bool no_more_dirty(struct cbd_cache *cache)
{
	struct cbd_cache_kset_onmedia *kset_onmedia;
	struct cbd_cache_pos *pos;
	void *addr;

	pos = &cache->dirty_tail;

	addr = cache_pos_addr(pos);
	kset_onmedia = (struct cbd_cache_kset_onmedia *)addr;
	if (kset_onmedia->magic != CBD_KSET_MAGIC) {
		cbd_cache_err(cache, "dirty_tail: %u:%u magic: %llx, not expected: %llx\n",
				pos->cache_seg->cache_seg_id, pos->seg_off,
				kset_onmedia->magic, CBD_KSET_MAGIC);
		return true;
	}

	if (kset_onmedia->crc != cache_kset_crc(kset_onmedia)) {
		cbd_cache_err(cache, "dirty_tail: %u:%u crc: %x, not expected: %x\n",
				pos->cache_seg->cache_seg_id, pos->seg_off,
				cache_kset_crc(kset_onmedia), kset_onmedia->crc);
		return true;
	}

	//cbd_cache_err(cache, "dirty\n");

	return false;
}

static void cache_writeback_exit(struct cbd_cache *cache)
{
	if (!cache->bioset)
		return;

	cache_flush(cache);

	while (!no_more_dirty(cache))
		msleep(100);

	cancel_delayed_work_sync(&cache->writeback_work);
	bioset_exit(cache->bioset);
	kfree(cache->bioset);
}

static int cache_writeback_init(struct cbd_cache *cache)
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
	struct cbd_cache_segment *cache_seg;
	struct cbd_segment *segment;
	u32 seg_remain;
	u64 off;

	if (cache_key_clean(key))
		return 0;

	pos = &key->cache_pos;

	cache_seg = pos->cache_seg;
	BUG_ON(!cache_seg);

	segment = &cache_seg->segment;
	seg_remain = segment->data_size - pos->seg_off;
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

static void writeback_fn(struct work_struct *work)
{
	struct cbd_cache *cache = container_of(work, struct cbd_cache, writeback_work.work);
	struct cbd_cache_pos *pos;
	struct cbd_cache_kset_onmedia *kset_onmedia;
	struct cbd_cache_key_onmedia *key_onmedia;
	struct cbd_cache_key *key = NULL;
	int ret = 0;
	void *addr;
	int i;

	cbd_cache_err(cache, "into writeback\n");
	while (true) {
		if (no_more_dirty(cache)) {
			queue_delayed_work(cache->cache_wq, &cache->writeback_work, CBD_CACHE_WRITEBACK_INTERVAL);
			return;
		}

		pos = &cache->dirty_tail;
		addr = cache_pos_addr(pos);
		kset_onmedia = (struct cbd_cache_kset_onmedia *)addr;

		if (kset_onmedia->flags & CBD_KSET_FLAGS_LAST) {
			struct cbd_cache_segment *cur_seg, *next_seg;

			cbd_cache_err(cache, "last kset, next: %u\n", kset_onmedia->next_cache_seg_id);
			cur_seg = pos->cache_seg;
			next_seg = &cache->segments[kset_onmedia->next_cache_seg_id];
			pos->cache_seg = next_seg;
			pos->seg_off = 0;
			cache_encode_dirty_tail(cache);

			continue;
		}
#ifdef CONFIG_CBD_CRC
		/* check the data crc */
		for (i = 0; i < kset_onmedia->key_num; i++) {
			struct cbd_cache_key key_tmp = { 0 };

			key = &key_tmp;

			kref_init(&key->ref);
			key->cache = cache;
			INIT_LIST_HEAD(&key->list_node);

			key_onmedia = &kset_onmedia->data[i];

			cache_key_decode(key_onmedia, key);
			if (key->data_crc != cache_key_data_crc(key)) {
				cbd_cache_debug(cache, "key: %llu:%u data crc(%x) is not expected(%x), wait for data ready.\n",
						key->off, key->len, cache_key_data_crc(key), key->data_crc);
				queue_delayed_work(cache->cache_wq, &cache->writeback_work, CBD_CACHE_WRITEBACK_INTERVAL);
				return;
			}
		}
#endif
		for (i = 0; i < kset_onmedia->key_num; i++) {
			key_onmedia = &kset_onmedia->data[i];

			key = cache_key_alloc(cache);
			if (!key) {
				cbd_cache_err(cache, "writeback error failed to alloc key\n");
				queue_delayed_work(cache->cache_wq, &cache->writeback_work, CBD_CACHE_WRITEBACK_INTERVAL);
				return;
			}

			cache_key_decode(key_onmedia, key);
			ret = cache_key_writeback(cache, key);
			cache_key_put(key);

			if (ret) {
				cbd_cache_err(cache, "writeback error: %d\n", ret);
				queue_delayed_work(cache->cache_wq, &cache->writeback_work, CBD_CACHE_WRITEBACK_INTERVAL);
				return;
			}
		}

		vfs_fsync(cache->bdev_file, 1);

		//cbd_cache_err(cache, "writeback advance: %u:%u %u\n", pos->cache_seg->cache_seg_id, pos->seg_off, get_kset_onmedia_size(kset_onmedia));
		cache_pos_advance(pos, get_kset_onmedia_size(kset_onmedia));
		cache_encode_dirty_tail(cache);
	}
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

static void gc_fn(struct work_struct *work)
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
		cache_seg_init(cache, seg_id, i, new_cache);
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

	INIT_DELAYED_WORK(&cache->writeback_work, writeback_fn);
	INIT_DELAYED_WORK(&cache->gc_work, gc_fn);
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
