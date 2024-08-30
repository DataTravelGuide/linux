#include "cbd_internal.h"

#define CBD_CACHE_PARAL_MAX		(128)

#define CBD_CACHE_TREE_SIZE		(4 * 1024 * 1024)
#define CBD_CACHE_TREE_SIZE_MASK	0x3FFFFF
#define CBD_CACHE_TREE_SIZE_SHIFT	22

#define CBD_KSET_KEYS_MAX		128
#define CBD_KSET_ONMEDIA_SIZE_MAX	struct_size_t(struct cbd_cache_kset_onmedia, data, CBD_KSET_KEYS_MAX)
#define CBD_KSET_SIZE			(sizeof(struct cbd_cache_kset) + sizeof(struct cbd_cache_key_onmedia) * CBD_KSET_KEYS_MAX)

#define CBD_CACHE_GC_PERCENT_MIN	0
#define CBD_CACHE_GC_PERCENT_MAX	90
#define CBD_CACHE_GC_PERCENT_DEFAULT	70

static inline struct cbd_cache_tree *get_cache_tree(struct cbd_cache *cache, u64 off)
{
	return &cache->cache_trees[off >> CBD_CACHE_TREE_SIZE_SHIFT];
}

static inline void *cache_pos_addr(struct cbd_cache_pos *pos)
{
	return (pos->cache_seg->segment.data + pos->seg_off);
}
static inline struct cbd_cache_kset_onmedia *get_key_head_addr(struct cbd_cache *cache)
{
	return (struct cbd_cache_kset_onmedia *)cache_pos_addr(&cache->key_head);
}

static inline u32 get_kset_id(struct cbd_cache *cache, u64 off)
{
	return (off >> CBD_CACHE_TREE_SIZE_SHIFT) % cache->n_ksets;
}

static inline struct cbd_cache_kset *get_kset(struct cbd_cache *cache, u32 kset_id)
{
	return (void *)cache->ksets + CBD_KSET_SIZE * kset_id;
}

static struct cbd_cache_segment *cache_seg_get_next(struct cbd_cache_segment *cache_seg)
{
	struct cbd_cache *cache = cache_seg->cache;

	if (cache_seg->cache_seg_info->flags & CBD_CACHE_SEG_FLAGS_HAS_NEXT)
		return &cache->segments[cache_seg->cache_seg_info->next_cache_seg_id];

	return NULL;
}

static void cbd_cache_seg_sanitize_pos(struct cbd_seg_pos *pos)
{
	struct cbd_segment *segment;
	struct cbd_cache_segment *cache_seg;

again:
	segment = pos->segment;
	cache_seg = container_of(segment, struct cbd_cache_segment, segment);
	if (pos->off >= segment->data_size) {
		pos->off -= segment->data_size;
		cache_seg = cache_seg_get_next(cache_seg);
		BUG_ON(!cache_seg);
		pos->segment = &cache_seg->segment;

		goto again;
	}
}

static struct cbd_seg_ops cbd_cache_seg_ops = {
	.sanitize_pos = cbd_cache_seg_sanitize_pos
};

#define CACHE_KEY(node)		(container_of(node, struct cbd_cache_key, rb_node))

static ssize_t cache_segs_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_backend *backend;

	backend = container_of(dev, struct cbd_backend, cache_dev);

	return sprintf(buf, "%u\n", backend->cbd_cache->cache_info->n_segs);
}

static DEVICE_ATTR(cache_segs, 0400, cache_segs_show, NULL);

static ssize_t used_segs_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_backend *backend;
	struct cbd_cache *cache;

	backend = container_of(dev, struct cbd_backend, cache_dev);
	cache = backend->cbd_cache;

	return sprintf(buf, "%u\n", cache->cache_info->used_segs);
}

static DEVICE_ATTR(used_segs, 0400, used_segs_show, NULL);

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

	return size;
}

static DEVICE_ATTR(gc_percent, 0600, gc_percent_show, gc_percent_store);

static struct attribute *cbd_cache_attrs[] = {
	&dev_attr_cache_segs.attr,
	&dev_attr_used_segs.attr,
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

#ifdef CONFIG_CBD_DEBUG
static void dump_seg_map(struct cbd_cache *cache)
{
	int i;

	cbd_cache_debug(cache, "start seg map dump");
	for (i = 0; i < cache->n_segs; i++)
		cbd_cache_debug(cache, "seg: %u, %u", i, test_bit(i, cache->seg_map));
	cbd_cache_debug(cache, "end seg map dump");
}

static inline bool cache_key_empty(struct cbd_cache_key *key);
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

#define CBD_WAIT_NEW_CACHE_INTERVAL	100 /* usecs */
#define CBD_WAIT_NEW_CACHE_COUNT	100

static struct cbd_cache_segment *get_cache_segment(struct cbd_cache *cache)
{
	struct cbd_cache_segment *cache_seg;
	u32 seg_id;
	u32 wait_count = 0;

again:
	spin_lock(&cache->seg_map_lock);
	seg_id = find_next_zero_bit(cache->seg_map, cache->n_segs, cache->last_cache_seg);
	if (seg_id == cache->n_segs) {
		spin_unlock(&cache->seg_map_lock);
		if (cache->last_cache_seg) {
			cache->last_cache_seg = 0;
			goto again;
		}

		if (++wait_count >= CBD_WAIT_NEW_CACHE_COUNT)
			return NULL;
		udelay(CBD_WAIT_NEW_CACHE_INTERVAL);
		goto again;
	}

	set_bit(seg_id, cache->seg_map);
	cache->cache_info->used_segs++;
	cache->last_cache_seg = seg_id;
	spin_unlock(&cache->seg_map_lock);

	cache_seg = &cache->segments[seg_id];
	cache_seg->cache_seg_id = seg_id;
	cache_seg->cache_seg_info->flags = 0;

	cbdt_zero_range(cache->cbdt, cache_seg->segment.data, cache_seg->segment.data_size);

	return cache_seg;
}

static void cache_seg_get(struct cbd_cache_segment *cache_seg)
{
	atomic_inc(&cache_seg->keys);
}

static void cache_seg_invalidate(struct cbd_cache_segment *cache_seg)
{
	struct cbd_cache *cache;

	cache = cache_seg->cache;

	spin_lock(&cache_seg->gen_lock);
	cache_seg->cache_seg_info->gen++;
	spin_unlock(&cache_seg->gen_lock);

	spin_lock(&cache->seg_map_lock);
	clear_bit(cache_seg->cache_seg_id, cache->seg_map);
	cache->cache_info->used_segs--;
	spin_unlock(&cache->seg_map_lock);

	queue_work(cache->cache_wq, &cache->clean_work);
	cbd_cache_debug(cache, "gc invalidat seg: %u\n", cache_seg->cache_seg_id);

#ifdef CONFIG_CBD_DEBUG
	dump_seg_map(cache);
#endif
}

static void cache_seg_put(struct cbd_cache_segment *cache_seg)
{
	if (atomic_dec_and_test(&cache_seg->keys))
		cache_seg_invalidate(cache_seg);
}

static void cache_key_gc(struct cbd_cache *cache, struct cbd_cache_key *key)
{
	struct cbd_cache_segment *cache_seg = key->cache_pos.cache_seg;

	cache_seg_put(cache_seg);
}

static struct cbd_cache_data_head *get_data_head(struct cbd_cache *cache, u32 i)
{
	return &cache->data_heads[i % cache->n_heads];
}

static int cache_data_head_init(struct cbd_cache *cache, u32 i)
{
	struct cbd_cache_segment *next_seg;
	struct cbd_cache_data_head *data_head;

	data_head = get_data_head(cache, i);
	next_seg = get_cache_segment(cache);
	if (!next_seg)
		return -EBUSY;

	cache_seg_get(next_seg);
	data_head->head_pos.cache_seg = next_seg;
	data_head->head_pos.seg_off = 0;

	return 0;
}

static struct cbd_cache_key *cache_key_alloc(struct cbd_cache *cache)
{
	struct cbd_cache_key *key;

	key = kmem_cache_zalloc(cache->key_cache, GFP_NOWAIT);
	if (!key)
		return NULL;

	kref_init(&key->ref);
	key->cache = cache;
	INIT_LIST_HEAD(&key->list_node);

	return key;
}

static void cache_key_get(struct cbd_cache_key *key)
{
	kref_get(&key->ref);
}

static void cache_key_destroy(struct kref *ref)
{
	struct cbd_cache_key *key = container_of(ref, struct cbd_cache_key, ref);
	struct cbd_cache *cache = key->cache;

	kmem_cache_free(cache->key_cache, key);
}

static void cache_key_put(struct cbd_cache_key *key)
{
	kref_put(&key->ref, cache_key_destroy);
}

static inline u64 cache_key_lstart(struct cbd_cache_key *key)
{
	return key->off;
}

static inline u64 cache_key_lend(struct cbd_cache_key *key)
{
	return key->off + key->len;
}

static void cache_pos_copy(struct cbd_cache_pos *dst, struct cbd_cache_pos *src);
static inline void cache_key_copy(struct cbd_cache_key *key_dst, struct cbd_cache_key *key_src)
{
	key_dst->off = key_src->off;
	key_dst->len = key_src->len;
	key_dst->seg_gen = key_src->seg_gen;
	key_dst->cache_tree = key_src->cache_tree;

	cache_pos_copy(&key_dst->cache_pos, &key_src->cache_pos);
}

static void cache_pos_advance(struct cbd_cache_pos *pos, u32 len, bool set)
{
	struct cbd_cache_segment *cache_seg;
	struct cbd_segment *segment;
	u32 seg_remain, to_advance;
	u32 advanced = 0;

again:
	cache_seg = pos->cache_seg;
	BUG_ON(!cache_seg);
	segment = &cache_seg->segment;
	seg_remain = segment->data_size - pos->seg_off;
	to_advance = len - advanced;

	if (seg_remain >= to_advance) {
		pos->seg_off += to_advance;
		advanced += to_advance;
	} else if (seg_remain) {
		pos->seg_off += seg_remain;
		advanced += seg_remain;
	} else {
		pos->cache_seg = cache_seg_get_next(pos->cache_seg);
		BUG_ON(!pos->cache_seg);
		pos->seg_off = 0;
		if (set) {
			struct cbd_cache *cache = pos->cache_seg->cache;

			cbd_cache_debug(cache, "set seg in advance %u\n", pos->cache_seg->cache_seg_id);
			set_bit(pos->cache_seg->cache_seg_id, pos->cache_seg->cache->seg_map);
#ifdef CONFIG_CBD_DEBUG
			dump_seg_map(cache);
#endif
		}
	}

	if (advanced < len)
		goto again;
}

static inline void cache_key_cutfront(struct cbd_cache_key *key, u32 cut_len)
{
	if (key->cache_pos.cache_seg)
		cache_pos_advance(&key->cache_pos, cut_len, false);

	key->off += cut_len;
	key->len -= cut_len;
}

static inline void cache_key_cutback(struct cbd_cache_key *key, u32 cut_len)
{
	key->len -= cut_len;
}

static inline void cache_key_delete(struct cbd_cache_key *key)
{
	struct cbd_cache_tree *cache_tree;

	cache_tree = key->cache_tree;
	if (!cache_tree)
		return;

	rb_erase(&key->rb_node, &cache_tree->root);
	key->flags = 0;
	cache_key_put(key);
}

static inline u32 cache_key_data_crc(struct cbd_cache_key *key)
{
	void *data;

	data = cache_pos_addr(&key->cache_pos);

	return crc32(0, data, key->len);
}

static void cache_key_encode(struct cbd_cache_key_onmedia *key_onmedia,
			     struct cbd_cache_key *key)
{
	key_onmedia->off = key->off;
	key_onmedia->len = key->len;

	key_onmedia->cache_seg_id = key->cache_pos.cache_seg->cache_seg_id;
	key_onmedia->cache_seg_off = key->cache_pos.seg_off;

	key_onmedia->seg_gen = key->seg_gen;
	key_onmedia->flags = key->flags;

#ifdef CONFIG_CBD_CRC
	key_onmedia->data_crc = key->data_crc;
#endif
}

static void cache_key_decode(struct cbd_cache_key_onmedia *key_onmedia, struct cbd_cache_key *key)
{
	struct cbd_cache *cache = key->cache;

	key->off = key_onmedia->off;
	key->len = key_onmedia->len;

	key->cache_pos.cache_seg = &cache->segments[key_onmedia->cache_seg_id];
	key->cache_pos.seg_off = key_onmedia->cache_seg_off;

	key->seg_gen = key_onmedia->seg_gen;
	key->flags = key_onmedia->flags;

#ifdef CONFIG_CBD_CRC
	key->data_crc = key_onmedia->data_crc;
#endif
}

static inline u32 cache_kset_crc(struct cbd_cache_kset_onmedia *kset_onmedia)
{
	return crc32(0, (void *)kset_onmedia + 4, struct_size(kset_onmedia, data, kset_onmedia->key_num) - 4);
}

static inline u32 get_kset_onmedia_size(struct cbd_cache_kset_onmedia *kset_onmedia)
{
	return struct_size_t(struct cbd_cache_kset_onmedia, data, kset_onmedia->key_num);
}

static inline u32 get_seg_remain(struct cbd_cache_pos *pos)
{
	struct cbd_cache_segment *cache_seg;
	struct cbd_segment *segment;
	u32 seg_remain;

	cache_seg = pos->cache_seg;
	segment = &cache_seg->segment;
	seg_remain = segment->data_size - pos->seg_off;

	return seg_remain;
}

static int cache_kset_close(struct cbd_cache *cache, struct cbd_cache_kset *kset)
{
	struct cbd_cache_kset_onmedia *kset_onmedia;
	u32 kset_onmedia_size;
	int ret;

	kset_onmedia = &kset->kset_onmedia;

	if (!kset_onmedia->key_num)
		return 0;

	kset_onmedia_size = struct_size(kset_onmedia, data, kset_onmedia->key_num);

	spin_lock(&cache->key_head_lock);
again:
	if (get_seg_remain(&cache->key_head) < CBD_KSET_ONMEDIA_SIZE_MAX) {
		struct cbd_cache_segment *cur_seg, *next_seg;

		next_seg = get_cache_segment(cache);
		if (!next_seg) {
			ret = -EBUSY;
			goto out;
		}

		cur_seg = cache->key_head.cache_seg;

		cur_seg->cache_seg_info->next_cache_seg_id = next_seg->cache_seg_id;
		cur_seg->cache_seg_info->flags |= CBD_CACHE_SEG_FLAGS_HAS_NEXT;

		cache->key_head.cache_seg = next_seg;
		cache->key_head.seg_off = 0;
		goto again;
	}

	if (get_seg_remain(&cache->key_head) - kset_onmedia_size < CBD_KSET_ONMEDIA_SIZE_MAX)
		kset_onmedia->flags |= CBD_KSET_FLAGS_LAST;

	kset_onmedia->magic = CBD_KSET_MAGIC;
	kset_onmedia->crc = cache_kset_crc(kset_onmedia);

	memcpy(get_key_head_addr(cache), kset_onmedia, kset_onmedia_size);
	memset(kset_onmedia, 0, sizeof(struct cbd_cache_kset_onmedia));

	cache_pos_advance(&cache->key_head, kset_onmedia_size, false);

	ret = 0;
out:
	spin_unlock(&cache->key_head_lock);

	return ret;
}

static int cache_key_append(struct cbd_cache *cache, struct cbd_cache_key *key)
{
	struct cbd_cache_kset *kset;
	struct cbd_cache_kset_onmedia *kset_onmedia;
	struct cbd_cache_key_onmedia *key_onmedia;
	u32 kset_id = get_kset_id(cache, key->off);
	int ret = 0;

	kset = get_kset(cache, kset_id);
	kset_onmedia = &kset->kset_onmedia;

	spin_lock(&kset->kset_lock);
	key_onmedia = &kset_onmedia->data[kset_onmedia->key_num];
#ifdef CONFIG_CBD_CRC
	key->data_crc = cache_key_data_crc(key);
#endif
	cache_key_encode(key_onmedia, key);
	if (++kset_onmedia->key_num == CBD_KSET_KEYS_MAX) {
		ret = cache_kset_close(cache, kset);
		if (ret) {
			/* return ocuppied key back */
			kset_onmedia->key_num--;
			goto out;
		}
	} else {
		queue_delayed_work(cache->cache_wq, &kset->flush_work, 1 * HZ);
	}
out:
	spin_unlock(&kset->kset_lock);

	return ret;
}

static void cache_insert_key(struct cbd_cache *cache, struct cbd_cache_key *key, bool new);
static int cache_insert_fixup(struct cbd_cache *cache, struct cbd_cache_key *key, struct rb_node *prev_node)
{
	struct rb_node *node_tmp;
	struct cbd_cache_key *key_tmp;
	int ret;

	if (!prev_node)
		return 0;

	node_tmp = prev_node;
	while (node_tmp) {
		key_tmp = CACHE_KEY(node_tmp);
		/*
		 * |----------|
		 *		|=====|
		 */
		if (cache_key_lend(key_tmp) <= cache_key_lstart(key))
			goto next;

		/*
		 *	  |--------|
		 * |====|
		 */
		if (cache_key_lstart(key_tmp) >= cache_key_lend(key))
			break;

		/* overlap */
		if (cache_key_lstart(key_tmp) >= cache_key_lstart(key)) {
			/*
			 *     |----------------|	key_tmp
			 * |===========|		key
			 */
			if (cache_key_lend(key_tmp) >= cache_key_lend(key)) {
				cache_key_cutfront(key_tmp, cache_key_lend(key) - cache_key_lstart(key_tmp));
				if (key_tmp->len == 0) {
					cache_key_delete(key_tmp);
					ret = -EAGAIN;
					goto out;
				}

				goto next;
			}

			/*
			 *    |----|		key_tmp
			 * |==========|		key
			 */
			cache_key_delete(key_tmp);
			ret = -EAGAIN;
			goto out;
		}

		/*
		 * |-----------|	key_tmp
		 *   |====|		key
		 */
		if (cache_key_lend(key_tmp) > cache_key_lend(key)) {
			struct cbd_cache_key *key_fixup;

			key_fixup = cache_key_alloc(cache);
			if (!key_fixup) {
				ret = -ENOMEM;
				goto out;
			}

			cache_key_copy(key_fixup, key_tmp);

			cache_key_cutback(key_tmp, cache_key_lend(key_tmp) - cache_key_lstart(key));
			cache_key_cutfront(key_fixup, cache_key_lend(key) - cache_key_lstart(key_tmp));

			cache_insert_key(cache, key_fixup, false);

			ret = -EAGAIN;
			goto out;
		}

		/*
		 * |--------|		key_tmp
		 *   |==========|	key
		 */
		cache_key_cutback(key_tmp, cache_key_lend(key_tmp) - cache_key_lstart(key));
next:
		node_tmp = rb_next(node_tmp);
	}

	ret = 0;
out:
	return ret;
}

static inline bool cache_key_empty(struct cbd_cache_key *key)
{
	return key->flags & CBD_CACHE_KEY_FLAGS_EMPTY;
}

static inline bool cache_key_clean(struct cbd_cache_key *key)
{
	return key->flags & CBD_CACHE_KEY_FLAGS_CLEAN;
}

static inline bool cache_key_invalid(struct cbd_cache_key *key)
{
	if (cache_key_empty(key))
		return false;

	return (key->seg_gen < key->cache_pos.cache_seg->cache_seg_info->gen);
}

static void cache_insert_key(struct cbd_cache *cache, struct cbd_cache_key *key, bool new_key)
{
	struct rb_node **new, *parent = NULL;
	struct cbd_cache_tree *cache_tree;
	struct cbd_cache_key *key_tmp = NULL, *key_next;
	struct rb_node	*prev_node = NULL;
	LIST_HEAD(key_list);
	int ret;

	cache_tree = get_cache_tree(cache, key->off);

	if (new_key)
		key->cache_tree = cache_tree;

again:
	new = &(cache_tree->root.rb_node);
	parent = NULL;
	key_tmp = NULL;
	prev_node = NULL;
	while (*new) {
		key_tmp = container_of(*new, struct cbd_cache_key, rb_node);
		if (cache_key_invalid(key_tmp))
			list_add(&key_tmp->list_node, &key_list);

		parent = *new;
		if (key_tmp->off >= key->off) {
			new = &((*new)->rb_left);
		} else {
			prev_node = *new;
			new = &((*new)->rb_right);
		}
	}

	if (!list_empty(&key_list)) {
		list_for_each_entry_safe(key_tmp, key_next, &key_list, list_node) {
			list_del_init(&key_tmp->list_node);
			cache_key_delete(key_tmp);
		}
		goto again;
	}

	if (!prev_node)
		prev_node = rb_first(&cache_tree->root);

	if (new_key) {
		ret = cache_insert_fixup(cache, key, prev_node);
		if (ret == -EAGAIN)
			goto again;
		BUG_ON(ret);
	}

	rb_link_node(&key->rb_node, parent, new);
	rb_insert_color(&key->rb_node, &cache_tree->root);
}

static void cache_pos_copy(struct cbd_cache_pos *dst, struct cbd_cache_pos *src)
{
	memcpy(dst, src, sizeof(struct cbd_cache_pos));
}

static int cache_data_alloc(struct cbd_cache *cache, struct cbd_cache_key *key, u32 head_index)
{
	struct cbd_cache_data_head *data_head;
	struct cbd_cache_pos *head_pos;
	struct cbd_cache_segment *cache_seg;
	struct cbd_segment *segment;
	u32 seg_remain;
	u32 allocated = 0, to_alloc;
	int ret = 0;

	data_head = get_data_head(cache, head_index);

	spin_lock(&data_head->data_head_lock);
again:
	if (!data_head->head_pos.cache_seg) {
		seg_remain = 0;
	} else {
		cache_pos_copy(&key->cache_pos, &data_head->head_pos);
		key->seg_gen = key->cache_pos.cache_seg->cache_seg_info->gen;

		head_pos = &data_head->head_pos;
		cache_seg = head_pos->cache_seg;
		segment = &cache_seg->segment;
		seg_remain = segment->data_size - head_pos->seg_off;
		to_alloc = key->len - allocated;
	}

	if (seg_remain > to_alloc) {
		cache_pos_advance(head_pos, to_alloc, false);
		allocated += to_alloc;
		cache_seg_get(cache_seg);
	} else if (seg_remain) {
		cache_pos_advance(head_pos, seg_remain, false);
		key->len = seg_remain;
		cache_seg_get(cache_seg); /* get for key */

		cache_seg_put(head_pos->cache_seg); /* put for head_pos->cache_seg */
		head_pos->cache_seg = NULL;
	} else {
		ret = cache_data_head_init(cache, head_index);
		if (ret)
			goto out;

		goto again;
	}

out:
	spin_unlock(&data_head->data_head_lock);

	return ret;
}

static void cache_copy_from_bio(struct cbd_cache *cache, struct cbd_cache_key *key,
				struct bio *bio, u32 bio_off)
{
	struct cbd_cache_pos *pos = &key->cache_pos;
	struct cbd_segment *segment;

	segment = &pos->cache_seg->segment;

	cbds_copy_from_bio(segment, pos->seg_off, key->len, bio, bio_off);
}

static int cache_copy_to_bio(struct cbd_cache *cache, struct cbd_request *cbd_req,
			    u32 off, u32 len, struct cbd_cache_pos *pos, u64 key_gen)
{
	struct cbd_cache_segment *cache_seg = pos->cache_seg;
	struct cbd_segment *segment = &cache_seg->segment;

	spin_lock(&cache_seg->gen_lock);
	if (key_gen < cache_seg->cache_seg_info->gen) {
		spin_unlock(&cache_seg->gen_lock);
		return -EINVAL;
	}

	spin_lock(&cbd_req->lock);
	cbds_copy_to_bio(segment, pos->seg_off, len, cbd_req->bio, off);
	spin_unlock(&cbd_req->lock);
	spin_unlock(&cache_seg->gen_lock);

	return 0;
}

static void cache_copy_from_req(struct cbd_cache *cache, struct cbd_request *cbd_req,
				struct cbd_cache_pos *pos, u32 off, u32 len)
{
	struct cbd_seg_pos dst_pos, src_pos;

	src_pos.segment = &cbd_req->cbdq->channel.segment;
	src_pos.off = cbd_req->data_off;

	dst_pos.segment = &pos->cache_seg->segment;
	dst_pos.off = pos->seg_off;

	if (off) {
		cbds_pos_advance(&dst_pos, off);
		cbds_pos_advance(&src_pos, off);
	}

	cbds_copy_data(&dst_pos, &src_pos, len);
}

static void miss_read_end_req(struct cbd_cache *cache, struct cbd_request *cbd_req)
{
	void *priv_data = cbd_req->priv_data;
	int ret;

	if (priv_data) {
		struct cbd_cache_key *key;
		struct cbd_cache_tree *cache_tree;

		key = (struct cbd_cache_key *)priv_data;
		cache_tree = key->cache_tree;

		spin_lock(&cache_tree->tree_lock);
		if (key->flags & CBD_CACHE_KEY_FLAGS_EMPTY) {
			if (cbd_req->ret) {
				cache_key_delete(key);
				goto unlock;
			}

			/* TODO use seperate head for read cache */
			ret = cache_data_alloc(cache, key, cbd_req->cbdq->index);
			if (ret) {
				cache_key_delete(key);
				goto unlock;
			}
			cache_copy_from_req(cache, cbd_req, &key->cache_pos, key->off - cbd_req->off, key->len);
			key->flags &= ~CBD_CACHE_KEY_FLAGS_EMPTY;
			key->flags |= CBD_CACHE_KEY_FLAGS_CLEAN;

			ret = cache_key_append(cache, key);
			if (ret) {
				cache_seg_put(key->cache_pos.cache_seg);
				cache_key_delete(key);
				goto unlock;
			}
		}
unlock:
		spin_unlock(&cache_tree->tree_lock);
		cache_key_put(key);
	}

	cbd_queue_advance(cbd_req->cbdq, cbd_req);
	kmem_cache_free(cache->req_cache, cbd_req);
}

static void miss_read_end_work_fn(struct work_struct *work)
{
	struct cbd_cache *cache = container_of(work, struct cbd_cache, miss_read_end_work);
	struct cbd_request *cbd_req;
	LIST_HEAD(tmp_list);

	spin_lock(&cache->miss_read_reqs_lock);
	list_splice_init(&cache->miss_read_reqs, &tmp_list);
	spin_unlock(&cache->miss_read_reqs_lock);

	while (!list_empty(&tmp_list)) {
		cbd_req = list_first_entry(&tmp_list,
				struct cbd_request, inflight_reqs_node);
		list_del_init(&cbd_req->inflight_reqs_node);
		miss_read_end_req(cache, cbd_req);
	}
}

static void cache_backing_req_end_req(struct cbd_request *cbd_req, void *priv_data)
{
	struct cbd_cache *cache = cbd_req->cbdq->cbd_blkdev->cbd_cache;

	spin_lock(&cache->miss_read_reqs_lock);
	list_add_tail(&cbd_req->inflight_reqs_node, &cache->miss_read_reqs);
	spin_unlock(&cache->miss_read_reqs_lock);

	queue_work(cache->cache_wq, &cache->miss_read_end_work);
}

static int submit_backing_io(struct cbd_cache *cache, struct cbd_request *cbd_req,
			    u32 off, u32 len, bool insert_key)
{
	struct cbd_request *new_req;
	struct cbd_cache_key *key = NULL;
	int ret;

	if (insert_key) {
		key = cache_key_alloc(cache);
		if (!key) {
			ret = -ENOMEM;
			goto out;
		}

		key->off = cbd_req->off + off;
		key->len = len;
		key->flags |= CBD_CACHE_KEY_FLAGS_EMPTY;
		cache_insert_key(cache, key, true);
	}

	new_req = kmem_cache_zalloc(cache->req_cache, GFP_NOWAIT);
	if (!new_req) {
		ret = -ENOMEM;
		goto delete_key;
	}

	INIT_LIST_HEAD(&new_req->inflight_reqs_node);
	kref_init(&new_req->ref);
	spin_lock_init(&new_req->lock);

	new_req->cbdq = cbd_req->cbdq;
	new_req->bio = cbd_req->bio;
	new_req->off = cbd_req->off + off;
	new_req->op = cbd_req->op;
	new_req->bio_off = off;
	new_req->data_len = len;
	new_req->req = NULL;

	cbd_req_get(cbd_req);
	new_req->parent = cbd_req;

	if (key) {
		cache_key_get(key);
		new_req->priv_data = key;
	}

	new_req->end_req = cache_backing_req_end_req;
	ret = cbd_queue_req_to_backend(new_req);
	cbd_req_put(new_req, ret);

	return 0;

delete_key:
	if (key)
		cache_key_delete(key);
out:
	return ret;
}

static int cache_read(struct cbd_cache *cache, struct cbd_request *cbd_req)
{
	struct rb_node **new, *parent = NULL;
	struct cbd_cache_tree *cache_tree;
	struct cbd_cache_key *key_tmp = NULL, *key_next;
	struct rb_node *node_tmp;
	struct rb_node *prev_node = NULL;
	struct cbd_cache_key key_data = { .off = cbd_req->off, .len = cbd_req->data_len };
	struct cbd_cache_key *key = &key_data;
	struct cbd_cache_pos pos;
	u32 io_done = 0, total_io_done = 0, io_len = 0;
	LIST_HEAD(key_list);
	int ret;

next_tree:
	io_done = 0;
	key->off = cbd_req->off + total_io_done;
	key->len = cbd_req->data_len - total_io_done;
	if (key->len > CBD_CACHE_TREE_SIZE - (key->off & CBD_CACHE_TREE_SIZE_MASK))
		key->len = CBD_CACHE_TREE_SIZE - (key->off & CBD_CACHE_TREE_SIZE_MASK);
	cache_tree = get_cache_tree(cache, key->off);
	spin_lock(&cache_tree->tree_lock);
again:
	new = &(cache_tree->root.rb_node);
	parent = NULL;
	key_tmp = NULL;
	prev_node = NULL;
	while (*new) {
		key_tmp = container_of(*new, struct cbd_cache_key, rb_node);
		if (cache_key_invalid(key_tmp))
			list_add(&key_tmp->list_node, &key_list);

		parent = *new;
		if (key_tmp->off >= key->off) {
			new = &((*new)->rb_left);
		} else {
			prev_node = *new;
			new = &((*new)->rb_right);
		}
	}

cleanup_tree:
	if (!list_empty(&key_list)) {
		list_for_each_entry_safe(key_tmp, key_next, &key_list, list_node) {
			list_del_init(&key_tmp->list_node);
			cache_key_delete(key_tmp);
		}
		goto again;
	}

	if (!prev_node)
		prev_node = rb_first(&cache_tree->root);

	node_tmp = prev_node;
	while (node_tmp) {
		if (io_done >= cbd_req->data_len)
			break;

		key_tmp = CACHE_KEY(node_tmp);

		/*
		 * |----------|
		 *		|=====|
		 */
		if (cache_key_lend(key_tmp) <= cache_key_lstart(key))
			goto next;

		/*
		 *	  |--------|
		 * |====|
		 */
		if (cache_key_lstart(key_tmp) >= cache_key_lend(key)) {
			ret = submit_backing_io(cache, cbd_req, total_io_done + io_done, key->len, true);
			if (ret)
				goto out;
			io_done += key->len;
			cache_key_cutfront(key, key->len);

			break;
		}

		/* overlap */
		if (cache_key_lstart(key_tmp) >= cache_key_lstart(key)) {
			/*
			 *     |----------------|	key_tmp
			 * |===========|		key
			 */
			if (cache_key_lend(key_tmp) >= cache_key_lend(key)) {
				io_len = cache_key_lstart(key_tmp) - cache_key_lstart(key);
				if (io_len) {
					ret = submit_backing_io(cache, cbd_req, total_io_done + io_done, io_len, true);
					if (ret)
						goto out;
					io_done += io_len;
					cache_key_cutfront(key, io_len);
				}

				io_len = cache_key_lend(key) - cache_key_lstart(key_tmp);
				if (cache_key_empty(key_tmp)) {
					ret = submit_backing_io(cache, cbd_req, total_io_done + io_done, io_len, false);
					if (ret)
						goto out;
				} else {
					ret = cache_copy_to_bio(cache, cbd_req, total_io_done + io_done,
								io_len, &key_tmp->cache_pos, key_tmp->seg_gen);
					if (ret) {
						list_add(&key_tmp->list_node, &key_list);
						goto cleanup_tree;
					}
				}
				io_done += io_len;
				cache_key_cutfront(key, io_len);
				break;
			}

			/*
			 *    |----|		key_tmp
			 * |==========|		key
			 */
			io_len = cache_key_lstart(key_tmp) - cache_key_lstart(key);
			if (io_len) {
				ret = submit_backing_io(cache, cbd_req, total_io_done + io_done, io_len, true);
				if (ret)
					goto out;
				io_done += io_len;
				cache_key_cutfront(key, io_len);
			}

			io_len = key_tmp->len;
			if (cache_key_empty(key_tmp)) {
				ret = submit_backing_io(cache, cbd_req, total_io_done + io_done, io_len, false);
				if (ret)
					goto out;
			} else {
				ret = cache_copy_to_bio(cache, cbd_req, total_io_done + io_done,
							io_len, &key_tmp->cache_pos, key_tmp->seg_gen);
				if (ret) {
					list_add(&key_tmp->list_node, &key_list);
					goto cleanup_tree;
				}
			}
			io_done += io_len;
			cache_key_cutfront(key, io_len);
			goto next;
		}

		/*
		 * |-----------|	key_tmp
		 *   |====|		key
		 */
		if (cache_key_lend(key_tmp) >= cache_key_lend(key)) {
			if (cache_key_empty(key_tmp)) {
				ret = submit_backing_io(cache, cbd_req, total_io_done + io_done, io_len, false);
				if (ret)
					goto out;
			} else {
				cache_pos_copy(&pos, &key_tmp->cache_pos);
				cache_pos_advance(&pos, cache_key_lstart(key) - cache_key_lstart(key_tmp), false);

				ret = cache_copy_to_bio(cache, cbd_req, total_io_done + io_done,
							key->len, &pos, key_tmp->seg_gen);
				if (ret) {
					list_add(&key_tmp->list_node, &key_list);
					goto cleanup_tree;
				}
			}
			io_done += key->len;

			cache_key_cutfront(key, key->len);
			break;
		}

		/*
		 * |--------|		key_tmp
		 *   |==========|	key
		 */
		io_len = cache_key_lend(key_tmp) - cache_key_lstart(key);

		if (cache_key_empty(key_tmp)) {
			ret = submit_backing_io(cache, cbd_req, total_io_done + io_done, io_len, false);
			if (ret)
				goto out;
		} else {
			cache_pos_copy(&pos, &key_tmp->cache_pos);
			cache_pos_advance(&pos, cache_key_lstart(key) - cache_key_lstart(key_tmp), false);

			ret = cache_copy_to_bio(cache, cbd_req, total_io_done + io_done,
						io_len, &pos, key_tmp->seg_gen);
			if (ret) {
				list_add(&key_tmp->list_node, &key_list);
				goto cleanup_tree;
			}
		}
		io_done += io_len;
		cache_key_cutfront(key, io_len);
next:
		node_tmp = rb_next(node_tmp);
	}

	if (key->len) {
		ret = submit_backing_io(cache, cbd_req, total_io_done + io_done, key->len, true);
		if (ret)
			goto out;
		io_done += key->len;
	}
	spin_unlock(&cache_tree->tree_lock);

	total_io_done += io_done;
	io_done = 0;

	if (!ret && total_io_done < cbd_req->data_len)
		goto next_tree;

	return 0;
out:
	spin_unlock(&cache_tree->tree_lock);

	return ret;
}

static int cache_write(struct cbd_cache *cache, struct cbd_request *cbd_req)
{
	struct cbd_cache_tree *cache_tree;
	struct cbd_cache_key *key;
	u64 offset = cbd_req->off;
	u32 length = cbd_req->data_len;
	u32 io_done = 0;
	int ret;

	/* TODO support writethrough and writearound */
	while (true) {
		if (io_done >= length)
			break;

		key = cache_key_alloc(cache);
		if (!key) {
			ret = -ENOMEM;
			goto err;
		}

		key->off = offset + io_done;
		key->len = length - io_done;
		if (key->len > CBD_CACHE_TREE_SIZE - (key->off & CBD_CACHE_TREE_SIZE_MASK))
			key->len = CBD_CACHE_TREE_SIZE - (key->off & CBD_CACHE_TREE_SIZE_MASK);

		ret = cache_data_alloc(cache, key, cbd_req->cbdq->index);
		if (ret) {
			cache_key_put(key);
			goto err;
		}

		if (!key->len) {
			cache_seg_put(key->cache_pos.cache_seg);
			cache_key_put(key);
			continue;
		}

		BUG_ON(!key->cache_pos.cache_seg);
		cache_copy_from_bio(cache, key, cbd_req->bio, io_done);

		cache_tree = get_cache_tree(cache, key->off);
		spin_lock(&cache_tree->tree_lock);
		/* append key into key head pos */
		ret = cache_key_append(cache, key);
		if (ret) {
			spin_unlock(&cache_tree->tree_lock);
			cache_seg_put(key->cache_pos.cache_seg);
			cache_key_put(key);
			goto err;
		}

		io_done += key->len;

		/* add key into cache_tree, after this, key could be changed
		 * by other overlap key insert, so we need key_append before insert_key
		 */
		cache_insert_key(cache, key, true);
		spin_unlock(&cache_tree->tree_lock);
	}

	ret = 0;
err:
	return ret;
}

static int cache_flush(struct cbd_cache *cache)
{
	struct cbd_cache_kset *kset;
	u32 i, ret;

	for (i = 0; i < cache->n_ksets; i++) {
		kset = get_kset(cache, i);

		spin_lock(&kset->kset_lock);
		ret = cache_kset_close(cache, kset);
		spin_unlock(&kset->kset_lock);
		if (ret)
			return ret;
	}

	return 0;
}

int cbd_cache_handle_req(struct cbd_cache *cache, struct cbd_request *cbd_req)
{
	switch (cbd_req->op) {
	case CBD_OP_FLUSH:
		return cache_flush(cache);
	case CBD_OP_WRITE:
		return cache_write(cache, cbd_req);
	case CBD_OP_READ:
		return cache_read(cache, cbd_req);
	default:
		return -EIO;
	}

	return 0;
}

static void cache_pos_encode(struct cbd_cache *cache,
			     struct cbd_cache_pos_onmedia *pos_onmedia,
			     struct cbd_cache_pos *pos)
{
	pos_onmedia->cache_seg_id = pos->cache_seg->cache_seg_id;
	pos_onmedia->seg_off = pos->seg_off;
}

static void cache_pos_decode(struct cbd_cache *cache,
			     struct cbd_cache_pos_onmedia *pos_onmedia,
			     struct cbd_cache_pos *pos)
{
	pos->cache_seg = &cache->segments[pos_onmedia->cache_seg_id];
	pos->seg_off = pos_onmedia->seg_off;
}

static int cache_replay(struct cbd_cache *cache)
{
	struct cbd_cache_pos pos_tail;
	struct cbd_cache_pos *pos;
	struct cbd_cache_kset_onmedia *kset_onmedia;
	struct cbd_cache_key_onmedia *key_onmedia;
	struct cbd_cache_key *key = NULL;
	int ret = 0;
	void *addr;
	int i;

	cache_pos_copy(&pos_tail, &cache->key_tail);
	pos = &pos_tail;

	set_bit(pos->cache_seg->cache_seg_id, cache->seg_map);

	while (true) {
		addr = cache_pos_addr(pos);

		kset_onmedia = (struct cbd_cache_kset_onmedia *)addr;
		if (kset_onmedia->magic != CBD_KSET_MAGIC ||
				kset_onmedia->crc != cache_kset_crc(kset_onmedia)) {
			break;
		}

		for (i = 0; i < kset_onmedia->key_num; i++) {
			key_onmedia = &kset_onmedia->data[i];

			key = cache_key_alloc(cache);
			if (!key) {
				ret = -ENOMEM;
				goto out;
			}

			cache_key_decode(key_onmedia, key);
#ifdef CONFIG_CBD_CRC
			if (key->data_crc != cache_key_data_crc(key)) {
				cbd_cache_debug(cache, "key: %llu:%u seg %u:%u data_crc error: %x, expected: %x\n",
						key->off, key->len, key->cache_pos.cache_seg->cache_seg_id,
						key->cache_pos.seg_off, cache_key_data_crc(key), key->data_crc);
				ret = -EIO;
				cache_key_put(key);
				goto out;
			}
#endif
			set_bit(key->cache_pos.cache_seg->cache_seg_id, cache->seg_map);

			if (key->seg_gen < key->cache_pos.cache_seg->cache_seg_info->gen)
				cache_key_put(key);
			else
				cache_insert_key(cache, key, true);

			cache_seg_get(key->cache_pos.cache_seg);
		}

		cache_pos_advance(pos, get_kset_onmedia_size(kset_onmedia), false);

		if (kset_onmedia->flags & CBD_KSET_FLAGS_LAST) {
			struct cbd_cache_segment *cur_seg, *next_seg;

			cur_seg = pos->cache_seg;
			next_seg = cache_seg_get_next(cur_seg);
			if (!next_seg)
				break;
			pos->cache_seg = next_seg;
			pos->seg_off = 0;
			set_bit(pos->cache_seg->cache_seg_id, cache->seg_map);
			continue;
		}
	}

#ifdef CONFIG_CBD_DEBUG
	dump_cache(cache);
#endif

	spin_lock(&cache->key_head_lock);
	cache_pos_copy(&cache->key_head, pos);
	cache->cache_info->used_segs++;
	spin_unlock(&cache->key_head_lock);

out:
	return ret;
}

static void cache_seg_init(struct cbd_cache *cache,
			   u32 seg_id, u32 cache_seg_id)
{
	struct cbd_transport *cbdt = cache->cbdt;
	struct cbd_cache_segment *cache_seg = &cache->segments[cache_seg_id];
	struct cbds_init_options seg_options = { 0 };
	struct cbd_segment *segment = &cache_seg->segment;

	seg_options.type = cbds_type_cache;
	seg_options.data_off = round_up(sizeof(struct cbd_cache_seg_info), PAGE_SIZE);
	seg_options.seg_ops = &cbd_cache_seg_ops;
	seg_options.seg_id = seg_id;

	cbd_segment_init(cbdt, segment, &seg_options);

	atomic_set(&cache_seg->keys, 0);
	spin_lock_init(&cache_seg->gen_lock);
	cache_seg->cache = cache;
	cache_seg->cache_seg_id = cache_seg_id;
	cache_seg->cache_seg_info = (struct cbd_cache_seg_info *)segment->segment_info;
}

static void cache_seg_exit(struct cbd_cache_segment *cache_seg)
{
	cbd_segment_exit(&cache_seg->segment);
}

static inline u32 get_backend_id(struct cbd_transport *cbdt,
				 struct cbd_backend_info *backend_info)
{
	u64 backend_off;
	struct cbd_transport_info *transport_info;

	transport_info = cbdt->transport_info;
	backend_off = (void *)backend_info - (void *)transport_info;

	return (backend_off - transport_info->backend_area_off) / transport_info->backend_info_size;
}

static bool cache_seg_has_next(struct cbd_cache_segment *cache_seg)
{
	return (cache_seg->cache_seg_info->flags & CBD_CACHE_SEG_FLAGS_HAS_NEXT);
}

static bool cache_seg_wb_done(struct cbd_cache_segment *cache_seg)
{
	return (cache_seg->cache_seg_info->flags & CBD_CACHE_SEG_FLAGS_WB_DONE);
}

static bool cache_seg_gc_done(struct cbd_cache_segment *cache_seg)
{
	return (cache_seg->cache_seg_info->flags & CBD_CACHE_SEG_FLAGS_GC_DONE);
}

static bool no_more_dirty(struct cbd_cache *cache)
{
	struct cbd_cache_kset_onmedia *kset_onmedia;
	struct cbd_cache_pos *pos;
	void *addr;

	pos = &cache->dirty_tail;

	if (cache_seg_wb_done(pos->cache_seg)) {
		cbd_cache_debug(cache, "seg %u wb done\n", pos->cache_seg->cache_seg_id);
		return !cache_seg_has_next(pos->cache_seg);
	}

	addr = cache_pos_addr(pos);
	kset_onmedia = (struct cbd_cache_kset_onmedia *)addr;
	if (kset_onmedia->magic != CBD_KSET_MAGIC) {
		cbd_cache_debug(cache, "dirty_tail: %u:%u magic: %llx, not expected: %llx\n",
				pos->cache_seg->cache_seg_id, pos->seg_off,
				kset_onmedia->magic, CBD_KSET_MAGIC);
		return true;
	}

	if (kset_onmedia->crc != cache_kset_crc(kset_onmedia)) {
		cbd_cache_debug(cache, "dirty_tail: %u:%u crc: %x, not expected: %x\n",
				pos->cache_seg->cache_seg_id, pos->seg_off,
				cache_kset_crc(kset_onmedia), kset_onmedia->crc);
		return true;
	}

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

	/* TODO write back in async way, but it should consider
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

	while (true) {
		if (no_more_dirty(cache)) {
			queue_delayed_work(cache->cache_wq, &cache->writeback_work, 1 * HZ);
			return;
		}

		pos = &cache->dirty_tail;
		if (cache_seg_wb_done(pos->cache_seg))
			goto next_seg;

		addr = cache_pos_addr(pos);
		kset_onmedia = (struct cbd_cache_kset_onmedia *)addr;
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
				queue_delayed_work(cache->cache_wq, &cache->writeback_work, 1 * HZ);
				return;
			}
		}
#endif
		for (i = 0; i < kset_onmedia->key_num; i++) {
			key_onmedia = &kset_onmedia->data[i];

			key = cache_key_alloc(cache);
			if (!key) {
				cbd_cache_err(cache, "writeback error failed to alloc key\n");
				return;
			}

			cache_key_decode(key_onmedia, key);
			ret = cache_key_writeback(cache, key);
			cache_key_put(key);

			if (ret) {
				cbd_cache_err(cache, "writeback error: %d\n", ret);
				return;
			}
		}

		vfs_fsync(cache->bdev_file, 1);

		cache_pos_advance(pos, get_kset_onmedia_size(kset_onmedia), false);
		cache_pos_encode(cache, &cache->cache_info->dirty_tail_pos, &cache->dirty_tail);

		if (kset_onmedia->flags & CBD_KSET_FLAGS_LAST) {
			struct cbd_cache_segment *cur_seg, *next_seg;

			pos->cache_seg->cache_seg_info->flags |= CBD_CACHE_SEG_FLAGS_WB_DONE;
next_seg:
			cur_seg = pos->cache_seg;
			next_seg = cache_seg_get_next(cur_seg);
			if (!next_seg)
				continue;
			pos->cache_seg = next_seg;
			pos->seg_off = 0;
			cache_pos_encode(cache, &cache->cache_info->dirty_tail_pos, &cache->dirty_tail);
		}
	}
}

static bool need_gc(struct cbd_cache *cache)
{
	void *dirty_addr, *key_addr;

	cache_pos_decode(cache, &cache->cache_info->dirty_tail_pos, &cache->dirty_tail);

	dirty_addr = cache_pos_addr(&cache->dirty_tail);
	key_addr = cache_pos_addr(&cache->key_tail);

	if (dirty_addr == key_addr)
		return false;

	if (bitmap_weight(cache->seg_map, cache->n_segs) < (cache->n_segs / 100 * cache->cache_info->gc_percent))
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
	int i;

	while (true) {
		if (cache->state == cbd_cache_state_stopping)
			return;

		if (!need_gc(cache)) {
			queue_delayed_work(cache->cache_wq, &cache->gc_work, 1 * HZ);
			return;
		}

		pos = &cache->key_tail;
		if (cache_seg_gc_done(pos->cache_seg))
			goto next_seg;

		addr = cache_pos_addr(pos);
		kset_onmedia = (struct cbd_cache_kset_onmedia *)addr;
		if (kset_onmedia->magic != CBD_KSET_MAGIC ||
				kset_onmedia->crc != cache_kset_crc(kset_onmedia)) {
			cbd_cache_err(cache, "gc error crc is not expected. magic: %llx, expected: %llx\n",
									kset_onmedia->magic, CBD_KSET_MAGIC);
			return;
		}

		for (i = 0; i < kset_onmedia->key_num; i++) {
			key_onmedia = &kset_onmedia->data[i];

			key = cache_key_alloc(cache);
			if (!key) {
				cbd_cache_err(cache, "gc error failed to alloc key\n");
				return;
			}

			cache_key_decode(key_onmedia, key);
			cache_key_gc(cache, key);
			cache_key_put(key);
		}

		cache_pos_advance(pos, get_kset_onmedia_size(kset_onmedia), false);
		cache_pos_encode(cache, &cache->cache_info->key_tail_pos, &cache->key_tail);

		if (kset_onmedia->flags & CBD_KSET_FLAGS_LAST) {
			struct cbd_cache_segment *cur_seg, *next_seg;

			pos->cache_seg->cache_seg_info->flags |= CBD_CACHE_SEG_FLAGS_GC_DONE;
next_seg:
			cache_pos_decode(cache, &cache->cache_info->dirty_tail_pos, &cache->dirty_tail);
			/* dont move next segment if dirty_tail has not move */
			if (cache->dirty_tail.cache_seg == pos->cache_seg)
				continue;
			cur_seg = pos->cache_seg;
			next_seg = cache_seg_get_next(cur_seg);
			if (!next_seg)
				continue;
			pos->cache_seg = next_seg;
			pos->seg_off = 0;
			cache_pos_encode(cache, &cache->cache_info->key_tail_pos, &cache->key_tail);
			cbd_cache_debug(cache, "gc kset seg: %u\n", cur_seg->cache_seg_id);

			spin_lock(&cache->seg_map_lock);
			clear_bit(cur_seg->cache_seg_id, cache->seg_map);
			cache->cache_info->used_segs--;
			spin_unlock(&cache->seg_map_lock);
		}
	}
}

static void kset_flush_fn(struct work_struct *work)
{
	struct cbd_cache_kset *kset = container_of(work, struct cbd_cache_kset, flush_work.work);
	struct cbd_cache *cache = kset->cache;
	int ret;

	spin_lock(&kset->kset_lock);
	ret = cache_kset_close(cache, kset);
	spin_unlock(&kset->kset_lock);

	if (ret) {
		/* Failed to flush kset, retry it. */
		queue_delayed_work(cache->cache_wq, &kset->flush_work, 0);
	}
}

#define CBD_CACHE_SEGS_EACH_PARAL	4

#define CBD_CLEAN_KEYS_MAX		10

static void clean_fn(struct work_struct *work)
{
	struct cbd_cache *cache = container_of(work, struct cbd_cache, clean_work);
	struct cbd_cache_tree *cache_tree;
	struct rb_node *node;
	struct cbd_cache_key *key;
	int i, count;

	for (i = 0; i < cache->n_trees; i++) {
		cache_tree = &cache->cache_trees[i];

again:
		if (cache->state == cbd_cache_state_stopping)
			return;

		/* delete at most CBD_CLEAN_KEYS_MAX a round */
		count = 0;
		spin_lock(&cache_tree->tree_lock);
		node = rb_first(&cache_tree->root);
		while (node) {
			key = CACHE_KEY(node);
			node = rb_next(node);
			if (cache_key_invalid(key)) {
				count++;
				cache_key_delete(key);
			}

			if (count >= CBD_CLEAN_KEYS_MAX) {
				spin_unlock(&cache_tree->tree_lock);
				usleep_range(1000, 2000);
				goto again;
			}
		}
		spin_unlock(&cache_tree->tree_lock);

	}
}

struct cbd_cache *cbd_cache_alloc(struct cbd_transport *cbdt,
				  struct cbd_cache_opts *opts)
{
	struct cbd_cache_info *cache_info;
	struct cbd_backend_info *backend_info;
	struct cbd_segment_info *prev_seg_info = NULL;
	struct cbd_cache *cache;
	u32 seg_id;
	u32 backend_id;
	int ret;
	int i;

	/* options sanitize */
	if (opts->n_paral > CBD_CACHE_PARAL_MAX) {
		cbdt_err(cbdt, "n_paral too large (max %u).\n",
			 CBD_CACHE_PARAL_MAX);
		return NULL;
	}

	cache_info = opts->cache_info;
	backend_info = container_of(cache_info, struct cbd_backend_info, cache_info);
	backend_id = get_backend_id(cbdt, backend_info);

	if (opts->n_paral * CBD_CACHE_SEGS_EACH_PARAL > cache_info->n_segs) {
		cbdt_err(cbdt, "n_paral %u requires cache size (%llu), more than current (%llu).",
				opts->n_paral, opts->n_paral * CBD_CACHE_SEGS_EACH_PARAL * (u64)CBDT_SEG_SIZE,
				cache_info->n_segs * (u64)CBDT_SEG_SIZE);
		return NULL;
	}

	cache = kzalloc(struct_size(cache, segments, cache_info->n_segs), GFP_KERNEL);
	if (!cache)
		return NULL;

	cache->cache_id = backend_id;

	cache->seg_map = bitmap_zalloc(cache_info->n_segs, GFP_KERNEL);
	if (!cache->seg_map) {
		ret = -ENOMEM;
		goto destroy_cache;
	}

	cache->key_cache = KMEM_CACHE(cbd_cache_key, 0);
	if (!cache->key_cache) {
		ret = -ENOMEM;
		goto destroy_cache;
	}

	cache->req_cache = KMEM_CACHE(cbd_request, 0);
	if (!cache->req_cache) {
		ret = -ENOMEM;
		goto destroy_cache;
	}

	cache->cache_wq = alloc_workqueue("cbdt%d-c%u",  WQ_UNBOUND | WQ_MEM_RECLAIM,
					0, cbdt->id, cache->cache_id);
	if (!cache->cache_wq) {
		ret = -ENOMEM;
		goto destroy_cache;
	}

	cache->cbdt = cbdt;
	cache->cache_info = cache_info;
	cache->n_segs = cache_info->n_segs;
	spin_lock_init(&cache->seg_map_lock);
	cache->bdev_file = opts->bdev_file;
	cache->cache_info->gc_percent = CBD_CACHE_GC_PERCENT_DEFAULT;

	spin_lock_init(&cache->key_head_lock);
	spin_lock_init(&cache->miss_read_reqs_lock);
	INIT_LIST_HEAD(&cache->miss_read_reqs);

	INIT_DELAYED_WORK(&cache->writeback_work, writeback_fn);
	INIT_DELAYED_WORK(&cache->gc_work, gc_fn);
	INIT_WORK(&cache->clean_work, clean_fn);
	INIT_WORK(&cache->miss_read_end_work, miss_read_end_work_fn);

	cache->dev_size = opts->dev_size;

	for (i = 0; i < cache_info->n_segs; i++) {
		if (opts->alloc_segs) {
			ret = cbdt_get_empty_segment_id(cbdt, &seg_id);
			if (ret)
				goto destroy_cache;

			if (prev_seg_info)
				prev_seg_info->next_seg = seg_id;
			else
				cache_info->seg_id = seg_id;

		} else {
			if (prev_seg_info)
				seg_id = prev_seg_info->next_seg;
			else
				seg_id = cache_info->seg_id;
		}

		cache_seg_init(cache, seg_id, i);
		prev_seg_info = cbdt_get_segment_info(cbdt, seg_id);
	}

	cache_pos_decode(cache, &cache_info->key_tail_pos, &cache->key_tail);
	cache_pos_decode(cache, &cache_info->dirty_tail_pos, &cache->dirty_tail);

	cache->state = cbd_cache_state_running;

	if (opts->init_keys) {
		cache->init_keys = 1;

		cache->n_trees = DIV_ROUND_UP(cache->dev_size << SECTOR_SHIFT, CBD_CACHE_TREE_SIZE);
		cache->cache_trees = vzalloc(sizeof(struct cbd_cache_tree) * cache->n_trees);
		if (!cache->cache_trees) {
			ret = -ENOMEM;
			goto destroy_cache;
		}

		for (i = 0; i < cache->n_trees; i++) {
			struct cbd_cache_tree *cache_tree;

			cache_tree = &cache->cache_trees[i];
			cache_tree->root = RB_ROOT;
			spin_lock_init(&cache_tree->tree_lock);
		}

		ret = cache_replay(cache);
		if (ret) {
			cbd_cache_err(cache, "failed to replay keys\n");
			goto destroy_cache;
		}

		cache->n_ksets = opts->n_paral;
		cache->ksets = kcalloc(cache->n_ksets, CBD_KSET_SIZE, GFP_KERNEL);
		if (!cache->ksets) {
			ret = -ENOMEM;
			goto destroy_cache;
		}

		for (i = 0; i < cache->n_ksets; i++) {
			struct cbd_cache_kset *kset;

			kset = get_kset(cache, i);

			kset->cache = cache;
			spin_lock_init(&kset->kset_lock);
			INIT_DELAYED_WORK(&kset->flush_work, kset_flush_fn);
		}

		/* Init caceh->data_heads */
		cache->n_heads = opts->n_paral;
		cache->data_heads = kcalloc(cache->n_heads, sizeof(struct cbd_cache_data_head), GFP_KERNEL);
		if (!cache->data_heads) {
			ret = -ENOMEM;
			goto destroy_cache;
		}

		for (i = 0; i < cache->n_heads; i++) {
			struct cbd_cache_data_head *data_head;

			data_head = &cache->data_heads[i];
			spin_lock_init(&data_head->data_head_lock);
		}
	}

	/* start writeback */
	if (opts->start_writeback) {
		cache->start_writeback = 1;
		ret = cache_writeback_init(cache);
		if (ret)
			goto destroy_cache;
	}

	/* start gc */
	if (opts->start_gc) {
		cache->start_gc = 1;
		queue_delayed_work(cache->cache_wq, &cache->gc_work, 0);
	}

	return cache;

destroy_cache:
	cbd_cache_destroy(cache);

	return NULL;
}

void cbd_cache_destroy(struct cbd_cache *cache)
{
	int i;

	cache->state = cbd_cache_state_stopping;

	if (cache->start_gc) {
		cancel_delayed_work_sync(&cache->gc_work);
		flush_work(&cache->clean_work);
	}

	if (cache->start_writeback)
		cache_writeback_exit(cache);

	if (cache->init_keys) {
#ifdef CONFIG_CBD_DEBUG
		dump_cache(cache);
#endif
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

		cache_flush(cache);
	}

	if (cache->cache_wq) {
		drain_workqueue(cache->cache_wq);
		destroy_workqueue(cache->cache_wq);
	}

	kmem_cache_destroy(cache->req_cache);
	kmem_cache_destroy(cache->key_cache);

	if (cache->seg_map)
		bitmap_free(cache->seg_map);

	for (i = 0; i < cache->n_segs; i++)
		cache_seg_exit(&cache->segments[i]);

	kfree(cache->data_heads);
	kfree(cache->ksets);

	if (cache->cache_trees)
		vfree(cache->cache_trees);

	kfree(cache);
}
