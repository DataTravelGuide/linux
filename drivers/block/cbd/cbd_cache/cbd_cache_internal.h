/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CBD_CACHE_INTERNAL_H
#define _CBD_CACHE_INTERNAL_H

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

#define CBD_CACHE_SEGS_EACH_PARAL	10

#define CBD_CLEAN_KEYS_MAX		10

#define CBD_CACHE_WRITEBACK_INTERVAL	(10 * HZ)
#define CBD_CACHE_GC_INTERVAL	(10 * HZ)

#define CACHE_KEY(node)		(container_of(node, struct cbd_cache_key, rb_node))

struct cbd_cache_key *cache_key_alloc(struct cbd_cache *cache);
void cache_key_get(struct cbd_cache_key *key);
void cache_key_put(struct cbd_cache_key *key);
int cache_key_append(struct cbd_cache *cache, struct cbd_cache_key *key);
int cache_insert_key(struct cbd_cache *cache, struct cbd_cache_key *key, bool new_key);
void cache_pos_advance(struct cbd_cache_pos *pos, u32 len);
void cache_key_decode(struct cbd_cache_key_onmedia *key_onmedia, struct cbd_cache_key *key);

struct cbd_cache_tree_walk_ctx {
	struct cbd_cache *cache;
	struct rb_node *start_node;
	struct cbd_request *cbd_req;
	u32	req_done;
	struct cbd_cache_key *key;

	struct list_head *delete_key_list;
	struct list_head *submit_req_list;

	/*
	 *	  |--------|		key_tmp
	 * |====|			key
	 */
	int (*before)(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
			struct cbd_cache_tree_walk_ctx *ctx);

	/*
	 * |----------|			key_tmp
	 *		|=====|		key
	 */
	int (*after)(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
			struct cbd_cache_tree_walk_ctx *ctx);

	/*
	 *     |----------------|	key_tmp
	 * |===========|		key
	 */
	int (*overlap_tail)(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
			struct cbd_cache_tree_walk_ctx *ctx);

	/*
	 * |--------|			key_tmp
	 *   |==========|		key
	 */
	int (*overlap_head)(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
			struct cbd_cache_tree_walk_ctx *ctx);

	/*
	 *    |----|			key_tmp
	 * |==========|			key
	 */
	int (*overlap_contain)(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
			struct cbd_cache_tree_walk_ctx *ctx);

	/*
	 * |-----------|		key_tmp
	 *   |====|			key
	 */
	int (*overlap_contained)(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
			struct cbd_cache_tree_walk_ctx *ctx);

	int (*walk_finally)(struct cbd_cache_tree_walk_ctx *ctx);
	bool (*walk_done)(struct cbd_cache_tree_walk_ctx *ctx);
};

int cache_tree_walk(struct cbd_cache *cache, struct cbd_cache_tree_walk_ctx *ctx);
struct rb_node *cache_tree_search(struct cbd_cache_tree *cache_tree, struct cbd_cache_key *key,
				  struct rb_node **parentp, struct rb_node ***newp,
				  struct list_head *delete_key_list);
int cache_kset_close(struct cbd_cache *cache, struct cbd_cache_kset *kset);
void clean_fn(struct work_struct *work);
void kset_flush_fn(struct work_struct *work);
int cache_replay(struct cbd_cache *cache);

/* cache segments */
struct cbd_cache_segment *get_cache_segment(struct cbd_cache *cache);
void cache_seg_init(struct cbd_cache *cache, u32 seg_id, u32 cache_seg_id,
		    bool new_cache);
void cache_seg_exit(struct cbd_cache_segment *cache_seg);
void cache_seg_get(struct cbd_cache_segment *cache_seg);
void cache_seg_put(struct cbd_cache_segment *cache_seg);
void cache_seg_set_next_seg(struct cbd_cache_segment *cache_seg, u32 seg_id);

void cache_info_write(struct cbd_cache *cache);
int cache_flush(struct cbd_cache *cache);
void miss_read_end_work_fn(struct work_struct *work);

/* gc */
void cbd_cache_gc_fn(struct work_struct *work);

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

static inline struct cbd_cache_data_head *get_data_head(struct cbd_cache *cache, u32 i)
{
	return &cache->data_heads[i % cache->n_heads];
}

static inline bool cache_key_empty(struct cbd_cache_key *key)
{
	return key->flags & CBD_CACHE_KEY_FLAGS_EMPTY;
}

static inline bool cache_key_clean(struct cbd_cache_key *key)
{
	return key->flags & CBD_CACHE_KEY_FLAGS_CLEAN;
}

static inline void cache_pos_copy(struct cbd_cache_pos *dst, struct cbd_cache_pos *src)
{
	memcpy(dst, src, sizeof(struct cbd_cache_pos));
}

static inline bool cache_seg_is_meta_seg(u32 cache_seg_id)
{
	return (cache_seg_id == 0);
}

static inline void cache_key_cutfront(struct cbd_cache_key *key, u32 cut_len)
{
	if (key->cache_pos.cache_seg)
		cache_pos_advance(&key->cache_pos, cut_len);

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

static inline u32 cache_kset_crc(struct cbd_cache_kset_onmedia *kset_onmedia)
{
	u32 crc_size;

	if (kset_onmedia->flags & CBD_KSET_FLAGS_LAST)
		crc_size = sizeof(struct cbd_cache_kset_onmedia) - 4;
	else
		crc_size = struct_size(kset_onmedia, data, kset_onmedia->key_num) - 4;

	return crc32(0, (void *)kset_onmedia + 4, crc_size);
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

static inline bool cache_key_invalid(struct cbd_cache_key *key)
{
	if (cache_key_empty(key))
		return false;

	return (key->seg_gen < key->cache_pos.cache_seg->cache_seg_info.gen);
}

static inline u64 cache_key_lstart(struct cbd_cache_key *key)
{
	return key->off;
}

static inline u64 cache_key_lend(struct cbd_cache_key *key)
{
	return key->off + key->len;
}

static inline void cache_key_copy(struct cbd_cache_key *key_dst, struct cbd_cache_key *key_src)
{
	key_dst->off = key_src->off;
	key_dst->len = key_src->len;
	key_dst->seg_gen = key_src->seg_gen;
	key_dst->cache_tree = key_src->cache_tree;
	key_dst->flags = key_src->flags;

	cache_pos_copy(&key_dst->cache_pos, &key_src->cache_pos);
}


static inline u32 cache_pos_onmedia_crc(struct cbd_cache_pos_onmedia *pos_om)
{
	return crc32(0, (void *)pos_om + 4, sizeof(*pos_om) - 4);
}

static inline void cache_pos_encode(struct cbd_cache *cache,
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

static inline int cache_pos_decode(struct cbd_cache *cache,
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

static inline void cache_encode_key_tail(struct cbd_cache *cache)
{
	//pr_err("update key tail\n");
	mutex_lock(&cache->key_tail_lock);
	cache_pos_encode(cache, cache->cache_ctrl->key_tail_pos, &cache->key_tail, "key_tail");
	mutex_unlock(&cache->key_tail_lock);
}

static inline int cache_decode_key_tail(struct cbd_cache *cache)
{
	int ret;

	mutex_lock(&cache->key_tail_lock);
	ret = cache_pos_decode(cache, cache->cache_ctrl->key_tail_pos, &cache->key_tail);
	mutex_unlock(&cache->key_tail_lock);

	return ret;
}

static inline void cache_encode_dirty_tail(struct cbd_cache *cache)
{
	//pr_err("update dirty tail\n");
	mutex_lock(&cache->dirty_tail_lock);
	cache_pos_encode(cache, cache->cache_ctrl->dirty_tail_pos, &cache->dirty_tail, "dirty tail");
	mutex_unlock(&cache->dirty_tail_lock);
}

static inline int cache_decode_dirty_tail(struct cbd_cache *cache)
{
	int ret;

	mutex_lock(&cache->dirty_tail_lock);
	ret = cache_pos_decode(cache, cache->cache_ctrl->dirty_tail_pos, &cache->dirty_tail);
	mutex_unlock(&cache->dirty_tail_lock);

	return ret;
}

#endif /* _CBD_CACHE_INTERNAL_H */
