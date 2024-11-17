/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _CBD_CACHE_INTERNAL_H
#define _CBD_CACHE_INTERNAL_H

#include "cbd_cache.h"

#define CBD_CACHE_PARAL_MAX		128
#define CBD_CACHE_SEGS_EACH_PARAL	10

#define CBD_CACHE_SUBTREE_SIZE		(4 * 1024 * 1024)   /* 4MB total tree size */
#define CBD_CACHE_SUBTREE_SIZE_MASK	0x3FFFFF            /* Mask for tree size */
#define CBD_CACHE_SUBTREE_SIZE_SHIFT	22                  /* Bit shift for tree size */

/* Maximum number of keys per key set */
#define CBD_KSET_KEYS_MAX		128
#define CBD_CACHE_SEGS_MAX		(1024 * 1024)	/* maximum cache size for each device is 16T */
#define CBD_KSET_ONMEDIA_SIZE_MAX	struct_size_t(struct cbd_cache_kset_onmedia, data, CBD_KSET_KEYS_MAX)
#define CBD_KSET_SIZE			(sizeof(struct cbd_cache_kset) + sizeof(struct cbd_cache_key_onmedia) * CBD_KSET_KEYS_MAX)

/* Maximum number of keys to clean in one round of clean_work */
#define CBD_CLEAN_KEYS_MAX             10

/* Writeback and garbage collection intervals in jiffies */
#define CBD_CACHE_WRITEBACK_INTERVAL   (1 * HZ)
#define CBD_CACHE_GC_INTERVAL          (1 * HZ)

/* Macro to get the cache key structure from an rb_node pointer */
#define CACHE_KEY(node)                (container_of(node, struct cbd_cache_key, rb_node))

struct cbd_cache_pos_onmedia {
	struct cbd_meta_header header;
	u32 cache_seg_id;
	u32 seg_off;
};

/* Offset and size definitions for cache segment control */
#define CBDT_CACHE_SEG_CTRL_OFF     (CBDT_SEG_INFO_SIZE * CBDT_META_INDEX_MAX)
#define CBDT_CACHE_SEG_CTRL_SIZE    PAGE_SIZE

struct cbd_cache_seg_gen {
	struct cbd_meta_header header;
	u64 gen;
};

/* Control structure for cache segments */
struct cbd_cache_seg_ctrl {
	struct cbd_cache_seg_gen gen[CBDT_META_INDEX_MAX]; /* Updated by blkdev, incremented in invalidating */
	u64	res[64];
};

/*
 * cbd_cache_ctrl points to the address of the first cbd_cache_seg_ctrl.
 * It extends the control structure of the first cache segment, storing
 * information relevant to the entire cbd_cache.
 */
#define CBDT_CACHE_CTRL_OFF CBDT_SEG_INFO_SIZE
#define CBDT_CACHE_CTRL_SIZE PAGE_SIZE

struct cbd_cache_used_segs {
	struct cbd_meta_header header;
	u32	used_segs;
};

/* cbd_cache_info is a part of cbd_backend_info and can only be updated
 * by the backend. Its integrity is ensured by a unified meta_header.
 * In contrast, the information within cbd_cache_ctrl may be updated by blkdev.
 * Each piece of data in cbd_cache_ctrl has its own meta_header to ensure
 * integrity, allowing for independent updates.
 */
struct cbd_cache_ctrl {
	struct cbd_cache_seg_ctrl cache_seg_ctrl;

	/* Updated by blkdev gc_thread */
	struct cbd_cache_pos_onmedia key_tail_pos[CBDT_META_INDEX_MAX];

	/* Updated by backend writeback_thread */
	struct cbd_cache_pos_onmedia dirty_tail_pos[CBDT_META_INDEX_MAX];

	/* Updated by blkdev */
	struct cbd_cache_used_segs used_segs[CBDT_META_INDEX_MAX];
};

struct cbd_cache_data_head {
	spinlock_t data_head_lock;
	struct cbd_cache_pos head_pos;
};

struct cbd_cache_key {
	struct cbd_cache_tree		*cache_tree;
	struct cbd_cache_subtree	*cache_subtree;
	struct kref			ref;
	struct rb_node			rb_node;
	struct list_head		list_node;
	u64				off;
	u32				len;
	u64				flags;
	struct cbd_cache_pos		cache_pos;
	u64				seg_gen;
};

#define CBD_CACHE_KEY_FLAGS_EMPTY   (1 << 0)
#define CBD_CACHE_KEY_FLAGS_CLEAN   (1 << 1)

struct cbd_cache_key_onmedia {
	u64 off;
	u32 len;
	u32 flags;
	u32 cache_seg_id;
	u32 cache_seg_off;
	u64 seg_gen;
#ifdef CONFIG_CBD_CACHE_DATA_CRC
	u32 data_crc;
#endif
};

struct cbd_cache_kset_onmedia {
	u32 crc;
	union {
		u32 key_num;
		u32 next_cache_seg_id;
	};
	u64 magic;
	u64 flags;
	struct cbd_cache_key_onmedia data[];
};

extern struct cbd_cache_kset_onmedia cbd_empty_kset;

/* cache key */
struct cbd_cache_key *cache_key_alloc(struct cbd_cache_tree *cache_tree);
void cache_key_init(struct cbd_cache_tree *cache_tree, struct cbd_cache_key *key);
void cache_key_get(struct cbd_cache_key *key);
void cache_key_put(struct cbd_cache_key *key);
int cache_key_append(struct cbd_cache *cache, struct cbd_cache_key *key);
int cache_key_insert(struct cbd_cache_tree *cache_tree, struct cbd_cache_key *key, bool fixup);
int cache_key_decode(struct cbd_cache *cache,
			struct cbd_cache_key_onmedia *key_onmedia,
			struct cbd_cache_key *key);
void cache_pos_advance(struct cbd_cache_pos *pos, u32 len);

#define CBD_KSET_FLAGS_LAST (1 << 0)
#define CBD_KSET_MAGIC      0x676894a64e164f1aULL

struct cbd_cache_kset {
	struct cbd_cache *cache;
	spinlock_t        kset_lock;
	struct delayed_work flush_work;
	struct cbd_cache_kset_onmedia kset_onmedia;
};

struct cbd_cache_subtree_walk_ctx {
	struct cbd_cache_tree *cache_tree;
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
			struct cbd_cache_subtree_walk_ctx *ctx);

	/*
	 * |----------|			key_tmp
	 *		|=====|		key
	 */
	int (*after)(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
			struct cbd_cache_subtree_walk_ctx *ctx);

	/*
	 *     |----------------|	key_tmp
	 * |===========|		key
	 */
	int (*overlap_tail)(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
			struct cbd_cache_subtree_walk_ctx *ctx);

	/*
	 * |--------|			key_tmp
	 *   |==========|		key
	 */
	int (*overlap_head)(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
			struct cbd_cache_subtree_walk_ctx *ctx);

	/*
	 *    |----|			key_tmp
	 * |==========|			key
	 */
	int (*overlap_contain)(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
			struct cbd_cache_subtree_walk_ctx *ctx);

	/*
	 * |-----------|		key_tmp
	 *   |====|			key
	 */
	int (*overlap_contained)(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
			struct cbd_cache_subtree_walk_ctx *ctx);

	int (*walk_finally)(struct cbd_cache_subtree_walk_ctx *ctx);
	bool (*walk_done)(struct cbd_cache_subtree_walk_ctx *ctx);
};

int cache_subtree_walk(struct cbd_cache_subtree_walk_ctx *ctx);
struct rb_node *cache_subtree_search(struct cbd_cache_subtree *cache_subtree, struct cbd_cache_key *key,
				  struct rb_node **parentp, struct rb_node ***newp,
				  struct list_head *delete_key_list);
int cache_kset_close(struct cbd_cache *cache, struct cbd_cache_kset *kset);
void clean_fn(struct work_struct *work);
void kset_flush_fn(struct work_struct *work);
int cache_replay(struct cbd_cache *cache);
int cache_tree_init(struct cbd_cache *cache, struct cbd_cache_tree *cache_tree, u32 n_subtrees);
void cache_tree_exit(struct cbd_cache_tree *cache_tree);

/* cache segments */
struct cbd_cache_segment *get_cache_segment(struct cbd_cache *cache);
int cache_seg_init(struct cbd_cache *cache, u32 seg_id, u32 cache_seg_id,
		   bool new_cache);
void cache_seg_destroy(struct cbd_cache_segment *cache_seg);
void cache_seg_get(struct cbd_cache_segment *cache_seg);
void cache_seg_put(struct cbd_cache_segment *cache_seg);
void cache_seg_set_next_seg(struct cbd_cache_segment *cache_seg, u32 seg_id);

/* cache info */
void cache_info_write(struct cbd_cache *cache);
int cache_info_load(struct cbd_cache *cache);

/* cache request*/
int cache_flush(struct cbd_cache *cache);
void miss_read_end_work_fn(struct work_struct *work);

/* gc */
void cbd_cache_gc_fn(struct work_struct *work);

/* writeback */
void cache_writeback_exit(struct cbd_cache *cache);
int cache_writeback_init(struct cbd_cache *cache);
void cache_writeback_fn(struct work_struct *work);

/* inline functions */
static inline struct cbd_cache_subtree *get_subtree(struct cbd_cache_tree *cache_tree, u64 off)
{
	if (cache_tree->n_subtrees == 1)
		return &cache_tree->subtrees[0];

	return &cache_tree->subtrees[off >> CBD_CACHE_SUBTREE_SIZE_SHIFT];
}

static inline void *cache_pos_addr(struct cbd_cache_pos *pos)
{
	return (pos->cache_seg->segment.data + pos->seg_off);
}

static inline void *get_key_head_addr(struct cbd_cache *cache)
{
	return cache_pos_addr(&cache->key_head);
}

static inline u32 get_kset_id(struct cbd_cache *cache, u64 off)
{
	return (off >> CBD_CACHE_SUBTREE_SIZE_SHIFT) % cache->n_ksets;
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

/**
 * cache_seg_is_ctrl_seg - Checks if a cache segment is a cache ctrl segment.
 * @cache_seg_id: ID of the cache segment.
 *
 * Returns true if the cache segment ID corresponds to a cache ctrl segment.
 *
 * Note: We extend the segment control of the first cache segment
 * (cache segment ID 0) to serve as the cache control (cbd_cache_ctrl)
 * for the entire CBD cache. This function determines whether the given
 * cache segment is the one storing the cbd_cache_ctrl information.
 */
static inline bool cache_seg_is_ctrl_seg(u32 cache_seg_id)
{
	return (cache_seg_id == 0);
}

/**
 * cache_key_cutfront - Cuts a specified length from the front of a cache key.
 * @key: Pointer to cbd_cache_key structure.
 * @cut_len: Length to cut from the front.
 *
 * Advances the cache key position by cut_len and adjusts offset and length accordingly.
 */
static inline void cache_key_cutfront(struct cbd_cache_key *key, u32 cut_len)
{
	if (key->cache_pos.cache_seg)
		cache_pos_advance(&key->cache_pos, cut_len);

	key->off += cut_len;
	key->len -= cut_len;
}

/**
 * cache_key_cutback - Cuts a specified length from the back of a cache key.
 * @key: Pointer to cbd_cache_key structure.
 * @cut_len: Length to cut from the back.
 *
 * Reduces the length of the cache key by cut_len.
 */
static inline void cache_key_cutback(struct cbd_cache_key *key, u32 cut_len)
{
	key->len -= cut_len;
}

static inline void cache_key_delete(struct cbd_cache_key *key)
{
	struct cbd_cache_subtree *cache_subtree;

	cache_subtree = key->cache_subtree;
	if (!cache_subtree)
		return;

	rb_erase(&key->rb_node, &cache_subtree->root);
	key->flags = 0;
	cache_key_put(key);
}

/**
 * cache_key_data_crc - Calculates CRC for data in a cache key.
 * @key: Pointer to the cbd_cache_key structure.
 *
 * Returns the CRC-32 checksum of the data within the cache key's position.
 */
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

/**
 * cache_seg_remain - Computes remaining space in a cache segment.
 * @pos: Pointer to cbd_cache_pos structure.
 *
 * Returns the amount of remaining space in the segment data starting from
 * the current position offset.
 */
static inline u32 cache_seg_remain(struct cbd_cache_pos *pos)
{
	struct cbd_cache_segment *cache_seg;
	struct cbd_segment *segment;
	u32 seg_remain;

	cache_seg = pos->cache_seg;
	segment = &cache_seg->segment;
	seg_remain = segment->data_size - pos->seg_off;

	return seg_remain;
}

/**
 * cache_key_invalid - Checks if a cache key is invalid.
 * @key: Pointer to cbd_cache_key structure.
 *
 * Returns true if the cache key is invalid due to its generation being
 * less than the generation of its segment; otherwise returns false.
 *
 * When the GC (garbage collection) thread identifies a segment
 * as reclaimable, it increments the segment's generation (gen). However,
 * it does not immediately remove all related cache keys. When accessing
 * such a cache key, this function can be used to determine if the cache
 * key has already become invalid.
 */
static inline bool cache_key_invalid(struct cbd_cache_key *key)
{
	if (cache_key_empty(key))
		return false;

	return (key->seg_gen < key->cache_pos.cache_seg->gen);
}

/**
 * cache_key_lstart - Retrieves the logical start offset of a cache key.
 * @key: Pointer to cbd_cache_key structure.
 *
 * Returns the logical start offset for the cache key.
 */
static inline u64 cache_key_lstart(struct cbd_cache_key *key)
{
	return key->off;
}

/**
 * cache_key_lend - Retrieves the logical end offset of a cache key.
 * @key: Pointer to cbd_cache_key structure.
 *
 * Returns the logical end offset for the cache key.
 */
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
	key_dst->cache_subtree = key_src->cache_subtree;
	key_dst->flags = key_src->flags;

	cache_pos_copy(&key_dst->cache_pos, &key_src->cache_pos);
}

/**
 * cache_pos_onmedia_crc - Calculates the CRC for an on-media cache position.
 * @pos_om: Pointer to cbd_cache_pos_onmedia structure.
 *
 * Calculates the CRC-32 checksum of the position, excluding the first 4 bytes.
 * Returns the computed CRC value.
 */
static inline u32 cache_pos_onmedia_crc(struct cbd_cache_pos_onmedia *pos_om)
{
	return crc32(0, (void *)pos_om + 4, sizeof(*pos_om) - 4);
}

static inline void cache_pos_encode(struct cbd_cache *cache,
			     struct cbd_cache_pos_onmedia *pos_onmedia,
			     struct cbd_cache_pos *pos)
{
	struct cbd_cache_pos_onmedia *oldest;

	oldest = cbd_meta_find_oldest(&pos_onmedia->header, sizeof(struct cbd_cache_pos_onmedia));
	BUG_ON(!oldest);

	oldest->cache_seg_id = pos->cache_seg->cache_seg_id;
	oldest->seg_off = pos->seg_off;
	oldest->header.seq = cbd_meta_get_next_seq(&pos_onmedia->header, sizeof(struct cbd_cache_pos_onmedia));
	oldest->header.crc = cache_pos_onmedia_crc(oldest);
	cbdt_flush(cache->cbdt, oldest, sizeof(struct cbd_cache_pos_onmedia));
}

static inline int cache_pos_decode(struct cbd_cache *cache,
			    struct cbd_cache_pos_onmedia *pos_onmedia,
			    struct cbd_cache_pos *pos)
{
	struct cbd_cache_pos_onmedia *latest;

	latest = cbd_meta_find_latest(&pos_onmedia->header, sizeof(struct cbd_cache_pos_onmedia));
	if (!latest)
		return -EIO;

	pos->cache_seg = &cache->segments[latest->cache_seg_id];
	pos->seg_off = latest->seg_off;

	return 0;
}

static inline void cache_encode_key_tail(struct cbd_cache *cache)
{
	mutex_lock(&cache->key_tail_lock);
	cache_pos_encode(cache, cache->cache_ctrl->key_tail_pos, &cache->key_tail);
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
	mutex_lock(&cache->dirty_tail_lock);
	cache_pos_encode(cache, cache->cache_ctrl->dirty_tail_pos, &cache->dirty_tail);
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
