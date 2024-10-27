/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _CBD_CACHE_INTERNAL_H
#define _CBD_CACHE_INTERNAL_H

#include "cbd_cache.h"

/* Maximum level of parallelism in cache IO */
#define CBD_CACHE_PARAL_MAX            128
/* Number of segments handled per parallel operation */
#define CBD_CACHE_SEGS_EACH_PARAL      10

/* Cache tree structure sizes and masking values */
#define CBD_CACHE_TREE_SIZE            (4 * 1024 * 1024)   /* 4MB total tree size */
#define CBD_CACHE_TREE_SIZE_MASK       0x3FFFFF            /* Mask for tree size */
#define CBD_CACHE_TREE_SIZE_SHIFT      22                  /* Bit shift for tree size */

/* Maximum number of keys per key set */
#define CBD_KSET_KEYS_MAX              128

/* Maximum on-media size for key set structure */
#define CBD_KSET_ONMEDIA_SIZE_MAX      struct_size_t(struct cbd_cache_kset_onmedia, data, CBD_KSET_KEYS_MAX)
/* Total size of a cache key set */
#define CBD_KSET_SIZE                  (sizeof(struct cbd_cache_kset) + sizeof(struct cbd_cache_key_onmedia) * CBD_KSET_KEYS_MAX)

/* Garbage collection thresholds */
#define CBD_CACHE_GC_PERCENT_MIN       0                   /* Minimum GC percentage */
#define CBD_CACHE_GC_PERCENT_MAX       90                  /* Maximum GC percentage */
#define CBD_CACHE_GC_PERCENT_DEFAULT   70                  /* Default GC percentage */

/* Maximum number of keys to clean in one round of clean_work */
#define CBD_CLEAN_KEYS_MAX             10

/* Writeback and garbage collection intervals in jiffies */
#define CBD_CACHE_WRITEBACK_INTERVAL   (1 * HZ)           /* Writeback interval */
#define CBD_CACHE_GC_INTERVAL          (1 * HZ)           /* Garbage collection interval */

/* Macro to get the cache key structure from an rb_node pointer */
#define CACHE_KEY(node)                (container_of(node, struct cbd_cache_key, rb_node))

/* cache key */
struct cbd_cache_key *cache_key_alloc(struct cbd_cache *cache);
void cache_key_init(struct cbd_cache *cache, struct cbd_cache_key *key);
void cache_key_get(struct cbd_cache_key *key);
void cache_key_put(struct cbd_cache_key *key);
int cache_key_append(struct cbd_cache *cache, struct cbd_cache_key *key);
int cache_key_insert(struct cbd_cache *cache, struct cbd_cache_key *key, bool new_key);
void cache_key_decode(struct cbd_cache_key_onmedia *key_onmedia, struct cbd_cache_key *key);
void cache_pos_advance(struct cbd_cache_pos *pos, u32 len);

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
int cache_seg_init(struct cbd_cache *cache, u32 seg_id, u32 cache_seg_id,
		   bool new_cache);
void cache_seg_destroy(struct cbd_cache_segment *cache_seg);
void cache_seg_get(struct cbd_cache_segment *cache_seg);
void cache_seg_put(struct cbd_cache_segment *cache_seg);
void cache_seg_set_next_seg(struct cbd_cache_segment *cache_seg, u32 seg_id);

/* cache info */
void cache_info_write(struct cbd_cache *cache);
void cache_info_load(struct cbd_cache *cache);

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
/**
 * get_cache_tree - Retrieves the cache tree based on offset.
 * @cache: Pointer to cbd_cache structure.
 * @off: Offset value to determine cache tree.
 *
 * Returns the cache tree corresponding to the specified offset.
 */
static inline struct cbd_cache_tree *get_cache_tree(struct cbd_cache *cache, u64 off)
{
	return &cache->cache_trees[off >> CBD_CACHE_TREE_SIZE_SHIFT];
}

/**
 * cache_pos_addr - Gets address in cache segment based on position.
 * @pos: Pointer to cbd_cache_pos structure.
 *
 * Returns the memory address within the cache segment corresponding to the given position.
 */
static inline void *cache_pos_addr(struct cbd_cache_pos *pos)
{
	return (pos->cache_seg->segment.data + pos->seg_off);
}

/**
 * get_key_head_addr - Gets the address of key head.
 * @cache: Pointer to cbd_cache structure.
 *
 * Returns a pointer to the head of the key set in on-media format.
 */
static inline struct cbd_cache_kset_onmedia *get_key_head_addr(struct cbd_cache *cache)
{
	return (struct cbd_cache_kset_onmedia *)cache_pos_addr(&cache->key_head);
}

/**
 * get_kset_id - Determines key set ID based on offset.
 * @cache: Pointer to cbd_cache structure.
 * @off: Offset value.
 *
 * Calculates the ID of the key set based on the provided offset.
 */
static inline u32 get_kset_id(struct cbd_cache *cache, u64 off)
{
	return (off >> CBD_CACHE_TREE_SIZE_SHIFT) % cache->n_ksets;
}

/**
 * get_kset - Retrieves a key set by its ID.
 * @cache: Pointer to cbd_cache structure.
 * @kset_id: ID of the key set.
 *
 * Returns a pointer to the key set with the specified ID.
 */
static inline struct cbd_cache_kset *get_kset(struct cbd_cache *cache, u32 kset_id)
{
	return (void *)cache->ksets + CBD_KSET_SIZE * kset_id;
}

/**
 * get_data_head - Retrieves a data head based on index.
 * @cache: Pointer to cbd_cache structure.
 * @i: Index of the data head.
 *
 * Returns the data head corresponding to the specified index.
 */
static inline struct cbd_cache_data_head *get_data_head(struct cbd_cache *cache, u32 i)
{
	return &cache->data_heads[i % cache->n_heads];
}

/**
 * cache_key_empty - Checks if cache key is empty.
 * @key: Pointer to cbd_cache_key structure.
 *
 * Returns true if the key is marked as empty.
 */
static inline bool cache_key_empty(struct cbd_cache_key *key)
{
	return key->flags & CBD_CACHE_KEY_FLAGS_EMPTY;
}

/**
 * cache_key_clean - Checks if cache key is clean.
 * @key: Pointer to cbd_cache_key structure.
 *
 * Returns true if the key is marked as clean.
 */
static inline bool cache_key_clean(struct cbd_cache_key *key)
{
	return key->flags & CBD_CACHE_KEY_FLAGS_CLEAN;
}

/**
 * cache_pos_copy - Copies one cache position to another.
 * @dst: Destination position.
 * @src: Source position.
 *
 * Copies the cache position data from src to dst.
 */
static inline void cache_pos_copy(struct cbd_cache_pos *dst, struct cbd_cache_pos *src)
{
	memcpy(dst, src, sizeof(struct cbd_cache_pos));
}

/**
 * cache_seg_is_meta_seg - Checks if a cache segment is a metadata segment.
 * @cache_seg_id: ID of the cache segment.
 *
 * Returns true if the cache segment ID corresponds to a metadata segment.
 */
static inline bool cache_seg_is_meta_seg(u32 cache_seg_id)
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

/**
 * cache_key_delete - Removes a cache key from the cache tree.
 * @key: Pointer to the cbd_cache_key structure to be deleted.
 *
 * Removes the cache key from its red-black tree and clears its flags.
 * Calls cache_key_put to release the key.
 */
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

/**
 * cache_kset_crc - Calculates CRC for a key set.
 * @kset_onmedia: Pointer to cbd_cache_kset_onmedia structure.
 *
 * Calculates the CRC-32 checksum of the key set, excluding the last 4 bytes.
 * Adjusts size based on whether the set is the last in sequence.
 */
static inline u32 cache_kset_crc(struct cbd_cache_kset_onmedia *kset_onmedia)
{
	u32 crc_size;

	if (kset_onmedia->flags & CBD_KSET_FLAGS_LAST)
		crc_size = sizeof(struct cbd_cache_kset_onmedia) - 4;
	else
		crc_size = struct_size(kset_onmedia, data, kset_onmedia->key_num) - 4;

	return crc32(0, (void *)kset_onmedia + 4, crc_size);
}

/**
 * get_kset_onmedia_size - Calculates the size of a key set on media.
 * @kset_onmedia: Pointer to cbd_cache_kset_onmedia structure.
 *
 * Returns the size of the key set, including the data for each key.
 */
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

/**
 * cache_key_copy - Copies one cache key's details to another.
 * @key_dst: Destination cache key.
 * @key_src: Source cache key.
 *
 * Copies the properties and position of key_src to key_dst.
 */
static inline void cache_key_copy(struct cbd_cache_key *key_dst, struct cbd_cache_key *key_src)
{
	key_dst->off = key_src->off;
	key_dst->len = key_src->len;
	key_dst->seg_gen = key_src->seg_gen;
	key_dst->cache_tree = key_src->cache_tree;
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

/**
 * cache_pos_encode - Encodes and updates the cache position on media.
 * @cache: Pointer to the cbd_cache structure.
 * @pos_onmedia: Pointer to the on-media position structure to update.
 * @pos: Pointer to the current cache position.
 * @debug: Debug message for logging.
 *
 * Encodes the cache position by finding the oldest entry, updating its
 * sequence and segment information, and calculating its CRC. The cache
 * position is flushed to media after encoding.
 */
static inline void cache_pos_encode(struct cbd_cache *cache,
			     struct cbd_cache_pos_onmedia *pos_onmedia,
			     struct cbd_cache_pos *pos,
			     char *debug)
{
	struct cbd_cache_pos_onmedia *oldest;

	oldest = cbd_meta_find_oldest(&pos_onmedia->header, sizeof(struct cbd_cache_pos_onmedia));

	BUG_ON(!oldest);

	oldest->header.seq = cbd_meta_get_next_seq(&pos_onmedia->header, sizeof(struct cbd_cache_pos_onmedia));

	oldest->cache_seg_id = pos->cache_seg->cache_seg_id;
	oldest->seg_off = pos->seg_off;

	oldest->header.crc = cache_pos_onmedia_crc(oldest);
}

/**
 * cache_pos_decode - Decodes the latest cache position from media.
 * @cache: Pointer to the cbd_cache structure.
 * @pos_onmedia: Pointer to the on-media position structure.
 * @pos: Pointer to the cache position structure to store the decoded position.
 *
 * Finds the latest entry from on-media position and decodes its segment and
 * offset information into the cache position structure.
 *
 * Returns 0 on success, -EIO on failure.
 */
static inline int cache_pos_decode(struct cbd_cache *cache,
		            struct cbd_cache_pos_onmedia *pos_onmedia,
			    struct cbd_cache_pos *pos)
{
	struct cbd_cache_pos_onmedia *latest;

	latest = cbd_meta_find_latest(&pos_onmedia->header, sizeof(struct cbd_cache_pos_onmedia), NULL);
	if (!latest)
		return -EIO;

	pos->cache_seg = &cache->segments[latest->cache_seg_id];
	pos->seg_off = latest->seg_off;

	return 0;
}

/**
 * cache_encode_key_tail - Encodes the key tail position on media.
 * @cache: Pointer to the cbd_cache structure.
 *
 * Locks the key tail position, encodes it on media, and releases the lock.
 */
static inline void cache_encode_key_tail(struct cbd_cache *cache)
{
	mutex_lock(&cache->key_tail_lock);
	cache_pos_encode(cache, cache->cache_ctrl->key_tail_pos, &cache->key_tail, "key_tail");
	mutex_unlock(&cache->key_tail_lock);
}

/**
 * cache_decode_key_tail - Decodes the key tail position from media.
 * @cache: Pointer to the cbd_cache structure.
 *
 * Locks the key tail position, decodes it from media, and releases the lock.
 *
 * Returns 0 on success, -EIO on failure.
 */
static inline int cache_decode_key_tail(struct cbd_cache *cache)
{
	int ret;

	mutex_lock(&cache->key_tail_lock);
	ret = cache_pos_decode(cache, cache->cache_ctrl->key_tail_pos, &cache->key_tail);
	mutex_unlock(&cache->key_tail_lock);

	return ret;
}

/**
 * cache_encode_dirty_tail - Encodes the dirty tail position on media.
 * @cache: Pointer to the cbd_cache structure.
 *
 * Locks the dirty tail position, encodes it on media, and releases the lock.
 */
static inline void cache_encode_dirty_tail(struct cbd_cache *cache)
{
	mutex_lock(&cache->dirty_tail_lock);
	cache_pos_encode(cache, cache->cache_ctrl->dirty_tail_pos, &cache->dirty_tail, "dirty tail");
	mutex_unlock(&cache->dirty_tail_lock);
}

/**
 * cache_decode_dirty_tail - Decodes the dirty tail position from media.
 * @cache: Pointer to the cbd_cache structure.
 *
 * Locks the dirty tail position, decodes it from media, and releases the lock.
 *
 * Returns 0 on success, -EIO on failure.
 */
static inline int cache_decode_dirty_tail(struct cbd_cache *cache)
{
	int ret;

	mutex_lock(&cache->dirty_tail_lock);
	ret = cache_pos_decode(cache, cache->cache_ctrl->dirty_tail_pos, &cache->dirty_tail);
	mutex_unlock(&cache->dirty_tail_lock);

	return ret;
}

#endif /* _CBD_CACHE_INTERNAL_H */
