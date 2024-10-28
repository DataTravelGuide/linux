// SPDX-License-Identifier: GPL-2.0-or-later
#include "cbd_cache_internal.h"

/**
 * cache_key_init - Initialize a cache key structure.
 * @cache: Pointer to the associated cbd_cache structure.
 * @key: Pointer to the cbd_cache_key structure to be initialized.
 *
 * This function initializes the reference count, sets the cache pointer,
 * and initializes the list and red-black tree nodes for the cache key.
 */
void cache_key_init(struct cbd_cache *cache, struct cbd_cache_key *key)
{
	kref_init(&key->ref);                   /* Initialize reference count */
	key->cache = cache;                     /* Set the associated cache */
	INIT_LIST_HEAD(&key->list_node);        /* Initialize the list head */
	RB_CLEAR_NODE(&key->rb_node);           /* Clear the red-black tree node */
}

/**
 * cache_key_alloc - Allocate and initialize a cache key structure.
 * @cache: Pointer to the associated cbd_cache structure.
 *
 * This function allocates memory for a new cache key using a slab cache,
 * initializes it, and returns a pointer to the allocated key.
 * Returns NULL if allocation fails.
 */
struct cbd_cache_key *cache_key_alloc(struct cbd_cache *cache)
{
	struct cbd_cache_key *key;

	/* Allocate a cache key from the slab cache, zeroed on allocation */
	key = kmem_cache_zalloc(cache->key_cache, GFP_NOWAIT);
	if (!key)
		return NULL;  /* Return NULL if allocation fails */

	cache_key_init(cache, key);  /* Initialize the allocated key */

	return key;  /* Return the allocated and initialized key */
}

/**
 * cache_key_get - Increment the reference count of a cache key.
 * @key: Pointer to the cbd_cache_key structure.
 *
 * This function increments the reference count of the specified cache key,
 * ensuring that it is not freed while still in use.
 */
void cache_key_get(struct cbd_cache_key *key)
{
	kref_get(&key->ref);  /* Increment the reference count */
}

/**
 * cache_key_destroy - Free a cache key structure when its reference count drops to zero.
 * @ref: Pointer to the kref structure.
 *
 * This function is called when the reference count of the cache key reaches zero.
 * It frees the allocated cache key back to the slab cache.
 */
static void cache_key_destroy(struct kref *ref)
{
	struct cbd_cache_key *key = container_of(ref, struct cbd_cache_key, ref);
	struct cbd_cache *cache = key->cache;

	kmem_cache_free(cache->key_cache, key);  /* Free the cache key */
}

/**
 * cache_key_put - Decrement the reference count of a cache key.
 * @key: Pointer to the cbd_cache_key structure.
 *
 * This function decrements the reference count of the specified cache key.
 * If the reference count drops to zero, the key is destroyed.
 */
void cache_key_put(struct cbd_cache_key *key)
{
	kref_put(&key->ref, cache_key_destroy);  /* Decrement ref count and free if zero */
}

/**
 * cache_pos_advance - Advance the position in the cache.
 * @pos: Pointer to the cache position structure.
 * @len: Length to advance the position by.
 *
 * This function advances the position by the specified length.
 * It checks that there is enough remaining space in the current segment.
 * If not, it triggers a BUG.
 */
void cache_pos_advance(struct cbd_cache_pos *pos, u32 len)
{
	/* Ensure enough space remains in the current segment */
	BUG_ON(cache_seg_remain(pos) < len);

	pos->seg_off += len;  /* Advance the segment offset by the specified length */
}

/**
 * cache_key_encode - Encode a cache key for storage.
 * @key_onmedia: Pointer to the cache key structure to encode into.
 * @key: Pointer to the cache key structure to encode from.
 *
 * This function populates the on-media representation of a cache key
 * from its in-memory representation.
 */
static void cache_key_encode(struct cbd_cache_key_onmedia *key_onmedia,
			     struct cbd_cache_key *key)
{
	key_onmedia->off = key->off;  /* Set the offset */
	key_onmedia->len = key->len;  /* Set the length */

	key_onmedia->cache_seg_id = key->cache_pos.cache_seg->cache_seg_id;  /* Set segment ID */
	key_onmedia->cache_seg_off = key->cache_pos.seg_off;  /* Set segment offset */

	key_onmedia->seg_gen = key->seg_gen;  /* Set segment generation */
	key_onmedia->flags = key->flags;  /* Set flags */

#ifdef CONFIG_CBD_CRC
	key_onmedia->data_crc = key->data_crc;  /* Set data CRC if configured */
#endif
}

/**
 * cache_key_decode - Decode a cache key from storage.
 * @key_onmedia: Pointer to the cache key structure to decode from.
 * @key: Pointer to the cache key structure to decode into.
 *
 * This function populates the in-memory representation of a cache key
 * from its on-media representation.
 */
void cache_key_decode(struct cbd_cache_key_onmedia *key_onmedia, struct cbd_cache_key *key)
{
	struct cbd_cache *cache = key->cache;

	key->off = key_onmedia->off;  /* Set the offset */
	key->len = key_onmedia->len;  /* Set the length */

	key->cache_pos.cache_seg = &cache->segments[key_onmedia->cache_seg_id];  /* Set segment pointer */
	key->cache_pos.seg_off = key_onmedia->cache_seg_off;  /* Set segment offset */

	key->seg_gen = key_onmedia->seg_gen;  /* Set segment generation */
	key->flags = key_onmedia->flags;  /* Set flags */

#ifdef CONFIG_CBD_CRC
	key->data_crc = key_onmedia->data_crc;  /* Set data CRC if configured */
#endif
}

/**
 * append_last_kset - Append the last kset to the cache.
 * @cache: Pointer to the cbd_cache structure.
 * @next_seg: ID of the next cache segment.
 *
 * This function appends the last kset to the cache, updating its flags,
 * segment ID, magic number, and CRC. It also advances the key head position.
 */
static void append_last_kset(struct cbd_cache *cache, u32 next_seg)
{
	struct cbd_cache_kset_onmedia *kset_onmedia;

	kset_onmedia = get_key_head_addr(cache);
	kset_onmedia->flags |= CBD_KSET_FLAGS_LAST;  /* Mark as the last kset */
	kset_onmedia->next_cache_seg_id = next_seg;  /* Set the next segment ID */
	kset_onmedia->magic = CBD_KSET_MAGIC;  /* Set magic number */
	kset_onmedia->crc = cache_kset_crc(kset_onmedia);  /* Compute and set CRC */
	cache_pos_advance(&cache->key_head, sizeof(struct cbd_cache_kset_onmedia));  /* Advance key head position */
}

/**
 * cache_kset_close - Close and flush a kset to the cache.
 * @cache: Pointer to the cbd_cache structure.
 * @kset: Pointer to the cache kset structure to close.
 *
 * This function reserves space for the kset on media and flushes it to the
 * storage. It handles segment overflow by obtaining new segments if necessary.
 * Returns 0 on success, or a negative error code on failure.
 */
int cache_kset_close(struct cbd_cache *cache, struct cbd_cache_kset *kset)
{
	struct cbd_cache_kset_onmedia *kset_onmedia;
	u32 kset_onmedia_size;
	int ret;

	kset_onmedia = &kset->kset_onmedia;  /* Get the on-media kset structure */

	if (!kset_onmedia->key_num)  /* No keys to close */
		return 0;

	kset_onmedia_size = struct_size(kset_onmedia, data, kset_onmedia->key_num);  /* Calculate size */

	spin_lock(&cache->key_head_lock);  /* Lock for safe access */
again:
	/* Reserve space for the last kset */
	if (cache_seg_remain(&cache->key_head) < kset_onmedia_size + sizeof(struct cbd_cache_kset_onmedia)) {
		struct cbd_cache_segment *next_seg;

		next_seg = get_cache_segment(cache);  /* Obtain a new cache segment */
		if (!next_seg) {
			ret = -EBUSY;  /* No segment available */
			goto out;  /* Exit the function */
		}

		append_last_kset(cache, next_seg->cache_seg_id);  /* Append the last kset */

		cache->key_head.cache_seg = next_seg;  /* Update the key head to the new segment */
		cache->key_head.seg_off = 0;  /* Reset segment offset */
		goto again;  /* Retry to reserve space */
	}

	kset_onmedia->magic = CBD_KSET_MAGIC;  /* Set magic number */
	kset_onmedia->crc = cache_kset_crc(kset_onmedia);  /* Compute CRC */

	memcpy(get_key_head_addr(cache), kset_onmedia, kset_onmedia_size);  /* Copy the kset to the cache */
	cbdt_flush(cache->cbdt, get_key_head_addr(cache), kset_onmedia_size);  /* Flush the kset to storage */
	memset(kset_onmedia, 0, sizeof(struct cbd_cache_kset_onmedia));  /* Clear the kset structure */

	cache_pos_advance(&cache->key_head, kset_onmedia_size);  /* Advance the key head position */

	ret = 0;  /* Success */
out:
	spin_unlock(&cache->key_head_lock);  /* Unlock after operation */

	return ret;  /* Return result */
}

/**
 * cache_key_append - Append a cache key to the related kset.
 * @cache: Pointer to the cbd_cache structure.
 * @key: Pointer to the cache key structure to append.
 *
 * This function appends a cache key to the appropriate kset. If the kset
 * is full, it closes the kset. If not, it queues a flush work to write
 * the kset to storage.
 *
 * Returns 0 on success, or a negative error code on failure.
 */
int cache_key_append(struct cbd_cache *cache, struct cbd_cache_key *key)
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

	/* Check if the current kset has reached the maximum number of keys */
	if (++kset_onmedia->key_num == CBD_KSET_KEYS_MAX) {
		/* If full, close the kset */
		ret = cache_kset_close(cache, kset);
		if (ret) {
			kset_onmedia->key_num--;
			goto out;
		}
	} else {
		/* If not full, queue a delayed work to flush the kset */
		queue_delayed_work(cache->cache_wq, &kset->flush_work, 1 * HZ);
	}
out:
	spin_unlock(&kset->kset_lock);

	return ret;
}

/**
 * cache_tree_walk - Traverse the cache tree.
 * @cache: Pointer to the cbd_cache structure.
 * @ctx: Pointer to the context structure for traversal.
 *
 * This function traverses the cache tree starting from the specified node.
 * It calls the appropriate callback functions based on the relationships
 * between the keys in the cache tree.
 *
 * Returns 0 on success, or a negative error code on failure.
 */
int cache_tree_walk(struct cbd_cache *cache, struct cbd_cache_tree_walk_ctx *ctx)
{
	struct cbd_cache_key *key_tmp, *key;
	struct rb_node *node_tmp;
	int ret;

	key = ctx->key;
	node_tmp = ctx->start_node;

	while (node_tmp) {
		if (ctx->walk_done && ctx->walk_done(ctx))
			break;

		key_tmp = CACHE_KEY(node_tmp);
		/*
		 * If key_tmp ends before the start of key, continue to the next node.
		 * |----------|
		 *              |=====|
		 */
		if (cache_key_lend(key_tmp) <= cache_key_lstart(key)) {
			if (ctx->after) {
				ret = ctx->after(key, key_tmp, ctx);
				if (ret)
					goto out;
			}
			goto next;
		}

		/*
		 * If key_tmp starts after the end of key, stop traversing.
		 *	  |--------|
		 * |====|
		 */
		if (cache_key_lstart(key_tmp) >= cache_key_lend(key)) {
			if (ctx->before) {
				ret = ctx->before(key, key_tmp, ctx);
				if (ret)
					goto out;
			}
			break;
		}

		/* Handle overlapping keys */
		if (cache_key_lstart(key_tmp) >= cache_key_lstart(key)) {
			/*
			 * If key_tmp encompasses key.
			 *     |----------------|	key_tmp
			 * |===========|		key
			 */
			if (cache_key_lend(key_tmp) >= cache_key_lend(key)) {
				if (ctx->overlap_tail) {
					ret = ctx->overlap_tail(key, key_tmp, ctx);
					if (ret)
						goto out;
				}
				break;
			}

			/*
			 * If key_tmp is contained within key.
			 *    |----|		key_tmp
			 * |==========|		key
			 */
			if (ctx->overlap_contain) {
				ret = ctx->overlap_contain(key, key_tmp, ctx);
				if (ret)
					goto out;
			}

			goto next;
		}

		/*
		 * If key_tmp starts before key ends but ends after key.
		 * |-----------|	key_tmp
		 *   |====|		key
		 */
		if (cache_key_lend(key_tmp) > cache_key_lend(key)) {
			if (ctx->overlap_contained) {
				ret = ctx->overlap_contained(key, key_tmp, ctx);
				if (ret)
					goto out;
			}
			break;
		}

		/*
		 * If key_tmp starts before key and ends within key.
		 * |--------|		key_tmp
		 *   |==========|	key
		 */
		if (ctx->overlap_head) {
			ret = ctx->overlap_head(key, key_tmp, ctx);
			if (ret)
				goto out;
		}
next:
		node_tmp = rb_next(node_tmp);  /* Move to the next node in the red-black tree */
	}

	if (ctx->walk_finally) {
		ret = ctx->walk_finally(ctx);
		if (ret)
			goto out;
	}

	return 0;  /* Return success */
out:
	return ret;  /* Return error code */
}

/* cache_tree_search, search in a cache_tree */
struct rb_node *cache_tree_search(struct cbd_cache_tree *cache_tree, struct cbd_cache_key *key,
				  struct rb_node **parentp, struct rb_node ***newp,
				  struct list_head *delete_key_list)
{
	struct rb_node **new, *parent = NULL;
	struct cbd_cache_key *key_tmp;
	struct rb_node *prev_node = NULL;

	new = &(cache_tree->root.rb_node);
	while (*new) {
		key_tmp = container_of(*new, struct cbd_cache_key, rb_node);
		if (cache_key_invalid(key_tmp))
			list_add(&key_tmp->list_node, delete_key_list);

		parent = *new;
		if (key_tmp->off >= key->off) {
			new = &((*new)->rb_left);
		} else {
			prev_node = *new;
			new = &((*new)->rb_right);
		}
	}

	if (!prev_node)
		prev_node = rb_first(&cache_tree->root);

	if (parentp)
		*parentp = parent;

	if (newp)
		*newp = new;

	return prev_node;
}

/* cache insert fixup, which will walk the cache_tree and do some fixup for key insert
 * if the new key has overlap with existing keys in cache_tree
 */
static int fixup_overlap_tail(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
		struct cbd_cache_tree_walk_ctx *ctx)
{
	int ret;

	/*
	 *     |----------------|	key_tmp
	 * |===========|		key
	 */
	cache_key_cutfront(key_tmp, cache_key_lend(key) - cache_key_lstart(key_tmp));
	if (key_tmp->len == 0) {
		cache_key_delete(key_tmp);
		ret = -EAGAIN;
		goto out;
	}

	return 0;
out:
	return ret;
}

static int fixup_overlap_contain(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
		struct cbd_cache_tree_walk_ctx *ctx)
{
	/*
	 *    |----|			key_tmp
	 * |==========|			key
	 */
	cache_key_delete(key_tmp);

	return -EAGAIN;
}

static int fixup_overlap_contained(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
		struct cbd_cache_tree_walk_ctx *ctx)
{
	struct cbd_cache *cache = ctx->cache;
	int ret;

	/*
	 * |-----------|		key_tmp
	 *   |====|			key
	 */
	if (cache_key_empty(key_tmp)) {
		/* if key_tmp is empty, dont split key_tmp */
		cache_key_cutback(key_tmp, cache_key_lend(key_tmp) - cache_key_lstart(key));
		if (key_tmp->len == 0) {
			cache_key_delete(key_tmp);
			ret = -EAGAIN;
			goto out;
		}
	} else {
		struct cbd_cache_key *key_fixup;
		bool need_research = false;

		key_fixup = cache_key_alloc(cache);
		if (!key_fixup) {
			ret = -ENOMEM;
			goto out;
		}

		cache_key_copy(key_fixup, key_tmp);

		cache_key_cutback(key_tmp, cache_key_lend(key_tmp) - cache_key_lstart(key));
		if (key_tmp->len == 0) {
			cache_key_delete(key_tmp);
			need_research = true;
		}

		cache_key_cutfront(key_fixup, cache_key_lend(key) - cache_key_lstart(key_tmp));
		if (key_fixup->len == 0) {
			cache_key_put(key_fixup);
		} else {
			ret = cache_key_insert(cache, key_fixup, false);
			if (ret)
				goto out;
			need_research = true;
		}

		if (need_research) {
			ret = -EAGAIN;
			goto out;
		}
	}

	return 0;
out:
	return ret;
}

static int fixup_overlap_head(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
		struct cbd_cache_tree_walk_ctx *ctx)
{
	/*
	 * |--------|		key_tmp
	 *   |==========|	key
	 */
	cache_key_cutback(key_tmp, cache_key_lend(key_tmp) - cache_key_lstart(key));
	if (key_tmp->len == 0) {
		cache_key_delete(key_tmp);
		return -EAGAIN;
	}

	return 0;
}

static int cache_insert_fixup(struct cbd_cache *cache, struct cbd_cache_key *key, struct rb_node *prev_node)
{
	struct cbd_cache_tree_walk_ctx walk_ctx = { 0 };

	walk_ctx.cache = cache;
	walk_ctx.start_node = prev_node;
	walk_ctx.key = key;

	walk_ctx.overlap_tail = fixup_overlap_tail;
	walk_ctx.overlap_head = fixup_overlap_head;
	walk_ctx.overlap_contain = fixup_overlap_contain;
	walk_ctx.overlap_contained = fixup_overlap_contained;

	return cache_tree_walk(cache, &walk_ctx);
}

int cache_key_insert(struct cbd_cache *cache, struct cbd_cache_key *key, bool new_key)
{
	struct rb_node **new, *parent = NULL;
	struct cbd_cache_tree *cache_tree;
	struct cbd_cache_key *key_tmp = NULL, *key_next;
	struct rb_node	*prev_node = NULL;
	LIST_HEAD(delete_key_list);
	int ret;

	cache_tree = get_cache_tree(cache, key->off);

	if (new_key)
		key->cache_tree = cache_tree;

search:
	prev_node = cache_tree_search(cache_tree, key, &parent, &new, &delete_key_list);

	if (!list_empty(&delete_key_list)) {
		list_for_each_entry_safe(key_tmp, key_next, &delete_key_list, list_node) {
			list_del_init(&key_tmp->list_node);
			cache_key_delete(key_tmp);
		}
		goto search;
	}

	if (new_key) {
		ret = cache_insert_fixup(cache, key, prev_node);
		if (ret == -EAGAIN)
			goto search;
		if (ret)
			goto out;
	}

	rb_link_node(&key->rb_node, parent, new);
	rb_insert_color(&key->rb_node, &cache_tree->root);

	return 0;
out:
	return ret;
}

/* function to clean_work, clean work would be queued after a cache_segment to be invalidated
 * in cache gc, then it will clean up the invalid keys from cache_tree in backgroud.
 *
 * As this clean need to spin_lock(&cache_tree->tree_lock), we unlock after
 * CBD_CLEAN_KEYS_MAX keys deleted and start another round for clean.
 */
void clean_fn(struct work_struct *work)
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

/*
 * function for flush_work, flush_work is queued in cache_key_append(). When key append
 * to kset, if this kset is full, then the kset will be closed immediately, if this kset
 * is not full, cache_key_append() will queue a kset->flush_work to close this kset later.
 */
void kset_flush_fn(struct work_struct *work)
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

static int kset_replay(struct cbd_cache *cache, struct cbd_cache_kset_onmedia *kset_onmedia)
{
	struct cbd_cache_key_onmedia *key_onmedia;
	struct cbd_cache_key *key;
	int ret;
	int i;

	for (i = 0; i < kset_onmedia->key_num; i++) {
		key_onmedia = &kset_onmedia->data[i];

		key = cache_key_alloc(cache);
		if (!key) {
			ret = -ENOMEM;
			goto err;
		}

		cache_key_decode(key_onmedia, key);
#ifdef CONFIG_CBD_CRC
		if (key->data_crc != cache_key_data_crc(key)) {
			cbd_cache_debug(cache, "key: %llu:%u seg %u:%u data_crc error: %x, expected: %x\n",
					key->off, key->len, key->cache_pos.cache_seg->cache_seg_id,
					key->cache_pos.seg_off, cache_key_data_crc(key), key->data_crc);
			ret = -EIO;
			cache_key_put(key);
			goto err;
		}
#endif
		set_bit(key->cache_pos.cache_seg->cache_seg_id, cache->seg_map);

		if (key->seg_gen < key->cache_pos.cache_seg->gen) {
			cache_key_put(key);
		} else {
			ret = cache_key_insert(cache, key, true);
			if (ret) {
				cache_key_put(key);
				goto err;
			}
		}

		cache_seg_get(key->cache_pos.cache_seg);
	}

	return 0;
err:
	return ret;
}

int cache_replay(struct cbd_cache *cache)
{
	struct cbd_cache_pos pos_tail;
	struct cbd_cache_pos *pos;
	struct cbd_cache_kset_onmedia *kset_onmedia;
	int ret = 0;
	void *addr;

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

		if (kset_onmedia->crc != cache_kset_crc(kset_onmedia))
			break;

		if (kset_onmedia->flags & CBD_KSET_FLAGS_LAST) {
			struct cbd_cache_segment *next_seg;

			cbd_cache_debug(cache, "last kset replay, next: %u\n", kset_onmedia->next_cache_seg_id);

			next_seg = &cache->segments[kset_onmedia->next_cache_seg_id];

			pos->cache_seg = next_seg;
			pos->seg_off = 0;

			set_bit(pos->cache_seg->cache_seg_id, cache->seg_map);
			continue;
		}

		ret = kset_replay(cache, kset_onmedia);
		if (ret)
			goto out;

		cache_pos_advance(pos, get_kset_onmedia_size(kset_onmedia));
	}

	/* pos is the latest position of key_head after replay */
	spin_lock(&cache->key_head_lock);
	cache_pos_copy(&cache->key_head, pos);
	spin_unlock(&cache->key_head_lock);

out:
	return ret;
}

