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

#ifdef CONFIG_CBD_CACHE_DATA_CRC
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

#ifdef CONFIG_CBD_CACHE_DATA_CRC
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
 * key_data_flush - Flush the data of a cache key to persistent media.
 * @cache: Pointer to the cache structure.
 * @key: Pointer to the cache key whose data is to be flushed.
 *
 * This function flushes the data associated with the specified cache key
 * to ensure that it is persisted in the underlying media. It retrieves the
 * address of the data using the cache position and then calls the appropriate
 * flush function to perform the operation.
 */
static void key_data_flush(struct cbd_cache *cache, struct cbd_cache_key *key)
{
	void *pos;

	pos = cache_pos_addr(&key->cache_pos);
	cbdt_flush(cache->cbdt, pos, key->len);
}

/**
 * kset_data_flush - Flush the data of all keys in a kset to persistent media.
 * @cache: Pointer to the cache structure.
 * @kset_onmedia: Pointer to the kset on media containing keys to be flushed.
 *
 * This function iterates through all the keys in the specified kset and
 * flushes their data to ensure that it is persisted in the underlying media
 * before the kset is closed. It initializes a temporary cache key structure,
 * decodes the key information from the on-media format, and calls the
 * key_data_flush function for each key.
 *
 * This function should be called during the kset_close process to guarantee
 * that all key data is safely stored before finalizing the kset.
 */
static void kset_data_flush(struct cbd_cache *cache, struct cbd_cache_kset_onmedia *kset_onmedia)
{
	struct cbd_cache_key_onmedia *key_onmedia;
	struct cbd_cache_key *key;
	u32 i;

	for (i = 0; i < kset_onmedia->key_num; i++) {
		struct cbd_cache_key key_tmp = { 0 };

		key = &key_tmp;
		key_onmedia = &kset_onmedia->data[i];
		cache_key_init(cache, key);
		cache_key_decode(key_onmedia, key);

		key_data_flush(cache, key);
	}
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

	/*
	 * Before writing kset_onmedia to the key head address,
	 * we need to ensure that all the data corresponding to
	 * the keys in the kset have been flushed to persistent media.
	 * This guarantees that the key data is safely stored before
	 * the kset itself is persisted.
	 */
	kset_data_flush(cache, kset_onmedia);

	memcpy(get_key_head_addr(cache), kset_onmedia, kset_onmedia_size);
	cbdt_flush(cache->cbdt, get_key_head_addr(cache), kset_onmedia_size);  /* Flush the kset to storage */

	memset(kset_onmedia, 0, sizeof(struct cbd_cache_kset_onmedia));
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
#ifdef CONFIG_CBD_CACHE_DATA_CRC
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

/**
 * cache_tree_search - Search for a key in the cache tree.
 * @cache_tree: Pointer to the cache tree structure.
 * @key: Pointer to the cache key to search for.
 * @parentp: Pointer to store the parent node of the found node.
 * @newp: Pointer to store the location where the new node should be inserted.
 * @delete_key_list: List to collect invalid keys for deletion.
 *
 * This function searches the cache tree for a specific key and returns
 * the node that is the predecessor of the key, or first node if the key is
 * less than all keys in the tree. If any invalid keys are found during
 * the search, they are added to the delete_key_list for later cleanup.
 *
 * Returns a pointer to the previous node.
 */
struct rb_node *cache_tree_search(struct cbd_cache_tree *cache_tree, struct cbd_cache_key *key,
				  struct rb_node **parentp, struct rb_node ***newp,
				  struct list_head *delete_key_list)
{
	struct rb_node **new, *parent = NULL;  /* Pointers for tree traversal */
	struct cbd_cache_key *key_tmp;  /* Temporary pointer to the current key */
	struct rb_node *prev_node = NULL;  /* Pointer to the previous node */

	new = &(cache_tree->root.rb_node);  /* Start at the root of the tree */
	while (*new) {
		key_tmp = container_of(*new, struct cbd_cache_key, rb_node);  /* Get the key from the node */
		if (cache_key_invalid(key_tmp))
			list_add(&key_tmp->list_node, delete_key_list);  /* Add invalid key to the delete list */

		parent = *new;  /* Update the parent pointer */
		if (key_tmp->off >= key->off) {
			new = &((*new)->rb_left);  /* Traverse left if current key is greater than or equal to search key */
		} else {
			prev_node = *new;  /* Update the previous node */
			new = &((*new)->rb_right);  /* Traverse right otherwise */
		}
	}

	if (!prev_node)
		prev_node = rb_first(&cache_tree->root);  /* Get the first node if no previous node was found */

	if (parentp)
		*parentp = parent;

	if (newp)
		*newp = new;

	return prev_node;
}

/**
 * fixup_overlap_tail - Adjust the key when it overlaps at the tail.
 * @key: Pointer to the new cache key being inserted.
 * @key_tmp: Pointer to the existing key that overlaps.
 * @ctx: Pointer to the context for walking the cache tree.
 *
 * This function modifies the existing key (key_tmp) when there is an
 * overlap at the tail with the new key. If the modified key becomes
 * empty, it is deleted. Returns 0 on success, or -EAGAIN if the key
 * needs to be reinserted.
 */
static int fixup_overlap_tail(struct cbd_cache_key *key,
			       struct cbd_cache_key *key_tmp,
			       struct cbd_cache_tree_walk_ctx *ctx)
{
	int ret;

	/*
	 *     |----------------|	key_tmp
	 * |===========|		key
	 */
	cache_key_cutfront(key_tmp, cache_key_lend(key) - cache_key_lstart(key_tmp));
	if (key_tmp->len == 0) {
		cache_key_delete(key_tmp);  /* Delete the key if it becomes empty */
		ret = -EAGAIN;  /* Indicate that a reinsert is needed */

		/*
		 * Deleting key_tmp may change the structure of the
		 * entire cache tree, so we need to re-search the tree
		 * to determine the new insertion point for the key.
		 */
		goto out;
	}

	return 0;  /* Return success */
out:
	return ret;  /* Return error code */
}

/**
 * fixup_overlap_contain - Handle case where new key completely contains an existing key.
 * @key: Pointer to the new cache key being inserted.
 * @key_tmp: Pointer to the existing key that is being contained.
 * @ctx: Pointer to the context for walking the cache tree.
 *
 * This function deletes the existing key (key_tmp) when the new key
 * completely contains it. It returns -EAGAIN to indicate that the
 * tree structure may have changed, necessitating a re-insertion of
 * the new key.
 */
static int fixup_overlap_contain(struct cbd_cache_key *key,
				  struct cbd_cache_key *key_tmp,
				  struct cbd_cache_tree_walk_ctx *ctx)
{
	/*
	 *    |----|			key_tmp
	 * |==========|			key
	 */
	cache_key_delete(key_tmp);  /* Delete the contained key */

	return -EAGAIN;  /* Indicate that a re-insert is needed */
}

/**
 * fixup_overlap_contained - Handle overlap when a new key is contained in an existing key.
 * @key: The new cache key being inserted.
 * @key_tmp: The existing cache key that overlaps with the new key.
 * @ctx: Context for the cache tree walk.
 *
 * This function adjusts the existing key if the new key is contained
 * within it. If the existing key is empty, it indicates a placeholder key
 * that was inserted during a miss read. This placeholder will later be
 * updated with real data from the backend, making it no longer an empty key.
 *
 * If we delete key or insert a key, the structure of the entire cache tree may change,
 * requiring a full research of the tree to find a new insertion point.
 */
static int fixup_overlap_contained(struct cbd_cache_key *key,
	struct cbd_cache_key *key_tmp, struct cbd_cache_tree_walk_ctx *ctx)
{
	struct cbd_cache *cache = ctx->cache;
	int ret;

	/*
	 * |-----------|		key_tmp
	 *   |====|			key
	 */
	if (cache_key_empty(key_tmp)) {
		/* If key_tmp is empty, don't split it;
		 * it's a placeholder key for miss reads that will be updated later.
		 */
		cache_key_cutback(key_tmp, cache_key_lend(key_tmp) - cache_key_lstart(key));
		if (key_tmp->len == 0) {
			cache_key_delete(key_tmp);
			ret = -EAGAIN;  /* Need to research the tree after deletion */
			goto out;
		}
	} else {
		struct cbd_cache_key *key_fixup;
		bool need_research = false;

		/* Allocate a new cache key for splitting key_tmp */
		key_fixup = cache_key_alloc(cache);
		if (!key_fixup) {
			ret = -ENOMEM;
			goto out;
		}

		cache_key_copy(key_fixup, key_tmp);  /* Copy key_tmp to key_fixup for modifications */

		/* Split key_tmp based on the new key's range */
		cache_key_cutback(key_tmp, cache_key_lend(key_tmp) - cache_key_lstart(key));
		if (key_tmp->len == 0) {
			cache_key_delete(key_tmp);
			need_research = true;  /* Key deleted, need to research tree */
		}

		/* Create a new portion for key_fixup */
		cache_key_cutfront(key_fixup, cache_key_lend(key) - cache_key_lstart(key_tmp));
		if (key_fixup->len == 0) {
			cache_key_put(key_fixup);  /* If the new portion is empty, release it */
		} else {
			/* Insert the new key into the cache */
			ret = cache_key_insert(cache, key_fixup, false);
			if (ret)
				goto out;
			need_research = true;  /* Key inserted, may need to research */
		}

		if (need_research) {
			ret = -EAGAIN;  /* Need to research the tree */
			goto out;
		}
	}

	return 0;
out:
	return ret;
}

/**
 * fixup_overlap_head - Handle overlap when a new key overlaps with the head of an existing key.
 * @key: The new cache key being inserted.
 * @key_tmp: The existing cache key that overlaps with the new key.
 * @ctx: Context for the cache tree walk.
 *
 * This function adjusts the existing key if the new key overlaps
 * with the beginning of it. If the resulting key length is zero
 * after the adjustment, the key is deleted. This indicates that
 * the key no longer holds valid data and requires the tree to be
 * re-researched for a new insertion point.
 */
static int fixup_overlap_head(struct cbd_cache_key *key,
	struct cbd_cache_key *key_tmp, struct cbd_cache_tree_walk_ctx *ctx)
{
	/*
	 * |--------|		key_tmp
	 *   |==========|	key
	 */
	/* Adjust key_tmp by cutting back based on the new key's start */
	cache_key_cutback(key_tmp, cache_key_lend(key_tmp) - cache_key_lstart(key));
	if (key_tmp->len == 0) {
		/* If the adjusted key_tmp length is zero, delete it */
		cache_key_delete(key_tmp);
		return -EAGAIN;  /* Indicates that tree research is needed */
	}

	return 0;  /* Successful adjustment */
}

/**
 * cache_insert_fixup - Fix up overlaps when inserting a new key.
 * @cache: Pointer to the cache structure.
 * @key: The new cache key to insert.
 * @prev_node: The last visited node during the search.
 *
 * This function initializes a walking context and calls the
 * cache_tree_walk function to handle potential overlaps between
 * the new key and existing keys in the cache tree. Various
 * fixup functions are provided to manage different overlap scenarios.
 */
static int cache_insert_fixup(struct cbd_cache *cache,
	struct cbd_cache_key *key, struct rb_node *prev_node)
{
	struct cbd_cache_tree_walk_ctx walk_ctx = { 0 };  /* Initialize the walk context */

	/* Set up the context with the cache, start node, and new key */
	walk_ctx.cache = cache;
	walk_ctx.start_node = prev_node;
	walk_ctx.key = key;

	/* Assign overlap handling functions for different scenarios */
	walk_ctx.overlap_tail = fixup_overlap_tail;
	walk_ctx.overlap_head = fixup_overlap_head;
	walk_ctx.overlap_contain = fixup_overlap_contain;
	walk_ctx.overlap_contained = fixup_overlap_contained;

	/* Begin walking the cache tree to fix overlaps */
	return cache_tree_walk(cache, &walk_ctx);
}

/**
 * cache_key_insert - Insert a new cache key into the cache tree.
 * @cache: Pointer to the cache structure.
 * @key: The cache key to insert.
 * @new_key: Indicates if this is a new key being inserted.
 *
 * This function searches for the appropriate location to insert
 * a new cache key into the cache tree. It handles key overlaps
 * and ensures any invalid keys are removed before insertion.
 *
 * Returns 0 on success or a negative error code on failure.
 */
int cache_key_insert(struct cbd_cache *cache, struct cbd_cache_key *key,
	bool new_key)
{
	struct rb_node **new, *parent = NULL;  /* Pointers for the new node and parent */
	struct cbd_cache_tree *cache_tree;  /* Pointer to the cache tree */
	struct cbd_cache_key *key_tmp = NULL, *key_next;  /* Temporary keys for deletion */
	struct rb_node *prev_node = NULL;  /* Previous node during search */
	LIST_HEAD(delete_key_list);  /* List for keys marked for deletion */
	int ret;  /* Return value */

	cache_tree = get_cache_tree(cache, key->off);  /* Get the cache tree based on key offset */

	if (new_key)
		key->cache_tree = cache_tree;  /* Associate the key with the cache tree */

search:
	prev_node = cache_tree_search(cache_tree, key, &parent, &new, &delete_key_list);  /* Search for the position to insert */

	if (!list_empty(&delete_key_list)) {
		/* Remove invalid keys from the delete list */
		list_for_each_entry_safe(key_tmp, key_next, &delete_key_list, list_node) {
			list_del_init(&key_tmp->list_node);
			cache_key_delete(key_tmp);  /* Delete the invalid key */
		}
		goto search;  /* Restart search after deletions */
	}

	if (new_key) {
		ret = cache_insert_fixup(cache, key, prev_node);  /* Handle potential overlaps */
		if (ret == -EAGAIN)
			goto search;  /* Retry if cache tree was changed in fixup */
		if (ret)
			goto out;  /* Handle other errors */
	}

	/* Link and insert the new key into the red-black tree */
	rb_link_node(&key->rb_node, parent, new);
	rb_insert_color(&key->rb_node, &cache_tree->root);

	return 0;  /* Success */
out:
	return ret;  /* Return error code */
}

/**
 * clean_fn - Cleanup function to remove invalid keys from the cache tree.
 * @work: Pointer to the work_struct associated with the cleanup.
 *
 * This function cleans up invalid keys from the cache tree in the background
 * after a cache segment has been invalidated during cache garbage collection.
 * It processes a maximum of CBD_CLEAN_KEYS_MAX keys per iteration and holds
 * the tree lock to ensure thread safety.
 */
void clean_fn(struct work_struct *work)
{
	struct cbd_cache *cache = container_of(work, struct cbd_cache, clean_work);
	struct cbd_cache_tree *cache_tree;  /* Pointer to the cache tree */
	struct rb_node *node;  /* Current node in the red-black tree */
	struct cbd_cache_key *key;  /* Pointer to the cache key */
	int i, count;  /* Loop index and count of deleted keys */

	for (i = 0; i < cache->n_trees; i++) {
		cache_tree = &cache->cache_trees[i];  /* Access the current cache tree */

again:
		if (cache->state == cbd_cache_state_stopping)
			return;  /* Exit if cache is stopping */

		/* Delete up to CBD_CLEAN_KEYS_MAX keys in one iteration */
		count = 0;  /* Initialize deletion count */
		spin_lock(&cache_tree->tree_lock);  /* Acquire lock for thread safety */
		node = rb_first(&cache_tree->root);  /* Get the first node in the tree */
		while (node) {
			key = CACHE_KEY(node);  /* Get the cache key from the node */
			node = rb_next(node);  /* Move to the next node */
			if (cache_key_invalid(key)) {
				count++;  /* Increment count for each invalid key */
				cache_key_delete(key);  /* Delete the invalid key */
			}

			if (count >= CBD_CLEAN_KEYS_MAX) {
				/* Unlock and pause before continuing cleanup */
				spin_unlock(&cache_tree->tree_lock);
				usleep_range(1000, 2000);  /* Sleep for a short duration */
				goto again;  /* Restart cleanup process */
			}
		}
		spin_unlock(&cache_tree->tree_lock);  /* Release the lock */
	}
}

/*
 * kset_flush_fn - Flush work for a cache kset.
 *
 * This function is called when a kset flush work is queued from
 * cache_key_append(). If the kset is full, it will be closed
 * immediately. If not, the flush work will be queued for later closure.
 *
 * If cache_kset_close detects that a new segment is required to store
 * the kset and there are no available segments, it will return an error.
 * In this scenario, a retry will be attempted.
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
		/* Failed to flush kset, schedule a retry. */
		queue_delayed_work(cache->cache_wq, &kset->flush_work, 0);
	}
}

/*
 * kset_replay - Replay a kset from on-media structure.
 *
 * This function iterates over the keys in the provided kset_onmedia,
 * allocating and decoding each key. It checks for data integrity using
 * a CRC, and if the key's segment generation is valid, it inserts
 * the key into the cache. Keys with invalid CRCs or insufficient
 * segment generation are logged and discarded.
 *
 * Returns:
 * 0 on success, negative error code on failure.
 */
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
#ifdef CONFIG_CBD_CACHE_DATA_CRC
		/* Validate the key's data CRC against the calculated CRC. */
		if (key->data_crc != cache_key_data_crc(key)) {
			cbd_cache_debug(cache, "key: %llu:%u seg %u:%u data_crc error: %x, expected: %x\n",
					key->off, key->len, key->cache_pos.cache_seg->cache_seg_id,
					key->cache_pos.seg_off, cache_key_data_crc(key), key->data_crc);
			ret = -EIO;
			cache_key_put(key);
			goto err;
		}
#endif
		/* Mark the segment as used in the segment map. */
		set_bit(key->cache_pos.cache_seg->cache_seg_id, cache->seg_map);

		/* Check if the segment generation is valid for insertion. */
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

/*
 * cache_replay - Replay the cache from the on-media structure.
 *
 * This function begins replaying ksets from the cache until it
 * encounters a kset with an invalid magic number or CRC. It also
 * advances the cache position after each kset is replayed. The
 * last kset flag is checked to determine if further processing
 * is required.
 *
 * Returns:
 * 0 on success, negative error code on failure.
 */
int cache_replay(struct cbd_cache *cache)
{
	struct cbd_cache_pos pos_tail;
	struct cbd_cache_pos *pos;
	struct cbd_cache_kset_onmedia *kset_onmedia;
	int ret = 0;
	void *addr;

	cache_pos_copy(&pos_tail, &cache->key_tail);
	pos = &pos_tail;

	/* Mark the segment as used in the segment map. */
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

		/* Process the last kset and prepare for the next segment. */
		if (kset_onmedia->flags & CBD_KSET_FLAGS_LAST) {
			struct cbd_cache_segment *next_seg;

			cbd_cache_debug(cache, "last kset replay, next: %u\n", kset_onmedia->next_cache_seg_id);

			next_seg = &cache->segments[kset_onmedia->next_cache_seg_id];

			pos->cache_seg = next_seg;
			pos->seg_off = 0;

			set_bit(pos->cache_seg->cache_seg_id, cache->seg_map);
			continue;
		}

		/* Replay the kset and check for errors. */
		ret = kset_replay(cache, kset_onmedia);
		if (ret)
			goto out;

		/* Advance the position after processing the kset. */
		cache_pos_advance(pos, get_kset_onmedia_size(kset_onmedia));
	}

	/* Update the key_head position after replaying. */
	spin_lock(&cache->key_head_lock);
	cache_pos_copy(&cache->key_head, pos);
	spin_unlock(&cache->key_head_lock);

out:
	return ret;
}
