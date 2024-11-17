// SPDX-License-Identifier: GPL-2.0-or-later

#include "cbd_cache_internal.h"
#include "../cbd_queue.h"

static int cache_data_head_init(struct cbd_cache *cache, u32 head_index)
{
	struct cbd_cache_segment *next_seg;
	struct cbd_cache_data_head *data_head;

	data_head = get_data_head(cache, head_index);
	next_seg = get_cache_segment(cache);
	if (!next_seg)
		return -EBUSY;

	cache_seg_get(next_seg);
	data_head->head_pos.cache_seg = next_seg;
	data_head->head_pos.seg_off = 0;

	return 0;
}

/*
 * cache_data_alloc - Allocate data for a cache key.
 * @cache: Pointer to the cache structure.
 * @key: Pointer to the cache key to allocate data for.
 * @head_index: Index of the data head to use for allocation.
 *
 * This function tries to allocate space from the cache segment specified by the
 * data head. If the remaining space in the segment is insufficient to allocate
 * the requested length for the cache key, it will allocate whatever is available
 * and adjust the key's length accordingly. This function does not allocate
 * space that crosses segment boundaries.
 */
static int cache_data_alloc(struct cbd_cache *cache, struct cbd_cache_key *key, u32 head_index)
{
	struct cbd_cache_data_head *data_head;
	struct cbd_cache_pos *head_pos;
	struct cbd_cache_segment *cache_seg;
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
		key->seg_gen = key->cache_pos.cache_seg->gen;

		head_pos = &data_head->head_pos;
		cache_seg = head_pos->cache_seg;
		seg_remain = cache_seg_remain(head_pos);
		to_alloc = key->len - allocated;
	}

	if (seg_remain > to_alloc) {
		/* If remaining space in segment is sufficient for the cache key, allocate it. */
		cache_pos_advance(head_pos, to_alloc);
		allocated += to_alloc;
		cache_seg_get(cache_seg);
	} else if (seg_remain) {
		/* If remaining space is not enough, allocate the remaining space and adjust the cache key length. */
		cache_pos_advance(head_pos, seg_remain);
		key->len = seg_remain;

		/* Get for key: obtain a reference to the cache segment for the key. */
		cache_seg_get(cache_seg);
		/* Put for head_pos->cache_seg: release the reference for the current head's segment. */
		cache_seg_put(head_pos->cache_seg);
		head_pos->cache_seg = NULL;
	} else {
		/* Initialize a new data head if no segment is available. */
		ret = cache_data_head_init(cache, head_index);
		if (ret)
			goto out;

		goto again;
	}

out:
	spin_unlock(&data_head->data_head_lock);

	return ret;
}

static void cache_copy_from_req_bio(struct cbd_cache *cache, struct cbd_cache_key *key,
				struct cbd_request *cbd_req, u32 bio_off)
{
	struct cbd_cache_pos *pos = &key->cache_pos;
	struct cbd_segment *segment;

	segment = &pos->cache_seg->segment;

	cbds_copy_from_bio(segment, pos->seg_off, key->len, cbd_req->bio, bio_off);
}

static int cache_copy_to_req_bio(struct cbd_cache *cache, struct cbd_request *cbd_req,
			    u32 bio_off, u32 len, struct cbd_cache_pos *pos, u64 key_gen)
{
	struct cbd_cache_segment *cache_seg = pos->cache_seg;
	struct cbd_segment *segment = &cache_seg->segment;
	int ret;

	spin_lock(&cache_seg->gen_lock);
	if (key_gen < cache_seg->gen) {
		spin_unlock(&cache_seg->gen_lock);
		return -EINVAL;
	}

	spin_lock(&cbd_req->lock);
	ret = cbds_copy_to_bio(segment, pos->seg_off, len, cbd_req->bio, bio_off);
	spin_unlock(&cbd_req->lock);
	spin_unlock(&cache_seg->gen_lock);

	return ret;
}

static void cache_copy_from_req_channel(struct cbd_cache *cache, struct cbd_request *cbd_req,
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

/**
 * miss_read_end_req - Handle the end of a miss read request.
 * @cache: Pointer to the cache structure.
 * @cbd_req: Pointer to the request structure.
 *
 * This function is called when a backing request to read data from
 * the backend is completed. If the key associated with the request
 * is empty (a placeholder), it allocates cache space for the key,
 * copies the data read from the backend into the cache, and updates
 * the key's status. If the key has been overwritten by a write
 * request during this process, it will be deleted from the cache
 * tree and no further action will be taken.
 */
static void miss_read_end_req(struct cbd_cache *cache, struct cbd_request *cbd_req)
{
	void *priv_data = cbd_req->priv_data;
	int ret;

	if (priv_data) {
		struct cbd_cache_key *key;
		struct cbd_cache_subtree *cache_subtree;

		key = (struct cbd_cache_key *)priv_data;
		cache_subtree = key->cache_subtree;

		/* if this key was deleted from cache_subtree by a write, key->flags should be cleared,
		 * so if cache_key_empty() return true, this key is still in cache_subtree
		 */
		spin_lock(&cache_subtree->tree_lock);
		if (cache_key_empty(key)) {
			/* Check if the backing request was successful. */
			if (cbd_req->ret) {
				cache_key_delete(key);
				goto unlock;
			}

			/* Allocate cache space for the key and copy data from the backend. */
			ret = cache_data_alloc(cache, key, cbd_req->cbdq->index);
			if (ret) {
				cache_key_delete(key);
				goto unlock;
			}
			cache_copy_from_req_channel(cache, cbd_req, &key->cache_pos,
						    key->off - cbd_req->off, key->len);
			key->flags &= ~CBD_CACHE_KEY_FLAGS_EMPTY;
			key->flags |= CBD_CACHE_KEY_FLAGS_CLEAN;

			/* Append the key to the cache. */
			ret = cache_key_append(cache, key);
			if (ret) {
				cache_seg_put(key->cache_pos.cache_seg);
				cache_key_delete(key);
				goto unlock;
			}
		}
unlock:
		spin_unlock(&cache_subtree->tree_lock);
		cache_key_put(key);
	}

	cbd_queue_advance(cbd_req->cbdq, cbd_req);
	kmem_cache_free(cache->req_cache, cbd_req);
}

/**
 * miss_read_end_work_fn - Work function to handle the completion of cache miss reads
 * @work: Pointer to the work_struct associated with miss read handling
 *
 * This function processes requests that were placed on the miss read list
 * (`cache->miss_read_reqs`) to wait for data retrieval from the backend storage.
 * Once the data has been retrieved, the requests are handled to complete the
 * read operation.
 *
 * The function transfers the pending miss read requests to a temporary list to
 * process them without holding the spinlock, improving concurrency. It then
 * iterates over each request, removing it from the list and calling
 * `miss_read_end_req()` to finalize the read operation.
 */
void miss_read_end_work_fn(struct work_struct *work)
{
	struct cbd_cache *cache = container_of(work, struct cbd_cache, miss_read_end_work);
	struct cbd_request *cbd_req;
	LIST_HEAD(tmp_list);

	/* Lock and transfer miss read requests to temporary list */
	spin_lock(&cache->miss_read_reqs_lock);
	list_splice_init(&cache->miss_read_reqs, &tmp_list);
	spin_unlock(&cache->miss_read_reqs_lock);

	/* Process each request in the temporary list */
	while (!list_empty(&tmp_list)) {
		cbd_req = list_first_entry(&tmp_list,
					    struct cbd_request, inflight_reqs_node);
		list_del_init(&cbd_req->inflight_reqs_node);
		miss_read_end_req(cache, cbd_req);
	}
}

/**
 * cache_backing_req_end_req - Handle the end of a cache miss read request
 * @cbd_req: The cache request that has completed
 * @priv_data: Private data associated with the request (unused in this function)
 *
 * This function is called when a cache miss read request completes. The request
 * is added to the `miss_read_reqs` list, which stores pending miss read requests
 * to be processed later by `miss_read_end_work_fn`.
 *
 * After adding the request to the list, the function triggers the `miss_read_end_work`
 * workqueue to process the completed requests.
 */
static void cache_backing_req_end_req(struct cbd_request *cbd_req, void *priv_data)
{
	struct cbd_cache *cache = cbd_req->cbdq->cbd_blkdev->cbd_cache;

	/* Lock the miss read requests list and add the completed request */
	spin_lock(&cache->miss_read_reqs_lock);
	list_add_tail(&cbd_req->inflight_reqs_node, &cache->miss_read_reqs);
	spin_unlock(&cache->miss_read_reqs_lock);

	/* Queue work to process the miss read requests */
	queue_work(cache->cache_wq, &cache->miss_read_end_work);
}

/**
 * submit_backing_req - Submit a backend request when cache data is missing
 * @cache: The cache context that manages cache operations
 * @cbd_req: The cache request containing information about the read request
 *
 * This function is used to handle cases where a cache read request cannot locate
 * the required data in the cache. When such a miss occurs during `cache_subtree_walk`,
 * it triggers a backend read request to fetch data from the storage backend.
 *
 * If `cbd_req->priv_data` is set, it points to a `cbd_cache_key`, representing
 * a new cache key to be inserted into the cache. The function calls `cache_key_insert`
 * to attempt adding the key. On insertion failure, it releases the key reference and
 * clears `priv_data` to avoid further processing.
 *
 * After handling the potential cache key insertion, the request is queued to the
 * backend using `cbd_queue_req_to_backend`. Finally, `cbd_req_put` is called to
 * release the request resources with the result of the backend operation.
 */
static void submit_backing_req(struct cbd_cache *cache, struct cbd_request *cbd_req)
{
	int ret;

	if (cbd_req->priv_data) {
		struct cbd_cache_key *key;

		/* Attempt to insert the key into the cache if priv_data is set */
		key = (struct cbd_cache_key *)cbd_req->priv_data;
		ret = cache_key_insert(&cache->req_key_tree, key, true);
		if (ret) {
			/* Release the key if insertion fails */
			cache_key_put(key);
			cbd_req->priv_data = NULL;
			goto out;
		}
	}

	/* Queue the request to the backend for data retrieval */
	ret = cbd_queue_req_to_backend(cbd_req);
out:
	/* Release the cache request resources based on backend result */
	cbd_req_put(cbd_req, ret);
}

/**
 * create_backing_req - Create a backend read request for a cache miss
 * @cache: The cache structure that manages cache operations
 * @parent: The parent request structure initiating the miss read
 * @off: Offset in the parent request to read from
 * @len: Length of data to read from the backend
 * @insert_key: Determines whether to insert a placeholder empty key in the cache tree
 *
 * This function generates a new backend read request when a cache miss occurs. The
 * `insert_key` parameter controls whether a placeholder (empty) cache key should be
 * added to the cache tree to prevent multiple backend requests for the same missing
 * data. Generally, when the miss read occurs in a cache segment that doesn't contain
 * the requested data, a placeholder key is created and inserted.
 *
 * However, if the cache tree already has an empty key at the location for this
 * read, there is no need to create another. Instead, this function just send the
 * new request without adding a duplicate placeholder.
 *
 * Returns:
 * A pointer to the newly created request structure on success, or NULL on failure.
 * If an empty key is created, it will be released if any errors occur during the
 * process to ensure proper cleanup.
 */
static struct cbd_request *create_backing_req(struct cbd_cache *cache, struct cbd_request *parent,
					u32 off, u32 len, bool insert_key)
{
	struct cbd_request *new_req;
	struct cbd_cache_key *key = NULL;
	int ret;

	/* Allocate a new empty key if insert_key is set */
	if (insert_key) {
		key = cache_key_alloc(&cache->req_key_tree);
		if (!key) {
			ret = -ENOMEM;
			goto out;
		}

		/* Initialize the empty key with offset, length, and empty flag */
		key->off = parent->off + off;
		key->len = len;
		key->flags |= CBD_CACHE_KEY_FLAGS_EMPTY;
	}

	/* Allocate memory for the new backend request */
	new_req = kmem_cache_zalloc(cache->req_cache, GFP_NOWAIT);
	if (!new_req) {
		ret = -ENOMEM;
		goto delete_key;
	}

	/* Initialize the request structure */
	INIT_LIST_HEAD(&new_req->inflight_reqs_node);
	kref_init(&new_req->ref);
	spin_lock_init(&new_req->lock);

	new_req->cbdq = parent->cbdq;
	new_req->bio = parent->bio;
	new_req->off = parent->off + off;
	new_req->op = parent->op;
	new_req->bio_off = off;
	new_req->data_len = len;
	new_req->req = NULL;

	/* Reference the parent request */
	cbd_req_get(parent);
	new_req->parent = parent;

	/* Attach the empty key to the request if it was created */
	if (key) {
		cache_key_get(key);
		new_req->priv_data = key;
	}
	new_req->end_req = cache_backing_req_end_req;

	return new_req;

delete_key:
	if (key)
		cache_key_delete(key);
out:
	return NULL;
}

static int send_backing_req(struct cbd_cache *cache, struct cbd_request *cbd_req,
			    u32 off, u32 len, bool insert_key)
{
	struct cbd_request *new_req;

	new_req = create_backing_req(cache, cbd_req, off, len, insert_key);
	if (!new_req)
		return -ENOMEM;

	submit_backing_req(cache, new_req);

	return 0;
}

/*
 * In the process of walking the cache tree to locate cached data, this
 * function handles the situation where the requested data range lies
 * entirely before an existing cache node (`key_tmp`). This outcome
 * signifies that the target data is absent from the cache (cache miss).
 *
 * To fulfill this portion of the read request, the function creates a
 * backend request (`backing_req`) for the missing data range represented
 * by `key`. It then appends this request to the submission list in the
 * `ctx`, which will later be processed to retrieve the data from backend
 * storage. After setting up the backend request, `req_done` in `ctx` is
 * updated to reflect the length of the handled range, and the range
 * in `key` is adjusted by trimming off the portion that is now handled.
 *
 * The scenario handled here:
 *
 *	  |--------|			  key_tmp (existing cached range)
 * |====|					   key (requested range, preceding key_tmp)
 *
 * Since `key` is before `key_tmp`, it signifies that the requested data
 * range is missing in the cache (cache miss) and needs retrieval from
 * backend storage.
 */
static int read_before(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
		struct cbd_cache_subtree_walk_ctx *ctx)
{
	struct cbd_request *backing_req;
	int ret;

	/*
	 * In this scenario, `key` represents a range that precedes `key_tmp`,
	 * meaning the requested data range is missing from the cache tree
	 * and must be retrieved from the backend.
	 */
	backing_req = create_backing_req(ctx->cache_tree->cache, ctx->cbd_req, ctx->req_done, key->len, true);
	if (!backing_req) {
		ret = -ENOMEM;
		goto out;
	}

	list_add(&backing_req->inflight_reqs_node, ctx->submit_req_list);
	ctx->req_done += key->len;
	cache_key_cutfront(key, key->len);

	return 0;
out:
	return ret;
}

/*
 * During cache_subtree_walk, this function manages a scenario where part of the
 * requested data range overlaps with an existing cache node (`key_tmp`).
 *
 *	 |----------------|  key_tmp (existing cached range)
 * |===========|		   key (requested range, overlapping the tail of key_tmp)
 */
static int read_overlap_tail(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
		struct cbd_cache_subtree_walk_ctx *ctx)
{
	struct cbd_request *backing_req;
	u32 io_len;
	int ret;

	/*
	 * Calculate the length of the non-overlapping portion of `key`
	 * before `key_tmp`, representing the data missing in the cache.
	 */
	io_len = cache_key_lstart(key_tmp) - cache_key_lstart(key);
	if (io_len) {
		backing_req = create_backing_req(ctx->cache_tree->cache, ctx->cbd_req, ctx->req_done, io_len, true);
		if (!backing_req) {
			ret = -ENOMEM;
			goto out;
		}

		list_add(&backing_req->inflight_reqs_node, ctx->submit_req_list);
		ctx->req_done += io_len;
		cache_key_cutfront(key, io_len);
	}

	/*
	 * Handle the overlapping portion by calculating the length of
	 * the remaining data in `key` that coincides with `key_tmp`.
	 */
	io_len = cache_key_lend(key) - cache_key_lstart(key_tmp);
	if (cache_key_empty(key_tmp)) {
		ret = send_backing_req(ctx->cache_tree->cache, ctx->cbd_req, ctx->req_done, io_len, false);
		if (ret)
			goto out;
	} else {
		ret = cache_copy_to_req_bio(ctx->cache_tree->cache, ctx->cbd_req, ctx->req_done,
					io_len, &key_tmp->cache_pos, key_tmp->seg_gen);
		if (ret) {
			list_add(&key_tmp->list_node, ctx->delete_key_list);
			goto out;
		}
	}

	ctx->req_done += io_len;
	cache_key_cutfront(key, io_len);

	return 0;

out:
	return ret;
}

/**
 * The scenario handled here:
 *
 *    |----|          key_tmp (existing cached range)
 * |==========|       key (requested range)
 */
static int read_overlap_contain(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
		struct cbd_cache_subtree_walk_ctx *ctx)
{
	struct cbd_request *backing_req;
	u32 io_len;
	int ret;

	/*
	 * Calculate the non-overlapping part of `key` before `key_tmp`
	 * to identify the missing data length.
	 */
	io_len = cache_key_lstart(key_tmp) - cache_key_lstart(key);
	if (io_len) {
		backing_req = create_backing_req(ctx->cache_tree->cache, ctx->cbd_req, ctx->req_done, io_len, true);
		if (!backing_req) {
			ret = -ENOMEM;
			goto out;
		}
		list_add(&backing_req->inflight_reqs_node, ctx->submit_req_list);

		ctx->req_done += io_len;
		cache_key_cutfront(key, io_len);
	}

	/*
	 * Handle the overlapping portion between `key` and `key_tmp`.
	 */
	io_len = key_tmp->len;
	if (cache_key_empty(key_tmp)) {
		ret = send_backing_req(ctx->cache_tree->cache, ctx->cbd_req, ctx->req_done, io_len, false);
		if (ret)
			goto out;
	} else {
		ret = cache_copy_to_req_bio(ctx->cache_tree->cache, ctx->cbd_req, ctx->req_done,
					io_len, &key_tmp->cache_pos, key_tmp->seg_gen);
		if (ret) {
			list_add(&key_tmp->list_node, ctx->delete_key_list);
			goto out;
		}
	}

	ctx->req_done += io_len;
	cache_key_cutfront(key, io_len);

	return 0;
out:
	return ret;
}

/*
 *	 |-----------|		key_tmp (existing cached range)
 *	   |====|			key (requested range, fully within key_tmp)
 *
 * If `key_tmp` contains valid cached data, this function copies the relevant
 * portion to the request's bio. Otherwise, it sends a backend request to
 * fetch the required data range.
 */
static int read_overlap_contained(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
		struct cbd_cache_subtree_walk_ctx *ctx)
{
	struct cbd_cache_pos pos;
	int ret;

	/*
	 * Check if `key_tmp` is empty, indicating a miss. If so, initiate
	 * a backend request to fetch the required data for `key`.
	 */
	if (cache_key_empty(key_tmp)) {
		ret = send_backing_req(ctx->cache_tree->cache, ctx->cbd_req, ctx->req_done, key->len, false);
		if (ret)
			goto out;
	} else {
		cache_pos_copy(&pos, &key_tmp->cache_pos);
		cache_pos_advance(&pos, cache_key_lstart(key) - cache_key_lstart(key_tmp));

		ret = cache_copy_to_req_bio(ctx->cache_tree->cache, ctx->cbd_req, ctx->req_done,
					key->len, &pos, key_tmp->seg_gen);
		if (ret) {
			list_add(&key_tmp->list_node, ctx->delete_key_list);
			goto out;
		}
	}

	ctx->req_done += key->len;
	cache_key_cutfront(key, key->len);

	return 0;
out:
	return ret;
}

/*
 *	 |--------|		  key_tmp (existing cached range)
 *	   |==========|	  key (requested range, overlapping the head of key_tmp)
 */
static int read_overlap_head(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
		struct cbd_cache_subtree_walk_ctx *ctx)
{
	struct cbd_cache_pos pos;
	u32 io_len;
	int ret;

	io_len = cache_key_lend(key_tmp) - cache_key_lstart(key);

	if (cache_key_empty(key_tmp)) {
		ret = send_backing_req(ctx->cache_tree->cache, ctx->cbd_req, ctx->req_done, io_len, false);
		if (ret)
			goto out;
	} else {
		cache_pos_copy(&pos, &key_tmp->cache_pos);
		cache_pos_advance(&pos, cache_key_lstart(key) - cache_key_lstart(key_tmp));

		ret = cache_copy_to_req_bio(ctx->cache_tree->cache, ctx->cbd_req, ctx->req_done,
					io_len, &pos, key_tmp->seg_gen);
		if (ret) {
			list_add(&key_tmp->list_node, ctx->delete_key_list);
			goto out;
		}
	}

	ctx->req_done += io_len;
	cache_key_cutfront(key, io_len);

	return 0;
out:
	return ret;
}

/*
 * read_walk_finally - Finalizes the cache read tree walk by submitting any
 *					 remaining backend requests
 * @ctx:	   Context structure holding information about the cache,
 *			 read request, and submission list
 *
 * This function is called at the end of the `cache_subtree_walk` during a
 * cache read operation. It completes the walk by checking if any data
 * requested by `key` was not found in the cache tree, and if so, it sends
 * a backend request to retrieve that data. Then, it iterates through the
 * submission list of backend requests created during the walk, removing
 * each request from the list and submitting it.
 *
 * The scenario managed here includes:
 * - Sending a backend request for the remaining length of `key` if it was
 *   not fulfilled by existing cache entries.
 * - Iterating through `ctx->submit_req_list` to submit each backend request
 *   enqueued during the walk.
 *
 * This ensures all necessary backend requests for cache misses are submitted
 * to the backend storage to retrieve any data that could not be found in
 * the cache.
 */
static int read_walk_finally(struct cbd_cache_subtree_walk_ctx *ctx)
{
	struct cbd_request *backing_req, *next_req;
	struct cbd_cache_key *key = ctx->key;
	int ret;

	if (key->len) {
		ret = send_backing_req(ctx->cache_tree->cache, ctx->cbd_req, ctx->req_done, key->len, true);
		if (ret)
			goto out;
		ctx->req_done += key->len;
	}

	list_for_each_entry_safe(backing_req, next_req, ctx->submit_req_list, inflight_reqs_node) {
		list_del_init(&backing_req->inflight_reqs_node);
		submit_backing_req(ctx->cache_tree->cache, backing_req);
	}

	return 0;

out:
	return ret;
}

/*
 * This function is used within `cache_subtree_walk` to determine whether the
 * read operation has covered the requested data length. It compares the
 * amount of data processed (`ctx->req_done`) with the total data length
 * specified in the original request (`ctx->cbd_req->data_len`).
 *
 * If `req_done` meets or exceeds the required data length, the function
 * returns `true`, indicating the walk is complete. Otherwise, it returns `false`,
 * signaling that additional data processing is needed to fulfill the request.
 */
static bool read_walk_done(struct cbd_cache_subtree_walk_ctx *ctx)
{
	return (ctx->req_done >= ctx->cbd_req->data_len);
}

/*
 * cache_read - Process a read request by traversing the cache tree
 * @cache:	 Cache structure holding cache trees and related configurations
 * @cbd_req:   Request structure with information about the data to read
 *
 * This function attempts to fulfill a read request by traversing the cache tree(s)
 * to locate cached data for the requested range. If parts of the data are missing
 * in the cache, backend requests are generated to retrieve the required segments.
 *
 * The function operates by initializing a key for the requested data range and
 * preparing a context (`walk_ctx`) to manage the cache tree traversal. The context
 * includes pointers to functions (e.g., `read_before`, `read_overlap_tail`) that handle
 * specific conditions encountered during the traversal. The `walk_finally` and `walk_done`
 * functions manage the end stages of the traversal, while the `delete_key_list` and
 * `submit_req_list` lists track any keys to be deleted or requests to be submitted.
 *
 * The function first calculates the requested range and checks if it fits within the
 * current cache tree (based on the tree's size limits). It then locks the cache tree
 * and performs a search to locate any matching keys. If there are outdated keys,
 * these are deleted, and the search is restarted to ensure accurate data retrieval.
 *
 * If the requested range spans multiple cache trees, the function moves on to the
 * next tree once the current range has been processed. This continues until the
 * entire requested data length has been handled.
 */
static int cache_read(struct cbd_cache *cache, struct cbd_request *cbd_req)
{
	struct cbd_cache_key key_data = { .off = cbd_req->off, .len = cbd_req->data_len };
	struct cbd_cache_subtree *cache_subtree;
	struct cbd_cache_key *key_tmp = NULL, *key_next;
	struct rb_node *prev_node = NULL;
	struct cbd_cache_key *key = &key_data;
	struct cbd_cache_subtree_walk_ctx walk_ctx = { 0 };
	LIST_HEAD(delete_key_list);
	LIST_HEAD(submit_req_list);
	int ret;

	walk_ctx.cache_tree = &cache->req_key_tree;
	walk_ctx.req_done = 0;
	walk_ctx.cbd_req = cbd_req;
	walk_ctx.before = read_before;
	walk_ctx.overlap_tail = read_overlap_tail;
	walk_ctx.overlap_head = read_overlap_head;
	walk_ctx.overlap_contain = read_overlap_contain;
	walk_ctx.overlap_contained = read_overlap_contained;
	walk_ctx.walk_finally = read_walk_finally;
	walk_ctx.walk_done = read_walk_done;
	walk_ctx.delete_key_list = &delete_key_list;
	walk_ctx.submit_req_list = &submit_req_list;

next_tree:
	key->off = cbd_req->off + walk_ctx.req_done;
	key->len = cbd_req->data_len - walk_ctx.req_done;
	if (key->len > CBD_CACHE_SUBTREE_SIZE - (key->off & CBD_CACHE_SUBTREE_SIZE_MASK))
		key->len = CBD_CACHE_SUBTREE_SIZE - (key->off & CBD_CACHE_SUBTREE_SIZE_MASK);

	cache_subtree = get_subtree(&cache->req_key_tree, key->off);
	spin_lock(&cache_subtree->tree_lock);

search:
	prev_node = cache_subtree_search(cache_subtree, key, NULL, NULL, &delete_key_list);

cleanup_tree:
	if (!list_empty(&delete_key_list)) {
		list_for_each_entry_safe(key_tmp, key_next, &delete_key_list, list_node) {
			list_del_init(&key_tmp->list_node);
			cache_key_delete(key_tmp);
		}
		goto search;
	}

	walk_ctx.start_node = prev_node;
	walk_ctx.key = key;

	ret = cache_subtree_walk(&walk_ctx);
	if (ret == -EINVAL)
		goto cleanup_tree;
	else if (ret)
		goto out;

	spin_unlock(&cache_subtree->tree_lock);

	if (walk_ctx.req_done < cbd_req->data_len)
		goto next_tree;

	return 0;
out:
	spin_unlock(&cache_subtree->tree_lock);

	return ret;
}

static int cache_write(struct cbd_cache *cache, struct cbd_request *cbd_req)
{
	struct cbd_cache_subtree *cache_subtree;
	struct cbd_cache_key *key;
	u64 offset = cbd_req->off;
	u32 length = cbd_req->data_len;
	u32 io_done = 0;
	int ret;

	while (true) {
		if (io_done >= length)
			break;

		key = cache_key_alloc(&cache->req_key_tree);
		if (!key) {
			ret = -ENOMEM;
			goto err;
		}

		key->off = offset + io_done;
		key->len = length - io_done;
		if (key->len > CBD_CACHE_SUBTREE_SIZE - (key->off & CBD_CACHE_SUBTREE_SIZE_MASK))
			key->len = CBD_CACHE_SUBTREE_SIZE - (key->off & CBD_CACHE_SUBTREE_SIZE_MASK);

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

		cache_copy_from_req_bio(cache, key, cbd_req, io_done);

		cache_subtree = get_subtree(&cache->req_key_tree, key->off);
		spin_lock(&cache_subtree->tree_lock);
		ret = cache_key_insert(&cache->req_key_tree, key, true);
		if (ret) {
			cache_seg_put(key->cache_pos.cache_seg);
			cache_key_put(key);
			goto unlock;
		}

		ret = cache_key_append(cache, key);
		if (ret) {
			cache_seg_put(key->cache_pos.cache_seg);
			cache_key_delete(key);
			goto unlock;
		}

		io_done += key->len;
		spin_unlock(&cache_subtree->tree_lock);
	}

	return 0;
unlock:
	spin_unlock(&cache_subtree->tree_lock);
err:
	return ret;
}

/**
 * cache_flush - Flush all ksets to persist any pending cache data
 * @cache: Pointer to the cache structure
 *
 * This function iterates through all ksets associated with the provided `cache`
 * and ensures that any data marked for persistence is written to media. For each
 * kset, it acquires the kset lock, then invokes `cache_kset_close`, which handles
 * the persistence logic for that kset.
 *
 * If `cache_kset_close` encounters an error, the function exits immediately with
 * the respective error code, preventing the flush operation from proceeding to
 * subsequent ksets.
 */
int cache_flush(struct cbd_cache *cache)
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

/**
 * cbd_cache_handle_req - Entry point for handling cache requests
 * @cache: Pointer to the cache structure
 * @cbd_req: Pointer to the request structure containing operation and data details
 *
 * This function serves as the main entry for cache operations, directing
 * requests based on their operation type. Depending on the operation (`op`)
 * specified in `cbd_req`, the function calls the appropriate helper function
 * to process the request.
 */
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
