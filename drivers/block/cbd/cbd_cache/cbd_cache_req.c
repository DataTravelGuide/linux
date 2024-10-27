/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../cbd_internal.h"
#include "../cbd_transport.h"
#include "cbd_cache_internal.h"
#include "../cbd_queue.h"

static int cache_data_head_init(struct cbd_cache *cache, u32 i)
{
	struct cbd_cache_segment *next_seg;
	struct cbd_cache_data_head *data_head;

	data_head = get_data_head(cache, i);
	next_seg = get_cache_segment(cache);
	if (!next_seg)
		return -EBUSY;

	//cbd_cache_err(cache, "next_seg for data: %u\n", next_seg->cache_seg_id);
	cache_seg_get(next_seg);
	data_head->head_pos.cache_seg = next_seg;
	data_head->head_pos.seg_off = 0;

	return 0;
}

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
		cache_pos_advance(head_pos, to_alloc);
		allocated += to_alloc;
		cache_seg_get(cache_seg);
	} else if (seg_remain) {
		cache_pos_advance(head_pos, seg_remain);
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

static void cache_copy_from_req_bio(struct cbd_cache *cache, struct cbd_cache_key *key,
				struct cbd_request *cbd_req, u32 bio_off)
{
	struct cbd_cache_pos *pos = &key->cache_pos;
	struct cbd_segment *segment;

	segment = &pos->cache_seg->segment;

	//cbd_cache_err(cache, "copy_from_req_bio: %u:%u %u, bio_off: %u\n", pos->cache_seg->cache_seg_id, pos->seg_off, key->len, bio_off);
	cbds_copy_from_bio(segment, pos->seg_off, key->len, cbd_req->bio, bio_off);
}

static int cache_copy_to_req_bio(struct cbd_cache *cache, struct cbd_request *cbd_req,
			    u32 off, u32 len, struct cbd_cache_pos *pos, u64 key_gen)
{
	struct cbd_cache_segment *cache_seg = pos->cache_seg;
	struct cbd_segment *segment = &cache_seg->segment;

	//cbd_cache_err(cache, "copy_to_req_bio: %u:%u %u, bio_off: %u\n", pos->cache_seg->cache_seg_id, pos->seg_off, len, off);

	spin_lock(&cache_seg->gen_lock);
	if (key_gen < cache_seg->gen) {
		spin_unlock(&cache_seg->gen_lock);
		return -EINVAL;
	}

	spin_lock(&cbd_req->lock);
	cbds_copy_to_bio(segment, pos->seg_off, len, cbd_req->bio, off);
	spin_unlock(&cbd_req->lock);
	spin_unlock(&cache_seg->gen_lock);

	return 0;
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

/* cache miss: when a read miss happen on cbd_cache, it will submit a backing request
 * to read from backend, and when this backing request done, it will copy the data
 * read from backend into cache, then next user can read the same data immediately from
 * cache
 */
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

			ret = cache_data_alloc(cache, key, cbd_req->cbdq->index);
			if (ret) {
				cache_key_delete(key);
				goto unlock;
			}
			cache_copy_from_req_channel(cache, cbd_req, &key->cache_pos,
						    key->off - cbd_req->off, key->len);
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

void miss_read_end_work_fn(struct work_struct *work)
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

static void submit_backing_req(struct cbd_cache *cache, struct cbd_request *cbd_req)
{
	int ret;

	//cbd_cache_err(cache, "backend_req: %lu:%u\n", cbd_req->off, cbd_req->data_len);

	if (cbd_req->priv_data) {
		struct cbd_cache_key *key;

		key = (struct cbd_cache_key *)cbd_req->priv_data;
		ret = cache_insert_key(cache, key, true);
		if (ret) {
			cache_key_put(key);
			cbd_req->priv_data = NULL;
			goto out;
		}
	}

	ret = cbd_queue_req_to_backend(cbd_req);
out:
	cbd_req_put(cbd_req, ret);
}

static struct cbd_request *create_backing_req(struct cbd_cache *cache, struct cbd_request *parent,
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

		key->off = parent->off + off;
		key->len = len;
		key->flags |= CBD_CACHE_KEY_FLAGS_EMPTY;
	}

	new_req = kmem_cache_zalloc(cache->req_cache, GFP_NOWAIT);
	if (!new_req) {
		ret = -ENOMEM;
		goto delete_key;
	}

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

	cbd_req_get(parent);
	new_req->parent = parent;

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

/* cache tree walk for cache_read */
static int read_before(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
		struct cbd_cache_tree_walk_ctx *ctx)
{
	struct cbd_request *backing_req;
	int ret;


	backing_req = create_backing_req(ctx->cache, ctx->cbd_req, ctx->req_done, key->len, true);
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

static int read_overlap_tail(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
		struct cbd_cache_tree_walk_ctx *ctx)
{
	struct cbd_request *backing_req;
	u32 io_len;
	int ret;

	/*
	 *     |----------------|	key_tmp
	 * |===========|		key
	 */
	io_len = cache_key_lstart(key_tmp) - cache_key_lstart(key);
	if (io_len) {
		backing_req = create_backing_req(ctx->cache, ctx->cbd_req, ctx->req_done, io_len, true);
		if (!backing_req) {
			ret = -ENOMEM;
			goto out;
		}
		list_add(&backing_req->inflight_reqs_node, ctx->submit_req_list);

		ctx->req_done += io_len;
		cache_key_cutfront(key, io_len);
	}

	io_len = cache_key_lend(key) - cache_key_lstart(key_tmp);
	if (cache_key_empty(key_tmp)) {
		ret = send_backing_req(ctx->cache, ctx->cbd_req, ctx->req_done, io_len, false);
		if (ret)
			goto out;
	} else {
		ret = cache_copy_to_req_bio(ctx->cache, ctx->cbd_req, ctx->req_done,
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

static int read_overlap_contain(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
		struct cbd_cache_tree_walk_ctx *ctx)
{
	struct cbd_request *backing_req;
	u32 io_len;
	int ret;
	/*
	 *    |----|			key_tmp
	 * |==========|			key
	 */
	io_len = cache_key_lstart(key_tmp) - cache_key_lstart(key);
	if (io_len) {
		backing_req = create_backing_req(ctx->cache, ctx->cbd_req, ctx->req_done, io_len, true);
		if (!backing_req) {
			ret = -ENOMEM;
			goto out;
		}
		list_add(&backing_req->inflight_reqs_node, ctx->submit_req_list);

		ctx->req_done += io_len;
		cache_key_cutfront(key, io_len);
	}

	io_len = key_tmp->len;
	if (cache_key_empty(key_tmp)) {
		ret = send_backing_req(ctx->cache, ctx->cbd_req, ctx->req_done, io_len, false);
		if (ret)
			goto out;
	} else {
		ret = cache_copy_to_req_bio(ctx->cache, ctx->cbd_req, ctx->req_done,
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

static int read_overlap_contained(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
		struct cbd_cache_tree_walk_ctx *ctx)
{
	struct cbd_cache_pos pos;
	int ret;

	/*
	 * |-----------|		key_tmp
	 *   |====|			key
	 */
	if (cache_key_empty(key_tmp)) {
		ret = send_backing_req(ctx->cache, ctx->cbd_req, ctx->req_done, key->len, false);
		if (ret)
			goto out;
	} else {
		cache_pos_copy(&pos, &key_tmp->cache_pos);
		cache_pos_advance(&pos, cache_key_lstart(key) - cache_key_lstart(key_tmp));

		ret = cache_copy_to_req_bio(ctx->cache, ctx->cbd_req, ctx->req_done,
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

static int read_overlap_head(struct cbd_cache_key *key, struct cbd_cache_key *key_tmp,
		struct cbd_cache_tree_walk_ctx *ctx)
{
	struct cbd_cache_pos pos;
	u32 io_len;
	int ret;
	/*
	 * |--------|		key_tmp
	 *   |==========|	key
	 */
	io_len = cache_key_lend(key_tmp) - cache_key_lstart(key);

	if (cache_key_empty(key_tmp)) {
		ret = send_backing_req(ctx->cache, ctx->cbd_req, ctx->req_done, io_len, false);
		if (ret)
			goto out;
	} else {
		cache_pos_copy(&pos, &key_tmp->cache_pos);
		cache_pos_advance(&pos, cache_key_lstart(key) - cache_key_lstart(key_tmp));

		ret = cache_copy_to_req_bio(ctx->cache, ctx->cbd_req, ctx->req_done,
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

static int read_walk_finally(struct cbd_cache_tree_walk_ctx *ctx)
{
	struct cbd_request *backing_req, *next_req;
	struct cbd_cache_key *key = ctx->key;
	int ret;

	if (key->len) {
		ret = send_backing_req(ctx->cache, ctx->cbd_req, ctx->req_done, key->len, true);
		if (ret)
			goto out;
		ctx->req_done += key->len;
	}

	list_for_each_entry_safe(backing_req, next_req, ctx->submit_req_list, inflight_reqs_node) {
		list_del_init(&backing_req->inflight_reqs_node);
		submit_backing_req(ctx->cache, backing_req);
	}

	return 0;
out:
	return ret;
}
static bool read_walk_done(struct cbd_cache_tree_walk_ctx *ctx)
{
	return (ctx->req_done >= ctx->cbd_req->data_len);
}

static int cache_read(struct cbd_cache *cache, struct cbd_request *cbd_req)
{
	struct cbd_cache_key key_data = { .off = cbd_req->off, .len = cbd_req->data_len };
	struct cbd_cache_tree *cache_tree;
	struct cbd_cache_key *key_tmp = NULL, *key_next;
	struct rb_node *prev_node = NULL;
	struct cbd_cache_key *key = &key_data;
	struct cbd_cache_tree_walk_ctx walk_ctx = { 0 };
	LIST_HEAD(delete_key_list);
	LIST_HEAD(submit_req_list);
	int ret;

	walk_ctx.cache = cache;
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
	if (key->len > CBD_CACHE_TREE_SIZE - (key->off & CBD_CACHE_TREE_SIZE_MASK))
		key->len = CBD_CACHE_TREE_SIZE - (key->off & CBD_CACHE_TREE_SIZE_MASK);
	cache_tree = get_cache_tree(cache, key->off);
	spin_lock(&cache_tree->tree_lock);
search:
	prev_node = cache_tree_search(cache_tree, key, NULL, NULL, &delete_key_list);

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

	ret = cache_tree_walk(cache, &walk_ctx);
	if (ret == -EINVAL)
		goto cleanup_tree;
	else if (ret)
		goto out;

	spin_unlock(&cache_tree->tree_lock);

	if (walk_ctx.req_done < cbd_req->data_len)
		goto next_tree;

	return 0;
out:
	spin_unlock(&cache_tree->tree_lock);

	return ret;
}

/* cache write */
static int cache_write(struct cbd_cache *cache, struct cbd_request *cbd_req)
{
	struct cbd_cache_tree *cache_tree;
	struct cbd_cache_key *key;
	u64 offset = cbd_req->off;
	u32 length = cbd_req->data_len;
	u32 io_done = 0;
	int ret;

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

		//cbd_cache_err(cache, "data_alloc: %u:%u %u\n", key->cache_pos.cache_seg->cache_seg_id, key->cache_pos.seg_off, key->len);
		BUG_ON(!key->cache_pos.cache_seg);
		cache_copy_from_req_bio(cache, key, cbd_req, io_done);

		cache_tree = get_cache_tree(cache, key->off);
		spin_lock(&cache_tree->tree_lock);
		ret = cache_insert_key(cache, key, true);
		if (ret) {
			cache_seg_put(key->cache_pos.cache_seg);
			cache_key_put(key);
			goto unlock;
		}

		ret = cache_key_append(cache, key);
		if (ret) {
			//cbd_cache_err(cache, "append failed\n");
			cache_seg_put(key->cache_pos.cache_seg);
			cache_key_delete(key);
			goto unlock;
		}

		io_done += key->len;
		spin_unlock(&cache_tree->tree_lock);
	}

	return 0;
unlock:
	spin_unlock(&cache_tree->tree_lock);
err:
	return ret;
}

/* cache flush */
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

/* This function is the cache request entry */
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
