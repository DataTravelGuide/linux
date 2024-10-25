#include "../cbd_internal.h"
#include "cbd_cache_internal.h"

void cache_key_init(struct cbd_cache *cache, struct cbd_cache_key *key)
{
	kref_init(&key->ref);
	key->cache = cache;
	INIT_LIST_HEAD(&key->list_node);
	RB_CLEAR_NODE(&key->rb_node);
}

struct cbd_cache_key *cache_key_alloc(struct cbd_cache *cache)
{
	struct cbd_cache_key *key;

	key = kmem_cache_zalloc(cache->key_cache, GFP_NOWAIT);
	if (!key)
		return NULL;

	cache_key_init(cache, key);

	return key;
}

void cache_key_get(struct cbd_cache_key *key)
{
	kref_get(&key->ref);
}

static void cache_key_destroy(struct kref *ref)
{
	struct cbd_cache_key *key = container_of(ref, struct cbd_cache_key, ref);
	struct cbd_cache *cache = key->cache;

	kmem_cache_free(cache->key_cache, key);
}

void cache_key_put(struct cbd_cache_key *key)
{
	kref_put(&key->ref, cache_key_destroy);
}

void cache_pos_advance(struct cbd_cache_pos *pos, u32 len)
{
	/* currently, key for data is splitted into different cache_seg */
	BUG_ON(cache_seg_remain(pos) < len);

	pos->seg_off += len;
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

void cache_key_decode(struct cbd_cache_key_onmedia *key_onmedia, struct cbd_cache_key *key)
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

/* cache_kset */
static void append_last_kset(struct cbd_cache *cache, u32 next_seg)
{
	struct cbd_cache_kset_onmedia *kset_onmedia;

	kset_onmedia = get_key_head_addr(cache);
	kset_onmedia->flags |= CBD_KSET_FLAGS_LAST;
	kset_onmedia->next_cache_seg_id = next_seg;
	kset_onmedia->magic = CBD_KSET_MAGIC;
	kset_onmedia->crc = cache_kset_crc(kset_onmedia);
	cbd_cache_err(cache, "append last kset: flags: %llu %u/%u next: %u\n", kset_onmedia->flags, cache->key_head.cache_seg->cache_seg_id, cache->key_head.seg_off, next_seg);
	cache_pos_advance(&cache->key_head, sizeof(struct cbd_cache_kset_onmedia));
}
int cache_kset_close(struct cbd_cache *cache, struct cbd_cache_kset *kset)
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
	/* reserve a kset_onmedia for last kset */
	if (cache_seg_remain(&cache->key_head) < kset_onmedia_size + sizeof(struct cbd_cache_kset_onmedia)) {
		struct cbd_cache_segment *next_seg;

		next_seg = get_cache_segment(cache);
		if (!next_seg) {
			//cbd_cache_err(cache, "no segment for kset\n");
			ret = -EBUSY;
			goto out;
		}

		append_last_kset(cache, next_seg->cache_seg_id);

		cache->key_head.cache_seg = next_seg;
		cache->key_head.seg_off = 0;
		goto again;
	}

	kset_onmedia->magic = CBD_KSET_MAGIC;
	kset_onmedia->crc = cache_kset_crc(kset_onmedia);

	memcpy(get_key_head_addr(cache), kset_onmedia, kset_onmedia_size);
	cbdt_flush(cache->cbdt, get_key_head_addr(cache), kset_onmedia_size);
	//dax_flush(cache->cbdt->dax_dev, get_key_head_addr(cache), kset_onmedia_size);
	cbd_cache_err(cache, "flush kset: flags: %llu %u/%u size: %u\n", kset_onmedia->flags, cache->key_head.cache_seg->cache_seg_id, cache->key_head.seg_off, kset_onmedia_size);
	memset(kset_onmedia, 0, sizeof(struct cbd_cache_kset_onmedia));

	cache_pos_advance(&cache->key_head, kset_onmedia_size);

	ret = 0;
out:
	spin_unlock(&cache->key_head_lock);

	return ret;
}

/* append a cache_key into related kset, if this kset full, close this kset,
 * else queue a flush_work to do kset writting.
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
	//cbd_cache_err(cache, "key_num: %u\n", kset_onmedia->key_num);
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

/* cache_tree walk */
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
		 * |----------|
		 *		|=====|
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

		/* overlap */
		if (cache_key_lstart(key_tmp) >= cache_key_lstart(key)) {
			/*
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
		 * |--------|		key_tmp
		 *   |==========|	key
		 */
		if (ctx->overlap_head) {
			ret = ctx->overlap_head(key, key_tmp, ctx);
			if (ret)
				goto out;
		}
next:
		node_tmp = rb_next(node_tmp);
	}

	if (ctx->walk_finally) {
		ret = ctx->walk_finally(ctx);
		if (ret)
			goto out;
	}

	return 0;
out:
	return ret;
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
			ret = cache_insert_key(cache, key_fixup, false);
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

int cache_insert_key(struct cbd_cache *cache, struct cbd_cache_key *key, bool new_key)
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

int cache_replay(struct cbd_cache *cache)
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
	//pr_err("into replay : %u:%u\n", pos->cache_seg->cache_seg_id, pos->seg_off);

	set_bit(pos->cache_seg->cache_seg_id, cache->seg_map);

	while (true) {
		addr = cache_pos_addr(pos);

		kset_onmedia = (struct cbd_cache_kset_onmedia *)addr;
		if (kset_onmedia->magic != CBD_KSET_MAGIC ||
				kset_onmedia->crc != cache_kset_crc(kset_onmedia)) {
			pr_err("magic not expected, break;\n");
			break;
		}

		if (kset_onmedia->flags & CBD_KSET_FLAGS_LAST) {
			struct cbd_cache_segment *cur_seg, *next_seg;

			//cbd_cache_err(cache, "last kset\n");
			cur_seg = pos->cache_seg;
			next_seg = &cache->segments[kset_onmedia->next_cache_seg_id];
			pos->cache_seg = next_seg;
			pos->seg_off = 0;
			set_bit(pos->cache_seg->cache_seg_id, cache->seg_map);
			//cbd_cache_err(cache, "nest seg: %u:%u\n", pos->cache_seg->cache_seg_id, pos->seg_off);
			continue;
		}

		//pr_err("replay kset: %u:%u\n", pos->cache_seg->cache_seg_id, pos->seg_off);
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

			if (key->seg_gen < key->cache_pos.cache_seg->cache_seg_info.gen) {
				cache_key_put(key);
			} else {
				ret = cache_insert_key(cache, key, true);
				if (ret) {
					cache_key_put(key);
					goto out;
				}
			}

			cache_seg_get(key->cache_pos.cache_seg);
		}

		cache_pos_advance(pos, get_kset_onmedia_size(kset_onmedia));
		//cbd_cache_err(cache, "after advance: %u:%u\n", pos->cache_seg->cache_seg_id, pos->seg_off);
	}

#ifdef CONFIG_CBD_DEBUG
	dump_cache(cache);
#endif

	spin_lock(&cache->key_head_lock);
	cache_pos_copy(&cache->key_head, pos);
	//cache_seg_get(cache->key_head.cache_seg);
	//cbd_cache_err(cache, "after reply key_head: %u:%u\n", cache->key_head.cache_seg->cache_seg_id, cache->key_head.seg_off);
	spin_unlock(&cache->key_head_lock);

out:
	return ret;
}

