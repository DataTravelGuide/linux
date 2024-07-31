#include "cbd_internal.h"

static struct cache_key {
	struct cbd_cache *cache;
	struct kref ref;

	struct rb_node rb_node;

	u64		off;
	u32		len;

	struct cbd_cache_pos	cache_pos;

	u64		flags;
	u64		seg_gen;
};

static struct cache_key_onmedia {
	u64	off;
	u32	len;

	u32	cache_seg_id;
	u32	cache_seg_off;

	u64	seg_gen;
#ifdef CBD_CRC
	u32	data_crc;
#endif
};

#define CBD_KSET_FLAGS_LAST	1

static struct cache_key_set {
	u64	crc;
	u64	magic;
	u16	version;
	u16	res;
	u32	key_epoch;
	u64	flags;
	u32	key_num;
	u32	latest_seg_id;
	struct cache_key_onmedia	data[];
};

#define CBD_KSET_MAGIC		0x676894a64e164f1aULL

static inline void *cache_pos_addr(struct cbd_cache_pos *pos);
static inline struct cache_key_set *get_cur_kset(struct cbd_cache *cache)
{
	return (struct cache_key_set *)cache_pos_addr(&cache->key_head);
}

static void cbd_cache_seg_sanitize_pos(struct cbd_seg_pos *pos)
{
	struct cbd_segment *segment;
	struct cbd_cache_segment *cache_seg;

again:
	segment = pos->segment;
	cache_seg = container_of(segment, struct cbd_cache_segment, segment);
	if (pos->off >= segment->data_size) {
		//pr_err("sanitize next segment, pos off: %u, data_size: %u\n", pos->off, segment->data_size);
		pos->off -= segment->data_size;
		//pr_err("cacheseg: %p ", cache_seg);
		cache_seg = cache_seg->next;
		//pr_err("next is %p, %u", cache_seg->segment.data, cache_seg->cache_seg_id);
		pos->segment = &cache_seg->segment;
		goto again;
	}
}

static struct cbd_seg_ops cbd_cache_seg_ops = {
	.sanitize_pos = cbd_cache_seg_sanitize_pos
};

static struct cbd_cache_segment *get_cache_segment(struct cbd_cache *cache)
{
	struct cbd_cache_segment *cache_seg;
	u32 seg_id;
again:
	spin_lock(&cache->seg_map_lock);
	seg_id = find_next_zero_bit(cache->seg_map, cache->n_segs, 0);
	if (seg_id == cache->n_segs) {
		spin_unlock(&cache->seg_map_lock);
		//pr_err("no seg avaialbe.");
		msleep(100);
		goto again;
	}

	set_bit(seg_id, cache->seg_map);
	spin_unlock(&cache->seg_map_lock);
;
	cache_seg = &cache->segments[seg_id];
	cache_seg->cache_seg_id = seg_id;

	//pr_err("clear all data for segid: %u segment_data: %p, %u", seg_id, cache_seg->segment.data, cache_seg->segment.data_size);
	cbdt_zero_range(cache->cbdt, cache_seg->segment.data, cache_seg->segment.data_size);

	return cache_seg;
}

static void seg_used_add(struct cbd_cache *cache, struct cache_key *key)
{
	struct cbd_cache_segment *cache_seg = key->cache_pos.cache_seg;

	if (!test_bit(cache_seg->cache_seg_id, cache->seg_map))
		set_bit(cache_seg->cache_seg_id, cache->seg_map);
}

#define CACHE_KEY(node)		(container_of(node, struct cache_key, rb_node))

static inline void cache_key_delete(struct cache_key *key);
static void clear_keys(struct cbd_cache *cache)
{
	struct cache_key *key;
	struct rb_node *node, *next;

	node = rb_first(&cache->cache_tree);
	for (node = rb_first(&cache->cache_tree); node; node = next) {
		key = CACHE_KEY(node);
		next = rb_next(node);

		if (key->seg_gen < key->cache_pos.cache_seg->gen)
			cache_key_delete(key);
	}
}

static bool cache_pos_is_seg_end(struct cbd_cache_pos *pos)
{
	return pos->seg_off == pos->cache_seg->segment.data_size;
}

static void dump_cache(struct cbd_cache *cache);
static void cache_pos_copy(struct cbd_cache_pos *dst, struct cbd_cache_pos *src);
static void cache_pos_advance(struct cbd_cache_pos *pos, u32 len, bool set);
static void seg_used_remove(struct cbd_cache *cache, struct cache_key *key)
{
	struct cbd_cache_segment *cache_seg = key->cache_pos.cache_seg;
	struct cbd_cache_pos pos_data;
	struct cbd_cache_pos *pos;
	bool invalidate = false;

	cache_pos_copy(&pos_data, &key->cache_pos);
	pos = &pos_data;

	cache_pos_advance(pos, key->len, false);
	if (pos->cache_seg != cache_seg || cache_pos_is_seg_end(pos))
		invalidate = true;

	if (invalidate) {
		mutex_lock(&cache->io_lock);
		pr_err("gc invalidat seg: %u, key: %lu:%u cache_pos: %lu:%u\n", cache_seg->cache_seg_id, key->off, key->len, key->cache_pos.seg_off, key->len);
		cache_seg->gen++;
		pr_err("cache_seg: %u, gen: %u\n", cache_seg->cache_seg_id, cache_seg->gen);
		/* TODO better way to remove key */
		clear_keys(cache);
		dump_cache(cache);
		clear_bit(cache_seg->cache_seg_id, cache->seg_map);
		mutex_unlock(&cache->io_lock);
	}
}


static int cache_data_head_init(struct cbd_cache *cache)
{
	cache->data_head.cache_seg = get_cache_segment(cache);
	cache->data_head.seg_off = 0;

	return 0;
}

static inline void *cache_pos_addr(struct cbd_cache_pos *pos)
{
	return (pos->cache_seg->segment.data + pos->seg_off);
}

static struct cache_key *cache_key_alloc(struct cbd_cache *cache)
{
	struct cache_key *key;

	key = kmem_cache_zalloc(cache->key_cache, GFP_NOIO);
	if (!key)
		return NULL;

	kref_init(&key->ref);
	key->cache = cache;

	return key;
}

static void cache_key_destroy(struct kref *ref)
{
	struct cache_key *key = container_of(ref, struct cache_key, ref);
	struct cbd_cache *cache = key->cache;

	kmem_cache_free(cache->key_cache, key);
}

static void cache_key_put(struct cache_key *key)
{
	kref_put(&key->ref, cache_key_destroy);
}

static void cache_copy_from_bio(struct cbd_cache *cache, struct cache_key *key, struct bio *bio)
{
	struct cbd_cache_pos *pos = &key->cache_pos;
	struct cbd_segment *segment;
	
	segment = &pos->cache_seg->segment;
	//pr_err("copy_from_bio key->off: %lu to segment: %p, seg_off: %u len: %u\n", key->off, segment, pos->seg_off, key->len);
	cbds_copy_from_bio(segment, pos->seg_off, key->len, bio, 0);
}

static inline u64 cache_key_lstart(struct cache_key *key)
{
	return key->off;
}

static inline u64 cache_key_lend(struct cache_key *key)
{
	return key->off + key->len;
}

static inline void cache_key_copy(struct cache_key *key_dst, struct cache_key *key_src)
{
	key_dst->off = key_src->off;
	key_dst->len = key_src->len;

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
	//pr_err("advance pos: %p, len: %u", pos, len);
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
		pos->cache_seg = cache_seg->next;
		BUG_ON(!pos->cache_seg);
		pos->seg_off = 0;
		if (set)
			set_bit(pos->cache_seg->cache_seg_id, pos->cache_seg->cache->seg_map);
	}

	if (advanced < len)
		goto again;
}

static inline void cache_key_cutfront(struct cache_key *key, u32 cut_len)
{
	if (key->cache_pos.cache_seg) {
		////pr_err("cutfront: %p\n", &key->cache_pos);
		cache_pos_advance(&key->cache_pos, cut_len, false);
	}
	key->off += cut_len;
	key->len -= cut_len;
}

static inline void cache_key_cutback(struct cache_key *key, u32 cut_len)
{
	key->len -= cut_len;
}

static inline void cache_key_delete(struct cache_key *key)
{
	rb_erase(&key->rb_node, &key->cache->cache_tree);
	////pr_err("delete key");
	cache_key_put(key);
}

static void dump_cache(struct cbd_cache *cache)
{
	struct cache_key *key;
	struct rb_node *node;

	pr_err("=====start dump");
	node = rb_first(&cache->cache_tree);
	while (node) {
		key = CACHE_KEY(node);
		pr_err("key: %p gen: %u key->off: %llu, len: %u, cache: %p segid: %u\n", key, key->seg_gen, key->off, key->len, cache_pos_addr(&key->cache_pos), key->cache_pos.cache_seg->cache_seg_id);
		node = rb_next(node);
	}
	pr_err("=====end dump");
}

static void cache_key_encode(struct cache_key_onmedia *key_onmedia,
			     struct cache_key *key)
{
	key_onmedia->off = key->off;
	key_onmedia->len = key->len;

	key_onmedia->cache_seg_id = key->cache_pos.cache_seg->cache_seg_id;
	key_onmedia->cache_seg_off = key->cache_pos.seg_off;

	key_onmedia->seg_gen = key->seg_gen;

#ifdef CBD_CRC
	/* TODO */
	key_onmedia->data_crc = 0;
#endif
}

static void cache_key_decode(struct cache_key_onmedia *key_onmedia, struct cache_key *key)
{
	struct cbd_cache *cache = key->cache;

	key->off = key_onmedia->off;
	key->len = key_onmedia->len;

	key->cache_pos.cache_seg = &cache->segments[key_onmedia->cache_seg_id];
	key->cache_pos.seg_off = key_onmedia->cache_seg_off;

	key->seg_gen = key_onmedia->seg_gen;
}

static inline u32 cache_kset_crc(struct cache_key_set *kset)
{
	return crc32(0, (void *)kset + 4, struct_size(kset, data, kset->key_num) - 4);
}

#define CBD_KSET_KEYS_MAX	1

static void kset_head_close(struct cbd_cache *cache)
{
	struct cache_key_set *kset;
	struct cbd_cache_pos *pos;
	struct cbd_cache_segment *cache_seg;
	struct cbd_segment *segment;
	u32 seg_remain;

	kset = get_cur_kset(cache);
	kset->magic = CBD_KSET_MAGIC;
	kset->crc = cache_kset_crc(kset);
//	//pr_err("close kset: %p, magic: %lx, crc: %u\n", kset, kset->magic, kset->crc);

	pos = &cache->key_head;
	cache_pos_advance(pos, struct_size(kset, data, kset->key_num), false);

	cache_seg = pos->cache_seg;
	segment = &cache_seg->segment;
	seg_remain = segment->data_size - pos->seg_off;
	if (seg_remain < struct_size(kset, data, CBD_KSET_KEYS_MAX)) {
		kset->flags |= CBD_KSET_FLAGS_LAST;
		cache->key_head.cache_seg = get_cache_segment(cache);
		cache->key_head.seg_off = 0;
		cache_seg->next = cache->key_head.cache_seg;
		cache_seg->cache_seg_info->next_cache_seg_id = cache_seg->next->cache_seg_id;
		cache_seg->cache_seg_info->flags |= CBD_CACHE_SEG_FLAGS_HAS_NEXT;
	}
}

static void cache_key_append(struct cbd_cache *cache, struct cache_key *key)
{
	struct cache_key_set *kset;
	struct cache_key_onmedia *key_onmedia;

	kset = get_cur_kset(cache);
	key_onmedia = &kset->data[kset->key_num];
	cache_key_encode(key_onmedia, key);
	if (key_onmedia->cache_seg_id != kset->latest_seg_id)
		kset->latest_seg_id = key_onmedia->cache_seg_id;

	////pr_err("key_num: %u", kset->key_num);
	if (++kset->key_num >= CBD_KSET_KEYS_MAX) {
		kset_head_close(cache);
	}
}

static int cache_insert_key(struct cbd_cache *cache, struct cache_key *key, bool fixup);
static int cache_insert_fixup(struct cbd_cache *cache, struct cache_key *key, struct rb_node *prev_node)
{
	struct rb_node *node_tmp;
	struct cache_key *key_tmp;
	int ret;

	if (!prev_node)
		return 0;

	////pr_err("start fixup: current: %llu", current->pid);
	node_tmp = prev_node;
	while (node_tmp) {
		key_tmp = CACHE_KEY(node_tmp);
		////pr_err("key_tmp: %llu:%u, key: %llu:%u", cache_key_lstart(key_tmp), key_tmp->len,
				//cache_key_lstart(key), key->len);
		/*
		 * |----------|
		 *		|=====|
		 * */
		if (cache_key_lend(key_tmp) <= cache_key_lstart(key)) {
			goto next;
		}

		/*
		 *	  |--------|
		 * |====|
		 */
		if (cache_key_lstart(key_tmp) >= cache_key_lend(key)) {
			break;
		}

		/* overlap */
		if (cache_key_lstart(key_tmp) >= cache_key_lstart(key)) {
			/*
			 *     |----------------|	key_tmp
			 * |===========|		key
			 */
			if (cache_key_lend(key_tmp) >= cache_key_lend(key)) {
				////pr_err("before cutfront");
				cache_key_cutfront(key_tmp, cache_key_lend(key) - cache_key_lstart(key_tmp));
				if (key_tmp->len == 0) {
					////pr_err("delete key_tmp\n");
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
			struct cache_key *key_fixup;

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

static int cache_insert_key(struct cbd_cache *cache, struct cache_key *key, bool fixup)
{
  	struct rb_node **new = &(cache->cache_tree.rb_node), *parent = NULL;
	struct cache_key *key_tmp = NULL;
	struct rb_node	*prev_node = NULL;
	int ret;

	if (fixup)
		seg_used_add(cache, key);
again:
	new = &(cache->cache_tree.rb_node);
	parent = NULL;
	key_tmp = NULL;
	prev_node = NULL;
  	while (*new) {
  		key_tmp = container_of(*new, struct cache_key, rb_node);
		BUG_ON(key_tmp->seg_gen < key_tmp->cache_pos.cache_seg->gen);

		parent = *new;
		if (key_tmp->off >= key->off) {
  			new = &((*new)->rb_left);
		} else {
			prev_node = *new;
  			new = &((*new)->rb_right);
		}
  	}

	if (!prev_node)
		prev_node = rb_first(&cache->cache_tree);

	if (fixup) {
		ret = cache_insert_fixup(cache, key, prev_node);
		////pr_err("after fixup\n");
		if (ret == -EAGAIN)
			goto again;
		else if (ret)
			goto err;
	}

  	rb_link_node(&key->rb_node, parent, new);
  	rb_insert_color(&key->rb_node, &cache->cache_tree);

	////pr_err("after insert off: %llu, len: %u\n", key->off, key->len);

	return 0;
err:
	return ret;;
}

static struct cbd_cache_segment *get_data_head_segment(struct cbd_cache *cache)
{
	return cache->data_head.cache_seg;
}

static void cache_pos_copy(struct cbd_cache_pos *dst, struct cbd_cache_pos *src)
{
	memcpy(dst, src, sizeof(struct cbd_cache_pos));
}

static int cache_data_alloc(struct cbd_cache *cache, struct cache_key *key)
{
	struct cbd_cache_pos *head_pos;
	struct cbd_cache_segment *cache_seg;
	struct cbd_segment *segment;
	u32 seg_remain;
	u32 allocated = 0, to_alloc;

	cache_pos_copy(&key->cache_pos, &cache->data_head);

again:
	head_pos = &cache->data_head;
	cache_seg = get_data_head_segment(cache);
	segment = &cache_seg->segment;
	seg_remain = segment->data_size - head_pos->seg_off;
	to_alloc = key->len - allocated;
	if (seg_remain > to_alloc) {
		cache_pos_advance(head_pos, to_alloc, false);
		allocated += to_alloc;
	} else if (seg_remain) {
		cache_pos_advance(head_pos, seg_remain, false);
		allocated += seg_remain;
	} else {
		cache_data_head_init(cache);
		cache_seg->next = get_data_head_segment(cache);
		cache_seg->cache_seg_info->next_cache_seg_id = cache_seg->next->cache_seg_id;
		cache_seg->cache_seg_info->flags |= CBD_CACHE_SEG_FLAGS_HAS_NEXT;
	}

	if (allocated < key->len)
		goto again;

	return 0;
}

static int submit_cache_io(struct cbd_cache *cache, struct cbd_request *cbd_req,
			    u32 off, u32 len, struct cbd_cache_pos *pos)
{
	struct cbd_cache_segment *cache_seg = pos->cache_seg;
	struct cbd_segment *segment = &cache_seg->segment;

	//pr_err("cache off %u, len %u\n", cbd_req->off + off, len);
	//pr_err("copy_to_bio from segment: %p, seg_off: %u len: %u\n", segment, pos->seg_off, len);
	spin_lock(&cbd_req->lock);
	cbds_copy_to_bio(segment, pos->seg_off, len, cbd_req->bio, off);
	spin_unlock(&cbd_req->lock);
	return 0;
}

static int submit_backing_io(struct cbd_cache *cache, struct cbd_request *cbd_req,
			    u32 off, u32 len)
{
	struct cbd_request *new_req;
	int ret;

	//pr_err("backing off %u, len %u\n", cbd_req->off + off, len);
	new_req = kmem_cache_zalloc(cache->req_cache, GFP_NOIO);
	if (!new_req)
		return -ENOMEM;

	//pr_err("alloc new req: %p, parent: %p\n", new_req, cbd_req);
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

	kref_get(&cbd_req->ref);
	new_req->parent = cbd_req;
	new_req->kmem_cache = cache->req_cache;

	ret = cbd_queue_req_to_backend(new_req);

	cbd_req_end(new_req, ret);

	return ret;
}

int cache_read(struct cbd_cache *cache, struct cbd_request *cbd_req)
{
  	struct rb_node **new = &(cache->cache_tree.rb_node), *parent = NULL;
	struct cache_key *key_tmp = NULL;
	struct rb_node	*prev_node = NULL, *next_node = NULL;
	struct cache_key key_data = { .off = cbd_req->off, .len = cbd_req->data_len };
	struct cache_key *key = &key_data;
	struct cbd_cache_pos pos;
	u32 io_done = 0, total_io_done = 0, io_len = 0;
	int ret;

	//pr_err("cache_read: off %llu, len: %u\n", cbd_req->off, cbd_req->data_len);

	mutex_lock(&cache->io_lock);
  	while (*new) {
  		key_tmp = container_of(*new, struct cache_key, rb_node);
		BUG_ON(key_tmp->seg_gen < key_tmp->cache_pos.cache_seg->gen);

		parent = *new;
		if (key_tmp->off >= key->off) {
			next_node = *new;
  			new = &((*new)->rb_left);
		} else {
			prev_node = *new;
  			new = &((*new)->rb_right);
		}
  	}

	if (!prev_node)
		prev_node = rb_first(&cache->cache_tree);

	struct rb_node *node_tmp;

	if (!prev_node) {
		submit_backing_io(cache, cbd_req, 0, cbd_req->data_len);
		mutex_unlock(&cache->io_lock);
		return 0;
	}

	node_tmp = prev_node;
	while (node_tmp) {
		if (io_done >= cbd_req->data_len)
			break;;

		key_tmp = CACHE_KEY(node_tmp);

		/*
		 * |----------|
		 *		|=====|
		 * */
		if (cache_key_lend(key_tmp) <= cache_key_lstart(key)) {
			goto next;
		}

		/*
		 *	  |--------|
		 * |====|
		 */
		if (cache_key_lstart(key_tmp) >= cache_key_lend(key)) {
			submit_backing_io(cache, cbd_req, total_io_done + io_done, key->len);
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
					submit_backing_io(cache, cbd_req, total_io_done + io_done, io_len);
					io_done += io_len;
					cache_key_cutfront(key, io_len);
				}

				io_len = cache_key_lend(key) - cache_key_lstart(key_tmp);
				submit_cache_io(cache, cbd_req, total_io_done + io_done, io_len, &key_tmp->cache_pos);
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
				submit_backing_io(cache, cbd_req, total_io_done + io_done, io_len);
				io_done += io_len;
				cache_key_cutfront(key, io_len);
			}

			io_len = key_tmp->len;
			ret = submit_cache_io(cache, cbd_req, total_io_done + io_done, io_len, &key_tmp->cache_pos);
			if (ret)
				ret = 0;
			io_done += io_len;
			cache_key_cutfront(key, io_len);
			goto next;
		}


		/*
		 * |-----------|	key_tmp
		 *   |====|		key
		 */
		if (cache_key_lend(key_tmp) >= cache_key_lend(key)) {
			cache_pos_copy(&pos, &key_tmp->cache_pos);
			cache_pos_advance(&pos, cache_key_lstart(key) - cache_key_lstart(key_tmp), false);

			ret = submit_cache_io(cache, cbd_req, total_io_done + io_done, key->len, &pos);
			io_done += key->len;
			if (ret)
				ret = 0;

			cache_key_cutfront(key, key->len);
			break;
		}


		/*
		 * |--------|		key_tmp
		 *   |==========|	key
		 */
		io_len = cache_key_lend(key_tmp) - cache_key_lstart(key);

		cache_pos_copy(&pos, &key_tmp->cache_pos);
		cache_pos_advance(&pos, cache_key_lstart(key) - cache_key_lstart(key_tmp), false);

		ret = submit_cache_io(cache, cbd_req, total_io_done + io_done, io_len, &pos);
		if (ret)
			ret = 0;
		io_done += io_len;
		cache_key_cutfront(key, io_len);
next:
		node_tmp = rb_next(node_tmp);
	}

	if (key->len) {
		submit_backing_io(cache, cbd_req, total_io_done + io_done, key->len);
		io_done += key->len;
	}

	total_io_done += io_done;
	io_done = 0;

	/*
	if (!ret && total_io_done < io->len) {
		goto next_skiplist;
	}
	*/

	mutex_unlock(&cache->io_lock);
	return 0;
}

int cache_write(struct cbd_cache *cache, struct cbd_request *cbd_req)
{
	u64 offset = cbd_req->off;
	u32 length = cbd_req->data_len;
	u32 io_done = 0;
	struct cache_key *key;
	int ret;

	//submit_backing_io(cache, cbd_req, 0, cbd_req->data_len);

	//pr_err("cache_write: %lu: %u", offset, length);
	mutex_lock(&cache->io_lock);
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

		ret = cache_data_alloc(cache, key);
		if (ret) {
			cache_key_put(key);
			goto err;
		}

		key->seg_gen = key->cache_pos.cache_seg->gen;
		BUG_ON(!key->cache_pos.cache_seg);
		cache_copy_from_bio(cache, key, cbd_req->bio);

		//pr_err("insert key segid: %u\n", key->cache_pos.cache_seg->cache_seg_id);
		ret = cache_insert_key(cache, key, true);
		if (ret)
			goto err;

		/* append key into key head pos */
		cache_key_append(cache, key);

		io_done += key->len;
	}

	ret = 0;
err:
	mutex_unlock(&cache->io_lock);
	return ret;
}

int cbd_cache_handle_req(struct cbd_cache *cache, struct cbd_request *cbd_req)
{
	switch (cbd_req->op) {
	case CBD_OP_FLUSH:
		break;
	case CBD_OP_DISCARD:
		break;
	case CBD_OP_WRITE_ZEROES:
		break;
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
	pr_err("pos_encode seg: %p seg_id: %u\n", pos->cache_seg, pos_onmedia->cache_seg_id);
}

static void cache_pos_decode(struct cbd_cache *cache,
			     struct cbd_cache_pos_onmedia *pos_onmedia,
			     struct cbd_cache_pos *pos)
{
	pos->cache_seg = &cache->segments[pos_onmedia->cache_seg_id];
	pos->seg_off = pos_onmedia->seg_off;
}

static void cache_set_range(struct cbd_cache *cache,
			    struct cbd_cache_pos *range_pos,
			    u32 len)
{
	struct cbd_cache_pos pos_data = { 0 };
	struct cbd_cache_pos *pos;
	
	cache_pos_copy(&pos_data, range_pos);
	pos = &pos_data;

	cache_pos_advance(pos, len, true);
}

static int cache_replay(struct cbd_cache *cache)
{
	struct cbd_cache_pos pos_tail;
	struct cbd_cache_pos *pos;
	struct cache_key_set *kset;
	struct cache_key_onmedia *key_onmedia;
	struct cache_key *key = NULL;
	int ret = 0;
	u64 addr;
	int i;

	cache_pos_copy(&pos_tail, &cache->key_tail);
	pos = &pos_tail;

	set_bit(pos->cache_seg->cache_seg_id, cache->seg_map);

	while (true) {
again:
		addr = cache_pos_addr(pos);

		kset = (struct cache_key_set *)addr;
		////pr_err("replay kset: %p, magic: %lx, crc: %u\n", kset, kset->magic, kset->crc);
		////pr_err("crc is %u, expected: %u\n", cache_kset_crc(kset), kset->crc);
		if (kset->magic != CBD_KSET_MAGIC ||
				kset->crc != cache_kset_crc(kset)) {
			//pr_err("crc is not expected. magic: %lx, expected: %lx\n", kset->magic, CBD_KSET_MAGIC);
			break;
		}

		for (i = 0; i < kset->key_num; i++) {
			key_onmedia = &kset->data[i];

			key = cache_key_alloc(cache);
			if (!key) {
				ret = -ENOMEM;
				goto err;
			}

			cache_key_decode(key_onmedia, key);
			////pr_err("onmedia cache_seg_id: %u set bit: %u", key_onmedia->cache_seg_id, key->cache_pos.cache_seg->cache_seg_id);
			set_bit(key->cache_pos.cache_seg->cache_seg_id, cache->seg_map);
			cache_set_range(cache, &key->cache_pos, key->len);

			if (key->cache_pos.cache_seg->gen < key->seg_gen)
				key->cache_pos.cache_seg->gen = key->seg_gen;

			pr_err("replay key key: %lu:%u cache_pos: %lu:%u\n", key->off, key->len, key->cache_pos.seg_off, key->len);
			ret = cache_insert_key(cache, key, true);
			if (ret) {
				goto err;
			}
		}

		if (kset->flags & CBD_KSET_FLAGS_LAST) {
			pos->cache_seg = pos->cache_seg->next;
			pos->seg_off = 0;
			set_bit(pos->cache_seg->cache_seg_id, cache->seg_map);
			continue;
		}
		cache_pos_advance(pos, struct_size(kset, data, kset->key_num), false);
	}

	clear_keys(cache);

	pr_err("init keyhead\n");
	cache_pos_copy(&cache->key_head, pos);

	return 0;
err:
	return ret;
}

static void cache_seg_init(struct cbd_cache *cache,
			   u32 seg_id, u32 cache_seg_id)
{
	struct cbd_transport *cbdt = cache->cbdt;
	struct cbd_cache_segment *cache_seg = &cache->segments[cache_seg_id];
	struct cbds_init_options seg_options = { 0 };
	struct cbd_segment *segment = &cache_seg->segment;
	u32 next_cache_seg_id;

	seg_options.type = cbds_type_cache;
	seg_options.data_off = round_up(sizeof(struct cbd_cache_seg_info), PAGE_SIZE);
	seg_options.seg_ops = &cbd_cache_seg_ops;
	seg_options.seg_id = seg_id;

	cbd_segment_init(cbdt, segment, &seg_options);

	cache_seg->cache = cache;
	pr_err("init seg %p, id %u\n", cache_seg, cache_seg_id);
	cache_seg->cache_seg_id = cache_seg_id;
	cache_seg->cache_seg_info = (struct cbd_cache_seg_info *)segment->segment_info;

	if (cache_seg->cache_seg_info->flags & CBD_CACHE_SEG_FLAGS_HAS_NEXT) {
		next_cache_seg_id = cache_seg->cache_seg_info->next_cache_seg_id;
		cache_seg->next = &cache->segments[next_cache_seg_id];
	}
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

enum cbd_cache_state {
	cbd_cache_state_none = 0,
	cbd_cache_state_running,
	cbd_cache_state_removing
};

static void cache_writeback_exit(struct cbd_cache *cache)
{
	if (!cache->bioset)
		return;

	cancel_delayed_work_sync(&cache->writeback_work);
	cancel_delayed_work_sync(&cache->writeback_work);
	bioset_exit(cache->bioset);
	kfree(cache->bioset);
}

static int cache_writeback_init(struct cbd_cache *cache)
{
	int ret;

	//pr_err("start writeback\n");
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

static int cache_writeback(struct cbd_cache *cache, struct cache_key *key)
{
	struct cbd_cache_pos pos_data;
	struct cbd_cache_pos *pos;
	void *addr;
	ssize_t written;
	struct cbd_cache_segment *cache_seg;
	struct cbd_segment *segment;
	u32 seg_remain, to_write;
	u32 advanced = 0;
	u64 off;

	cache_pos_copy(&pos_data, &key->cache_pos);
	pos = &pos_data;
again:
	cache_seg = pos->cache_seg;
	BUG_ON(!cache_seg);
	segment = &cache_seg->segment;
	seg_remain = segment->data_size - pos->seg_off;
	if (!seg_remain) {
		BUG_ON(!cache_seg->cache_seg_info->flags & CBD_CACHE_SEG_FLAGS_HAS_NEXT);

		if (cache_seg->cache_seg_info->flags & CBD_CACHE_SEG_FLAGS_HAS_NEXT) {
			u32 next_cache_seg_id;

			next_cache_seg_id = cache_seg->cache_seg_info->next_cache_seg_id;
			cache_seg->next = &cache->segments[next_cache_seg_id];
		}

		pos->cache_seg = cache_seg->next;
		BUG_ON(!pos->cache_seg);
		pos->seg_off = 0;
		goto again;
	}

	to_write = key->len - advanced;
	if (seg_remain < to_write)
		to_write = seg_remain;

	addr = cache_pos_addr(pos);
	off = key->off + advanced;

	pr_err("writeback: kernel_write %lu:%u\n", off, to_write);
	/* TODO write back in async way */
	written = kernel_write(cache->bdev_file, addr, to_write, &off);
	if (written != to_write) {
		//pr_err("writeback error: kernel_write return err\n");
		return -EIO;
	}
	vfs_fsync(cache->bdev_file, 0);
	pos->seg_off += to_write;
	advanced += to_write;

	if (advanced < key->len)
		goto again;

	return 0;
}

static void writeback_fn(struct work_struct *work)
{
	struct cbd_cache *cache = container_of(work, struct cbd_cache, writeback_work.work);
	struct cbd_cache_pos *pos;
	struct cache_key_set *kset;
	struct cache_key_onmedia *key_onmedia;
	struct cache_key *key = NULL;
	int ret = 0;
	void *addr;
	int i;

	if (cache->state == cbd_cache_state_removing)
		return;

	pos = &cache->dirty_tail;
	while (true) {
		//pr_err("dirty tail: seg %u off: %u\n", pos->cache_seg->cache_seg_id, pos->seg_off);
		addr = cache_pos_addr(pos);
		kset = (struct cache_key_set *)addr;
		////pr_err("replay kset: %p, magic: %lx, crc: %u\n", kset, kset->magic, kset->crc);
		////pr_err("crc is %u, expected: %u\n", cache_kset_crc(kset), kset->crc);
		if (kset->magic != CBD_KSET_MAGIC ||
				kset->crc != cache_kset_crc(kset)) {
			////pr_err("writeback error crc is not expected. magic: %lx, expected: %lx\n", kset->magic, CBD_KSET_MAGIC);
			queue_delayed_work(cache->cache_wq, &cache->writeback_work, 1 * HZ);
			return;
		}

		for (i = 0; i < kset->key_num; i++) {
			key_onmedia = &kset->data[i];

			key = cache_key_alloc(cache);
			if (!key) {
				//pr_err("writeback error failed to alloc key\n");
				return;
			}

			cache_key_decode(key_onmedia, key);
			pr_err("writeback: write %lu:%u\n", key->off, key->len);
			ret = cache_writeback(cache, key);
			cache_key_put(key);

			if (ret) {
				return;
			}
		}

		if (kset->flags & CBD_KSET_FLAGS_LAST) {
			pos->cache_seg = pos->cache_seg->next;
			pos->seg_off = 0;
			cache_pos_encode(cache, &cache->cache_info->dirty_tail_pos, &cache->dirty_tail);
			continue;
		}
		cache_pos_advance(pos, struct_size(kset, data, kset->key_num), false);
		cache_pos_encode(cache, &cache->cache_info->dirty_tail_pos, &cache->dirty_tail);
	}

	pr_info("writeback thread exit: %d\n", ret);
}

static bool need_gc(struct cbd_cache *cache)
{
	void *dirty_addr, *key_addr;
	struct cache_key_set *kset;

	cache_pos_decode(cache, &cache->cache_info->dirty_tail_pos, &cache->dirty_tail);

	//pr_err("gc: dirty seg:%u, off: %u, key: %u:%u\n", cache->dirty_tail.cache_seg->cache_seg_id, cache->dirty_tail.seg_off, cache->key_tail.cache_seg->cache_seg_id, cache->key_tail.seg_off);

	dirty_addr = cache_pos_addr(&cache->dirty_tail);
	key_addr = cache_pos_addr(&cache->key_tail);

	if (dirty_addr == key_addr) {
		////pr_err("all gc-ed\n");
		return false;
	}

	kset = (struct cache_key_set *)key_addr;

	if (!cache->data_head.cache_seg)
		return false;

	if (kset->latest_seg_id == cache->data_head.cache_seg->cache_seg_id)
		return false;

	return true;
	if (bitmap_weight(cache->seg_map, cache->n_segs) < (cache->n_segs / 10 * 7))
		return false;

	return true;
}

static void gc_fn(struct work_struct *work)
{
	struct cbd_cache *cache = container_of(work, struct cbd_cache, gc_work.work);
	struct cbd_cache_pos *pos;
	struct cache_key_set *kset;
	struct cache_key_onmedia *key_onmedia;
	struct cache_key *key = NULL;
	int ret = 0;
	void *addr;
	int i;

	if (cache->state == cbd_cache_state_removing)
		return;

	while (true) {
		if (!need_gc(cache)) {
			queue_delayed_work(cache->cache_wq, &cache->gc_work, 1 * HZ);
			return;
		}

		pos = &cache->key_tail;
		addr = cache_pos_addr(pos);
		kset = (struct cache_key_set *)addr;
		if (kset->magic != CBD_KSET_MAGIC ||
				kset->crc != cache_kset_crc(kset)) {
			//pr_err("gc error crc is not expected. magic: %lx, expected: %lx\n", kset->magic, CBD_KSET_MAGIC);
			return;
		}

		for (i = 0; i < kset->key_num; i++) {
			key_onmedia = &kset->data[i];

			key = cache_key_alloc(cache);
			if (!key) {
				//pr_err("gc error failed to alloc key\n");
				return;
			}

			cache_key_decode(key_onmedia, key);
			seg_used_remove(cache, key);
			cache_key_put(key);
		}

		if (kset->flags & CBD_KSET_FLAGS_LAST) {
			/* clear key seg directly */
			clear_bit(pos->cache_seg->cache_seg_id, cache->seg_map);

			pos->cache_seg = pos->cache_seg->next;
			pos->seg_off = 0;
			cache_pos_encode(cache, &cache->cache_info->key_tail_pos, &cache->key_tail);
			continue;
		}
		cache_pos_advance(pos, struct_size(kset, data, kset->key_num), false);
		cache_pos_encode(cache, &cache->cache_info->key_tail_pos, &cache->key_tail);
	}
}

struct cbd_cache *cbd_cache_alloc(struct cbd_transport *cbdt,
				  struct cbd_cache_opts *opts)
{
	struct cbd_cache_info *cache_info;
	struct cbd_backend_info *backend_info;
	struct cbd_segment_info *prev_seg_info = NULL;
	struct cbd_cache *cache;
	struct cbd_cache_segment *cache_seg;
	u32 seg_id;
	u32 backend_id;
	int ret;
	int i;

	cache_info = opts->cache_info;
	backend_info = container_of(cache_info, struct cbd_backend_info, cache_info);
	backend_id = get_backend_id(cbdt, backend_info);

	cache = kzalloc(struct_size(cache, segments, cache_info->n_segs), GFP_KERNEL);
	if (!cache)
		return NULL;

	cache->seg_map = bitmap_zalloc(cache_info->n_segs, GFP_KERNEL);
	if (!cache->seg_map) {
		ret = -ENOMEM;
		goto destroy_cache;
	}

	cache->key_cache = KMEM_CACHE(cache_key, 0);
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
					0, cbdt->id, backend_id);
	if (!cache->cache_wq) {
		ret = -ENOMEM;
		goto destroy_cache;
	}

	cache->cbdt = cbdt;
	cache->cache_info = cache_info;
	cache->n_segs = cache_info->n_segs;
	cache->cache_tree = RB_ROOT;
	mutex_init(&cache->io_lock);
	spin_lock_init(&cache->seg_map_lock);
	cache->bdev_file = opts->bdev_file;

	INIT_DELAYED_WORK(&cache->writeback_work, writeback_fn);
	INIT_DELAYED_WORK(&cache->gc_work, gc_fn);

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

		////pr_err("get seg: %u", seg_id);
		cache_seg_init(cache, seg_id, i);

		prev_seg_info = cbdt_get_segment_info(cbdt, seg_id);
	}

	cache_pos_decode(cache, &cache_info->key_tail_pos, &cache->key_tail);
	cache_pos_decode(cache, &cache_info->dirty_tail_pos, &cache->dirty_tail);

	cache->state = cbd_cache_state_running;
	/* start writeback */
	if (opts->start_writeback) {
		ret = cache_writeback_init(cache);
		if (ret)
			goto destroy_cache;
	}

	/* start gc */
	if (opts->start_gc) {
		queue_delayed_work(cache->cache_wq, &cache->gc_work, 0);
	}

	if (opts->init_keys) {
		ret = cache_replay(cache);
		if (ret) {
			//pr_err("failed to replay\n");
			goto destroy_cache;
		}

		dump_cache(cache);
		cache_data_head_init(cache);
	}

	return cache;

destroy_cache:
	cbd_cache_destroy(cache);

	return NULL;
}

void cbd_cache_destroy(struct cbd_cache *cache)
{
	int i;

	cache->state = cbd_cache_state_removing;

	cancel_delayed_work_sync(&cache->gc_work);
	cancel_delayed_work_sync(&cache->gc_work);

	cache_writeback_exit(cache);


	dump_cache(cache);
	while (!RB_EMPTY_ROOT(&cache->cache_tree)) {
		struct rb_node *node = rb_first(&cache->cache_tree);
		struct cache_key *key = CACHE_KEY(node);

		cache_key_delete(key);
	}

	if (cache->cache_wq) {
		drain_workqueue(cache->cache_wq);
		destroy_workqueue(cache->cache_wq);
	}

	if (cache->req_cache)
		kmem_cache_destroy(cache->req_cache);

	if (cache->key_cache)
		kmem_cache_destroy(cache->key_cache);

	if (cache->seg_map)
		bitmap_free(cache->seg_map);

	for (i = 0; i < cache->n_segs; i++)
		cache_seg_exit(&cache->segments[i]);

	kfree(cache);
}
