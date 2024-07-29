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
		pr_err("sanitize next segment, pos off: %u, data_size: %u\n", pos->off, segment->data_size);
		pos->off -= segment->data_size;
		pr_err("cacheseg: %p ", cache_seg);
		cache_seg = cache_seg->next;
		pr_err("next is %p, %u", cache_seg->segment.data, cache_seg->cache_seg_id);
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
		pr_err("no seg avaialbe.");
		msleep(100);
		goto again;
	}

	set_bit(seg_id, cache->seg_map);
	spin_unlock(&cache->seg_map_lock);
;
	cache_seg = &cache->segments[seg_id];
	cache_seg->cache_seg_id = seg_id;

	pr_err("clear all data for segment_data: %p, %u", cache_seg->segment.data, cache_seg->segment.data_size);
	cbdt_zero_range(cache->cbdt, cache_seg->segment.data, cache_seg->segment.data_size);

	return cache_seg;
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

	key = kmem_cache_zalloc(cache->key_cache, GFP_KERNEL);
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
	//pr_err("copy_from_bio to segment: %p, seg_off: %u len: %u\n", segment, pos->seg_off, key->len);
	cbds_copy_from_bio(segment, pos->seg_off, key->len, bio);
}

#define CACHE_KEY(node)		(container_of(node, struct cache_key, rb_node))

static inline u64 cache_key_lstart(struct cache_key *key)
{
	return key->off;
}

static inline u64 cache_key_lend(struct cache_key *key)
{
	return key->off + key->len;
}

static void cache_pos_copy(struct cbd_cache_pos *dst, struct cbd_cache_pos *src);
static inline void cache_key_copy(struct cache_key *key_dst, struct cache_key *key_src)
{
	key_dst->off = key_src->off;
	key_dst->len = key_src->len;

	cache_pos_copy(&key_dst->cache_pos, &key_src->cache_pos);
}

static void cache_pos_advance(struct cbd_cache_pos *pos, u32 len)
{
	struct cbd_cache_segment *cache_seg;
	struct cbd_segment *segment;
	u32 seg_remain;
	u32 advanced = 0;

again:
	cache_seg = pos->cache_seg;
	//pr_err("advance pos: %p, len: %u", pos, len);
	BUG_ON(!cache_seg);
	segment = &cache_seg->segment;
	seg_remain = segment->data_size - pos->seg_off;

	if (seg_remain >= len) {
		pos->seg_off += len;
		advanced += len;
	} else if (seg_remain) {
		pos->seg_off += seg_remain;
		advanced += seg_remain;
	} else {
		pos->cache_seg = cache_seg->next;
		if (!pos->cache_seg)
			pr_err("next is NULL\n");
		pos->seg_off = 0;
	}

	if (advanced < len)
		goto again;
}

static inline void cache_key_cutfront(struct cache_key *key, u32 cut_len)
{
	if (key->cache_pos.cache_seg) {
		pr_err("cutfront: %p\n", &key->cache_pos);
		cache_pos_advance(&key->cache_pos, cut_len);
	}
	key->off += cut_len;
	key->len -= cut_len;
}

static inline void cache_key_cutback(struct cache_key *key, u32 cut_len)
{
	key->len -= cut_len;
}

static void dump_cache(struct cbd_cache *cache);
static inline void cache_key_delete(struct cache_key *key)
{
	rb_erase(&key->rb_node, &key->cache->cache_tree);
	//pr_err("delete key");
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
		pr_err("key: %p key->off: %llu, len: %u, cache: %p\n", key, key->off, key->len, cache_pos_addr(&key->cache_pos));
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
//	pr_err("close kset: %p, magic: %lx, crc: %u\n", kset, kset->magic, kset->crc);

	pos = &cache->key_head;
	cache_pos_advance(pos, struct_size(kset, data, kset->key_num));

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

	//pr_err("key_num: %u", kset->key_num);
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

	//pr_err("start fixup: current: %llu", current->pid);
	node_tmp = prev_node;
	while (node_tmp) {
		key_tmp = CACHE_KEY(node_tmp);
		//pr_err("key_tmp: %llu:%u, key: %llu:%u", cache_key_lstart(key_tmp), key_tmp->len,
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
				//pr_err("before cutfront");
				cache_key_cutfront(key_tmp, cache_key_lend(key) - cache_key_lstart(key_tmp));
				if (key_tmp->len == 0) {
					//pr_err("delete key_tmp\n");
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

again:
	new = &(cache->cache_tree.rb_node);
	parent = NULL;
	key_tmp = NULL;
	prev_node = NULL;
  	while (*new) {
  		key_tmp = container_of(*new, struct cache_key, rb_node);

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
		//pr_err("after fixup\n");
		if (ret == -EAGAIN)
			goto again;
		else if (ret)
			goto err;
	}

  	rb_link_node(&key->rb_node, parent, new);
  	rb_insert_color(&key->rb_node, &cache->cache_tree);

	pr_err("after insert off: %llu, len: %u\n", key->off, key->len);

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
		cache_pos_advance(head_pos, to_alloc);
		allocated += to_alloc;
	} else if (seg_remain) {
		cache_pos_advance(head_pos, seg_remain);
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

	pr_err("cache off %u, len %u\n", cbd_req->off + off, len);
	//pr_err("copy_to_bio from segment: %p, seg_off: %u len: %u\n", segment, pos->seg_off, len);
	cbds_copy_to_bio(segment, pos->seg_off, len, cbd_req->bio, off);
	return 0;
}

static int submit_backing_io(struct cbd_cache *cache, struct cbd_request *cbd_req,
			    u32 off, u32 len)
{
	//pr_err("backing off %u, len %u\n", cbd_req->off + off, len);
	return 0;
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

	pr_err("cache_read: off %llu, len: %u\n", cbd_req->off, cbd_req->data_len);

	mutex_lock(&cache->cache_tree_lock);
  	while (*new) {
  		key_tmp = container_of(*new, struct cache_key, rb_node);

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
		mutex_unlock(&cache->cache_tree_lock);
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
			cache_pos_advance(&pos, cache_key_lstart(key) - cache_key_lstart(key_tmp));

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
		cache_pos_advance(&pos, cache_key_lstart(key) - cache_key_lstart(key_tmp));

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

	mutex_unlock(&cache->cache_tree_lock);
	return 0;
}

int cache_write(struct cbd_cache *cache, struct cbd_request *cbd_req)
{
	u64 offset = cbd_req->off;
	u32 length = cbd_req->data_len;
	u32 io_done = 0;
	struct cache_key *key;
	int ret;

	pr_err("cache_write: %lu: %u", offset, length);
	mutex_lock(&cache->cache_tree_lock);
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

		BUG_ON(!key->cache_pos.cache_seg);
		cache_copy_from_bio(cache, key, cbd_req->bio);

		ret = cache_insert_key(cache, key, true);
		if (ret)
			goto err;

		/* append key into key head pos */
		cache_key_append(cache, key);

		io_done += key->len;
	}

	ret = 0;
err:
	mutex_unlock(&cache->cache_tree_lock);
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
	struct cbd_cache_pos *pos = &cache->key_tail;
	struct cache_key_set *kset;
	struct cache_key_onmedia *key_onmedia;
	struct cache_key *key = NULL;
	int ret = 0;
	u64 addr;
	int i;

	set_bit(pos->cache_seg->cache_seg_id, cache->seg_map);

	while (true) {
again:
		addr = cache_pos_addr(pos);

		kset = (struct cache_key_set *)addr;
		//pr_err("replay kset: %p, magic: %lx, crc: %u\n", kset, kset->magic, kset->crc);
		//pr_err("crc is %u, expected: %u\n", cache_kset_crc(kset), kset->crc);
		if (kset->magic != CBD_KSET_MAGIC ||
				kset->crc != cache_kset_crc(kset)) {
			pr_err("crc is not expected. magic: %lx, expected: %lx\n", kset->magic, CBD_KSET_MAGIC);
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
			set_bit(key->cache_pos.cache_seg->cache_seg_id, cache->seg_map);

			if (key->cache_pos.cache_seg->gen < key->seg_gen)
				key->cache_pos.cache_seg->gen = key->seg_gen;

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
		cache_pos_advance(pos, struct_size(kset, data, kset->key_num));
	}

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

struct cbd_cache *cbd_cache_alloc(struct cbd_transport *cbdt,
				  struct cbd_cache_opts *opts)
{
	struct cbd_cache_info *cache_info;
	struct cbd_segment_info *prev_seg_info = NULL;
	struct cbd_cache *cache;
	struct cbd_cache_segment *cache_seg;
	u32 seg_id;
	int ret;
	int i;

	cache_info = opts->cache_info;

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

	cache->cbdt = cbdt;
	cache->cache_info = cache_info;
	cache->n_segs = cache_info->n_segs;
	cache->cache_tree = RB_ROOT;
	mutex_init(&cache->cache_tree_lock);
	spin_lock_init(&cache->seg_map_lock);

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

		//pr_err("get seg: %u", seg_id);
		cache_seg_init(cache, seg_id, i);

		prev_seg_info = cbdt_get_segment_info(cbdt, seg_id);
	}

	/* start writeback */
	if (opts->start_writeback) {
		pr_err("start writeback\n");
	}
	/* start gc */

	cache_pos_decode(cache, &cache_info->key_tail_pos, &cache->key_tail);
	cache_pos_decode(cache, &cache_info->dirty_tail_pos, &cache->dirty_tail);

	if (opts->init_keys) {
		ret = cache_replay(cache);
		if (ret) {
			pr_err("failed to replay\n");
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

	dump_cache(cache);
	while (!RB_EMPTY_ROOT(&cache->cache_tree)) {
		struct rb_node *node = rb_first(&cache->cache_tree);
		struct cache_key *key = CACHE_KEY(node);

		cache_key_delete(key);
	}

	if (cache->key_cache)
		kmem_cache_destroy(cache->key_cache);

	if (cache->seg_map)
		bitmap_free(cache->seg_map);

	for (i = 0; i < cache->n_segs; i++)
		cache_seg_exit(&cache->segments[i]);

	kfree(cache);
}
