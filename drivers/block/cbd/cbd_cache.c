#include "cbd_internal.h"

static struct cache_key {
	int level:10;
	int deleted:1;
	int fullylinked:1;

	struct kref ref;

	struct rb_node rb_node;

	uint64_t	l_off;
	uint64_t	p_off;
	uint32_t	len;
	uint64_t	flags;
	uint64_t	seg_gen;
};

/*
blk_status_t cbd_cache_queue_rq(struct cbd_cache *cache, struct request *req)
{
	u64 offset = (u64)blk_rq_pos(cbd_req->req) << SECTOR_SHIFT;
	u32 length = blk_rq_bytes(cbd_req->req);
	u32 io_done = 0;
	struct cache_key *key;

	while (true) {
		if (io_done >= length)
			break;

		key = cache_key_alloc(cache_b, io->queue_id);
		if (!key) {
			ret = -ENOMEM;
			goto finish;
		}

		key->l_off = offset + io_done;
		key->len = io->len - io_done;
		if (key->len > CACHE_KEY_LIST_SIZE - (key->l_off & CACHE_KEY_LIST_MASK))
			key->len = CACHE_KEY_LIST_SIZE - (key->l_off & CACHE_KEY_LIST_MASK);

		ret = cache_data_alloc(cache_b, key, io);
		if (ret) {
			cache_key_put(key);
			goto finish;
		}

		if (!key->len) {
			ubbd_err("len of key is 0\n");
			cache_key_put(key);
			continue;
		}

		backend_index = get_cache_backend(cache_b, key->p_off);
		backend = cache_b->cache_backends[backend_index];

		cache_io = prepare_backend_io(cache_b, backend, io, io_done, key->len, cache_backend_write_io_finish);
		if (!cache_io) {
			cache_key_put(key);
			ret = -ENOMEM;
			goto finish;
		}
		cache_io->offset = key->p_off - (backend_index * (cache_b->cache_sb.segs_per_device << CACHE_SEG_SHIFT));

		struct cache_backend_io_ctx_data *data;

		data = (struct cache_backend_io_ctx_data *)cache_io->ctx->data;
		data->cache_io = true;
		data->key = key;
		data->cache_b = cache_b;
		cache_seg_get(cache_b, key->p_off >> CACHE_SEG_SHIFT);

		if (cache_b->lcache_debug)
			ubbd_err("submit write cache io: %lu:%u seg: %lu\n",
					cache_io->offset, cache_io->len,
					cache_io->offset >> CACHE_SEG_SHIFT);

		ret = backend->backend_ops->writev(backend, cache_io);

		if (ret) {
			ubbd_err("cache io failed.\n");
			cache_seg_put(cache_b, key->p_off >> CACHE_SEG_SHIFT);
			cache_key_put(key);
			goto finish;
		}

		io_done += key->len;
	}

	if (cache_b->cache_mode == UBBD_CACHE_MODE_WT) {
		struct ubbd_backend_io *backing_io;
		backing_io = prepare_backend_io(cache_b, cache_b->backing_backend, io, 0, io->len, cache_backend_read_io_finish);
		if (cache_b->lcache_debug)
			ubbd_err("submit write backing io: %lu:%u crc: %lu, iov_len: %lu, iocnt: %d\n",
					backing_io->offset, backing_io->len,
					crc64(backing_io->iov[0].iov_base, backing_io->iov[0].iov_len),
					backing_io->iov[0].iov_len, backing_io->iov_cnt);

		ret = cache_b->backing_backend->backend_ops->writev(cache_b->backing_backend, backing_io);
		if (ret) {
			ubbd_err("failed to submit backing io\n");
		}
	}

	ret = 0;
finish:
	ubbd_backend_io_finish(io, ret);
	return 0;
}
*/

static struct cbd_seg_ops cbd_cache_seg_ops = {};

struct cbd_cache *cbd_cache_alloc(struct cbd_transport *cbdt, struct cbd_cache_info *cache_info, bool alloc_seg)
{
	struct cbd_segment_info *prev_seg_info = NULL;
	struct cbds_init_options seg_options = { 0 };
	struct cbd_cache *cache;
	struct cbd_segment *segment;
	u32 seg_id;
	int ret;
	int i;

	cache = kzalloc(struct_size(cache, segments, cache_info->n_segs), GFP_KERNEL);
	if (!cache)
		return NULL;

	cache->seg_map = bitmap_zalloc(cache_info->n_segs, GFP_KERNEL);
	if (!cache->seg_map) {
		ret = -ENOMEM;
		goto destroy_cache;
	}

	cache->cbdt = cbdt;
	cache->cache_info = cache_info;
	cache->n_segs = cache_info->n_segs;
	cache->cache_tree = RB_ROOT;

	seg_options.type = cbds_type_cache;
	seg_options.data_off = round_up(sizeof(struct cbd_cache_seg_info), PAGE_SIZE);
	seg_options.seg_ops = &cbd_cache_seg_ops;

	for (i = 0; i < cache_info->n_segs; i++) {
		if (alloc_seg) {
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

		pr_err("get seg: %u", seg_id);
		segment = &cache->segments[i];
		seg_options.seg_id = seg_id;
		cbd_segment_init(cbdt, segment, &seg_options);

		prev_seg_info = cbdt_get_segment_info(cbdt, seg_id);
	}

	return cache;

destroy_cache:
	cbd_cache_destroy(cache);

	return NULL;
}

void cbd_cache_destroy(struct cbd_cache *cache)
{
	int i;

	if (cache->seg_map)
		bitmap_free(cache->seg_map);

	for (i = 0; i < cache->n_segs; i++)
		cbd_segment_exit(&cache->segments[i]);

	kfree(cache);
}
