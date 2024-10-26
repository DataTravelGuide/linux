#include "../cbd_internal.h"
#include "cbd_cache_internal.h"

static void cache_seg_info_write(struct cbd_cache_segment *cache_seg)
{
	mutex_lock(&cache_seg->info_lock);
	cbdt_segment_info_write(cache_seg->cache->cbdt, &cache_seg->cache_seg_info,
				sizeof(struct cbd_cache_seg_info), cache_seg->segment.seg_id,
				cache_seg->info_index);
	cache_seg->info_index = (cache_seg->info_index + 1) % CBDT_META_INDEX_MAX;
	mutex_unlock(&cache_seg->info_lock);
}

static int cache_seg_info_load(struct cbd_cache_segment *cache_seg)
{
	struct cbd_segment_info *cache_seg_info;
	int ret = 0;

	mutex_lock(&cache_seg->info_lock);
	cache_seg_info = cbdt_segment_info_read(cache_seg->cache->cbdt,
						cache_seg->segment.seg_id,
						&cache_seg->info_index);
	if (!cache_seg_info) {
		cbd_cache_err(cache_seg->cache, "can't read segment info of segment: %u\n",
			      cache_seg->segment.seg_id);
		ret = -EIO;
		goto out;
	}
	memcpy(&cache_seg->cache_seg_info, cache_seg_info, sizeof(struct cbd_cache_seg_info));
out:
	mutex_unlock(&cache_seg->info_lock);
	return ret;
}

static void cache_seg_ctrl_load(struct cbd_cache_segment *cache_seg)
{
	struct cbd_cache_seg_ctrl *cache_seg_ctrl = cache_seg->cache_seg_ctrl;
	struct cbd_cache_seg_gen *cache_seg_gen;

	mutex_lock(&cache_seg->ctrl_lock);
	cache_seg_gen = cbd_meta_find_latest(&cache_seg_ctrl->gen->header,
					     sizeof(struct cbd_cache_seg_gen),
					     NULL);
	if (!cache_seg_gen) {
		cache_seg->gen = 0;
		goto out;
	}

	cache_seg->gen = cache_seg_gen->gen;
out:
	mutex_unlock(&cache_seg->ctrl_lock);

	cbd_cache_debug(cache_seg->cache, "load cache_seg->gen: %llu\n", cache_seg->gen);
}

static void cache_seg_ctrl_write(struct cbd_cache_segment *cache_seg)
{
	struct cbd_cache_seg_ctrl *cache_seg_ctrl = cache_seg->cache_seg_ctrl;
	struct cbd_cache_seg_gen *cache_seg_gen;

	cbd_cache_debug(cache_seg->cache, "write cache_seg->gen: %llu\n", cache_seg->gen);

	mutex_lock(&cache_seg->ctrl_lock);
	cache_seg_gen = cbd_meta_find_oldest(&cache_seg_ctrl->gen->header,
					     sizeof(struct cbd_cache_seg_gen));
	BUG_ON(!cache_seg_gen);
	cache_seg_gen->gen = cache_seg->gen;
	cache_seg_gen->header.seq = cbd_meta_get_next_seq(&cache_seg_ctrl->gen->header,
							  sizeof(struct cbd_cache_seg_gen));
	cache_seg_gen->header.crc = cbd_meta_crc(&cache_seg_gen->header,
						 sizeof(struct cbd_cache_seg_gen));
	mutex_unlock(&cache_seg->ctrl_lock);
}

static int cache_seg_meta_load(struct cbd_cache_segment *cache_seg)
{
	int ret;

	ret = cache_seg_info_load(cache_seg);
	if (ret)
		goto err;

	cache_seg_ctrl_load(cache_seg);

	return 0;
err:
	return ret;
}

void cache_seg_set_next_seg(struct cbd_cache_segment *cache_seg, u32 seg_id)
{
	cache_seg->cache_seg_info.segment_info.flags |= CBD_SEG_INFO_FLAGS_HAS_NEXT;
	cache_seg->cache_seg_info.segment_info.next_seg = seg_id;
	cache_seg_info_write(cache_seg);
}

/* cbd_cache_seg_ops */
static void cbd_cache_seg_sanitize_pos(struct cbd_seg_pos *pos)
{
	BUG_ON(pos->off > pos->segment->data_size);
}

static struct cbd_seg_ops cbd_cache_seg_ops = {
	.sanitize_pos = cbd_cache_seg_sanitize_pos
};

/* cache_segment allocation and reclaim */
int cache_seg_init(struct cbd_cache *cache, u32 seg_id, u32 cache_seg_id,
		   bool new_cache)
{
	struct cbd_transport *cbdt = cache->cbdt;
	struct cbd_cache_segment *cache_seg = &cache->segments[cache_seg_id];
	struct cbds_init_options seg_options = { 0 };
	struct cbd_segment *segment = &cache_seg->segment;
	int ret;

	cache_seg->cache = cache;
	cache_seg->cache_seg_id = cache_seg_id;
	spin_lock_init(&cache_seg->gen_lock);
	atomic_set(&cache_seg->refs, 0);
	cache_seg->info_index = 0;
	mutex_init(&cache_seg->info_lock);
	mutex_init(&cache_seg->ctrl_lock);

	/* init cbd_segment */
	seg_options.type = cbds_type_cache;
	seg_options.data_off = CBDT_CACHE_SEG_CTRL_OFF + CBDT_CACHE_SEG_CTRL_SIZE;
	seg_options.seg_ops = &cbd_cache_seg_ops;
	seg_options.seg_id = seg_id;
	cbd_segment_init(cbdt, segment, &seg_options);

	cache_seg->cache_seg_ctrl = (void *)segment->data + CBDT_CACHE_SEG_CTRL_OFF;

	if (new_cache) {
		cache_seg->cache_seg_info.segment_info.type = cbds_type_cache;
		cache_seg->cache_seg_info.segment_info.state = cbd_segment_state_running;
		cache_seg->cache_seg_info.segment_info.flags = 0;

		cache_seg->cache_seg_info.backend_id = cache->cache_id;
		cache_seg_info_write(cache_seg);
	} else {
		ret = cache_seg_meta_load(cache_seg);
		if (ret)
			goto err;
	}

	return 0;
err:
	return ret;
}

void cache_seg_exit(struct cbd_cache_segment *cache_seg)
{
	cbd_segment_info_clear(&cache_seg->segment);
}

#define CBD_WAIT_NEW_CACHE_INTERVAL	100 /* usecs */
#define CBD_WAIT_NEW_CACHE_COUNT	100

struct cbd_cache_segment *get_cache_segment(struct cbd_cache *cache)
{
	struct cbd_cache_segment *cache_seg;
	u32 seg_id;
	u32 wait_count = 0;

again:
	spin_lock(&cache->seg_map_lock);
	seg_id = find_next_zero_bit(cache->seg_map, cache->n_segs, cache->last_cache_seg);
	if (seg_id == cache->n_segs) {
		spin_unlock(&cache->seg_map_lock);
		if (cache->last_cache_seg) {
			cache->last_cache_seg = 0;
			goto again;
		}

		if (++wait_count >= CBD_WAIT_NEW_CACHE_COUNT)
			return NULL;

		udelay(CBD_WAIT_NEW_CACHE_INTERVAL);
		goto again;
	}

	set_bit(seg_id, cache->seg_map);
	cache->last_cache_seg = seg_id;
	spin_unlock(&cache->seg_map_lock);

	cache_seg = &cache->segments[seg_id];
	cache_seg->cache_seg_id = seg_id;

	cbdt_zero_range(cache->cbdt, cache_seg->segment.data, cache_seg->segment.data_size);

	return cache_seg;
}

static void cache_seg_gen_increase(struct cbd_cache_segment *cache_seg)
{
	spin_lock(&cache_seg->gen_lock);
	cache_seg->gen++;
	spin_unlock(&cache_seg->gen_lock);

	cache_seg_ctrl_write(cache_seg);
}

void cache_seg_get(struct cbd_cache_segment *cache_seg)
{
	atomic_inc(&cache_seg->refs);
}

static void cache_seg_invalidate(struct cbd_cache_segment *cache_seg)
{
	struct cbd_cache *cache;

	cache = cache_seg->cache;

	cache_seg_gen_increase(cache_seg);

	spin_lock(&cache->seg_map_lock);
	clear_bit(cache_seg->cache_seg_id, cache->seg_map);
	spin_unlock(&cache->seg_map_lock);

	queue_work(cache->cache_wq, &cache->clean_work);
}

void cache_seg_put(struct cbd_cache_segment *cache_seg)
{
	if (atomic_dec_and_test(&cache_seg->refs))
		cache_seg_invalidate(cache_seg);
}
