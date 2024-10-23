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

void cache_seg_set_next_seg(struct cbd_cache_segment *cache_seg, u32 seg_id)
{
	cache_seg->cache_seg_info.segment_info.next_seg = seg_id;
	cache_seg_info_write(cache_seg);
}

/* cbd_cache_seg_ops */
static void cbd_cache_seg_sanitize_pos(struct cbd_seg_pos *pos)
{
	struct cbd_segment *segment;
	struct cbd_cache_segment *cache_seg;

again:
	segment = pos->segment;
	cache_seg = container_of(segment, struct cbd_cache_segment, segment);
	if (pos->off >= segment->data_size) {
		pos->off -= segment->data_size;
		cache_seg = cache_seg_get_next(cache_seg);
		if (unlikely(!cache_seg)) {
			pr_err("FIXME: %s %d no next seg for sanitize, pos->off: %u\n",
					__func__, __LINE__, pos->off);
			BUG_ON(!cache_seg);
		}
		pos->segment = &cache_seg->segment;

		goto again;
	}
}

static struct cbd_seg_ops cbd_cache_seg_ops = {
	.sanitize_pos = cbd_cache_seg_sanitize_pos
};

/* cache_segment allocation and reclaim */
void cache_seg_init(struct cbd_cache *cache, u32 seg_id, u32 cache_seg_id,
		    bool new_cache)
{
	struct cbd_transport *cbdt = cache->cbdt;
	struct cbd_cache_segment *cache_seg = &cache->segments[cache_seg_id];
	struct cbds_init_options seg_options = { 0 };
	struct cbd_segment *segment = &cache_seg->segment;

	seg_options.type = cbds_type_cache;
	/*TODO CBDT_CACHE_CTRL_OFF splite frequently changed member from info to meta*/
	seg_options.data_off = CBDT_CACHE_SEG_CTRL_OFF + CBDT_CACHE_SEG_CTRL_SIZE;
	seg_options.seg_ops = &cbd_cache_seg_ops;
	seg_options.seg_id = seg_id;

	cbd_segment_init(cbdt, segment, &seg_options);

	atomic_set(&cache_seg->refs, 0);
	spin_lock_init(&cache_seg->gen_lock);
	cache_seg->cache = cache;
	cache_seg->cache_seg_id = cache_seg_id;

	if (!new_cache)
		return;

	cache_seg->cache_seg_info.segment_info.type = cbds_type_cache;
	cache_seg->cache_seg_info.segment_info.state = cbd_segment_state_running;
	cache_seg->cache_seg_info.segment_info.flags = 0;

	cache_seg->cache_seg_info.backend_id = cache->cache_id;
	cache_seg_info_write(cache_seg);
}

void cache_seg_exit(struct cbd_cache_segment *cache_seg)
{
	cbd_segment_exit(&cache_seg->segment);
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
	//cbd_cache_err(cache, "init seg: %u flags\n", cache_seg->cache_seg_id);
	cache_seg->cache_seg_info.flags = 0;

	cbdt_zero_range(cache->cbdt, cache_seg->segment.data, cache_seg->segment.data_size);

	return cache_seg;
}

void cache_seg_get(struct cbd_cache_segment *cache_seg)
{
	//cbd_cache_err(cache_seg->cache, "before get seg id: %u, ref: %u\n", cache_seg->cache_seg_id, atomic_read(&cache_seg->refs));
	atomic_inc(&cache_seg->refs);
}

static void cache_seg_invalidate(struct cbd_cache_segment *cache_seg)
{
	struct cbd_cache *cache;

	cache = cache_seg->cache;

	spin_lock(&cache_seg->gen_lock);
	cache_seg->cache_seg_info.gen++;
	spin_unlock(&cache_seg->gen_lock);

	spin_lock(&cache->seg_map_lock);
	clear_bit(cache_seg->cache_seg_id, cache->seg_map);
	spin_unlock(&cache->seg_map_lock);

	queue_work(cache->cache_wq, &cache->clean_work);
	//cbd_cache_err(cache, "gc invalidat seg: %u\n", cache_seg->cache_seg_id);

#ifdef CONFIG_CBD_DEBUG
	dump_seg_map(cache);
#endif
}

void cache_seg_put(struct cbd_cache_segment *cache_seg)
{
	//cbd_cache_err(cache_seg->cache, "before put seg id: %u, ref: %u\n", cache_seg->cache_seg_id, atomic_read(&cache_seg->refs));
	if (atomic_dec_and_test(&cache_seg->refs))
		cache_seg_invalidate(cache_seg);
}
