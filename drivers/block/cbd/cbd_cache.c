#include "cbd_internal.h"


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

	cache->cbdt = cbdt;
	cache->cache_info = cache_info;
	cache->n_segs = cache_info->n_segs;

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

	for (i = 0; i < cache->n_segs; i++)
		cbd_segment_exit(&cache->segments[i]);

	kfree(cache);
}
