// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/dax.h>

#include "pcache_internal.h"
#include "cache_dev.h"
#include "cache.h"
#include "backing_dev.h"
#include "meta_segment.h"
#include "segment.h"

int segment_pos_advance(struct pcache_segment_pos *seg_pos, u32 len)
{
	u32 to_advance;

	while (len) {
		to_advance = len;

		if (to_advance > seg_pos->segment->data_size - seg_pos->off)
			to_advance = seg_pos->segment->data_size - seg_pos->off;

		seg_pos->off += to_advance;

		len -= to_advance;
	}

	return 0;
}

int segment_copy_to_bio(struct pcache_segment *segment,
		u32 data_off, u32 data_len, struct bio *bio, u32 bio_off)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	void *dst;
	u32 to_copy, page_off = 0;
	struct pcache_segment_pos pos = { .segment = segment,
				   .off = data_off };
next:
	bio_for_each_segment(bv, bio, iter) {
		if (bio_off > bv.bv_len) {
			bio_off -= bv.bv_len;
			continue;
		}
		page_off = bv.bv_offset;
		page_off += bio_off;
		bio_off = 0;

		dst = kmap_local_page(bv.bv_page);
again:
		segment = pos.segment;

		to_copy = min(bv.bv_offset + bv.bv_len - page_off,
				segment->data_size - pos.off);
		if (to_copy > data_len)
			to_copy = data_len;

		flush_dcache_page(bv.bv_page);
		memcpy(dst + page_off, segment->data + pos.off, to_copy);

		/* advance */
		pos.off += to_copy;
		page_off += to_copy;
		data_len -= to_copy;
		if (!data_len) {
			kunmap_local(dst);
			return 0;
		}

		/* more data in this bv page */
		if (page_off < bv.bv_offset + bv.bv_len)
			goto again;
		kunmap_local(dst);
	}

	if (bio->bi_next) {
		bio = bio->bi_next;
		goto next;
	}

	return 0;
}

void segment_copy_from_bio(struct pcache_segment *segment,
		u32 data_off, u32 data_len, struct bio *bio, u32 bio_off)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	void *src;
	u32 to_copy, page_off = 0;
	struct pcache_segment_pos pos = { .segment = segment,
				   .off = data_off };
next:
	bio_for_each_segment(bv, bio, iter) {
		if (bio_off > bv.bv_len) {
			bio_off -= bv.bv_len;
			continue;
		}
		page_off = bv.bv_offset;
		page_off += bio_off;
		bio_off = 0;

		src = kmap_local_page(bv.bv_page);
again:
		segment = pos.segment;

		to_copy = min(bv.bv_offset + bv.bv_len - page_off,
				segment->data_size - pos.off);
		if (to_copy > data_len)
			to_copy = data_len;

		memcpy_flushcache(segment->data + pos.off, src + page_off, to_copy);
		flush_dcache_page(bv.bv_page);

		/* advance */
		pos.off += to_copy;
		page_off += to_copy;
		data_len -= to_copy;
		if (!data_len) {
			kunmap_local(src);
			return;
		}

		/* more data in this bv page */
		if (page_off < bv.bv_offset + bv.bv_len)
			goto again;
		kunmap_local(src);
	}

	if (bio->bi_next) {
		bio = bio->bi_next;
		goto next;
	}
}

int pcache_segment_init(struct pcache_cache_dev *cache_dev, struct pcache_segment *segment,
		      struct pcache_segment_init_options *options)
{
	segment->seg_info = options->seg_info;

	segment->seg_info->type = options->type;
	segment->seg_info->state = options->state;
	segment->seg_info->seg_id = options->seg_id;
	segment->seg_info->data_off = options->data_off;

	segment->cache_dev = cache_dev;
	segment->data_size = PCACHE_SEG_SIZE - options->data_off;
	segment->data = CACHE_DEV_SEGMENT(cache_dev, options->seg_id) + options->data_off;

	return 0;
}

void pcache_segment_info_write(struct pcache_cache_dev *cache_dev, struct pcache_segment_info *seg_info, u32 seg_id)
{
	struct pcache_segment_info *seg_info_addr;

	seg_info->header.seq++;

	seg_info_addr = CACHE_DEV_SEGMENT(cache_dev, seg_id);
	seg_info_addr = pcache_meta_find_oldest(&seg_info_addr->header, PCACHE_SEG_INFO_SIZE);

	memcpy(seg_info_addr, seg_info, sizeof(struct pcache_segment_info));

	seg_info_addr->header.crc = pcache_meta_crc(&seg_info_addr->header, PCACHE_SEG_INFO_SIZE);
	cache_dev_flush(cache_dev, seg_info_addr, PCACHE_SEG_INFO_SIZE);

}

struct pcache_segment_info *pcache_segment_info_read(struct pcache_cache_dev *cache_dev, u32 seg_id)
{
	struct pcache_segment_info *seg_info_addr;

	seg_info_addr = CACHE_DEV_SEGMENT(cache_dev, seg_id);

	return pcache_meta_find_latest(&seg_info_addr->header, PCACHE_SEG_INFO_SIZE);
}
