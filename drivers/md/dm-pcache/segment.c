// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/dax.h>

#include "pcache_internal.h"
#include "cache_dev.h"
#include "segment.h"

void segment_pos_advance(struct pcache_segment_pos *seg_pos, u32 len)
{
	u32 to_advance;

	while (len) {
		to_advance = len;

		if (to_advance > seg_pos->segment->data_size - seg_pos->off)
			to_advance = seg_pos->segment->data_size - seg_pos->off;

		seg_pos->off += to_advance;

		len -= to_advance;
	}
}

int segment_copy_to_bio(struct pcache_segment *segment,
		u32 data_off, u32 data_len, struct bio *bio, u32 bio_off)
{
	struct iov_iter iter;
	size_t copied;
	void *src;

	iov_iter_bvec(&iter, ITER_DEST, &bio->bi_io_vec[bio->bi_iter.bi_idx], bio_segments(bio), bio->bi_iter.bi_size);
	iter.iov_offset = bio->bi_iter.bi_bvec_done;
	if (bio_off)
		iov_iter_advance(&iter, bio_off);

	src = segment->data + data_off;
	copied = _copy_mc_to_iter(src, data_len, &iter);
	if (copied != data_len)
		return -EIO;

	return 0;
}

int segment_copy_from_bio(struct pcache_segment *segment,
		u32 data_off, u32 data_len, struct bio *bio, u32 bio_off)
{
	struct iov_iter iter;
	size_t copied;
	void *dst;

	iov_iter_bvec(&iter, ITER_SOURCE, &bio->bi_io_vec[bio->bi_iter.bi_idx], bio_segments(bio), bio->bi_iter.bi_size);
	iter.iov_offset = bio->bi_iter.bi_bvec_done;
	if (bio_off)
		iov_iter_advance(&iter, bio_off);

	dst = segment->data + data_off;
	copied = _copy_from_iter_flushcache(dst, data_len, &iter);
	pmem_wmb();

	if (copied != data_len)
		return -EIO;

	return 0;
}

void pcache_segment_init(struct pcache_cache_dev *cache_dev, struct pcache_segment *segment,
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
