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

static int segment_copy_between_bio(struct pcache_segment *segment,
				u32 data_off, u32 data_len,
				struct bio *bio, u32 bio_off,
				bool to_bio)
{
	struct kvec kv = { .iov_base = segment->data + data_off,
			.iov_len  = data_len };
	struct iov_iter seg_iter;
	struct bio_vec bvec;
	struct bvec_iter bio_iter;
	u32 remaining = data_len;
	u32 skip = bio_off;
	ssize_t ret;

	if (to_bio)
		iov_iter_kvec(&seg_iter, WRITE, &kv, 1, data_len);
	else
		iov_iter_kvec(&seg_iter, READ, &kv, 1, data_len);

	bio_for_each_segment(bvec, bio, bio_iter) {
		u32 this_len = bvec.bv_len;

		if (skip) {
			if (skip >= this_len) {
				skip -= this_len;
				continue;
			}
			this_len -= skip;
		}

		if (this_len > remaining)
			this_len = remaining;

		if (to_bio)
			ret = copy_page_from_iter(bvec.bv_page,
						bvec.bv_offset + skip,
						this_len,
						&seg_iter);
		else
			ret = copy_page_to_iter(bvec.bv_page,
						bvec.bv_offset + skip,
						this_len,
						&seg_iter);
		skip = 0;

		if (ret < this_len)
			return -EFAULT;

		remaining -= ret;
		if (!iov_iter_count(&seg_iter))
			break;
	}

	return remaining ? -EFAULT : 0;
}

int segment_copy_to_bio(struct pcache_segment *segment,
		u32 data_off, u32 data_len, struct bio *bio, u32 bio_off)
{
	return segment_copy_between_bio(segment, data_off, data_len,
					bio, bio_off, true);
}

int segment_copy_from_bio(struct pcache_segment *segment,
		u32 data_off, u32 data_len, struct bio *bio, u32 bio_off)
{
	return segment_copy_between_bio(segment, data_off, data_len,
					bio, bio_off, false);
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
