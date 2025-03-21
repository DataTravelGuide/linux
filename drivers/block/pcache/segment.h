/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _PCACHE_SEGMENT_H
#define _PCACHE_SEGMENT_H

#include <linux/bio.h>

#include "pcache_internal.h"

#define segment_err(segment, fmt, ...)					\
	cache_dev_err(segment->cache_dev, "segment%d: " fmt,				\
		 segment->seg_id, ##__VA_ARGS__)
#define segment_info(segment, fmt, ...)					\
	cache_dev_info(segment->cache_dev, "segment%d: " fmt,				\
		 segment->seg_id, ##__VA_ARGS__)
#define segment_debug(segment, fmt, ...)					\
	cache_dev_debug(segment->cache_dev, "segment%d: " fmt,				\
		 segment->seg_id, ##__VA_ARGS__)


#define PCACHE_SEGMENT_STATE_NONE		0
#define PCACHE_SEGMENT_STATE_RUNNING	1

#define PCACHES_TYPE_NONE			0
#define PCACHES_TYPE_META			1
#define PCACHE_SEGMENT_TYPE_DATA			2

static inline const char *segment_type_str(u8 type)
{
	if (type == PCACHES_TYPE_META)
		return "meta";
	else if (type == PCACHE_SEGMENT_TYPE_DATA)
		return "data";

	return "Unknown";
}

struct segment_info {
	struct pcache_meta_header	header;	/* Metadata header for the segment */
	u8			type;
	u8			state;
	u16			flags;
	u32			next_seg;
	u32			seg_id;
	u32			data_off;
};

#define PCACHE_SEG_INFO_FLAGS_HAS_NEXT	(1 << 0)

static inline bool segment_info_has_next(struct segment_info *seg_info)
{
	return (seg_info->flags & PCACHE_SEG_INFO_FLAGS_HAS_NEXT);
}

struct segment_pos {
	struct pcache_segment	*segment;	/* Segment associated with the position */
	u32			off;		/* Offset within the segment */
};

struct pcache_segment_init_options {
	u8			type;
	u8			state;
	u32			seg_id;
	u32			data_off;

	struct segment_info	*seg_info;
};

struct pcache_segment {
	struct pcache_cache_dev	*cache_dev;

	void			*data;
	u32			data_size;

	struct segment_info	*seg_info;
};

//void segment_info_clear(struct pcache_segment *segment);
//void segment_clear(struct pcache_cache_dev *cache_dev, u32 segment_id);
//void segment_init(struct pcache_cache_dev *cache_dev, struct pcache_segment *segment,
//		      struct segment_init_options *options);
int segment_copy_to_bio(struct pcache_segment *segment,
		      u32 data_off, u32 data_len, struct bio *bio, u32 bio_off);
void segment_copy_from_bio(struct pcache_segment *segment,
			u32 data_off, u32 data_len, struct bio *bio, u32 bio_off);
//u32 segment_crc(struct pcache_segment *segment, u32 data_off, u32 data_len);
//int segment_map_pages(struct pcache_segment *segment,
//		   struct bio *bio,
//		   u32 off, u32 size);
int segment_pos_advance(struct segment_pos *seg_pos, u32 len);
void segment_copy_data(struct segment_pos *dst_pos,
		    struct segment_pos *src_pos, u32 len);
//void *segment_addr(struct pcache_segment *segment);
//
int pcache_segment_init(struct pcache_cache_dev *cache_dev, struct pcache_segment *segment,
		      struct pcache_segment_init_options *options);
void pcache_segment_clear(struct pcache_cache_dev *cache_dev, u32 seg_id);

void pcache_segment_info_write(struct pcache_cache_dev *cache_dev, struct segment_info *seg_info, u32 seg_id);
struct segment_info *pcache_segment_info_read(struct pcache_cache_dev *cache_dev, u32 set_id);

#endif /* _PCACHE_SEGMENT_H */
