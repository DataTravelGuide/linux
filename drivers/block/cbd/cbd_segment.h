/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _CBD_SEGMENT_H
#define _CBD_SEGMENT_H

#include <linux/bio.h>

#include "cbd_internal.h"

#define cbd_segment_err(segment, fmt, ...)					\
	cbdt_err(segment->cbdt, "segment%d: " fmt,				\
		 segment->seg_id, ##__VA_ARGS__)
#define cbd_segment_info(segment, fmt, ...)					\
	cbdt_info(segment->cbdt, "segment%d: " fmt,				\
		 segment->seg_id, ##__VA_ARGS__)
#define cbd_segment_debug(segment, fmt, ...)					\
	cbdt_debug(segment->cbdt, "segment%d: " fmt,				\
		 segment->seg_id, ##__VA_ARGS__)


CBD_DEVICE(segment);

#define CBD_SEGMENT_STATE_NONE		0
#define CBD_SEGMENT_STATE_RUNNING	1

#define CBDS_TYPE_NONE			0
#define CBDS_TYPE_CHANNEL		1
#define CBDS_TYPE_CACHE			2

static inline const char *cbds_type_str(u8 type)
{
	if (type == CBDS_TYPE_CHANNEL)
		return "channel";
	else if (type == CBDS_TYPE_CACHE)
		return "cache";

	return "Unknown";
}

struct cbd_segment_info {
	struct cbd_meta_header	meta_header;	/* Metadata header for the segment */
	u8			type;
	u8			state;
	u16			flags;
	u32			next_seg;
	u32			backend_id;
};

#define CBD_SEG_INFO_FLAGS_HAS_NEXT	(1 << 0)

static inline bool cbd_segment_info_has_next(struct cbd_segment_info *seg_info)
{
	return (seg_info->flags & CBD_SEG_INFO_FLAGS_HAS_NEXT);
}

struct cbd_seg_pos {
	struct cbd_segment	*segment;	/* Segment associated with the position */
	u32			off;		/* Offset within the segment */
};

struct cbd_seg_ops {
	void (*sanitize_pos)(struct cbd_seg_pos *pos);
};

struct cbds_init_options {
	u8			type;
	u8			state;
	u32			seg_id;
	u32			data_off;
	struct cbd_seg_ops	*seg_ops;
};

struct cbd_segment {
	struct cbd_transport	*cbdt;
	struct cbd_seg_ops	*seg_ops;
	u32			seg_id;

	void			*data;
	u32			data_size;
};

void cbd_segment_info_clear(struct cbd_segment *segment);
void cbd_segment_clear(struct cbd_transport *cbdt, u32 segment_id);
void cbd_segment_init(struct cbd_transport *cbdt, struct cbd_segment *segment,
		      struct cbds_init_options *options);
int cbds_copy_to_bio(struct cbd_segment *segment,
		      u32 data_off, u32 data_len, struct bio *bio, u32 bio_off);
void cbds_copy_from_bio(struct cbd_segment *segment,
			u32 data_off, u32 data_len, struct bio *bio, u32 bio_off);
u32 cbd_seg_crc(struct cbd_segment *segment, u32 data_off, u32 data_len);
int cbds_map_pages(struct cbd_segment *segment,
		   struct bio *bio,
		   u32 off, u32 size);
int cbds_pos_advance(struct cbd_seg_pos *seg_pos, u32 len);
void cbds_copy_data(struct cbd_seg_pos *dst_pos,
		    struct cbd_seg_pos *src_pos, u32 len);
void *cbd_segment_addr(struct cbd_segment *segment);

#define cbd_for_each_segment_info(cbdt, i, segment_info)			\
	for (i = 0;								\
	     i < cbdt->transport_info.segment_num &&				\
	     (segment_info = cbdt_segment_info_read(cbdt, i));			\
	     i++)

#endif /* _CBD_SEGMENT_H */
