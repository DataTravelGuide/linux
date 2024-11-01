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


CBD_DEVICE(segment); /* Macro to define CBD device named "segment" */

/* Enumeration for CBD segment states */
enum cbd_segment_state {
	cbd_segment_state_none		= 0,	/* Segment is in a none (uninitialized) state */
	cbd_segment_state_running,		/* Segment is active and running */
};

/* Enumeration for segment types */
enum cbd_seg_type {
	cbds_type_none = 0,		/* No specific segment type */
	cbds_type_channel,		/* Segment type: channel */
	cbds_type_cache			/* Segment type: cache */
};

/**
 * cbds_type_str - Get string representation of segment type.
 * @type: The segment type enumeration.
 *
 * Returns the string corresponding to the segment type.
 */
static inline const char *cbds_type_str(enum cbd_seg_type type)
{
	if (type == cbds_type_channel)
		return "channel";
	else if (type == cbds_type_cache)
		return "cache";

	return "Unknown";
}

/* Structure for CBD segment information */
struct cbd_segment_info {
	struct cbd_meta_header	meta_header;	/* Metadata header for the segment */
	u8			type;		/* Segment type (see enum cbd_seg_type) */
	u8			state;		/* Segment state (see enum cbd_segment_state) */
	u16			flags;		/* Flags for segment properties */
	u32			next_seg;	/* ID of the next segment (if applicable) */
};

#define CBD_SEG_INFO_FLAGS_HAS_NEXT	(1 << 0) /* Flag indicating segment has a successor */

typedef ssize_t (*detail_show_fn)(struct cbd_segment_info *seg_info, char *buf); /* Type for detail display function */

/* Defined in cbd_channel.c - Shows details of a channel segment */
ssize_t cbd_channel_seg_detail_show(struct cbd_segment_info *seg_info, char *buf);

/* Defined in cbd_cache.c - Shows details of a cache segment */
ssize_t cbd_cache_seg_detail_show(struct cbd_segment_info *seg_info, char *buf);

/**
 * cbd_seg_get_detail_shower - Retrieve detail function based on segment type.
 * @type: Segment type enumeration.
 *
 * Returns the function pointer to the detail display function for a specific
 * segment type.
 */
static inline detail_show_fn cbd_seg_get_detail_shower(enum cbd_seg_type type)
{
	if (type == cbds_type_channel)
		return cbd_channel_seg_detail_show;
	else if (type == cbds_type_cache)
		return cbd_cache_seg_detail_show;

	return NULL;
}

/* Structure defining position within a segment */
struct cbd_seg_pos {
	struct cbd_segment	*segment;	/* Segment associated with the position */
	u32			off;		/* Offset within the segment */
};

/* Operations available for CBD segments */
struct cbd_seg_ops {
	void (*sanitize_pos)(struct cbd_seg_pos *pos); /* Function to sanitize a segment position */
};

/* Initialization options for CBD segments */
struct cbds_init_options {
	enum cbd_seg_type	type;		/* Type of segment */
	enum cbd_segment_state	state;		/* Initial state of the segment */
	u32			seg_id;		/* Segment ID */
	u32			data_off;	/* Data offset within the segment */
	struct cbd_seg_ops	*seg_ops;	/* Segment operations */
};

/* Main CBD segment structure */
struct cbd_segment {
	struct cbd_transport	*cbdt;		/* Associated transport */
	struct cbd_seg_ops	*seg_ops;	/* Segment operations */
	u32			seg_id;		/* Segment ID */

	void			*data;		/* Pointer to segment data */
	u32			data_size;	/* Size of the segment data */
};

/* Function declarations for CBD segment operations */
void cbd_segment_info_clear(struct cbd_segment *segment);
void cbd_segment_clear(struct cbd_transport *cbdt, u32 segment_id);
void cbd_segment_init(struct cbd_transport *cbdt, struct cbd_segment *segment,
		      struct cbds_init_options *options);
void cbds_copy_to_bio(struct cbd_segment *segment,
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

#define cbd_for_each_segment_info(cbdt, i, segment_info)			\
	for (i = 0;								\
	     i < cbdt->transport_info->segment_num &&				\
	     (segment_info = cbdt_segment_info_read(cbdt, i, NULL));		\
	     i++)

#endif /* _CBD_SEGMENT_H */
