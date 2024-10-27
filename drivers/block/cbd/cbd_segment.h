/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CBD_SEGMENT_H
#define _CBD_SEGMENT_H

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/blk-mq.h>
#include <asm/byteorder.h>
#include <asm/types.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/dax.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/parser.h>
#include <linux/idr.h>
#include <linux/workqueue.h>
#include <linux/uuid.h>
#include <linux/bitfield.h>
#include <linux/crc32.h>
#include <linux/hashtable.h>

extern struct cbd_transport;

CBD_DEVICE(segment);

enum cbd_segment_state {
	cbd_segment_state_none		= 0,
	cbd_segment_state_running,
};

enum cbd_seg_type {
	cbds_type_none = 0,
	cbds_type_channel,
	cbds_type_cache
};

static inline const char *cbds_type_str(enum cbd_seg_type type)
{
	if (type == cbds_type_channel)
		return "channel";
	else if (type == cbds_type_cache)
		return "cache";

	return "Unknown";
}

struct cbd_segment_info {
	struct cbd_meta_header	meta_header;
	u8			type;
	u8			state;
	u16			flags;
	u32			next_seg;
};

#define CBD_SEG_INFO_FLAGS_HAS_NEXT	(1 << 0)

struct cbd_seg_pos {
	struct cbd_segment *segment;
	u32 off;
};

struct cbd_seg_ops {
	void (*sanitize_pos)(struct cbd_seg_pos *pos);
};

struct cbds_init_options {
	enum cbd_seg_type type;
	enum cbd_segment_state state;
	u32 seg_id;
	u32 data_off;
	struct cbd_seg_ops *seg_ops;
};

struct cbd_segment {
	struct cbd_transport		*cbdt;
	struct cbd_seg_ops		*seg_ops;
	u32				seg_id;

	void				*data;
	u32				data_size;

	struct delayed_work		hb_work; /* heartbeat work */
};

void cbd_segment_info_clear(struct cbd_segment *segment);
void cbd_segment_clear(struct cbd_transport *cbdt, u32 segment_id);
void cbd_segment_init(struct cbd_transport *cbdt, struct cbd_segment *segment,
		      struct cbds_init_options *options);
void cbd_segment_exit(struct cbd_segment *segment);
bool cbd_segment_info_is_alive(struct cbd_segment_info *info);
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

#endif /* _CBD_SEGMENT_H */
