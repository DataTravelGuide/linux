/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _CBD_CHANNEL_H
#define _CBD_CHANNEL_H

#include "cbd_internal.h"

#include "cbd_segment.h"

#include "cbd_cache/cbd_cache.h"

#define cbd_channel_err(channel, fmt, ...)					\
	cbdt_err(channel->cbdt, "channel%d: " fmt,				\
		 channel->seg_id, ##__VA_ARGS__)
#define cbd_channel_info(channel, fmt, ...)					\
	cbdt_info(channel->cbdt, "channel%d: " fmt,				\
		 channel->seg_id, ##__VA_ARGS__)
#define cbd_channel_debug(channel, fmt, ...)					\
	cbdt_debug(channel->cbdt, "channel%d: " fmt,				\
		 channel->seg_id, ##__VA_ARGS__)

enum cbd_op {
	CBD_OP_WRITE = 0,
	CBD_OP_READ,
	CBD_OP_FLUSH,
};

struct cbd_se {
#ifdef CONFIG_CBD_CRC
	u32			se_crc;		/* should be the first member */
	u32			data_crc;
#endif
	u32			op;
	u32			flags;
	u64			req_tid;

	u64			offset;
	u32			len;

	u32			data_off;
	u32			data_len;
};

struct cbd_ce {
#ifdef CONFIG_CBD_CRC
	u32		ce_crc;		/* should be the first member */
	u32		data_crc;
#endif
	u64		req_tid;
	u32		result;
	u32		flags;
};

#ifdef CONFIG_CBD_CRC
static inline u32 cbd_se_crc(struct cbd_se *se)
{
	return crc32(0, (void *)se + 4, sizeof(*se) - 4);
}

static inline u32 cbd_ce_crc(struct cbd_ce *ce)
{
	return crc32(0, (void *)ce + 4, sizeof(*ce) - 4);
}
#endif

/* cbd channel segment metadata */
#define CBDC_META_SIZE          (4 * 1024 * 1024)                   /* Metadata size for each CBD channel segment (4 MB) */
#define CBDC_SUBMR_RESERVED     sizeof(struct cbd_se)               /* Reserved space for SUBMR (submission metadata region) */
#define CBDC_COMPR_RESERVED      sizeof(struct cbd_ce)               /* Reserved space for COMPR (completion metadata region) */

#define CBDC_DATA_ALIGN         4096                                /* Data alignment boundary (4 KB) */
#define CBDC_DATA_RESERVED      CBDC_DATA_ALIGN                     /* Reserved space aligned to data boundary */

#define CBDC_CTRL_OFF           (CBDT_SEG_INFO_SIZE * CBDT_META_INDEX_MAX)  /* Offset for control data */
#define CBDC_CTRL_SIZE          PAGE_SIZE                           /* Control data size (1 page) */
#define CBDC_COMPR_OFF          (CBDC_CTRL_OFF + CBDC_CTRL_SIZE)    /* Offset for COMPR metadata */
#define CBDC_COMPR_SIZE         (sizeof(struct cbd_ce) * 1024)      /* Size of COMPR metadata region (1024 entries) */
#define CBDC_SUBMR_OFF          (CBDC_COMPR_OFF + CBDC_COMPR_SIZE)  /* Offset for SUBMR metadata */
#define CBDC_SUBMR_SIZE         (CBDC_META_SIZE - CBDC_SUBMR_OFF)   /* Size of SUBMR metadata region */

#define CBDC_DATA_OFF           CBDC_META_SIZE                      /* Offset for data storage following metadata */
#define CBDC_DATA_SIZE          (CBDT_SEG_SIZE - CBDC_META_SIZE)    /* Size of data storage in a segment */

/* Update macros for SUBMR head and tail pointers */
#define CBDC_UPDATE_SUBMR_HEAD(head, used, size)    (head = ((head % size) + used) % size)
#define CBDC_UPDATE_SUBMR_TAIL(tail, used, size)    (tail = ((tail % size) + used) % size)

/* Update macros for COMPR head and tail pointers */
#define CBDC_UPDATE_COMPR_HEAD(head, used, size)    (head = ((head % size) + used) % size)
#define CBDC_UPDATE_COMPR_TAIL(tail, used, size)    (tail = ((tail % size) + used) % size)

/* cbd_channel */
enum cbdc_blkdev_state {
	cbdc_blkdev_state_none		= 0,
	cbdc_blkdev_state_running,
};

enum cbdc_backend_state {
	cbdc_backend_state_none		= 0,
	cbdc_backend_state_running,
};

struct cbd_channel_seg_info {
	struct cbd_segment_info seg_info;	/* must be the first member */
	u32	backend_id;
};

struct cbd_channel_ctrl {
	u64	polling:1;
	u64	need_reset:1;

	u32	submr_head;
	u32	submr_tail;

	u32	compr_head;
	u32	compr_tail;
};

struct cbd_channel_init_options {
	struct cbd_transport *cbdt;
	bool	new_channel;

	u32	seg_id;
	u32	backend_id;
};

struct cbd_channel {
	u32				seg_id;
	struct cbd_segment		segment;

	struct cbd_channel_seg_info	channel_info;
	struct mutex			info_lock;
	u32				info_index;

	struct cbd_transport		*cbdt;

	struct cbd_channel_ctrl		*ctrl;
	void				*submr;
	void				*compr;

	u32				submr_size;
	u32				compr_size;

	u32				data_size;
	u32				data_head;
	u32				data_tail;

	spinlock_t			submr_lock;
	spinlock_t			compr_lock;
};

int cbd_channel_init(struct cbd_channel *channel, struct cbd_channel_init_options *init_opts);
void cbd_channel_destroy(struct cbd_channel *channel);
void cbdc_copy_from_bio(struct cbd_channel *channel,
		u32 data_off, u32 data_len, struct bio *bio, u32 bio_off);
void cbdc_copy_to_bio(struct cbd_channel *channel,
		u32 data_off, u32 data_len, struct bio *bio, u32 bio_off);
u32 cbd_channel_crc(struct cbd_channel *channel, u32 data_off, u32 data_len);
int cbdc_map_pages(struct cbd_channel *channel, struct bio *bio, u32 off, u32 size);

#endif /* _CBD_CHANNEL_H */
