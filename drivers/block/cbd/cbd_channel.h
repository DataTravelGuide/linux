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
#ifdef CONFIG_CBD_CHANNEL_CRC
	u32			se_crc;		/* should be the first member */
#endif
#ifdef CONFIG_CBD_CHANNEL_DATA_CRC
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
#ifdef CONFIG_CBD_CHANNEL_CRC
	u32		ce_crc;		/* should be the first member */
#endif
#ifdef CONFIG_CBD_CHANNEL_DATA_CRC
	u32		data_crc;
#endif
	u64		req_tid;
	u32		result;
	u32		flags;
};

static inline u32 cbd_se_crc(struct cbd_se *se)
{
	return crc32(0, (void *)se + 4, sizeof(*se) - 4);
}

static inline u32 cbd_ce_crc(struct cbd_ce *ce)
{
	return crc32(0, (void *)ce + 4, sizeof(*ce) - 4);
}

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

struct cbd_channel_seg_info {
	struct cbd_segment_info seg_info;	/* must be the first member */
	u32	backend_id;
};

/**
 * struct cbdc_mgmt_cmd - Management command structure for CBD channel
 * @header:        Metadata header for data integrity protection
 * @cmd_seq:      Command sequence number
 * @cmd_op:       Command operation type
 * @res:          Reserved field
 * @res1:         Additional reserved field
 *
 * This structure is used for data transfer of management commands
 * within a CBD channel. Note that a CBD channel can only handle
 * one mgmt_cmd at a time. If there is a management plane request
 * on the blkdev side, it will be written into channel_ctrl->mgmt_cmd.
 * The mgmt_cmd is protected by the meta_header for data integrity
 * and is double updated. When the handler's mgmt_worker detects
 * a new mgmt_cmd, it processes it and writes the result into
 * channel_ctrl->mgmt_ret, where mgmt_ret->cmd_seq equals the
 * corresponding mgmt_cmd->cmd_seq.
 */
struct cbdc_mgmt_cmd {
	struct cbd_meta_header header;  /**< Metadata header */
	u8 cmd_seq;                     /**< Command sequence number */
	u8 cmd_op;                      /**< Command operation type */
	u16 res;                        /**< Reserved field */
	u32 res1;                       /**< Additional reserved field */
};

enum cbdc_mgmt_cmd_op {
	cbdc_mgmt_cmd_none	= 0,
	cbdc_mgmt_cmd_reset,
};

/**
 * struct cbdc_mgmt_ret - Management command result structure for CBD channel
 * @header:        Metadata header for data integrity protection
 * @cmd_seq:      Command sequence number corresponding to the mgmt_cmd
 * @cmd_ret:      Command return value
 * @res:          Reserved field
 * @res1:         Additional reserved field
 *
 * This structure contains the result after the handler processes
 * the management command (mgmt_cmd). The result is written into
 * channel_ctrl->mgmt_ret, where cmd_seq equals the corresponding
 * mgmt_cmd->cmd_seq.
 */
struct cbdc_mgmt_ret {
	struct cbd_meta_header header;  /**< Metadata header */
	u8 cmd_seq;                     /**< Command sequence number */
	u8 cmd_ret;                     /**< Command return value */
	u16 res;                        /**< Reserved field */
	u32 res1;                       /**< Additional reserved field */
};

enum cbdc_mgmt_cmd_ret {
	cbdc_mgmt_cmd_ret_ok	= 0,
	cbdc_mgmt_cmd_ret_eio
};

static inline int cbdc_mgmt_cmd_ret_to_errno(enum cbdc_mgmt_cmd_ret cmd_ret)
{
	int ret;

	switch (cmd_ret) {
	case cbdc_mgmt_cmd_ret_ok:
		ret = 0;
		break;
	case cbdc_mgmt_cmd_ret_eio:
		ret = -EIO;
		break;
	default:
		ret = -EFAULT;
	}

	return ret;
}

struct cbd_channel_ctrl {
	u64	flags;

	/* management plane */
	struct cbdc_mgmt_cmd	mgmt_cmd[CBDT_META_INDEX_MAX];
	struct cbdc_mgmt_ret	mgmt_ret[CBDT_META_INDEX_MAX];

	/* data plane */
	u32	submr_head;
	u32	submr_tail;

	u32	compr_head;
	u32	compr_tail;
};

#define CBDC_FLAGS_POLLING		(1 << 0)

static inline struct cbdc_mgmt_cmd *__mgmt_latest_cmd(struct cbd_channel_ctrl *channel_ctrl)
{
	struct cbd_meta_header *meta_latest;

	meta_latest = cbd_meta_find_latest(&channel_ctrl->mgmt_cmd->header,
					   sizeof(struct cbdc_mgmt_cmd), NULL);
	if (!meta_latest)
		return NULL;

	return (struct cbdc_mgmt_cmd *)meta_latest;
}

static inline struct cbdc_mgmt_cmd *__mgmt_oldest_cmd(struct cbd_channel_ctrl *channel_ctrl)
{
	struct cbd_meta_header *meta_oldest;

	meta_oldest = cbd_meta_find_oldest(&channel_ctrl->mgmt_cmd->header,
					   sizeof(struct cbdc_mgmt_cmd));

	return (struct cbdc_mgmt_cmd *)meta_oldest;
}

static inline struct cbdc_mgmt_ret *__mgmt_latest_ret(struct cbd_channel_ctrl *channel_ctrl)
{
	struct cbd_meta_header *meta_latest;

	meta_latest = cbd_meta_find_latest(&channel_ctrl->mgmt_ret->header,
					   sizeof(struct cbdc_mgmt_ret), NULL);
	if (!meta_latest)
		return NULL;

	return (struct cbdc_mgmt_ret *)meta_latest;
}

static inline struct cbdc_mgmt_ret *__mgmt_oldest_ret(struct cbd_channel_ctrl *channel_ctrl)
{
	struct cbd_meta_header *meta_oldest;

	meta_oldest = cbd_meta_find_oldest(&channel_ctrl->mgmt_ret->header,
					   sizeof(struct cbdc_mgmt_ret));

	return (struct cbdc_mgmt_ret *)meta_oldest;
}

static inline u8 cbdc_mgmt_latest_cmd_seq(struct cbd_channel_ctrl *channel_ctrl)
{
	struct cbdc_mgmt_cmd *cmd_latest;

	cmd_latest = __mgmt_latest_cmd(channel_ctrl);
	if (!cmd_latest)
		return 0;

	return cmd_latest->cmd_seq;
}

static inline u8 cbdc_mgmt_latest_ret_seq(struct cbd_channel_ctrl *channel_ctrl)
{
	struct cbdc_mgmt_ret *ret_latest;

	ret_latest = __mgmt_latest_ret(channel_ctrl);
	if (!ret_latest)
		return 0;

	return ret_latest->cmd_seq;
}

/**
 * cbdc_mgmt_completed - Check if the management command has been processed
 * @channel_ctrl: Pointer to the CBD channel control structure
 *
 * This function is important for the management plane of the CBD channel.
 * It indicates whether the current mgmt_cmd has been processed.
 *
 * (1) If processing is complete, the latest mgmt_ret can be retrieved as the
 * result, and a new mgmt_cmd can be sent.
 * (2) If processing is not complete, it indicates that the management plane
 * is busy and a new mgmt_cmd cannot be sent. The CBD channel management
 * plane can only handle one mgmt_cmd at a time.
 *
 * Return: true if the mgmt_cmd has been processed, false otherwise.
 */
static inline bool cbdc_mgmt_completed(struct cbd_channel_ctrl *channel_ctrl)
{
	u8 cmd_seq = cbdc_mgmt_latest_cmd_seq(channel_ctrl);
	u8 ret_seq = cbdc_mgmt_latest_ret_seq(channel_ctrl);

	return (cmd_seq == ret_seq);
}

static inline enum cbdc_mgmt_cmd_op cbdc_mgmt_cmd_op_get(struct cbd_channel_ctrl *channel_ctrl)
{
	struct cbdc_mgmt_cmd *cmd_latest;

	cmd_latest = __mgmt_latest_cmd(channel_ctrl);
	if (!cmd_latest)
		return cbdc_mgmt_cmd_none;

	return cmd_latest->cmd_op;
}

static inline int cbdc_mgmt_cmd_op_send(struct cbd_channel_ctrl *channel_ctrl, enum cbdc_mgmt_cmd_op op)
{
	struct cbdc_mgmt_cmd *cmd_oldest;
	u32 latest_seq;

	if (!cbdc_mgmt_completed(channel_ctrl))
		return -EBUSY;

	latest_seq = cbdc_mgmt_latest_cmd_seq(channel_ctrl);

	cmd_oldest = __mgmt_oldest_cmd(channel_ctrl);
	cmd_oldest->cmd_seq = (latest_seq + 1);
	cmd_oldest->cmd_op = op;

	cmd_oldest->header.seq = cbd_meta_get_next_seq(&channel_ctrl->mgmt_cmd->header,
						       sizeof(struct cbdc_mgmt_cmd));
	cmd_oldest->header.crc = cbd_meta_crc(&cmd_oldest->header, sizeof(struct cbdc_mgmt_cmd));

	return 0;
}

static inline enum cbdc_mgmt_cmd_ret cbdc_mgmt_cmd_ret_get(struct cbd_channel_ctrl *channel_ctrl)
{
	struct cbdc_mgmt_ret *ret_latest;

	ret_latest = __mgmt_latest_ret(channel_ctrl);
	if (!ret_latest)
		return cbdc_mgmt_cmd_ret_ok;

	return ret_latest->cmd_ret;
}

static inline int cbdc_mgmt_cmd_ret_send(struct cbd_channel_ctrl *channel_ctrl, enum cbdc_mgmt_cmd_ret ret)
{
	struct cbdc_mgmt_ret *ret_oldest;
	u32 latest_seq;

	if (cbdc_mgmt_completed(channel_ctrl))
		return -EINVAL;

	latest_seq = cbdc_mgmt_latest_cmd_seq(channel_ctrl);

	ret_oldest = __mgmt_oldest_ret(channel_ctrl);
	ret_oldest->cmd_seq = latest_seq;
	ret_oldest->cmd_ret = ret;

	ret_oldest->header.seq = cbd_meta_get_next_seq(&channel_ctrl->mgmt_ret->header,
						       sizeof(struct cbdc_mgmt_ret));
	ret_oldest->header.crc = cbd_meta_crc(&ret_oldest->header, sizeof(struct cbdc_mgmt_ret));

	return 0;
}

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

static inline u64 cbd_channel_flags_get(struct cbd_channel_ctrl *channel_ctrl)
{
	/* get value written by the writter */
	return smp_load_acquire(&channel_ctrl->flags);
}

static inline void cbd_channel_flags_set_bit(struct cbd_channel_ctrl *channel_ctrl, u64 set)
{
	u64 flags = cbd_channel_flags_get(channel_ctrl);

	flags |= set;
	/* order the update of flags */
	smp_store_release(&channel_ctrl->flags, flags);
}

static inline void cbd_channel_flags_clear_bit(struct cbd_channel_ctrl *channel_ctrl, u64 clear)
{
	u64 flags = cbd_channel_flags_get(channel_ctrl);

	flags &= ~clear;
	/* order the update of flags */
	smp_store_release(&channel_ctrl->flags, flags);
}

/**
 * CBDC_CTRL_ACCESSOR - Create accessor functions for channel control members
 * @MEMBER: The name of the member in the control structure.
 * @SIZE: The size of the corresponding ring buffer.
 *
 * This macro defines two inline functions for accessing and updating the
 * specified member of the control structure for a given channel.
 *
 * For submr_head, submr_tail, and compr_tail:
 * (1) They have a unique writer on the blkdev side, while the backend
 *     acts only as a reader.
 *
 * For compr_head:
 * (2) The unique writer is on the backend side, with the blkdev acting
 *     only as a reader.
 */
#define CBDC_CTRL_ACCESSOR(MEMBER, SIZE)						\
static inline u32 cbdc_##MEMBER##_get(struct cbd_channel *channel)			\
{											\
	/* order the ring update */							\
	return smp_load_acquire(&channel->ctrl->MEMBER);				\
}											\
											\
static inline void cbdc_## MEMBER ##_advance(struct cbd_channel *channel, u32 len)	\
{											\
	u32 val = cbdc_## MEMBER ##_get(channel);					\
											\
	val = (val + len) % channel->SIZE;						\
	/* order the ring update */							\
	smp_store_release(&channel->ctrl->MEMBER, val);					\
}

CBDC_CTRL_ACCESSOR(submr_head, submr_size)
CBDC_CTRL_ACCESSOR(submr_tail, submr_size)
CBDC_CTRL_ACCESSOR(compr_head, compr_size)
CBDC_CTRL_ACCESSOR(compr_tail, compr_size)

#endif /* _CBD_CHANNEL_H */
