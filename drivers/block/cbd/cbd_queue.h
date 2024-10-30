/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _CBD_QUEUE_H
#define _CBD_QUEUE_H

#include "cbd_channel.h"
#include "cbd_blkdev.h"

#define cbd_queue_err(queue, fmt, ...)						\
	cbd_blk_err(queue->cbd_blkdev, "queue%d: " fmt,				\
		     queue->channel.seg_id, ##__VA_ARGS__)
#define cbd_queue_info(queue, fmt, ...)						\
	cbd_blk_info(queue->cbd_blkdev, "queue%d: " fmt,			\
		     queue->channel.seg_id, ##__VA_ARGS__)
#define cbd_queue_debug(queue, fmt, ...)					\
	cbd_blk_debug(queue->cbd_blkdev, "queue%d: " fmt,			\
		     queue->channel.seg_id, ##__VA_ARGS__)

/* cbd_queue */

struct cbd_request {
	struct cbd_queue	*cbdq;

	struct cbd_se		*se;
	struct cbd_ce		*ce;
	struct request		*req;

	u64			off;
	struct bio		*bio;
	u32			bio_off;
	spinlock_t		lock; /* race between cache and complete_work to access bio */

	enum cbd_op		op;
	u64			req_tid;
	struct list_head	inflight_reqs_node;

	u32			data_off;
	u32			data_len;

	struct work_struct	work;

	struct kref		ref;
	int			ret;
	struct cbd_request	*parent;

	void			*priv_data;
	void (*end_req)(struct cbd_request *cbd_req, void *priv_data);
};

struct cbd_cache_req {
	struct cbd_cache	*cache;
	enum cbd_op		op;
	struct work_struct	work;
};

#define CBD_SE_FLAGS_DONE	1

static inline bool cbd_se_flags_test(struct cbd_se *se, u32 bit)
{
	return (se->flags & bit);
}

static inline void cbd_se_flags_set(struct cbd_se *se, u32 bit)
{
	se->flags |= bit;
}

enum cbd_queue_state {
	cbd_queue_state_none	= 0,
	cbd_queue_state_running,
	cbd_queue_state_removing
};

struct cbd_queue {
	struct cbd_blkdev	*cbd_blkdev;
	u32			index;
	struct list_head	inflight_reqs;
	spinlock_t		inflight_reqs_lock;
	u64			req_tid;

	u64			*released_extents;

	struct cbd_channel_seg_info	*channel_info;
	struct cbd_channel	channel;
	struct cbd_channel_ctrl	*channel_ctrl;

	atomic_t		state;

	struct delayed_work	complete_work;
	struct cbd_worker_cfg	complete_worker_cfg;
};

int cbd_queue_start(struct cbd_queue *cbdq, u32 channel_id);
void cbd_queue_stop(struct cbd_queue *cbdq);
extern const struct blk_mq_ops cbd_mq_ops;
int cbd_queue_req_to_backend(struct cbd_request *cbd_req);
void cbd_req_get(struct cbd_request *cbd_req);
void cbd_req_put(struct cbd_request *cbd_req, int ret);
void cbd_queue_advance(struct cbd_queue *cbdq, struct cbd_request *cbd_req);

static inline struct cbd_se *get_submit_entry(struct cbd_queue *cbdq)
{
	return (struct cbd_se *)(cbdq->channel.submr + cbdc_submr_head_get(&cbdq->channel));
}

static inline struct cbd_se *get_oldest_se(struct cbd_queue *cbdq)
{
	if (cbdc_submr_tail_get(&cbdq->channel) == cbdc_submr_head_get(&cbdq->channel))
		return NULL;

	return (struct cbd_se *)(cbdq->channel.submr + cbdc_submr_tail_get(&cbdq->channel));
}

static inline bool queue_subm_ring_empty(struct cbd_queue *cbdq)
{
	return (cbdc_submr_tail_get(&cbdq->channel) == cbdc_submr_head_get(&cbdq->channel));
}

static inline struct cbd_ce *get_complete_entry(struct cbd_queue *cbdq)
{
	if (cbdc_compr_tail_get(&cbdq->channel) == cbdc_compr_head_get(&cbdq->channel))
		return NULL;

	return (struct cbd_ce *)(cbdq->channel.compr + cbdc_compr_tail_get(&cbdq->channel));
}

#endif /* _CBD_QUEUE_H */
