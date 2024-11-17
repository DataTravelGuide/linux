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

struct cbd_request {
	struct cbd_queue	*cbdq;

	struct cbd_se		*se;
	struct cbd_ce		*ce;
	struct request		*req;

	u64			off;
	struct bio		*bio;
	u32			bio_off;
	spinlock_t		lock; /* race between cache and complete_work to access bio */

	u8			op;
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
	u8			op;
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
	cbd_queue_state_none    = 0,
	cbd_queue_state_running
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

	atomic_t                state;

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
	u32 ce_head = cbdc_compr_head_get(&cbdq->channel);

	if (unlikely(ce_head > (cbdq->channel.compr_size - sizeof(struct cbd_ce))))
		return NULL;

	if (cbdc_compr_tail_get(&cbdq->channel) == cbdc_compr_head_get(&cbdq->channel))
		return NULL;

	return (struct cbd_ce *)(cbdq->channel.compr + cbdc_compr_tail_get(&cbdq->channel));
}

static inline bool cbd_req_nodata(struct cbd_request *cbd_req)
{
	switch (cbd_req->op) {
	case CBD_OP_WRITE:
	case CBD_OP_READ:
		return false;
	case CBD_OP_FLUSH:
		return true;
	default:
		BUG();
	}
}

static inline int copy_data_from_cbdreq(struct cbd_request *cbd_req)
{
	struct bio *bio = cbd_req->bio;
	struct cbd_queue *cbdq = cbd_req->cbdq;
	int ret;

	spin_lock(&cbd_req->lock);
	ret = cbdc_copy_to_bio(&cbdq->channel, cbd_req->data_off, cbd_req->data_len, bio, cbd_req->bio_off);
	spin_unlock(&cbd_req->lock);

	return ret;
}

static inline bool inflight_reqs_empty(struct cbd_queue *cbdq)
{
	bool empty;

	spin_lock(&cbdq->inflight_reqs_lock);
	empty = list_empty(&cbdq->inflight_reqs);
	spin_unlock(&cbdq->inflight_reqs_lock);

	return empty;
}

static inline void inflight_add_req(struct cbd_queue *cbdq, struct cbd_request *cbd_req)
{
	spin_lock(&cbdq->inflight_reqs_lock);
	list_add_tail(&cbd_req->inflight_reqs_node, &cbdq->inflight_reqs);
	spin_unlock(&cbdq->inflight_reqs_lock);
}

static inline void complete_inflight_req(struct cbd_queue *cbdq, struct cbd_request *cbd_req, int ret)
{
	if (cbd_req->op == CBD_OP_READ) {
		int copy_ret = 0;

		spin_lock(&cbdq->channel.submr_lock);
		copy_ret = copy_data_from_cbdreq(cbd_req);
		spin_unlock(&cbdq->channel.submr_lock);

		if (!ret && copy_ret)
			ret = copy_ret;
	}

	spin_lock(&cbdq->inflight_reqs_lock);
	list_del_init(&cbd_req->inflight_reqs_node);
	spin_unlock(&cbdq->inflight_reqs_lock);

	cbd_se_flags_set(cbd_req->se, CBD_SE_FLAGS_DONE);
	cbd_req_put(cbd_req, ret);
}

static inline struct cbd_request *find_inflight_req(struct cbd_queue *cbdq, u64 req_tid)
{
	struct cbd_request *req;
	bool found = false;

	spin_lock(&cbdq->inflight_reqs_lock);
	list_for_each_entry(req, &cbdq->inflight_reqs, inflight_reqs_node) {
		if (req->req_tid == req_tid) {
			found = true;
			break;
		}
	}
	spin_unlock(&cbdq->inflight_reqs_lock);

	if (found)
		return req;

	return NULL;
}

/**
 * data_space_enough - Check if there is sufficient data space available in the cbd_queue.
 * @cbdq: Pointer to the cbd_queue structure to check space in.
 * @cbd_req: Pointer to the cbd_request structure for which space is needed.
 *
 * This function evaluates whether the cbd_queue has enough available data space
 * to accommodate the data length required by the given cbd_request.
 *
 * The available space is calculated based on the current positions of the data_head
 * and data_tail. If data_head is ahead of data_tail, it indicates that the space
 * wraps around; otherwise, it calculates the space linearly.
 *
 * The space needed is rounded up according to the defined data alignment.
 *
 * If the available space minus the reserved space is less than the required space,
 * the function returns false, indicating insufficient space. Otherwise, it returns true.
 */
static inline bool data_space_enough(struct cbd_queue *cbdq, struct cbd_request *cbd_req)
{
	struct cbd_channel *channel = &cbdq->channel;
	u32 space_available = channel->data_size;
	u32 space_needed;

	if (channel->data_head > channel->data_tail) {
		space_available = channel->data_size - channel->data_head;
		space_available += channel->data_tail;
	} else if (channel->data_head < channel->data_tail) {
		space_available = channel->data_tail - channel->data_head;
	}

	space_needed = round_up(cbd_req->data_len, CBDC_DATA_ALIGN);

	if (space_available - CBDC_DATA_RESERVED < space_needed)
		return false;

	return true;
}

/**
 * submit_ring_full - Check if the submission ring is full.
 * @cbdq: Pointer to the cbd_queue structure representing the submission queue.
 *
 * This function determines whether the submission ring buffer for the cbd_queue
 * has enough available space to accept new entries.
 *
 * The available space is calculated based on the current positions of the
 * submission ring head and tail. If the head is ahead of the tail, it indicates
 * that the ring wraps around; otherwise, the available space is calculated
 * linearly.
 *
 * A reserved space is maintained at the end of the ring to prevent it from
 * becoming completely filled, ensuring that there is always some space available
 * for processing. If the available space minus the reserved space is less than
 * the size of a submission entry (cbd_se), the function returns true, indicating
 * the ring is full. Otherwise, it returns false.
 */
static inline bool submit_ring_full(struct cbd_queue *cbdq)
{
	u32 space_available = cbdq->channel.submr_size;
	struct cbd_channel *channel = &cbdq->channel;

	if (cbdc_submr_head_get(channel) > cbdc_submr_tail_get(channel)) {
		space_available = cbdq->channel.submr_size - cbdc_submr_head_get(channel);
		space_available += cbdc_submr_tail_get(channel);
	} else if (cbdc_submr_head_get(channel) < cbdc_submr_tail_get(channel)) {
		space_available = cbdc_submr_tail_get(channel) - cbdc_submr_head_get(channel);
	}

	/* There is a SUBMR_RESERVED we dont use to prevent the ring to be used up */
	if (space_available - CBDC_SUBMR_RESERVED < sizeof(struct cbd_se))
		return true;

	return false;
}

#endif /* _CBD_QUEUE_H */
