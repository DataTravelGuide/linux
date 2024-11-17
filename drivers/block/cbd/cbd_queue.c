// SPDX-License-Identifier: GPL-2.0-or-later

#include "cbd_queue.h"

/**
 * end_req - Finalize a CBD request and handle its completion.
 * @ref: Pointer to the kref structure that manages the reference count of the CBD request.
 *
 * This function is called when the reference count of the cbd_request reaches zero. It
 * contains two key operations:
 *
 * (1) If the end_req callback is set in the cbd_request, this callback will be invoked.
 *     This allows different cbd_requests to perform specific operations upon completion.
 *     For example, in the case of a backend request sent in the cache miss reading, it may require
 *     cache-related operations, such as storing data retrieved during a miss read.
 *
 * (2) If cbd_req->req is not NULL, it indicates that this cbd_request corresponds to a
 *     block layer request. The function will finalize the block layer request accordingly.
 */
static void end_req(struct kref *ref)
{
	struct cbd_request *cbd_req = container_of(ref, struct cbd_request, ref);
	struct request *req = cbd_req->req;
	int ret = cbd_req->ret;

	/* Call the end_req callback if it is set */
	if (cbd_req->end_req)
		cbd_req->end_req(cbd_req, cbd_req->priv_data);

	if (req) {
		/* Complete the block layer request based on the return status */
		if (ret == -ENOMEM || ret == -EBUSY)
			blk_mq_requeue_request(req, true);
		else
			blk_mq_end_request(req, errno_to_blk_status(ret));
	}
}

void cbd_req_get(struct cbd_request *cbd_req)
{
	kref_get(&cbd_req->ref);
}

/**
 * This function decreases the reference count of the specified cbd_request. If the
 * reference count reaches zero, the end_req function is called to finalize the request.
 * Additionally, if the cbd_request has a parent and if the current request is being
 * finalized (i.e., the reference count reaches zero), the parent request will also
 * be put, potentially propagating the return status up the hierarchy.
 */
void cbd_req_put(struct cbd_request *cbd_req, int ret)
{
	struct cbd_request *parent = cbd_req->parent;

	/* Set the return status if it is not already set */
	if (ret && !cbd_req->ret)
		cbd_req->ret = ret;

	/* Decrease the reference count and finalize the request if it reaches zero */
	if (kref_put(&cbd_req->ref, end_req) && parent)
		cbd_req_put(parent, ret);
}

/**
 * When a submission entry is completed, it is marked with the CBD_SE_FLAGS_DONE flag.
 * If the entry is the oldest one in the submission queue, the tail of the submission ring
 * can be advanced. If it is not the oldest, the function will wait until all previous
 * entries have been completed before advancing the tail.
 */
static void advance_subm_ring(struct cbd_queue *cbdq)
{
	struct cbd_se *se;
again:
	se = get_oldest_se(cbdq);
	if (!se)
		goto out;

	if (cbd_se_flags_test(se, CBD_SE_FLAGS_DONE)) {
		cbdc_submr_tail_advance(&cbdq->channel, sizeof(struct cbd_se));
		goto again;
	}
out:
	return;
}

/**
 * This function checks if the specified data offset corresponds to the current
 * data tail. If it does, the function releases the corresponding extent by
 * setting the value in the released_extents array to zero and advances the
 * data tail by the specified length. The data tail is wrapped around if it
 * exceeds the channel's data size.
 */
static bool __advance_data_tail(struct cbd_queue *cbdq, u32 data_off, u32 data_len)
{
	if (data_off == cbdq->channel.data_tail) {
		cbdq->released_extents[data_off / PAGE_SIZE] = 0;
		cbdq->channel.data_tail += data_len;
		cbdq->channel.data_tail %= cbdq->channel.data_size;
		return true;
	}

	return false;
}

/**
 * This function attempts to advance the data tail in the CBD queue by processing
 * the released extents. It first normalizes the data offset with respect to the
 * channel's data size. It then marks the released extent and attempts to advance
 * the data tail by repeatedly checking if the next extent can be released.
 */
static void advance_data_tail(struct cbd_queue *cbdq, u32 data_off, u32 data_len)
{
	data_off %= cbdq->channel.data_size;
	cbdq->released_extents[data_off / PAGE_SIZE] = data_len;

	while (__advance_data_tail(cbdq, data_off, data_len)) {
		data_off += data_len;
		data_off %= cbdq->channel.data_size;
		data_len = cbdq->released_extents[data_off / PAGE_SIZE];
		/*
		 * if data_len in released_extents is zero, means this extent is not released,
		 * break and wait it to be released.
		 */
		if (!data_len)
			break;
	}
}

void cbd_queue_advance(struct cbd_queue *cbdq, struct cbd_request *cbd_req)
{
	spin_lock(&cbdq->channel.submr_lock);
	advance_subm_ring(cbdq);

	if (!cbd_req_nodata(cbd_req) && cbd_req->data_len)
		advance_data_tail(cbdq, cbd_req->data_off, round_up(cbd_req->data_len, PAGE_SIZE));
	spin_unlock(&cbdq->channel.submr_lock);
}

static int queue_ce_verify(struct cbd_queue *cbdq, struct cbd_request *cbd_req,
			   struct cbd_ce *ce)
{
#ifdef CONFIG_CBD_CHANNEL_CRC
	if (ce->ce_crc != cbd_ce_crc(ce)) {
		cbd_queue_err(cbdq, "ce crc bad 0x%x != 0x%x(expected)",
				cbd_ce_crc(ce), ce->ce_crc);
		return -EIO;
	}
#endif

#ifdef CONFIG_CBD_CHANNEL_DATA_CRC
	if (cbd_req->op == CBD_OP_READ &&
		ce->data_crc != cbd_channel_crc(&cbdq->channel,
					       cbd_req->data_off,
					       cbd_req->data_len)) {
		cbd_queue_err(cbdq, "ce data_crc bad 0x%x != 0x%x(expected)",
				cbd_channel_crc(&cbdq->channel,
						cbd_req->data_off,
						cbd_req->data_len),
				ce->data_crc);
		return -EIO;
	}
#endif
	return 0;
}

static int complete_miss(struct cbd_queue *cbdq)
{
	if (cbdwc_need_retry(&cbdq->complete_worker_cfg))
		return -EAGAIN;

	if (inflight_reqs_empty(cbdq)) {
		cbdwc_init(&cbdq->complete_worker_cfg);
		goto out;
	}

	cbdwc_miss(&cbdq->complete_worker_cfg);

	cpu_relax();
	queue_delayed_work(cbdq->cbd_blkdev->task_wq, &cbdq->complete_work, 0);
out:
	return 0;
}

static void complete_work_fn(struct work_struct *work)
{
	struct cbd_queue *cbdq = container_of(work, struct cbd_queue, complete_work.work);
	struct cbd_request *cbd_req;
	struct cbd_ce *ce;
	int ret;
again:
	/* compr_head would be updated by backend handler */
	spin_lock(&cbdq->channel.compr_lock);
	ce = get_complete_entry(cbdq);
	spin_unlock(&cbdq->channel.compr_lock);
	if (!ce)
		goto miss;

	cbd_req = find_inflight_req(cbdq, ce->req_tid);
	if (!cbd_req) {
		cbd_queue_err(cbdq, "inflight request not found: %llu.", ce->req_tid);
		goto miss;
	}

	ret = queue_ce_verify(cbdq, cbd_req, ce);
	if (ret)
		goto miss;

	cbdwc_hit(&cbdq->complete_worker_cfg);
	cbdc_compr_tail_advance(&cbdq->channel, sizeof(struct cbd_ce));
	complete_inflight_req(cbdq, cbd_req, ce->result);
	goto again;
miss:
	ret = complete_miss(cbdq);
	/* -EAGAIN means we need retry according to the complete_worker_cfg */
	if (ret == -EAGAIN)
		goto again;
}

static void cbd_req_init(struct cbd_queue *cbdq, u8 op, struct request *rq)
{
	struct cbd_request *cbd_req = blk_mq_rq_to_pdu(rq);

	cbd_req->req = rq;
	cbd_req->cbdq = cbdq;
	cbd_req->op = op;

	if (!cbd_req_nodata(cbd_req))
		cbd_req->data_len = blk_rq_bytes(rq);
	else
		cbd_req->data_len = 0;

	cbd_req->bio = rq->bio;
	cbd_req->off = (u64)blk_rq_pos(rq) << SECTOR_SHIFT;
}

static void queue_req_se_init(struct cbd_request *cbd_req)
{
	struct cbd_se	*se;
	u64 offset = cbd_req->off;
	u32 length = cbd_req->data_len;

	se = get_submit_entry(cbd_req->cbdq);
	memset(se, 0, sizeof(struct cbd_se));

	se->op = cbd_req->op;
	se->req_tid = cbd_req->req_tid;
	se->offset = offset;
	se->len = length;

	if (!cbd_req_nodata(cbd_req)) {
		se->data_off = cbd_req->cbdq->channel.data_head;
		se->data_len = length;
	}
	cbd_req->se = se;
}

static void cbd_req_crc_init(struct cbd_request *cbd_req)
{
#ifdef CONFIG_CBD_CHANNEL_DATA_CRC
	struct cbd_queue *cbdq = cbd_req->cbdq;

	if (cbd_req->op == CBD_OP_WRITE)
		cbd_req->se->data_crc = cbd_channel_crc(&cbdq->channel,
					       cbd_req->data_off,
					       cbd_req->data_len);
#endif

#ifdef CONFIG_CBD_CHANNEL_CRC
	cbd_req->se->se_crc = cbd_se_crc(cbd_req->se);
#endif
}

static void queue_req_channel_init(struct cbd_request *cbd_req)
{
	struct cbd_queue *cbdq = cbd_req->cbdq;
	struct bio *bio = cbd_req->bio;

	cbd_req->req_tid = cbdq->req_tid++;
	queue_req_se_init(cbd_req);

	if (cbd_req_nodata(cbd_req))
		goto crc_init;

	cbd_req->data_off = cbdq->channel.data_head;
	if (cbd_req->op == CBD_OP_WRITE)
		cbdc_copy_from_bio(&cbdq->channel, cbd_req->data_off,
				   cbd_req->data_len, bio, cbd_req->bio_off);

	cbdq->channel.data_head = round_up(cbdq->channel.data_head + cbd_req->data_len, PAGE_SIZE);
	cbdq->channel.data_head %= cbdq->channel.data_size;
crc_init:
	cbd_req_crc_init(cbd_req);
}

int cbd_queue_req_to_backend(struct cbd_request *cbd_req)
{
	struct cbd_queue *cbdq = cbd_req->cbdq;
	int ret;

	spin_lock(&cbdq->channel.submr_lock);
	/* Check if the submission ring is full or if there is enough data space */
	if (submit_ring_full(cbdq) ||
			!data_space_enough(cbdq, cbd_req)) {
		spin_unlock(&cbdq->channel.submr_lock);
		cbd_req->data_len = 0;
		ret = -ENOMEM;
		goto err;
	}

	/* Get a reference before submission, it will be put in cbd_req completion */
	cbd_req_get(cbd_req);

	inflight_add_req(cbdq, cbd_req);
	queue_req_channel_init(cbd_req);

	cbdc_submr_head_advance(&cbdq->channel, sizeof(struct cbd_se));
	spin_unlock(&cbdq->channel.submr_lock);

	if (cbdq->cbd_blkdev->backend)
		cbd_backend_notify(cbdq->cbd_blkdev->backend, cbdq->channel.seg_id);
	queue_delayed_work(cbdq->cbd_blkdev->task_wq, &cbdq->complete_work, 0);

	return 0;
err:
	return ret;
}

static void queue_req_end_req(struct cbd_request *cbd_req, void *priv_data)
{
	cbd_queue_advance(cbd_req->cbdq, cbd_req);
}

static void cbd_queue_req(struct cbd_queue *cbdq, struct cbd_request *cbd_req)
{
	int ret;

	if (cbdq->cbd_blkdev->cbd_cache) {
		ret = cbd_cache_handle_req(cbdq->cbd_blkdev->cbd_cache, cbd_req);
		goto end;
	}
	cbd_req->end_req = queue_req_end_req;
	ret = cbd_queue_req_to_backend(cbd_req);
end:
	cbd_req_put(cbd_req, ret);
}

static blk_status_t cbd_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	struct request *req = bd->rq;
	struct cbd_queue *cbdq = hctx->driver_data;
	struct cbd_request *cbd_req = blk_mq_rq_to_pdu(bd->rq);

	memset(cbd_req, 0, sizeof(struct cbd_request));
	INIT_LIST_HEAD(&cbd_req->inflight_reqs_node);
	kref_init(&cbd_req->ref);
	spin_lock_init(&cbd_req->lock);

	blk_mq_start_request(bd->rq);

	switch (req_op(bd->rq)) {
	case REQ_OP_FLUSH:
		cbd_req_init(cbdq, CBD_OP_FLUSH, req);
		break;
	case REQ_OP_WRITE:
		cbd_req_init(cbdq, CBD_OP_WRITE, req);
		break;
	case REQ_OP_READ:
		cbd_req_init(cbdq, CBD_OP_READ, req);
		break;
	default:
		return BLK_STS_IOERR;
	}

	cbd_queue_req(cbdq, cbd_req);

	return BLK_STS_OK;
}

static int cbd_init_hctx(struct blk_mq_hw_ctx *hctx, void *driver_data,
			unsigned int hctx_idx)
{
	struct cbd_blkdev *cbd_blkdev = driver_data;
	struct cbd_queue *cbdq;

	cbdq = &cbd_blkdev->queues[hctx_idx];
	hctx->driver_data = cbdq;

	return 0;
}

const struct blk_mq_ops cbd_mq_ops = {
	.queue_rq	= cbd_queue_rq,
	.init_hctx	= cbd_init_hctx,
};

#define CBDQ_RESET_CHANNEL_WAIT_INTERVAL	(HZ / 10)
#define CBDQ_RESET_CHANNEL_WAIT_COUNT		300

/**
 * queue_reset_channel - Sends a reset command to the management layer for a cbd_queue.
 * @cbdq: Pointer to the cbd_queue structure to be reset.
 *
 * This function initiates a channel reset by sending a management command to the
 * corresponding channel control structure. It waits for the reset operation to
 * complete, polling the status and allowing for a timeout to avoid indefinite blocking.
 *
 * Returns 0 on success, or a negative error code on failure (e.g., -ETIMEDOUT).
 */
static int queue_reset_channel(struct cbd_queue *cbdq)
{
	u8 cmd_ret;
	u16 count = 0;
	int ret;

	ret = cbdc_mgmt_cmd_op_send(cbdq->channel_ctrl, CBDC_MGMT_CMD_RESET);
	if (ret) {
		cbd_queue_err(cbdq, "send reset mgmt cmd error: %d\n", ret);
		return ret;
	}

	if (cbdq->cbd_blkdev->backend)
		cbd_backend_mgmt_notify(cbdq->cbd_blkdev->backend, cbdq->channel.seg_id);

	while (true) {
		if (cbdc_mgmt_completed(cbdq->channel_ctrl))
			break;

		if (count++ > CBDQ_RESET_CHANNEL_WAIT_COUNT) {
			ret = -ETIMEDOUT;
			goto err;
		}
		schedule_timeout_uninterruptible(CBDQ_RESET_CHANNEL_WAIT_INTERVAL);
	}
	cmd_ret = cbdc_mgmt_cmd_ret_get(cbdq->channel_ctrl);
	return cbdc_mgmt_cmd_ret_to_errno(cmd_ret);
err:
	return ret;
}

static int queue_channel_init(struct cbd_queue *cbdq, u32 channel_id)
{
	struct cbd_blkdev *cbd_blkdev = cbdq->cbd_blkdev;
	struct cbd_transport *cbdt = cbd_blkdev->cbdt;
	struct cbd_channel_init_options init_opts = { 0 };
	int ret;

	init_opts.cbdt = cbdt;
	init_opts.backend_id = cbdq->cbd_blkdev->backend_id;
	init_opts.seg_id = channel_id;
	init_opts.new_channel = false;
	ret = cbd_channel_init(&cbdq->channel, &init_opts);
	if (ret)
		return ret;

	cbdq->channel_ctrl = cbdq->channel.ctrl;
	if (!cbd_blkdev->backend)
		cbd_channel_flags_set_bit(cbdq->channel_ctrl, CBDC_FLAGS_POLLING);

	ret = queue_reset_channel(cbdq);
	if (ret)
		return ret;

	return 0;
}

static int queue_init(struct cbd_queue *cbdq, u32 channel_id)
{
	int ret;

	INIT_LIST_HEAD(&cbdq->inflight_reqs);
	spin_lock_init(&cbdq->inflight_reqs_lock);
	cbdq->req_tid = 0;
	INIT_DELAYED_WORK(&cbdq->complete_work, complete_work_fn);
	cbdwc_init(&cbdq->complete_worker_cfg);

	ret = queue_channel_init(cbdq, channel_id);
	if (ret)
		return ret;

	return 0;
}

int cbd_queue_start(struct cbd_queue *cbdq, u32 channel_id)
{
	int ret;

	cbdq->released_extents = kzalloc(sizeof(u64) * (CBDC_DATA_SIZE >> PAGE_SHIFT),
					 GFP_KERNEL);
	if (!cbdq->released_extents) {
		ret = -ENOMEM;
		goto out;
	}

	ret = queue_init(cbdq, channel_id);
	if (ret)
		goto free_extents;

	atomic_set(&cbdq->state, cbd_queue_state_running);

	return 0;

free_extents:
	kfree(cbdq->released_extents);
out:
	return ret;
}

void cbd_queue_stop(struct cbd_queue *cbdq)
{
	if (atomic_read(&cbdq->state) != cbd_queue_state_running)
		return;

	cancel_delayed_work_sync(&cbdq->complete_work);
	kfree(cbdq->released_extents);
}
