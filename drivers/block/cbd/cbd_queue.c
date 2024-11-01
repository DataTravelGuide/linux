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
 *     For example, in the case of a backend request sent to the cache, it may require
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
 * cbd_req_put - Decrease the reference count of a CBD request and handle its finalization.
 * @cbd_req: Pointer to the cbd_request to be released.
 * @ret: Return status to be set in the cbd_request if it is not already set.
 *
 * This function decreases the reference count of the specified cbd_request. If the
 * reference count reaches zero, the end_req function is called to finalize the request.
 * Additionally, if the cbd_request has a parent and if the current request is being
 * finalized (i.e., the reference count reaches zero), the parent request will also
 * be put, potentially propagating the return status up the hierarchy.
 *
 * The function checks if a return status is provided and if the cbd_request does not
 * already have a return status set. If both conditions are met, it updates the
 * cbd_request's return status with the provided value.
 */
void cbd_req_put(struct cbd_request *cbd_req, int ret)
{
	struct cbd_request *parent = cbd_req->parent;

	/* Set the return status if it is not already set */
	if (ret && !cbd_req->ret)
		cbd_req->ret = ret;

	/* Decrease the reference count and finalize the request if it reaches zero */
	if (kref_put(&cbd_req->ref, end_req) && parent)
		cbd_req_put(parent, ret); /* Propagate the return status to the parent */
}

/**
 * advance_subm_ring - Advance the tail of the submission ring for a CBD queue.
 * @cbdq: Pointer to the cbd_queue structure representing the queue.
 *
 * This function is called when a submission entry (se) completes. Since the completion
 * of submission entries does not necessarily occur in the order they were sent, this
 * function checks the status of the oldest submission entry.
 *
 * When a submission entry is completed, it is marked with the CBD_SE_FLAGS_DONE flag.
 * If the entry is the oldest one in the submission queue, the tail of the submission ring
 * can be advanced. If it is not the oldest, the function will wait until all previous
 * entries have been completed before advancing the tail.
 *
 * The function repeatedly checks for the oldest submission entry using get_oldest_se.
 * If it finds an entry marked as done, it advances the tail using cbdc_submr_tail_advance
 * and continues checking for additional completed entries until no more are found.
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
 * __advance_data_tail - Attempt to advance the data tail of a CBD queue.
 * @cbdq: Pointer to the cbd_queue structure representing the queue.
 * @data_off: Offset of the data to be advanced.
 * @data_len: Length of the data to be advanced.
 *
 * This function checks if the specified data offset corresponds to the current
 * data tail. If it does, the function releases the corresponding extent by
 * setting the value in the released_extents array to zero and advances the
 * data tail by the specified length. The data tail is wrapped around if it
 * exceeds the channel's data size.
 *
 * Returns true if the data tail was successfully advanced, false otherwise.
 */
static bool __advance_data_tail(struct cbd_queue *cbdq, u32 data_off, u32 data_len)
{
	if (data_off == cbdq->channel.data_tail) {
		cbdq->released_extents[data_off / PAGE_SIZE] = 0;
		cbdq->channel.data_tail += data_len; /* Advance data tail */
		cbdq->channel.data_tail %= cbdq->channel.data_size; /* Wrap around if needed */
		return true;
	}

	return false; // No advancement made
}

/**
 * advance_data_tail - Advance the data tail of a CBD queue based on released extents.
 * @cbdq: Pointer to the cbd_queue structure representing the queue.
 * @data_off: Offset of the data to be advanced.
 * @data_len: Length of the data to be advanced.
 *
 * This function attempts to advance the data tail in the CBD queue by processing
 * the released extents. It first normalizes the data offset with respect to the
 * channel's data size. It then marks the released extent and attempts to advance
 * the data tail by repeatedly checking if the next extent can be released.
 *
 * The function continues advancing the data tail until it encounters an extent
 * that is not yet released or until there are no more extents to advance.
 */
static void advance_data_tail(struct cbd_queue *cbdq, u32 data_off, u32 data_len)
{
	data_off %= cbdq->channel.data_size; /* Normalize data offset */
	cbdq->released_extents[data_off / PAGE_SIZE] = data_len; /* Mark extent as released */

	while (__advance_data_tail(cbdq, data_off, data_len)) {
		data_off += data_len; /* move to next extent */
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

/**
 * cbd_queue_advance - Advance the submission ring and data tail for a CBD queue.
 * @cbdq: Pointer to the cbd_queue structure representing the queue.
 * @cbd_req: Pointer to the cbd_request structure associated with the request.
 *
 * This function is responsible for advancing the submission ring of the CBD
 * queue and, if applicable, advancing the data tail based on the provided
 * cbd_request. It ensures that access to the submission ring is thread-safe
 * by using a spin lock.
 *
 * The function performs the following steps:
 * 1. Acquires the spin lock to protect the submission ring.
 * 2. Advances the submission ring by calling advance_subm_ring.
 * 3. If the request has data (i.e., it is not a "no data" request) and has a
 *    valid data length, it calls advance_data_tail to update the data tail
 *    with the specified data offset and length, rounded up to the nearest
 *    PAGE_SIZE.
 * 4. Releases the spin lock after the operations are completed.
 */
void cbd_queue_advance(struct cbd_queue *cbdq, struct cbd_request *cbd_req)
{
	spin_lock(&cbdq->channel.submr_lock);
	advance_subm_ring(cbdq);

	if (!cbd_req_nodata(cbd_req) && cbd_req->data_len)
		advance_data_tail(cbdq, cbd_req->data_off, round_up(cbd_req->data_len, PAGE_SIZE));
	spin_unlock(&cbdq->channel.submr_lock);
}

#ifdef CONFIG_CBD_CRC
static int queue_ce_verify(struct cbd_queue *cbdq, struct cbd_request *cbd_req,
			   struct cbd_ce *ce)
{
	if (ce->ce_crc != cbd_ce_crc(ce)) {
		cbd_queue_err(cbdq, "ce crc bad 0x%x != 0x%x(expected)",
				cbd_ce_crc(ce), ce->ce_crc);
		return -EIO;
	}

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

	return 0;
}
#endif

/**
 * complete_miss - Handle the situation when no completion events (CEs) are available.
 *
 * This function is called when `complete_work` detects that there are no CEs to process.
 * It evaluates the current state of `complete_worker_cfg` to determine if a busy wait and retry
 * mechanism is needed. When many CEs need processing, `complete_worker_cfg` will adjust its state
 * to favor busy waiting and retrying. If consecutive misses occur, the configuration will gradually
 * shift towards terminating the current work and re-queuing it.
 *
 * Additionally, if `inflight_reqs` is empty, it indicates that no CEs are pending, allowing the function
 * to conclude `complete_work` immediately.
 *
 * Returns:
 *     0 on success, or -EAGAIN if a retry is needed.
 */
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

/**
 * complete_work_fn - Main function for processing completion work.
 *
 * This function is called to handle the completion of requests. It is queued after a submission
 * entry (SE) is submitted to the submission ring and waits for the backend to return the corresponding
 * completion entry (CE).
 *
 * The function performs the following steps:
 * 1. Acquires the lock on the compression lock to safely retrieve a CE.
 * 2. If no CE is available, it invokes `complete_miss` to handle the absence.
 * 3. If it finds the corresponding inflight request using the CE's request ID.
 * 4. If the inflight request is not found, an error is logged, and it goes to handle the miss.
 * 5. If enabled, it verifies the CE against the request using CRC checks.
 * 6. Advances the completion tail and marks the inflight request as completed.
 * 7. It loops again to process any further available CEs.
 *
 * If a miss is encountered and a retry is needed (indicated by -EAGAIN), it will continue to loop
 * until there are no more CEs to process.
 */
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

#ifdef CONFIG_CBD_CRC
	ret = queue_ce_verify(cbdq, cbd_req, ce);
	if (ret)
		goto miss;
#endif

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

/**
 * cbd_req_init - Initialize a CBD request structure.
 * @cbdq: Pointer to the CBD queue associated with the request.
 * @op: The operation type (read, write, etc.) for the request.
 * @rq: Pointer to the block layer request structure.
 *
 * This function initializes the cbd_request structure associated with the given
 * block layer request. It sets up the necessary fields in the cbd_request, including
 * the request pointer, operation type, data length, and bio. The data length is determined
 * based on whether the request is a read or write operation.
 *
 * Note that this function does not allocate data space for the cbd_request. If data space
 * is required, it will be allocated later in the queue_req_channel_init function.
 */
static void cbd_req_init(struct cbd_queue *cbdq, enum cbd_op op, struct request *rq)
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

/**
 * queue_req_se_init - Initialize a submit entry (SE) for a CBD request.
 * @cbd_req: Pointer to the CBD request structure that requires an SE.
 *
 * This function retrieves a submit entry (SE) from the CBD queue and initializes
 * it based on the information in the provided cbd_request. The SE is set up with the
 * operation type, request ID, offset, and length. If the cbd_req need data,
 * the corresponding data offset and length are also set in the SE.
 *
 * This function is part of the queue_req_channel_init() process, where the SE is
 * prepared for submission to the backend.
 */
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

#ifdef CONFIG_CBD_CRC
static void cbd_req_crc_init(struct cbd_request *cbd_req)
{
	struct cbd_queue *cbdq = cbd_req->cbdq;
	struct cbd_se *se = cbd_req->se;

	if (cbd_req->op == CBD_OP_WRITE)
		se->data_crc = cbd_channel_crc(&cbdq->channel,
					       cbd_req->data_off,
					       cbd_req->data_len);
	se->se_crc = cbd_se_crc(se);
}
#endif

/**
 * queue_req_channel_init - Initialize channel-related information for a cbd_request.
 * @cbd_req: Pointer to the cbd_request structure to initialize.
 *
 * This function sets up the cbd_request with necessary information related to the
 * channel, including the submission entry (se) and data management.
 *
 * The request ID (req_tid) is assigned from the cbd_queue, and the
 * corresponding submission entry is initialized. If the cbd_request does not
 * require data (e.g., for flush operations), the function will skip the data
 * initialization steps and proceed to CRC initialization.
 *
 * If the request is a write operation (CBD_OP_WRITE), the function copies data
 * from the associated bio into the channel's data space using cbdc_copy_from_bio.
 *
 * After potentially modifying the data_head to reflect the new write, the function
 * ensures that data_head remains within the bounds of the channel's data size.
 *
 * Finally, if CRC configuration is enabled, it initializes the CRC for the request.
 */
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
#ifdef CONFIG_CBD_CRC
	cbd_req_crc_init(cbd_req);
#endif
}

/**
 * cbd_queue_req_to_backend - Submit a request to the backend for processing.
 * @cbd_req: Pointer to the cbd_request structure representing the request to be submitted.
 *
 * This function attempts to submit a cbd_request to the backend for processing.
 * It first checks if there is sufficient space in the submission ring and the data
 * space before proceeding. If either space is insufficient, the function will
 * unlock the submission ring and return an error.
 *
 * If space is available, a reference to the cbd_request is obtained to manage
 * its lifecycle properly during processing. The request is then added to the
 * inflight requests and the relevant channel information is initialized.
 *
 * After updating the submission ring head to indicate a new request has been
 * submitted, the function checks if it is single-host mode.
 * If so, it notifies the backend to process the request.
 *
 * Finally, a delayed work item is queued to handle completion of the request
 * once the backend has finished processing it. The function returns 0 on success
 * and an error code on failure.
 */
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

	/* Add the request to the inflight list for tracking */
	inflight_add_req(cbdq, cbd_req);
	/* Initialize channel information for the request */
	queue_req_channel_init(cbd_req);

	/* Advance the submission ring head to indicate a new request */
	cbdc_submr_head_advance(&cbdq->channel, sizeof(struct cbd_se));
	spin_unlock(&cbdq->channel.submr_lock);

	/* Notify the backend if it is available to process the request */
	if (cbdq->cbd_blkdev->backend)
		cbd_backend_notify(cbdq->cbd_blkdev->backend, cbdq->channel.seg_id);
	/* Queue delayed work to handle the completion of the request */
	queue_delayed_work(cbdq->cbd_blkdev->task_wq, &cbdq->complete_work, 0);

	return 0;
err:
	return ret;
}

/**
 * queue_req_end_req - Callback function to be called when a request is completed.
 * @cbd_req: Pointer to the cbd_request structure representing the completed request.
 * @priv_data: Private data for the callback (not used in this function).
 *
 * This function is called to advance the queue state after the request has been
 * processed and completed. It updates the cbd queue to reflect the completion of
 * the request.
 */
static void queue_req_end_req(struct cbd_request *cbd_req, void *priv_data)
{
	cbd_queue_advance(cbd_req->cbdq, cbd_req);
}

/**
 * cbd_queue_req - Queue a request for processing by the backend.
 * @cbdq: Pointer to the cbd_queue structure representing the queue.
 * @cbd_req: Pointer to the cbd_request structure representing the request to be queued.
 *
 * This function checks if caching is enabled for the block device and handles the
 * request accordingly. If caching is not enabled, it sets a callback for request
 * completion and queues the request to the backend for processing.
 */
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

/**
 * cbd_queue_rq - Main entry function for queuing a request in the blk-mq framework.
 * @hctx: Pointer to the hardware context representing the queue.
 * @bd: Pointer to the blk_mq_queue_data structure containing the request data.
 *
 * This function processes a block request by initializing a cbd_request structure,
 * determining the operation type (flush, write, or read), and queuing the request
 * for processing by the backend. It handles various request types and ensures
 * proper initialization and state management of the request.
 *
 * Returns BLK_STS_OK if the request is successfully queued, or an error status
 * (BLK_STS_IOERR) if the request type is unsupported.
 */
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

#define CBDQ_RESET_CHANNEL_WAIT_INTERVAL	HZ
#define CBDQ_RESET_CHANNEL_WAIT_COUNT		30

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
	enum cbdc_mgmt_cmd_ret cmd_ret;
	u16 count = 0;
	int ret;

	ret = cbdc_mgmt_cmd_op_send(cbdq->channel_ctrl, cbdc_mgmt_cmd_reset);
	if (ret)
		return ret;

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

	return 0;

free_extents:
	kfree(cbdq->released_extents);
out:
	return ret;
}

void cbd_queue_stop(struct cbd_queue *cbdq)
{
	cancel_delayed_work_sync(&cbdq->complete_work);

	kfree(cbdq->released_extents);
}
