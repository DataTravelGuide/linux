// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/blkdev.h>

#include "cbd_handler.h"

/**
 * complete_cmd - Completes a command by populating and updating a completion entry (ce).
 * @handler: Handler associated with the backend operation.
 * @se: Submission element (SE) representing the command to complete.
 * @ret: Result code indicating the success or failure of the command.
 *
 * This function get a completion entry (CE) that stores the command's result
 * and request transaction ID. For read operations, if CRC is enabled, it calculates
 * a CRC checksum for the data and the CE. It then advances the completion queue head
 * to ensure the entry is accessible.
 *
 * Context: This function requires `compr_lock` to prevent concurrent access
 * to the completion entries. Interrupts are disabled during the lock to
 * maintain atomicity and avoid race conditions in high-IRQ contexts.
 */
static inline void complete_cmd(struct cbd_handler *handler, struct cbd_se *se, int ret)
{
	struct cbd_ce *ce;
	unsigned long flags;

	spin_lock_irqsave(&handler->compr_lock, flags);
	ce = get_compr_head(handler);

	memset(ce, 0, sizeof(*ce));
	ce->req_tid = se->req_tid;
	ce->result = ret;

#ifdef CONFIG_CBD_CRC
	if (se->op == CBD_OP_READ)
		ce->data_crc = cbd_channel_crc(&handler->channel, se->data_off, se->data_len);
	ce->ce_crc = cbd_ce_crc(ce);
#endif
	cbdc_compr_head_advance(&handler->channel, sizeof(struct cbd_ce));
	spin_unlock_irqrestore(&handler->compr_lock, flags);
}

static void backend_bio_end(struct bio *bio)
{
	struct cbd_backend_io *backend_io = bio->bi_private;
	struct cbd_se *se = backend_io->se;
	struct cbd_handler *handler = backend_io->handler;
	struct cbd_backend *cbdb = handler->cbdb;

	complete_cmd(handler, se, bio->bi_status);

	bio_put(bio);
	kmem_cache_free(cbdb->backend_io_cache, backend_io);
	atomic_dec(&handler->inflight_cmds);
}

static struct cbd_backend_io *backend_prepare_io(struct cbd_handler *handler,
						 struct cbd_se *se, blk_opf_t opf)
{
	struct cbd_backend_io *backend_io;
	struct cbd_backend *cbdb = handler->cbdb;

	backend_io = kmem_cache_zalloc(cbdb->backend_io_cache, GFP_KERNEL);
	if (!backend_io)
		return NULL;

	backend_io->bio = bio_alloc_bioset(cbdb->bdev,
				DIV_ROUND_UP(se->len, PAGE_SIZE),
				opf, GFP_KERNEL, &handler->bioset);
	if (!backend_io->bio)
		goto free_backend_io;

	backend_io->se = se;
	backend_io->handler = handler;
	backend_io->bio->bi_iter.bi_sector = se->offset >> SECTOR_SHIFT;
	backend_io->bio->bi_iter.bi_size = 0;
	backend_io->bio->bi_private = backend_io;
	backend_io->bio->bi_end_io = backend_bio_end;

	atomic_inc(&handler->inflight_cmds);

	return backend_io;

free_backend_io:
	kmem_cache_free(cbdb->backend_io_cache, backend_io);

	return NULL;
}

/**
 * handle_backend_cmd - Processes commands for backend read, write, and flush operations.
 * @handler: The backend handler for the command.
 * @se: Submission element (SE) specifying the command operation and parameters.
 *
 * This function handles commands that are directed to the backend device.
 * - First, it checks if the command has already been marked as completed.
 * - Based on the operation code (`se->op`), it prepares an I/O request for the
 *   appropriate operation:
 *     - For `CBD_OP_READ` and `CBD_OP_WRITE`, a `bio` structure is created to
 *       handle data transfer by mapping pages from the existing channel data space.
 *       No new memory is allocated; instead, the channel's data
 *       space is directly mapped into the `bio`, which is then submitted to the
 *       backend device for processing.
 *     - For `CBD_OP_FLUSH`, a flush operation is issued directly to ensure
 *       data consistency at the block device level.
 *
 * If an unsupported operation is encountered, an error message is logged, and
 * the function completes the command with an error code.
 *
 * Returns:
 * 0 on successful command handling.
 * -ENOMEM if backend I/O preparation fails due to memory allocation issues.
 * Other error codes depending on specific operation failures.
 */
static int handle_backend_cmd(struct cbd_handler *handler, struct cbd_se *se)
{
	struct cbd_backend *cbdb = handler->cbdb;
	struct cbd_backend_io *backend_io = NULL;
	int ret;

	/* Check if command has already been completed */
	if (cbd_se_flags_test(se, CBD_SE_FLAGS_DONE))
		return 0;

	/* Process command based on operation type */
	switch (se->op) {
	case CBD_OP_READ:
		backend_io = backend_prepare_io(handler, se, REQ_OP_READ);
		break;
	case CBD_OP_WRITE:
		backend_io = backend_prepare_io(handler, se, REQ_OP_WRITE);
		break;
	case CBD_OP_FLUSH:
		ret = blkdev_issue_flush(cbdb->bdev); /* Issue flush for data consistency */
		goto complete_cmd;
	default:
		cbd_handler_err(handler, "unrecognized op: 0x%x", se->op); /* Log error for unknown operation */
		ret = -EIO;
		goto complete_cmd;
	}

	/* Check for memory allocation failure in backend I/O */
	if (!backend_io)
		return -ENOMEM;

	/*
	 * Map channel data pages directly into bio, reusing the channel's data space
	 * instead of allocating new memory. This enables efficient data transfer by
	 * using the preallocated buffer associated with the channel.
	 */
	ret = cbdc_map_pages(&handler->channel, backend_io->bio, se->data_off, se->data_len);
	if (ret) {
		kmem_cache_free(cbdb->backend_io_cache, backend_io);
		return ret;
	}

	/* Submit bio to initiate the I/O operation on the backend device */
	submit_bio(backend_io->bio);

	return 0;

complete_cmd:
	/* Finalize command by generating a completion entry */
	complete_cmd(handler, se, ret);
	return 0;
}

/**
 * cbd_handler_notify - Notify the backend to process a new submission element (SE).
 * @handler: Pointer to the `cbd_handler` structure for handling SEs.
 *
 * This function is called in a single-host setup when a new SE is submitted
 * from the block device (blkdev) side. After submission, the backend must be
 * notified to start processing the SE. The backend locates the handler through
 * the channel ID, then calls `cbd_handler_notify` to schedule immediate
 * execution of `handle_work`, which will process the SE in the backend's
 * work queue.
 */
void cbd_handler_notify(struct cbd_handler *handler)
{
	queue_delayed_work(handler->cbdb->task_wq, &handler->handle_work, 0);
}

/**
 * req_tid_valid - Verify if the given req_tid matches the expected req_tid.
 * @handler: Pointer to the `cbd_handler` managing SE requests.
 * @req_tid: Request transaction ID to validate.
 *
 * This function checks if the incoming `req_tid` matches the handler's
 * `req_tid_expected`, ensuring the SE sequence is followed. If `req_tid_expected`
 * is set to `U64_MAX`, this indicates a newly attached or reattached backend,
 * such as in reattach scenarios where no previous SEs exist.
 * In this case, the function permits the first SE with any `req_tid`,
 * subsequently establishing it as the expected `req_tid`.
 *
 * Returns: `true` if the `req_tid` matches `req_tid_expected`, or if it is the
 * first SE in a new handler instance; `false` otherwise.
 */
static bool req_tid_valid(struct cbd_handler *handler, u64 req_tid)
{
	/* New handler or reattach scenario */
	if (handler->req_tid_expected == U64_MAX)
		return true;

	return (req_tid == handler->req_tid_expected);
}

/**
 * handler_reset - Reset the state of a handler's channel and control information.
 * @handler: Pointer to the `cbd_handler` structure managing the channel.
 *
 * This function is called to reset the channel's state in scenarios where a block
 * device (blkdev) is connecting to the backend. There are two main cases where
 * this reset is required:
 * 1. A new backend and new blkdev are both being initialized, necessitating a fresh
 *    start for the channel.
 * 2. The backend has been continuously running, but a previously connected blkdev
 *    disconnected and is now being replaced by a newly connected blkdev. In this
 *    scenario, the state of the channel is reset to ensure it can handle requests
 *    from the new blkdev.
 *
 * In both cases, the blkdev sends a mgmt_cmd of reset into channel_ctrl->mgmt_cmd to
 * indicate that it requires a channel reset. This function clears all the channel
 * counters and control pointers, including `submr` and `compr` heads and tails,
 * resetting them to zero.
 *
 * After the reset is complete, the handler sends a cmd_ret of the reset cmd, signaling
 * to the blkdev that it can begin using the channel for data requests.
 *
 * Return: 0 on success, or a negative error code if the reset fails.
 *         -EBUSY if there are inflight commands indicating the channel is busy.
 */
static int handler_reset(struct cbd_handler *handler)
{
	int ret;

	/* Check if there are any inflight commands; if so, the channel is busy */
	if (atomic_read(&handler->inflight_cmds)) {
		cbd_handler_err(handler, "channel is busy, can't be reset\n");
		return -EBUSY;
	}

	/* Reset expected request transaction ID and handle count */
	handler->req_tid_expected = U64_MAX;
	handler->se_to_handle = 0;

	/* Reset channel data head and tail pointers */
	handler->channel.data_head = handler->channel.data_tail = 0;

	/* Reset submr and compr control pointers */
	handler->channel_ctrl->submr_tail = handler->channel_ctrl->submr_head = 0;
	handler->channel_ctrl->compr_tail = handler->channel_ctrl->compr_head = 0;

	/* Send a success response for the reset command */
	ret = cbdc_mgmt_cmd_ret_send(handler->channel_ctrl, cbdc_mgmt_cmd_ret_ok);
	if (ret)
		return ret;

	/* Queue the handler work to process any subsequent operations */
	queue_delayed_work(handler->cbdb->task_wq, &handler->handle_work, 0);

	return 0;
}

#ifdef CONFIG_CBD_CRC
static int channel_se_verify(struct cbd_handler *handler, struct cbd_se *se)
{
	if (se->se_crc != cbd_se_crc(se)) {
		cbd_handler_err(handler, "se crc(0x%x) is not expected(0x%x)",
				cbd_se_crc(se), se->se_crc);
		return -EIO;
	}

	if (se->op == CBD_OP_WRITE &&
		se->data_crc != cbd_channel_crc(&handler->channel,
						se->data_off,
						se->data_len)) {
		cbd_handler_err(handler, "data crc(0x%x) is not expected(0x%x)",
				cbd_channel_crc(&handler->channel, se->data_off, se->data_len),
				se->data_crc);
		return -EIO;
	}

	return 0;
}
#endif

static int handle_mgmt_cmd(struct cbd_handler *handler)
{
	enum cbdc_mgmt_cmd_op cmd_op;
	int ret;

	cmd_op = cbdc_mgmt_cmd_op_get(handler->channel_ctrl);
	switch (cmd_op) {
	case cbdc_mgmt_cmd_none:
		ret = 0;
		break;
	case cbdc_mgmt_cmd_reset:
		ret = handler_reset(handler);
		break;
	default:
		ret = -EIO;
	}

	return ret;
}

/**
 * handle_mgmt_work_fn - Handle management work for the CBD channel.
 * @work: Pointer to the work_struct associated with this management work.
 *
 * This function is the main function for handling management work related to the
 * CBD channel. It continuously checks if there are new management commands (mgmt_cmd)
 * to be processed in the management plane of the CBD channel.
 *
 * If a new mgmt_cmd is detected, it will be processed; if none are available, the function
 * will end this work iteration. The execution cycle of handle_mgmt_work is set to 1 second.
 *
 * The function follows a loop that:
 * 1. Checks if the current mgmt_cmd has been processed using cbdc_mgmt_completed.
 * 2. If not completed, it calls handle_mgmt_cmd to handle the mgmt_cmd.
 * 3. If handling is successful, it checks again for more mgmt_cmds.
 * 4. Once there are no new mgmt_cmds to process, it queues the work to run again
 *    after 1 second.
 */
static void handle_mgmt_work_fn(struct work_struct *work)
{
	struct cbd_handler *handler = container_of(work, struct cbd_handler,
						   handle_mgmt_work.work);
	int ret;
again:
	/* Check if the current mgmt_cmd has been completed */
	if (!cbdc_mgmt_completed(handler->channel_ctrl)) {
		/* Process the management command */
		ret = handle_mgmt_cmd(handler);
		if (ret)
			goto out; /* If an error occurs, exit the loop */
		goto again; /* Check for more mgmt_cmds */
	}

out:
	/* Re-queue the work to run again after 1 second */
	queue_delayed_work(handler->cbdb->task_wq, &handler->handle_mgmt_work, HZ);
}

/**
 * handle_work_fn - Main handler function to process SEs in the channel.
 * @work: pointer to the work_struct associated with the handler.
 *
 * This function is repeatedly called to handle incoming SEs (Submission Entries)
 * from the channel's control structure.
 *
 * In a multi-host environment, this function operates in a polling mode
 * to retrieve new SEs. For single-host cases, it mainly waits for
 * blkdev notifications.
 */
static void handle_work_fn(struct work_struct *work)
{
	struct cbd_handler *handler = container_of(work, struct cbd_handler,
						   handle_work.work);
	struct cbd_se *se_head;
	struct cbd_se *se;
	u64 req_tid;
	int ret;

again:
	/* Retrieve new SE from channel control */
	se_head = get_se_head(handler);
	if (!se_head)
		goto miss;

	se = get_se_to_handle(handler);
	if (se == se_head)
		goto miss;

	req_tid = se->req_tid;
	if (!req_tid_valid(handler, req_tid)) {
		cbd_handler_err(handler, "req_tid (%llu) is not expected (%llu)",
				req_tid, handler->req_tid_expected);
		goto miss;
	}

#ifdef CONFIG_CBD_CRC
	ret = channel_se_verify(handler, se);
	if (ret)
		goto miss;
#endif
	cbdwc_hit(&handler->handle_worker_cfg);

	ret = handle_backend_cmd(handler, se);
	if (!ret) {
		/* Successful SE handling */
		handler->req_tid_expected = req_tid + 1;
		handler->se_to_handle = (handler->se_to_handle + sizeof(struct cbd_se)) %
							handler->channel.submr_size;
	}

	goto again;

miss:
	/* No more SEs to handle in this round */
	if (cbdwc_need_retry(&handler->handle_worker_cfg))
		goto again;

	cbdwc_miss(&handler->handle_worker_cfg);

	/* Queue next work based on polling status */
	if (cbd_channel_flags_get(handler->channel_ctrl) & CBDC_FLAGS_POLLING)
		queue_delayed_work(handler->cbdb->task_wq, &handler->handle_work, 0);
}

static struct cbd_handler *handler_alloc(struct cbd_backend *cbdb)
{
	struct cbd_handler *handler;
	int ret;

	handler = kzalloc(sizeof(struct cbd_handler), GFP_KERNEL);
	if (!handler)
		return -ENOMEM;

	ret = bioset_init(&handler->bioset, 256, 0, BIOSET_NEED_BVECS);
	if (ret)
		goto free_handler;

	handler->cbdb = cbdb;
	cbdb_add_handler(cbdb, handler);

	return handler;
free_handler:
	kfree(handler);
	return NULL;
}

static void handler_free(struct cbd_handler *handler)
{
	cbdb_del_handler(handler->cbdb, handler);
	bioset_exit(&handler->bioset);
	kfree(handler);
}

static void handler_channel_init(struct cbd_handler *handler, u32 channel_id, bool new_channel)
{
	struct cbd_transport *cbdt = handler->cbdb->cbdt;
	struct cbd_channel_init_options init_opts = { 0 };

	init_opts.cbdt = cbdt;
	init_opts.backend_id = handler->cbdb->backend_id;
	init_opts.seg_id = channel_id;
	init_opts.new_channel = new_channel;
	cbd_channel_init(&handler->channel, &init_opts);

	handler->channel_ctrl = handler->channel.ctrl;
	handler->req_tid_expected = U64_MAX;
	atomic_set(&handler->inflight_cmds, 0);
	spin_lock_init(&handler->compr_lock);
	INIT_DELAYED_WORK(&handler->handle_work, handle_work_fn);
	INIT_DELAYED_WORK(&handler->handle_mgmt_work, handle_mgmt_work_fn);
	cbdwc_init(&handler->handle_worker_cfg);

	if (new_channel) {
		handler->channel.data_head = handler->channel.data_tail = 0;
		handler->channel_ctrl->submr_tail = handler->channel_ctrl->submr_head = 0;
		handler->channel_ctrl->compr_tail = handler->channel_ctrl->compr_head = 0;

		cbd_channel_flags_clear_bit(handler->channel_ctrl, ~0ULL);
	}

	handler->se_to_handle = cbdc_submr_tail_get(&handler->channel);
}

static void handler_channel_destroy(struct cbd_handler *handler)
{
	cbd_channel_destroy(&handler->channel);
}

/* handler start and stop */
static void handler_start(struct cbd_handler *handler)
{
	queue_delayed_work(cbdb->task_wq, &handler->handle_work, 0);
	queue_delayed_work(cbdb->task_wq, &handler->handle_mgmt_work, 0);
}

static void handler_stop(struct cbd_handler *handler)
{
	cancel_delayed_work_sync(&handler->handle_mgmt_work);
	cancel_delayed_work_sync(&handler->handle_work);

	while (atomic_read(&handler->inflight_cmds))
		schedule_timeout(HZ);
}

int cbd_handler_create(struct cbd_backend *cbdb, u32 channel_id, bool new_channel)
{
	struct cbd_handler *handler;
	int ret;

	handler = handler_alloc(cbdb);
	if (!handler)
		return -ENOMEM;

	handler_channel_init(handler, channel_id, new_channel);
	handler_start(handler);

	return 0;

free_handler:
	kfree(handler);
	return ret;
};

void cbd_handler_destroy(struct cbd_handler *handler)
{
	handler_stop(handler);
	handler_channel_destroy(handler);
	handler_free(handler);
}
