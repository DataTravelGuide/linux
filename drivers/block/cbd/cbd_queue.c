#include "cbd_internal.h"

static inline struct cbd_se *get_submit_entry(struct cbd_queue *cbdq)
{
	return (struct cbd_se *)(cbdq->channel.cmdr + cbdq->channel_info->cmdr_head);
}

static inline struct cbd_se *get_oldest_se(struct cbd_queue *cbdq)
{
	if (cbdq->channel_info->cmdr_tail == cbdq->channel_info->cmdr_head)
		return NULL;

	return (struct cbd_se *)(cbdq->channel.cmdr + cbdq->channel_info->cmdr_tail);
}

static inline struct cbd_ce *get_complete_entry(struct cbd_queue *cbdq)
{
	if (cbdq->channel_info->compr_tail == cbdq->channel_info->compr_head)
		return NULL;

	return (struct cbd_ce *)(cbdq->channel.compr + cbdq->channel_info->compr_tail);
}

static void cbd_req_init(struct cbd_queue *cbdq, enum cbd_op op, struct request *rq)
{
	struct cbd_request *cbd_req = blk_mq_rq_to_pdu(rq);

	cbd_req->req = rq;
	cbd_req->cbdq = cbdq;
	cbd_req->op = op;
}

static bool cbd_req_nodata(struct cbd_request *cbd_req)
{
	switch (cbd_req->op) {
	case CBD_OP_WRITE:
	case CBD_OP_READ:
		return false;
	case CBD_OP_DISCARD:
	case CBD_OP_WRITE_ZEROS:
	case CBD_OP_FLUSH:
		return true;
	default:
		BUG();
	}
}

static void queue_req_se_init(struct cbd_request *cbd_req)
{
	struct cbd_se	*se;
	u64 offset = (u64)blk_rq_pos(cbd_req->req) << SECTOR_SHIFT;
	u64 length = blk_rq_bytes(cbd_req->req);

	se = get_submit_entry(cbd_req->cbdq);
	memset(se, 0, sizeof(struct cbd_se));
	se->op = cbd_req->op;

	se->req_tid = cbd_req->req_tid;
	se->offset = offset;
	se->len = length;

	if (req_op(cbd_req->req) == REQ_OP_READ || req_op(cbd_req->req) == REQ_OP_WRITE) {
		se->data_off = cbd_req->cbdq->channel.data_head;
		se->data_len = length;
	}

	cbd_req->se = se;
}

static bool data_space_enough(struct cbd_queue *cbdq, struct cbd_request *cbd_req)
{
	struct cbd_channel *channel = &cbdq->channel;
	u64 space_available = channel->data_size;
	u32 space_needed;

	if (channel->data_head > channel->data_tail) {
		space_available = channel->data_size - channel->data_head;
		space_available += channel->data_tail;
	} else if (channel->data_head < channel->data_tail) {
		space_available = channel->data_tail - channel->data_head;
	}

	space_needed = round_up(cbd_req->data_len, CBDC_DATA_ALIGH);

	if (space_available - CBDC_DATA_RESERVED < space_needed) {
		cbd_queue_err(cbdq, "data space is not enough: availaible: %llu needed: %u",
			      space_available, space_needed);
		return false;
	}

	return true;
}

static bool submit_ring_full(struct cbd_queue *cbdq)
{
	u64 space_available = cbdq->channel_info->cmdr_size;
	struct cbd_channel_info *info = cbdq->channel_info;

	if (info->cmdr_head > info->cmdr_tail) {
		space_available = info->cmdr_size - info->cmdr_head;
		space_available += info->cmdr_tail;
	} else if (info->cmdr_head < info->cmdr_tail) {
		space_available = info->cmdr_tail - info->cmdr_head;
	}

	/* There is a CMDR_RESERVED we dont use to prevent the ring to be used up */
	if (space_available - CBDC_CMDR_RESERVED < sizeof(struct cbd_se))
		return true;

	return false;
}

static void queue_req_data_init(struct cbd_request *cbd_req)
{
	struct cbd_queue *cbdq = cbd_req->cbdq;
	struct bio *bio = cbd_req->req->bio;

	if (cbd_req->op == CBD_OP_READ)
		goto advance_data_head;

	cbdc_copy_from_bio(&cbdq->channel, cbd_req->data_off, cbd_req->data_len, bio);

advance_data_head:
	cbdq->channel.data_head = round_up(cbdq->channel.data_head + cbd_req->data_len, PAGE_SIZE);
	cbdq->channel.data_head %= cbdq->channel.data_size;
}

#ifdef CONFIG_CBD_CRC
static void cbd_req_crc_init(struct cbd_request *cbd_req)
{
	struct cbd_queue *cbdq = cbd_req->cbdq;
	struct cbd_se *se = cbd_req->se;

	if (!cbd_req_nodata(cbd_req))
		se->data_crc = cbd_channel_crc(&cbdq->channel,
					       cbd_req->data_off,
					       cbd_req->data_len);

	se->se_crc = cbd_se_crc(se);
}
#endif

static void complete_inflight_req(struct cbd_queue *cbdq, struct cbd_request *cbd_req, int ret);
static void cbd_queue_workfn(struct work_struct *work)
{
	struct cbd_request *cbd_req =
		container_of(work, struct cbd_request, work);
	struct cbd_queue *cbdq = cbd_req->cbdq;
	int ret = 0;
	size_t command_size;

	spin_lock(&cbdq->inflight_reqs_lock);
	if (atomic_read(&cbdq->state) == cbd_queue_state_removing) {
		spin_unlock(&cbdq->inflight_reqs_lock);
		ret = -EIO;
		goto end_request;
	}
	list_add_tail(&cbd_req->inflight_reqs_node, &cbdq->inflight_reqs);
	spin_unlock(&cbdq->inflight_reqs_lock);

	command_size = sizeof(struct cbd_se);

	spin_lock(&cbdq->channel.cmdr_lock);
	if (req_op(cbd_req->req) == REQ_OP_WRITE || req_op(cbd_req->req) == REQ_OP_READ) {
		cbd_req->data_off = cbdq->channel.data_head;
		cbd_req->data_len = blk_rq_bytes(cbd_req->req);
	} else {
		cbd_req->data_off = -1;
		cbd_req->data_len = 0;
	}

	if (submit_ring_full(cbdq) ||
			!data_space_enough(cbdq, cbd_req)) {
		spin_unlock(&cbdq->channel.cmdr_lock);

		/* remove request from inflight_reqs */
		spin_lock(&cbdq->inflight_reqs_lock);
		list_del_init(&cbd_req->inflight_reqs_node);
		spin_unlock(&cbdq->inflight_reqs_lock);

		cbd_blk_debug(cbdq->cbd_blkdev, "transport space is not enough");
		ret = -ENOMEM;
		goto end_request;
	}

	cbd_req->req_tid = ++cbdq->req_tid;
	queue_req_se_init(cbd_req);

	if (!cbd_req_nodata(cbd_req))
		queue_req_data_init(cbd_req);

#ifdef CONFIG_CBD_CRC
	cbd_req_crc_init(cbd_req);
#endif
	queue_delayed_work(cbdq->cbd_blkdev->task_wq, &cbdq->complete_work, 0);

	CBDC_UPDATE_CMDR_HEAD(cbdq->channel_info->cmdr_head,
			sizeof(struct cbd_se),
			cbdq->channel_info->cmdr_size);
	spin_unlock(&cbdq->channel.cmdr_lock);

	return;

end_request:
	if (ret == -ENOMEM || ret == -EBUSY)
		blk_mq_requeue_request(cbd_req->req, true);
	else
		blk_mq_end_request(cbd_req->req, errno_to_blk_status(ret));
}

static void advance_cmd_ring(struct cbd_queue *cbdq)
{
	struct cbd_se *se;
again:
	se = get_oldest_se(cbdq);
	if (!se)
		goto out;

	if (cbd_se_flags_test(se, CBD_SE_FLAGS_DONE)) {
		CBDC_UPDATE_CMDR_TAIL(cbdq->channel_info->cmdr_tail,
				sizeof(struct cbd_se),
				cbdq->channel_info->cmdr_size);
		goto again;
	}
out:
	return;
}

static bool __advance_data_tail(struct cbd_queue *cbdq, u64 data_off, u32 data_len)
{
	if (data_off == cbdq->channel.data_tail) {
		cbdq->released_extents[data_off / PAGE_SIZE] = 0;
		cbdq->channel.data_tail += data_len;
		if (cbdq->channel.data_tail >= cbdq->channel.data_size)
			cbdq->channel.data_tail %= cbdq->channel.data_size;
		return true;
	}

	return false;
}

static void advance_data_tail(struct cbd_queue *cbdq, u64 data_off, u32 data_len)
{
	cbdq->released_extents[data_off / PAGE_SIZE] = data_len;

	while (__advance_data_tail(cbdq, data_off, data_len)) {
		data_off += data_len;
		data_len = cbdq->released_extents[data_off / PAGE_SIZE];
		if (!data_len)
			break;
	}
}

static inline void complete_inflight_req(struct cbd_queue *cbdq, struct cbd_request *cbd_req, int ret)
{
	u64 data_off;
	u32 data_len;
	bool advance_data = false;

	spin_lock(&cbdq->inflight_reqs_lock);
	list_del_init(&cbd_req->inflight_reqs_node);
	spin_unlock(&cbdq->inflight_reqs_lock);

	cbd_se_flags_set(cbd_req->se, CBD_SE_FLAGS_DONE);
	data_off = cbd_req->data_off;
	data_len = cbd_req->data_len;
	advance_data = (!cbd_req_nodata(cbd_req));

	blk_mq_end_request(cbd_req->req, errno_to_blk_status(ret));

	spin_lock(&cbdq->channel.cmdr_lock);
	advance_cmd_ring(cbdq);
	if (advance_data)
		advance_data_tail(cbdq, data_off, round_up(data_len, PAGE_SIZE));
	spin_unlock(&cbdq->channel.cmdr_lock);
}

static struct cbd_request *fetch_inflight_req(struct cbd_queue *cbdq, u64 req_tid)
{
	struct cbd_request *req;
	bool found = false;

	list_for_each_entry(req, &cbdq->inflight_reqs, inflight_reqs_node) {
		if (req->req_tid == req_tid) {
			list_del_init(&req->inflight_reqs_node);
			found = true;
			break;
		}
	}

	if (found)
		return req;

	return NULL;
}

static void copy_data_from_cbdteq(struct cbd_request *cbd_req)
{
	struct bio *bio = cbd_req->req->bio;
	struct cbd_queue *cbdq = cbd_req->cbdq;

	cbdc_copy_to_bio(&cbdq->channel, cbd_req->data_off, cbd_req->data_len, bio);
}

static void complete_work_fn(struct work_struct *work)
{
	struct cbd_queue *cbdq = container_of(work, struct cbd_queue, complete_work.work);
	struct cbd_ce *ce;
	struct cbd_request *cbd_req;

	if (atomic_read(&cbdq->state) == cbd_queue_state_removing)
		return;

again:
	/* compr_head would be updated by backend handler */
	spin_lock(&cbdq->channel.compr_lock);
	ce = get_complete_entry(cbdq);
	spin_unlock(&cbdq->channel.compr_lock);
	if (!ce)
		goto miss;

	spin_lock(&cbdq->inflight_reqs_lock);
	cbd_req = fetch_inflight_req(cbdq, ce->req_tid);
	spin_unlock(&cbdq->inflight_reqs_lock);
	if (!cbd_req) {
		cbd_queue_err(cbdq, "inflight request not found: %llu.", ce->req_tid);
		goto miss;
	}

#ifdef CONFIG_CBD_CRC
	if (ce->ce_crc != cbd_ce_crc(ce)) {
		cbd_queue_err(cbdq, "ce crc bad 0x%x != 0x%x(expected)",
				cbd_ce_crc(ce), ce->ce_crc);
		goto miss;
	}
#endif

	cbdwc_hit(&cbdq->complete_worker_cfg);
	CBDC_UPDATE_COMPR_TAIL(cbdq->channel_info->compr_tail,
			       sizeof(struct cbd_ce),
			       cbdq->channel_info->compr_size);

	if (req_op(cbd_req->req) == REQ_OP_READ) {
		spin_lock(&cbdq->channel.cmdr_lock);
		copy_data_from_cbdteq(cbd_req);
		spin_unlock(&cbdq->channel.cmdr_lock);
	}

	complete_inflight_req(cbdq, cbd_req, ce->result);

	goto again;

miss:
	if (cbdwc_need_retry(&cbdq->complete_worker_cfg))
		goto again;

	spin_lock(&cbdq->inflight_reqs_lock);
	if (list_empty(&cbdq->inflight_reqs)) {
		spin_unlock(&cbdq->inflight_reqs_lock);
		cbdwc_init(&cbdq->complete_worker_cfg);
		return;
	}
	spin_unlock(&cbdq->inflight_reqs_lock);

	cbdwc_miss(&cbdq->complete_worker_cfg);

	queue_delayed_work(cbdq->cbd_blkdev->task_wq, &cbdq->complete_work, 0);
	return;
}

static blk_status_t cbd_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	struct request *req = bd->rq;
	struct cbd_queue *cbdq = hctx->driver_data;
	struct cbd_request *cbd_req = blk_mq_rq_to_pdu(bd->rq);

	memset(cbd_req, 0, sizeof(struct cbd_request));
	INIT_LIST_HEAD(&cbd_req->inflight_reqs_node);

	blk_mq_start_request(bd->rq);

	switch (req_op(bd->rq)) {
	case REQ_OP_FLUSH:
		cbd_req_init(cbdq, CBD_OP_FLUSH, req);
		break;
	case REQ_OP_DISCARD:
		cbd_req_init(cbdq, CBD_OP_DISCARD, req);
		break;
	case REQ_OP_WRITE_ZEROES:
		cbd_req_init(cbdq, CBD_OP_WRITE_ZEROS, req);
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

	INIT_WORK(&cbd_req->work, cbd_queue_workfn);
	queue_work(cbdq->cbd_blkdev->task_wq, &cbd_req->work);

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

static int cbd_queue_channel_init(struct cbd_queue *cbdq, u32 channel_id)
{
	struct cbd_blkdev *cbd_blkdev = cbdq->cbd_blkdev;
	struct cbd_transport *cbdt = cbd_blkdev->cbdt;

	cbdq->channel_id = channel_id;
	cbd_channel_init(&cbdq->channel, cbdt, channel_id);
	cbdq->channel_info = cbdq->channel.channel_info;

	cbdq->channel.data_head = cbdq->channel.data_tail = 0;
	cbdq->channel_info->cmdr_tail = cbdq->channel_info->cmdr_head = 0;
	cbdq->channel_info->compr_tail = cbdq->channel_info->compr_head = 0;

	/* Initialise the channel_info of the ring buffer */
	cbdq->channel_info->cmdr_off = CBDC_CMDR_OFF;
	cbdq->channel_info->cmdr_size = rounddown(CBDC_CMDR_SIZE, sizeof(struct cbd_se));
	cbdq->channel_info->compr_off = CBDC_COMPR_OFF;
	cbdq->channel_info->compr_size = rounddown(CBDC_COMPR_SIZE, sizeof(struct cbd_ce));

	cbdq->channel_info->backend_id = cbd_blkdev->backend_id;
	cbdq->channel_info->blkdev_id = cbd_blkdev->blkdev_id;
	cbdq->channel_info->blkdev_state = cbdc_blkdev_state_running;
	cbdq->channel_info->state = cbd_channel_state_running;

	return 0;
}

int cbd_queue_start(struct cbd_queue *cbdq)
{
	struct cbd_transport *cbdt = cbdq->cbd_blkdev->cbdt;
	u32 channel_id;
	int ret;

	ret = cbdt_get_empty_channel_id(cbdt, &channel_id);
	if (ret < 0) {
		cbdt_err(cbdt, "failed find available channel_id.\n");
		goto err;
	}

	ret = cbd_queue_channel_init(cbdq, channel_id);
	if (ret) {
		cbd_queue_err(cbdq, "failed to init dev channel_info: %d.", ret);
		goto err;
	}

	INIT_LIST_HEAD(&cbdq->inflight_reqs);
	spin_lock_init(&cbdq->inflight_reqs_lock);
	cbdq->req_tid = 0;
	INIT_DELAYED_WORK(&cbdq->complete_work, complete_work_fn);
	cbdwc_init(&cbdq->complete_worker_cfg);

	cbdq->released_extents = kzalloc(sizeof(u64) * (CBDC_DATA_SIZE >> PAGE_SHIFT), GFP_KERNEL);
	if (!cbdq->released_extents) {
		ret = -ENOMEM;
		goto err;
	}

	queue_delayed_work(cbdq->cbd_blkdev->task_wq, &cbdq->complete_work, 0);

	atomic_set(&cbdq->state, cbd_queue_state_running);

	return 0;
err:
	return ret;
}

void cbd_queue_stop(struct cbd_queue *cbdq)
{
	LIST_HEAD(tmp_list);
	struct cbd_request *cbd_req;

	if (atomic_read(&cbdq->state) != cbd_queue_state_running)
		return;

	atomic_set(&cbdq->state, cbd_queue_state_removing);
	cancel_delayed_work_sync(&cbdq->complete_work);

	spin_lock(&cbdq->inflight_reqs_lock);
	list_splice_init(&cbdq->inflight_reqs, &tmp_list);
	spin_unlock(&cbdq->inflight_reqs_lock);

	while (!list_empty(&tmp_list)) {
		cbd_req = list_first_entry(&tmp_list,
				struct cbd_request, inflight_reqs_node);
		list_del_init(&cbd_req->inflight_reqs_node);
		cancel_work_sync(&cbd_req->work);
		blk_mq_end_request(cbd_req->req, errno_to_blk_status(-EIO));
	}

	kfree(cbdq->released_extents);
	cbdq->channel_info->blkdev_state = cbdc_blkdev_state_none;
}
