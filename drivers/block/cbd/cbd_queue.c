// SPDX-License-Identifier: GPL-2.0-or-later

#include "cbd_internal.h"

static inline struct cbd_se *get_submit_entry(struct cbd_queue *cbdq)
{
	return (struct cbd_se *)(cbdq->channel.submr + cbdq->channel_info->submr_head);
}

static inline struct cbd_se *get_oldest_se(struct cbd_queue *cbdq)
{
	if (cbdq->channel_info->submr_tail == cbdq->channel_info->submr_head)
		return NULL;

	return (struct cbd_se *)(cbdq->channel.submr + cbdq->channel_info->submr_tail);
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

	if (req_op(rq) == REQ_OP_READ || req_op(rq) == REQ_OP_WRITE)
		cbd_req->data_len = blk_rq_bytes(rq);
	else
		cbd_req->data_len = 0;

	cbd_req->bio = rq->bio;
	cbd_req->off = (u64)blk_rq_pos(rq) << SECTOR_SHIFT;
}

static bool cbd_req_nodata(struct cbd_request *cbd_req)
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

	if (cbd_req->op == CBD_OP_READ || cbd_req->op == CBD_OP_WRITE) {
		se->data_off = cbd_req->cbdq->channel.data_head;
		se->data_len = length;
	}

	cbd_req->se = se;
}

static bool data_space_enough(struct cbd_queue *cbdq, struct cbd_request *cbd_req)
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

	space_needed = round_up(cbd_req->data_len, CBDC_DATA_ALIGH);

	if (space_available - CBDC_DATA_RESERVED < space_needed)
		return false;

	return true;
}

static bool submit_ring_full(struct cbd_queue *cbdq)
{
	u32 space_available = cbdq->channel.submr_size;
	struct cbd_channel_info *info = cbdq->channel_info;

	if (info->submr_head > info->submr_tail) {
		space_available = cbdq->channel.submr_size - info->submr_head;
		space_available += info->submr_tail;
	} else if (info->submr_head < info->submr_tail) {
		space_available = info->submr_tail - info->submr_head;
	}

	/* There is a SUBMR_RESERVED we dont use to prevent the ring to be used up */
	if (space_available - CBDC_SUBMR_RESERVED < sizeof(struct cbd_se))
		return true;

	return false;
}

static void queue_req_data_init(struct cbd_request *cbd_req)
{
	struct cbd_queue *cbdq = cbd_req->cbdq;
	struct bio *bio = cbd_req->bio;

	if (cbd_req->op == CBD_OP_READ)
		goto advance_data_head;

	cbdc_copy_from_bio(&cbdq->channel, cbd_req->data_off, cbd_req->data_len, bio, cbd_req->bio_off);

advance_data_head:
	cbdq->channel.data_head = round_up(cbdq->channel.data_head + cbd_req->data_len, PAGE_SIZE);
	cbdq->channel.data_head %= cbdq->channel.data_size;
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

static void end_req(struct kref *ref)
{
	struct cbd_request *cbd_req = container_of(ref, struct cbd_request, ref);
	struct request *req = cbd_req->req;
	int ret = cbd_req->ret;

	if (cbd_req->end_req)
		cbd_req->end_req(cbd_req, cbd_req->priv_data);

	if (req) {
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

void cbd_req_put(struct cbd_request *cbd_req, int ret)
{
	struct cbd_request *parent = cbd_req->parent;

	if (ret && !cbd_req->ret)
		cbd_req->ret = ret;

	if (kref_put(&cbd_req->ref, end_req) && parent)
		cbd_req_put(parent, ret);
}

static void complete_inflight_req(struct cbd_queue *cbdq, struct cbd_request *cbd_req, int ret);
int cbd_queue_req_to_backend(struct cbd_request *cbd_req)
{
	struct cbd_queue *cbdq = cbd_req->cbdq;
	size_t command_size;
	int ret;

	spin_lock(&cbdq->inflight_reqs_lock);
	if (atomic_read(&cbdq->state) == cbd_queue_state_removing) {
		spin_unlock(&cbdq->inflight_reqs_lock);
		ret = -EIO;
		goto err;
	}
	list_add_tail(&cbd_req->inflight_reqs_node, &cbdq->inflight_reqs);
	spin_unlock(&cbdq->inflight_reqs_lock);

	command_size = sizeof(struct cbd_se);

	spin_lock(&cbdq->channel.submr_lock);
	if (cbd_req->op == CBD_OP_WRITE || cbd_req->op == CBD_OP_READ)
		cbd_req->data_off = cbdq->channel.data_head;
	else
		cbd_req->data_off = -1;

	if (submit_ring_full(cbdq) ||
			!data_space_enough(cbdq, cbd_req)) {
		spin_unlock(&cbdq->channel.submr_lock);

		/* remove request from inflight_reqs */
		spin_lock(&cbdq->inflight_reqs_lock);
		list_del_init(&cbd_req->inflight_reqs_node);
		spin_unlock(&cbdq->inflight_reqs_lock);

		/* return ocuppied space */
		cbd_req->data_len = 0;

		ret = -ENOMEM;
		goto err;
	}

	cbd_req->req_tid = ++cbdq->req_tid;
	queue_req_se_init(cbd_req);

	if (!cbd_req_nodata(cbd_req))
		queue_req_data_init(cbd_req);

	cbd_req_get(cbd_req);
#ifdef CONFIG_CBD_CRC
	cbd_req_crc_init(cbd_req);
#endif
	CBDC_UPDATE_SUBMR_HEAD(cbdq->channel_info->submr_head,
			sizeof(struct cbd_se),
			cbdq->channel.submr_size);
	spin_unlock(&cbdq->channel.submr_lock);

	if (cbdq->cbd_blkdev->backend)
		cbd_backend_notify(cbdq->cbd_blkdev->backend, cbdq->channel.seg_id);
	queue_delayed_work(cbdq->cbd_blkdev->task_wq, &cbdq->complete_work, 0);

	return 0;

err:
	return ret;
}

static void queue_req_end_req(struct cbd_request *cbd_req, void *priv_data);
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

static void advance_subm_ring(struct cbd_queue *cbdq)
{
	struct cbd_se *se;
again:
	se = get_oldest_se(cbdq);
	if (!se)
		goto out;

	if (cbd_se_flags_test(se, CBD_SE_FLAGS_DONE)) {
		CBDC_UPDATE_SUBMR_TAIL(cbdq->channel_info->submr_tail,
				sizeof(struct cbd_se),
				cbdq->channel.submr_size);
		goto again;
	}
out:
	return;
}

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

static void advance_data_tail(struct cbd_queue *cbdq, u32 data_off, u32 data_len)
{
	data_off %= cbdq->channel.data_size;
	cbdq->released_extents[data_off / PAGE_SIZE] = data_len;

	while (__advance_data_tail(cbdq, data_off, data_len)) {
		data_off += data_len;
		data_off %= cbdq->channel.data_size;
		data_len = cbdq->released_extents[data_off / PAGE_SIZE];
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

static void queue_req_end_req(struct cbd_request *cbd_req, void *priv_data)
{
	cbd_queue_advance(cbd_req->cbdq, cbd_req);
}

static inline void complete_inflight_req(struct cbd_queue *cbdq, struct cbd_request *cbd_req, int ret)
{
	spin_lock(&cbdq->inflight_reqs_lock);
	list_del_init(&cbd_req->inflight_reqs_node);
	spin_unlock(&cbdq->inflight_reqs_lock);

	cbd_se_flags_set(cbd_req->se, CBD_SE_FLAGS_DONE);

	cbd_req_put(cbd_req, ret);
}

static struct cbd_request *find_inflight_req(struct cbd_queue *cbdq, u64 req_tid)
{
	struct cbd_request *req;
	bool found = false;

	list_for_each_entry(req, &cbdq->inflight_reqs, inflight_reqs_node) {
		if (req->req_tid == req_tid) {
			found = true;
			break;
		}
	}

	if (found)
		return req;

	return NULL;
}

static void copy_data_from_cbdreq(struct cbd_request *cbd_req)
{
	struct bio *bio = cbd_req->bio;
	struct cbd_queue *cbdq = cbd_req->cbdq;

	spin_lock(&cbd_req->lock);
	cbdc_copy_to_bio(&cbdq->channel, cbd_req->data_off, cbd_req->data_len, bio, cbd_req->bio_off);
	spin_unlock(&cbd_req->lock);
}

static void complete_work_fn(struct work_struct *work)
{
	struct cbd_queue *cbdq = container_of(work, struct cbd_queue, complete_work.work);
	struct cbd_ce *ce;
	struct cbd_request *cbd_req;

again:
	/* compr_head would be updated by backend handler */
	spin_lock(&cbdq->channel.compr_lock);
	ce = get_complete_entry(cbdq);
	spin_unlock(&cbdq->channel.compr_lock);
	if (!ce)
		goto miss;

	spin_lock(&cbdq->inflight_reqs_lock);
	cbd_req = find_inflight_req(cbdq, ce->req_tid);
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

	if (cbd_req->op == CBD_OP_READ &&
		ce->data_crc != cbd_channel_crc(&cbdq->channel,
					       cbd_req->data_off,
					       cbd_req->data_len)) {
		cbd_queue_err(cbdq, "ce data_crc bad 0x%x != 0x%x(expected)",
				cbd_channel_crc(&cbdq->channel,
						cbd_req->data_off,
						cbd_req->data_len),
				ce->data_crc);
		goto miss;
	}
#endif

	cbdwc_hit(&cbdq->complete_worker_cfg);
	CBDC_UPDATE_COMPR_TAIL(cbdq->channel_info->compr_tail,
			       sizeof(struct cbd_ce),
			       cbdq->channel.compr_size);

	if (cbd_req->op == CBD_OP_READ) {
		spin_lock(&cbdq->channel.submr_lock);
		copy_data_from_cbdreq(cbd_req);
		spin_unlock(&cbdq->channel.submr_lock);
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

	cpu_relax();
	queue_delayed_work(cbdq->cbd_blkdev->task_wq, &cbdq->complete_work, 0);
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

static int cbd_queue_channel_init(struct cbd_queue *cbdq, u32 channel_id)
{
	struct cbd_blkdev *cbd_blkdev = cbdq->cbd_blkdev;
	struct cbd_transport *cbdt = cbd_blkdev->cbdt;

	cbd_channel_init(&cbdq->channel, cbdt, channel_id);
	cbdq->channel_info = cbdq->channel.channel_info;

	if (!cbd_blkdev->backend)
		cbdq->channel_info->polling = true;

	cbdq->channel.data_head = cbdq->channel.data_tail = 0;
	cbdq->channel_info->submr_tail = cbdq->channel_info->submr_head = 0;
	cbdq->channel_info->compr_tail = cbdq->channel_info->compr_head = 0;

	cbdq->channel_info->backend_id = cbd_blkdev->backend_id;
	cbdq->channel_info->blkdev_id = cbd_blkdev->blkdev_id;
	cbdq->channel_info->blkdev_state = cbdc_blkdev_state_running;

	return 0;
}

int cbd_queue_start(struct cbd_queue *cbdq)
{
	struct cbd_transport *cbdt = cbdq->cbd_blkdev->cbdt;
	u32 channel_id;
	int ret;

	ret = cbd_get_empty_channel_id(cbdt, &channel_id);
	if (ret < 0) {
		cbdt_err(cbdt, "failed find available channel_id.\n");
		goto err;
	}

	ret = cbd_queue_channel_init(cbdq, channel_id);
	if (ret) {
		cbdt_err(cbdt, "failed to init dev channel_info: %d.", ret);
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
		goto channel_exit;
	}

	queue_delayed_work(cbdq->cbd_blkdev->task_wq, &cbdq->complete_work, 0);

	atomic_set(&cbdq->state, cbd_queue_state_running);

	return 0;

channel_exit:
	cbdq->channel_info->blkdev_state = cbdc_blkdev_state_none;
	cbd_channel_exit(&cbdq->channel);
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
		cbd_req_put(cbd_req, -EIO);
	}

	kfree(cbdq->released_extents);
	cbdq->channel_info->blkdev_state = cbdc_blkdev_state_none;
	cbd_channel_exit(&cbdq->channel);
}
