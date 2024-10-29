// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/blkdev.h>

#include "cbd_handler.h"

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
	CBDC_UPDATE_COMPR_HEAD(handler->channel_ctrl->compr_head,
			       sizeof(struct cbd_ce),
			       handler->channel.compr_size);
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
	backend_io->se = se;
	backend_io->handler = handler;
	backend_io->bio = bio_alloc_bioset(cbdb->bdev,
				DIV_ROUND_UP(se->len, PAGE_SIZE),
				opf, GFP_KERNEL, &handler->bioset);

	if (!backend_io->bio) {
		kmem_cache_free(cbdb->backend_io_cache, backend_io);
		return NULL;
	}

	atomic_inc(&handler->inflight_cmds);
	backend_io->bio->bi_iter.bi_sector = se->offset >> SECTOR_SHIFT;
	backend_io->bio->bi_iter.bi_size = 0;
	backend_io->bio->bi_private = backend_io;
	backend_io->bio->bi_end_io = backend_bio_end;

	return backend_io;
}

static int handle_backend_cmd(struct cbd_handler *handler, struct cbd_se *se)
{
	struct cbd_backend *cbdb = handler->cbdb;
	struct cbd_backend_io *backend_io = NULL;
	int ret;

	if (cbd_se_flags_test(se, CBD_SE_FLAGS_DONE))
		return 0;

	switch (se->op) {
	case CBD_OP_READ:
		backend_io = backend_prepare_io(handler, se, REQ_OP_READ);
		break;
	case CBD_OP_WRITE:
		backend_io = backend_prepare_io(handler, se, REQ_OP_WRITE);
		break;
	case CBD_OP_FLUSH:
		ret = blkdev_issue_flush(cbdb->bdev);
		goto complete_cmd;
	default:
		cbd_handler_err(handler, "unrecognized op: 0x%x", se->op);
		ret = -EIO;
		goto complete_cmd;
	}

	if (!backend_io)
		return -ENOMEM;

	ret = cbdc_map_pages(&handler->channel, backend_io->bio, se->data_off, se->data_len);
	if (ret) {
		kmem_cache_free(cbdb->backend_io_cache, backend_io);
		return ret;
	}

	submit_bio(backend_io->bio);

	return 0;

complete_cmd:
	complete_cmd(handler, se, ret);
	return 0;
}

void cbd_handler_notify(struct cbd_handler *handler)
{
	queue_delayed_work(handler->cbdb->task_wq, &handler->handle_work, 0);
}

static bool req_tid_valid(struct cbd_handler *handler, u64 req_tid)
{
	/* New handler */
	if (handler->req_tid_expected == U64_MAX)
		return true;

	return (req_tid == handler->req_tid_expected);
}

static void handler_channel_init(struct cbd_handler *handler, u32 channel_id, bool new_channel);
static void handler_reset(struct cbd_handler *handler)
{
	handler->req_tid_expected = U64_MAX;
	handler->se_to_handle = 0;

	handler->channel.data_head = handler->channel.data_tail = 0;
	handler->channel_ctrl->submr_tail = handler->channel_ctrl->submr_head = 0;
	handler->channel_ctrl->compr_tail = handler->channel_ctrl->compr_head = 0;

	handler->channel_ctrl->need_reset = 0;
	smp_mb();
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

static void handle_work_fn(struct work_struct *work)
{
	struct cbd_handler *handler = container_of(work, struct cbd_handler,
						   handle_work.work);
	struct cbd_se *se;
	u64 req_tid;
	int ret;

	smp_mb();
	if (handler->channel_ctrl->need_reset) {
		if (atomic_read(&handler->inflight_cmds))
			goto out;

		handler_reset(handler);
	}

again:
	/* channel ctrl would be updated by blkdev queue */
	se = get_se_to_handle(handler);
	if (se == get_se_head(handler))
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
		/* this se is handled */
		handler->req_tid_expected = req_tid + 1;
		handler->se_to_handle = (handler->se_to_handle + sizeof(struct cbd_se)) %
							handler->channel.submr_size;
	}

	goto again;

miss:
	/* miss means there is no new se need to handle,in this round */
	if (cbdwc_need_retry(&handler->handle_worker_cfg))
		goto again;

	cbdwc_miss(&handler->handle_worker_cfg);
out:
	if (handler->channel_ctrl->polling)
		queue_delayed_work(handler->cbdb->task_wq, &handler->handle_work, 0);
	else
		queue_delayed_work(handler->cbdb->task_wq, &handler->handle_work, 1);
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

	if (!new_channel)
		return;

	handler->channel.data_head = handler->channel.data_tail = 0;
	handler->channel_ctrl->submr_tail = handler->channel_ctrl->submr_head = 0;
	handler->channel_ctrl->compr_tail = handler->channel_ctrl->compr_head = 0;

	handler->channel_ctrl->need_reset = 0;
	handler->channel_ctrl->polling = 0;
}

int cbd_handler_create(struct cbd_backend *cbdb, u32 channel_id, bool new_channel)
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
	handler_channel_init(handler, channel_id, new_channel);

	handler->se_to_handle = handler->channel_ctrl->submr_tail;
	handler->req_tid_expected = U64_MAX;
	atomic_set(&handler->inflight_cmds, 0);
	spin_lock_init(&handler->compr_lock);
	INIT_DELAYED_WORK(&handler->handle_work, handle_work_fn);
	cbdwc_init(&handler->handle_worker_cfg);

	cbdb_add_handler(cbdb, handler);
	queue_delayed_work(cbdb->task_wq, &handler->handle_work, 0);

	return 0;

free_handler:
	kfree(handler);
	return ret;
};

void cbd_handler_destroy(struct cbd_handler *handler)
{
	cbdb_del_handler(handler->cbdb, handler);

	cancel_delayed_work_sync(&handler->handle_work);

	while (atomic_read(&handler->inflight_cmds))
		schedule_timeout(HZ);

	cbd_channel_destroy(&handler->channel);

	bioset_exit(&handler->bioset);
	kfree(handler);
}
