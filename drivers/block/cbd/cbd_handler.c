// SPDX-License-Identifier: GPL-2.0-or-later

#include "cbd_internal.h"

static inline struct cbd_se *get_se_head(struct cbd_handler *handler)
{
	return (struct cbd_se *)(handler->channel.submr + handler->channel_info->submr_head);
}

static inline struct cbd_se *get_se_to_handle(struct cbd_handler *handler)
{
	return (struct cbd_se *)(handler->channel.submr + handler->se_to_handle);
}

static inline struct cbd_ce *get_compr_head(struct cbd_handler *handler)
{
	return (struct cbd_ce *)(handler->channel.compr + handler->channel_info->compr_head);
}

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
	CBDC_UPDATE_COMPR_HEAD(handler->channel_info->compr_head,
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

	ret = cbdc_map_pages(&handler->channel, backend_io);
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

static void handle_work_fn(struct work_struct *work)
{
	struct cbd_handler *handler = container_of(work, struct cbd_handler,
						   handle_work.work);
	struct cbd_se *se;
	u64 req_tid;
	int ret;

again:
	/* channel ctrl would be updated by blkdev queue */
	se = get_se_to_handle(handler);
	if (se == get_se_head(handler))
		goto miss;

	req_tid = se->req_tid;
	if (handler->req_tid_expected != U64_MAX &&
			req_tid != handler->req_tid_expected) {
		cbd_handler_err(handler, "req_tid (%llu) is not expected (%llu)",
				req_tid, handler->req_tid_expected);
		goto miss;
	}

#ifdef CONFIG_CBD_CRC
	if (se->se_crc != cbd_se_crc(se)) {
		cbd_handler_err(handler, "se crc(0x%x) is not expected(0x%x)",
				cbd_se_crc(se), se->se_crc);
		goto miss;
	}

	if (se->op == CBD_OP_WRITE &&
		se->data_crc != cbd_channel_crc(&handler->channel,
						se->data_off,
						se->data_len)) {
		cbd_handler_err(handler, "data crc(0x%x) is not expected(0x%x)",
				cbd_channel_crc(&handler->channel, se->data_off, se->data_len),
				se->data_crc);
		goto miss;
	}
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
	if (cbdwc_need_retry(&handler->handle_worker_cfg))
		goto again;

	cbdwc_miss(&handler->handle_worker_cfg);

	if (handler->polling)
		queue_delayed_work(handler->cbdb->task_wq, &handler->handle_work, 0);
}

int cbd_handler_create(struct cbd_backend *cbdb, u32 channel_id)
{
	struct cbd_transport *cbdt = cbdb->cbdt;
	struct cbd_handler *handler;
	int ret;

	handler = kzalloc(sizeof(struct cbd_handler), GFP_KERNEL);
	if (!handler)
		return -ENOMEM;

	ret = bioset_init(&handler->bioset, 256, 0, BIOSET_NEED_BVECS);
	if (ret)
		goto err;

	handler->cbdb = cbdb;
	cbd_channel_init(&handler->channel, cbdt, channel_id);
	handler->channel_info = handler->channel.channel_info;

	if (handler->channel_info->polling)
		handler->polling = true;

	handler->se_to_handle = handler->channel_info->submr_tail;
	handler->req_tid_expected = U64_MAX;

	spin_lock_init(&handler->compr_lock);
	INIT_DELAYED_WORK(&handler->handle_work, handle_work_fn);

	cbdwc_init(&handler->handle_worker_cfg);

	cbdb_add_handler(cbdb, handler);
	handler->channel_info->backend_state = cbdc_backend_state_running;

	queue_delayed_work(cbdb->task_wq, &handler->handle_work, 0);

	return 0;
err:
	kfree(handler);
	return ret;
};

void cbd_handler_destroy(struct cbd_handler *handler)
{
	cbdb_del_handler(handler->cbdb, handler);

	cancel_delayed_work_sync(&handler->handle_work);

	handler->channel_info->backend_state = cbdc_backend_state_none;
	cbd_channel_exit(&handler->channel);

	bioset_exit(&handler->bioset);
	kfree(handler);
}
