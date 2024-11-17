/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _CBD_HANDLER_H
#define _CBD_HANDLER_H

#include "cbd_channel.h"
#include "cbd_backend.h"

#define cbd_handler_err(handler, fmt, ...)					\
	cbdb_err(handler->cbdb, "handler%d: " fmt,				\
		 handler->channel.seg_id, ##__VA_ARGS__)
#define cbd_handler_info(handler, fmt, ...)					\
	cbdb_info(handler->cbdb, "handler%d: " fmt,				\
		 handler->channel.seg_id, ##__VA_ARGS__)
#define cbd_handler_debug(handler, fmt, ...)					\
	cbdb_debug(handler->cbdb, "handler%d: " fmt,				\
		 handler->channel.seg_id, ##__VA_ARGS__)

/* cbd_handler */
struct cbd_handler {
	struct cbd_backend	*cbdb;

	struct cbd_channel	channel;
	struct cbd_channel_ctrl	*channel_ctrl;
	spinlock_t		compr_lock;
	spinlock_t		submr_lock;

	u32			se_to_handle;
	u64			req_tid_expected;

	struct delayed_work	handle_work;
	struct cbd_worker_cfg	handle_worker_cfg;

	struct delayed_work	handle_mgmt_work;

	atomic_t		inflight_cmds;

	struct hlist_node	hash_node;
	struct bio_set		bioset;
};

void cbd_handler_destroy(struct cbd_handler *handler);
int cbd_handler_create(struct cbd_backend *cbdb, u32 seg_id, bool init_channel);
void cbd_handler_notify(struct cbd_handler *handler);
void cbd_handler_mgmt_notify(struct cbd_handler *handler);

static inline struct cbd_se *get_se_head(struct cbd_handler *handler)
{
	u32 se_head = cbdc_submr_head_get(&handler->channel);

	if (unlikely(se_head > (handler->channel.submr_size - sizeof(struct cbd_se))))
		return NULL;

	return (struct cbd_se *)(handler->channel.submr + se_head);
}

static inline struct cbd_se *get_se_to_handle(struct cbd_handler *handler)
{
	return (struct cbd_se *)(handler->channel.submr + handler->se_to_handle);
}

static inline struct cbd_ce *get_compr_head(struct cbd_handler *handler)
{
	return (struct cbd_ce *)(handler->channel.compr + cbdc_compr_head_get(&handler->channel));
}

#endif /* _CBD_HANDLER_H */
