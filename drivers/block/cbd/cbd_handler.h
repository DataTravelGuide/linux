/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CBD_HANDLER_H
#define _CBD_HANDLER_H

/* cbd_handler */
struct cbd_handler {
	struct cbd_backend	*cbdb;

	struct cbd_channel	channel;
	struct cbd_channel_ctrl	*channel_ctrl;
	spinlock_t		compr_lock;

	u32			se_to_handle;
	u64			req_tid_expected;

	struct delayed_work	handle_work;
	struct cbd_worker_cfg	handle_worker_cfg;

	atomic_t		inflight_cmds;

	struct hlist_node	hash_node;
	struct bio_set		bioset;
};

void cbd_handler_destroy(struct cbd_handler *handler);
int cbd_handler_create(struct cbd_backend *cbdb, u32 seg_id, bool init_channel);
void cbd_handler_notify(struct cbd_handler *handler);

#endif /* _CBD_HANDLER_H */
