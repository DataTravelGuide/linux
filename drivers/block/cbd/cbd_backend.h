/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CBD_BACKEND_H
#define _CBD_BACKEND_H

#include <linux/hashtable.h>

#include "cbd_internal.h"

#include "cbd_transport.h"

#include "cbd_host.h"

#include "cbd_cache/cbd_cache.h"

#include "cbd_handler.h"
#include "cbd_blkdev.h"

/* cbd_backend */
CBD_DEVICE(backend);

enum cbd_backend_state {
	cbd_backend_state_none	= 0,
	cbd_backend_state_running,
	cbd_backend_state_removing
};

#define CBDB_BLKDEV_COUNT_MAX	1

struct cbd_backend_info {
	struct cbd_meta_header	meta_header;
	u8			state;
	u8			res;

	u16			res1;
	u32			host_id;

	u64			alive_ts;
	u64			dev_size; /* nr_sectors */

	char			path[CBD_PATH_LEN];

	u32			n_handlers;
	u32			handler_channels[CBD_HANDLERS_MAX];

	struct cbd_cache_info	cache_info;
};

struct cbd_backend_io {
	struct cbd_se		*se;
	u64			off;
	u32			len;
	struct bio		*bio;
	struct cbd_handler	*handler;
};

#define CBD_BACKENDS_HANDLER_BITS	7

struct cbd_backend {
	u32			backend_id;
	struct cbd_transport	*cbdt;
	spinlock_t		lock;

	u32			backend_info_index;
	struct cbd_backend_info	backend_info;
	struct mutex		info_lock;

	u32			host_id;

	struct block_device	*bdev;
	struct file		*bdev_file;

	struct workqueue_struct	*task_wq;
	struct delayed_work	hb_work; /* heartbeat work */

	struct list_head	node; /* cbd_transport->backends */
	DECLARE_HASHTABLE(handlers_hash, CBD_BACKENDS_HANDLER_BITS);

	struct cbd_backend_device *backend_device;
	struct kmem_cache	*backend_io_cache;

	struct cbd_cache	*cbd_cache;
	struct device		cache_dev;
};

int cbd_backend_start(struct cbd_transport *cbdt, char *path, u32 backend_id,
		      u32 handlers, u32 cache_segs);
int cbd_backend_stop(struct cbd_transport *cbdt, u32 backend_id);
int cbd_backend_clear(struct cbd_transport *cbdt, u32 backend_id);
int cbdb_add_handler(struct cbd_backend *cbdb, struct cbd_handler *handler);
void cbdb_del_handler(struct cbd_backend *cbdb, struct cbd_handler *handler);
bool cbd_backend_info_is_alive(struct cbd_backend_info *info);
bool cbd_backend_cache_on(struct cbd_backend_info *backend_info);
void cbd_backend_notify(struct cbd_backend *cbdb, u32 seg_id);
void cbd_backend_info_write(struct cbd_backend *cbdb);

#endif /* _CBD_BACKEND_H */
