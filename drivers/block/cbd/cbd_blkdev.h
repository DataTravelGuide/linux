/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _CBD_BLKDEV_H
#define _CBD_BLKDEV_H

#include <linux/blk-mq.h>

#include "cbd_internal.h"
#include "cbd_transport.h"
#include "cbd_channel.h"
#include "cbd_cache/cbd_cache.h"
#include "cbd_handler.h"
#include "cbd_backend.h"
#include "cbd_queue.h"

#define cbd_blk_err(dev, fmt, ...)						\
	cbdt_err(dev->cbdt, "cbd%d: " fmt,					\
		 dev->mapped_id, ##__VA_ARGS__)
#define cbd_blk_info(dev, fmt, ...)						\
	cbdt_info(dev->cbdt, "cbd%d: " fmt,					\
		 dev->mapped_id, ##__VA_ARGS__)
#define cbd_blk_debug(dev, fmt, ...)						\
	cbdt_debug(dev->cbdt, "cbd%d: " fmt,					\
		 dev->mapped_id, ##__VA_ARGS__)

/* cbd_blkdev */
CBD_DEVICE(blkdev);

#define CBD_BLKDEV_STATE_NONE		0
#define CBD_BLKDEV_STATE_RUNNING	1

struct cbd_blkdev_info {
	struct cbd_meta_header meta_header;
	u8	state;
	u64	alive_ts;
	u32	backend_id;
	u32	host_id;
	u32	mapped_id;
};

struct cbd_blkdev {
	u32			blkdev_id; /* index in transport blkdev area */
	u32			backend_id;
	int			mapped_id; /* id in block device such as: /dev/cbd0 */

	struct cbd_backend	*backend; /* reference to backend if blkdev and backend on the same host */

	int			major;		/* blkdev assigned major */
	int			minor;
	struct gendisk		*disk;		/* blkdev's gendisk and rq */

	struct mutex		lock;
	unsigned long		open_count;	/* protected by lock */

	struct list_head	node;
	struct delayed_work	hb_work; /* heartbeat work */

	/* Block layer tags. */
	struct blk_mq_tag_set	tag_set;

	uint32_t		num_queues;
	struct cbd_queue	*queues;

	u64			dev_size;

	struct workqueue_struct	*task_wq;

	struct cbd_blkdev_device *blkdev_dev;
	struct cbd_blkdev_info	blkdev_info;
	struct mutex		info_lock;

	struct cbd_transport *cbdt;

	struct cbd_cache_info	cache_info;
	struct cbd_cache	*cbd_cache;
};

int cbd_blkdev_init(void);
void cbd_blkdev_exit(void);
int cbd_blkdev_start(struct cbd_transport *cbdt, u32 backend_id, u32 queues);
int cbd_blkdev_stop(struct cbd_transport *cbdt, u32 devid);
int cbd_blkdev_clear(struct cbd_transport *cbdt, u32 devid);
bool cbd_blkdev_info_is_alive(struct cbd_blkdev_info *info);

extern struct workqueue_struct	*cbd_wq;

#define cbd_for_each_blkdev_info(cbdt, i, blkdev_info)					\
	for (i = 0;									\
	     i < cbdt->transport_info.blkdev_num &&					\
	     (blkdev_info = cbdt_blkdev_info_read(cbdt, i));				\
	     i++)

#endif /* _CBD_BLKDEV_H */
