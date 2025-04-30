/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _PCACHE_LOGIC_DEV_H
#define _PCACHE_LOGIC_DEV_H

#include <linux/blk-mq.h>

#include "pcache_internal.h"

#define logic_dev_err(logic_dev, fmt, ...)							\
	cache_dev_err(logic_dev->backing_dev->cache_dev, "logic_dev%d: " fmt,			\
		 logic_dev->mapped_id, ##__VA_ARGS__)
#define logic_dev_info(logic_dev, fmt, ...)							\
	cache_dev_info(logic_dev->backing_dev->cache_dev, "logic_dev%d: " fmt,			\
		 logic_dev->mapped_id, ##__VA_ARGS__)
#define logic_dev_debug(logic_dev, fmt, ...)							\
	cache_dev_debug(logic_dev->backing_dev->cache_dev, "logic_dev%d: " fmt,			\
		 logic_dev->mapped_id, ##__VA_ARGS__)

#define PCACHE_QUEUE_STATE_NONE			0
#define PCACHE_QUEUE_STATE_RUNNING		1

struct pcache_queue {
	struct pcache_logic_dev	*logic_dev;
	u32			index;

	u8	                state;
};

struct pcache_request {
	struct pcache_queue	*queue;
	struct request		*req;

	u64			off;
	u32			data_len;

	u8			op;

	struct kref		ref;
	int			ret;
};

struct pcache_logic_dev {
	int				mapped_id; /* id in block device such as: /dev/pcache0 */

	struct pcache_backing_dev	*backing_dev;

	int				major;		/* blkdev assigned major */
	int				minor;
	struct gendisk			*disk;		/* blkdev's gendisk and rq */

	struct mutex			lock;
	unsigned long			open_count;	/* protected by lock */

	struct list_head		node;

	/* Block layer tags. */
	struct blk_mq_tag_set		tag_set;

	uint32_t			num_queues;
	struct pcache_queue		*queues;

	u64				dev_size;
};

int logic_dev_start(struct pcache_backing_dev *backing_dev, u32 queues);
int logic_dev_stop(struct pcache_logic_dev *logic_dev);

void pcache_req_get(struct pcache_request *pcache_req);
void pcache_req_put(struct pcache_request *pcache_req, int ret);

int pcache_blkdev_init(void);
void pcache_blkdev_exit(void);
#endif /* _PCACHE_LOGIC_DEV_H */
