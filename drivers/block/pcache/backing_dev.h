/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _BACKING_DEV_H
#define _BACKING_DEV_H

#include <linux/hashtable.h>

#include "pcache_internal.h"
#include "cache_dev.h"

#define backing_dev_err(backing_dev, fmt, ...)						\
	cache_dev_err(backing_dev->cache_dev, "backing_dev%d: " fmt,			\
		 backing_dev->backing_dev_id, ##__VA_ARGS__)
#define backing_dev_info(backing_dev, fmt, ...)						\
	cache_dev_info(backing_dev->cache_dev, "backing_dev%d: " fmt,			\
		 backing_dev->backing_dev_id, ##__VA_ARGS__)
#define backing_dev_debug(backing_dev, fmt, ...)					\
	cache_dev_debug(backing_dev->cache_dev, "backing_dev%d: " fmt,			\
		 backing_dev->backing_dev_id, ##__VA_ARGS__)

#define PCACHE_BACKING_STATE_NONE		0
#define PCACHE_BACKING_STATE_RUNNING		1

struct pcache_cache_info;
struct pcache_backing_dev_info {
	struct pcache_meta_header	header;
	u8				state;
	u8				res;

	u16				res1;

	u32				backing_dev_id;
	u64				dev_size; /* nr_sectors */

	char				path[PCACHE_PATH_LEN];
	struct pcache_cache_info	cache_info;
};

struct pcache_backing_dev_req;
typedef void (*backing_req_end_fn_t)(struct pcache_backing_dev_req *backing_req, int ret);

struct pcache_request;
struct pcache_backing_dev_req {
	struct bio			*bio;
	struct pcache_backing_dev	*backing_dev;

	void				*priv_data;
	backing_req_end_fn_t		end_req;

	struct pcache_request		*upper_req;
	u32				bio_off;
	struct list_head		node;
	struct kref			ref;
	int				ret;
};

struct pcache_logic_dev;
struct pcache_backing_dev {
	u32				backing_dev_id;
	struct pcache_cache_dev		*cache_dev;
	spinlock_t			lock;
	struct list_head		node;
	struct device			device;

	struct pcache_backing_dev_info	backing_dev_info;
	struct pcache_backing_dev_info	*backing_dev_info_addr;
	struct mutex			info_lock;

	struct block_device		*bdev;
	struct file			*bdev_file;

	struct workqueue_struct		*task_wq;

	struct bio_set			bioset;
	struct kmem_cache		*backing_req_cache;
	struct list_head		submit_list;
	spinlock_t			submit_lock;
	struct work_struct		req_submit_work;

	struct list_head		complete_list;
	spinlock_t			complete_lock;
	struct work_struct		req_complete_work;

	struct pcache_logic_dev		*logic_dev;
	u64				dev_size;

	u32				cache_segs;
	struct pcache_cache		*cache;
};

int backing_dev_start(struct pcache_cache_dev *cache_dev, char *path, u32 queues, u32 cache_segs);
int backing_dev_stop(struct pcache_cache_dev *cache_dev, u32 backing_dev_id);
void backing_dev_info_write(struct pcache_backing_dev *backing_dev);

void backing_dev_req_submit(struct pcache_backing_dev_req *backing_req);
void backing_dev_req_end(struct pcache_backing_dev_req *backing_req);
struct pcache_backing_dev_req *backing_dev_req_create(struct pcache_backing_dev *backing_dev,
		struct pcache_request *pcache_req, u32 off, u32 len, backing_req_end_fn_t end_req);
#endif /* _BACKING_DEV_H */
