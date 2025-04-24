/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _BACKING_DEV_H
#define _BACKING_DEV_H

#include "pcache_internal.h"
#include "cache_dev.h"

#define PCACHE_BACKING_STATE_NONE		0
#define PCACHE_BACKING_STATE_RUNNING		1

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

struct pcache_backing_dev {
	struct pcache_cache		*cache;
	struct pcache_cache_dev		*cache_dev;
	spinlock_t			lock;

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

	u64				dev_size;
	u32				cache_segs;
};

struct pcache_backing_dev_opts {
	char *path;
	u32 queues;
	u32 cache_segs;
	bool data_crc;
};

struct dm_pcache;
int backing_dev_start(struct dm_pcache *pcache, char *backing_dev_path);
int backing_dev_stop(struct dm_pcache *pcache);

void backing_dev_req_submit(struct pcache_backing_dev_req *backing_req);
void backing_dev_req_end(struct pcache_backing_dev_req *backing_req);
struct pcache_backing_dev_req *backing_dev_req_create(struct pcache_backing_dev *backing_dev,
		struct pcache_request *pcache_req, u32 off, u32 len, backing_req_end_fn_t end_req);
#endif /* _BACKING_DEV_H */
