/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _DM_PCACHE_H
#define _DM_PCACHE_H
#include <linux/device-mapper.h>

#define CACHE_DEV_TO_PCACHE(cache_dev)		(container_of(cache_dev, struct dm_pcache, cache_dev))
#define BACKING_DEV_TO_PCACHE(backing_dev)	(container_of(backing_dev, struct dm_pcache, backing_dev))
#define CACHE_TO_PCACHE(cache)			(container_of(cache, struct dm_pcache, cache))

struct pcache_cache_dev;
struct pcache_backing_dev;
struct pcache_cache;
struct dm_pcache {
	struct dm_target *ti;
	struct pcache_cache_dev cache_dev;
	struct pcache_backing_dev backing_dev;
	struct pcache_cache cache;

	spinlock_t			defered_req_list_lock;
	struct list_head		defered_req_list;
	struct workqueue_struct		*task_wq;

	struct delayed_work		defered_req_work;
};

struct pcache_request {
	struct dm_pcache	*pcache;
	struct bio		*bio;

	u64			off;
	u32			data_len;

	struct kref		ref;
	int			ret;

	struct list_head	list_node;
};

void pcache_req_get(struct pcache_request *pcache_req);
void pcache_req_put(struct pcache_request *pcache_req, int ret);

#endif /* _DM_PCACHE_H */
