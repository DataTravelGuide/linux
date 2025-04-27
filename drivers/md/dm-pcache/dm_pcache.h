/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _DM_PCACHE_H
#define _DM_PCACHE_H

#define CACHE_DEV_TO_PCACHE(cache_dev)		(container_of(cache_dev, struct dm_pcache, cache_dev))
#define BACKING_DEV_TO_PCACHE(cache)		(container_of(backing_dev, struct dm_pcache, backing_dev))
#define CACHE_TO_PCACHE(cache)			(container_of(cache, struct dm_pcache, cache))

struct pcache_cache_dev;
struct pcache_backing_dev;
struct pcache_cache;
struct dm_pcache {
	struct pcache_cache_dev cache_dev;
	struct pcache_backing_dev backing_dev;
	struct pcache_cache cache;

	struct workqueue_struct		*task_wq;
};

#endif /* _DM_PCACHE_H */
