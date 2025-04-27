/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _DM_PCACHE_H
#define _DM_PCACHE_H

struct pcache_cache_dev;
struct pcache_backing_dev;
struct pcache_cache;
struct dm_pcache {
	struct pcache_cache_dev cache_dev;
	struct pcache_backing_dev backing_dev;
        unsigned long sec_nr;
	struct pcache_cache cache;
};

#endif /* _DM_PCACHE_H */
