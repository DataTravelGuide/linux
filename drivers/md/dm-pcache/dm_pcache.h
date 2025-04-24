/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _DM_PCACHE_H
#define _DM_PCACHE_H

struct pcache_cache_dev;
struct pcache_backing_dev;
struct dm_pcache {
	struct pcache_cache_dev cache_dev;
	struct pcache_backing_dev backing_dev;
        unsigned long sec_nr;
};

#endif /* _DM_PCACHE_H */
