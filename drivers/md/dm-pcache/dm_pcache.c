// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/device-mapper.h>
#include <linux/blkdev.h>
#include <linux/bio.h>

#include "../dm-core.h"

#include "cache_dev.h"
#include "backing_dev.h"
#include "cache.h"
#include "dm_pcache.h"

static void end_req(struct kref *ref)
{
	struct pcache_request *pcache_req = container_of(ref, struct pcache_request, ref);
	struct bio *bio = pcache_req->bio;
	int ret = pcache_req->ret;

	if (bio) {
		bio->bi_status = ret;
		bio_endio(bio);
	}
}

void pcache_req_get(struct pcache_request *pcache_req)
{
	kref_get(&pcache_req->ref);
}

void pcache_req_put(struct pcache_request *pcache_req, int ret)
{
	/* Set the return status if it is not already set */
	if (ret && !pcache_req->ret)
		pcache_req->ret = ret;

	kref_put(&pcache_req->ref, end_req);
}

/* ---------------- target callbacks -------------------------------- */
static int dm_pcache_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct dm_pcache *pcache;
	const char *cache_dev_path, *backing_dev_path;
	int ret;

	/* Check if we have the right number of arguments */
	if (argc != 2) {
		pr_err("argc: %d", argc);
		ti->error = "pcache: invalid argument count";
		return -EINVAL;
	}

	/* Allocate memory for the cache structure */
	pcache = kzalloc(sizeof(struct dm_pcache), GFP_KERNEL);
	if (!pcache)
		return -ENOMEM;

	pcache->task_wq = alloc_workqueue("pcache-%s-wq",  WQ_UNBOUND | WQ_MEM_RECLAIM, 0,
						ti->table->md->name);
	if (!pcache->task_wq) {
		ret = -ENOMEM;
		goto free_pcache;
	}

	cache_dev_path = argv[0];  // Cache device path
	backing_dev_path = argv[1];  // Backing device path

	ti->per_io_data_size = sizeof(struct pcache_request);
	ti->private = pcache;

	/* Log the parsed data (for debugging) */
	pr_info("Cache device: %s\n", cache_dev_path);
	pr_info("Backing device: %s\n", backing_dev_path);

	ret = cache_dev_start(pcache, cache_dev_path);
	if (ret) {
		pcache_err("failed to start cache_dev: %d", ret);
		goto destroy_wq;
	}

	ret = backing_dev_start(pcache, backing_dev_path);
	if (ret) {
		pcache_err("failed to start backing_dev: %d", ret);
		goto stop_cache_dev;
	}

	ret = pcache_cache_start(pcache, true);
	if (ret) {
		pcache_err("failed to start caching: %d", ret);
		goto stop_backing_dev;
	}

	return 0;

stop_backing_dev:
	backing_dev_stop(pcache);
stop_cache_dev:
	cache_dev_stop(pcache);
destroy_wq:
	destroy_workqueue(pcache->task_wq);
free_pcache:
	kfree(pcache);

	return ret;
}

static void dm_pcache_dtr(struct dm_target *ti)
{
	struct dm_pcache *pcache;

	pcache = ti->private;

	pcache_cache_stop(pcache);
	backing_dev_stop(pcache);
	cache_dev_stop(pcache);

	drain_workqueue(pcache->task_wq);
	destroy_workqueue(pcache->task_wq);

	kfree(pcache);
}

static int dm_pcache_map_bio(struct dm_target *ti, struct bio *bio)
{
	struct dm_pcache *pcache = ti->private;
	struct pcache_request *pcache_req = dm_per_bio_data(bio, sizeof(struct pcache_request));
	int ret;

	kref_init(&pcache_req->ref);
	pcache_req->ret = 0;
	pcache_req->bio = bio;
	pcache_req->off = (u64)bio->bi_iter.bi_sector << SECTOR_SHIFT;
	pcache_req->data_len = (u64)bio_sectors(bio) << SECTOR_SHIFT;

	ret = pcache_cache_handle_req(&pcache->cache, pcache_req);
	pcache_req_put(pcache_req, ret);
	if (ret)
		return DM_MAPIO_KILL;

	return DM_MAPIO_SUBMITTED;
}

static void dm_pcache_status(struct dm_target *ti, status_type_t type,
			     unsigned int status_flags, char *result,
			     unsigned int maxlen)
{
	snprintf(result, maxlen, "noop ok");
}

static int dm_pcache_message(struct dm_target *ti, unsigned int argc,
			     char **argv, char *result, unsigned int maxlen)
{
	return -EINVAL; /* no messages supported yet */
}

static struct target_type dm_pcache_target = {
	.name		= "pcache",
	.version	= {0, 1, 0},
	.module		= THIS_MODULE,
	.ctr		= dm_pcache_ctr,
	.dtr		= dm_pcache_dtr,
	.map		= dm_pcache_map_bio,
	.status		= dm_pcache_status,
	.message	= dm_pcache_message,
};

static int __init dm_pcache_init(void)
{
	return dm_register_target(&dm_pcache_target);
}
module_init(dm_pcache_init);

static void __exit dm_pcache_exit(void)
{
	dm_unregister_target(&dm_pcache_target);
}
module_exit(dm_pcache_exit);

MODULE_DESCRIPTION("dm-pcache Persistent Memory to be Cache for block device");
MODULE_AUTHOR("Dongsheng Yang <dongsheng.yang@linux.dev>");
MODULE_LICENSE("GPL v2");
