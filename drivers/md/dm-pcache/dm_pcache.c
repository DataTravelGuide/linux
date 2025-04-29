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
		if (ret == -ENOMEM || ret == -EBUSY)
			bio->bi_status = BLK_STS_DM_REQUEUE;
		else
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

static int parse_cache_dev(struct dm_pcache *pcache, struct dm_arg_set *as,
				char **error)
{
	const char *cache_dev_path;
	int ret;

	if (!as->argc) {
		*error = "Cache_dev_path required";
		return -EINVAL;
	}

	cache_dev_path = dm_shift_arg(as);
	ret = cache_dev_start(pcache, cache_dev_path);
	if (ret) {
		pcache_err("error to start cache dev: %s, ret: %d", cache_dev_path, ret);
		*error = "Failed to start cache dev";
		return ret;;
	}

	return 0;
}

static int parse_backing_dev(struct dm_pcache *pcache, struct dm_arg_set *as,
				char **error)
{
	const char *backing_dev_path;
	int ret;

	if (!as->argc) {
		*error = "Backing_dev_path required";
		return -EINVAL;
	}

	backing_dev_path = dm_shift_arg(as);
	ret = backing_dev_start(pcache, backing_dev_path);
	if (ret) {
		pcache_err("error to start backing dev: %s, ret: %d", backing_dev_path, ret);
		*error = "Failed to start backing dev";
		return ret;;
	}

	return 0;
}

static int parse_pcache_args(struct dm_pcache *pcache, unsigned int argc, char **argv,
				char **error)
{
	struct dm_arg_set as;
	int ret;

	as.argc = argc;
	as.argv = argv;

	ret = parse_cache_dev(pcache, &as, error);
	if (ret)
		goto err;

	ret = parse_backing_dev(pcache, &as, error);
	if (ret)
		goto stop_cache_dev;

	return 0;

stop_cache_dev:
	cache_dev_stop(pcache);
err:
	return ret;
}

static int dm_pcache_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct dm_pcache *pcache;
	int ret;

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

	pcache->ti = ti;

	ret = parse_pcache_args(pcache, argc, argv, &ti->error);
	if (ret) {
		pcache_err("parse args failed.");
		goto destroy_wq;
	}

	ret = pcache_cache_start(pcache, true);
	if (ret) {
		pcache_err("failed to start caching: %d", ret);
		goto stop_backing_dev;
	}

	ti->per_io_data_size = sizeof(struct pcache_request);
	ti->private = pcache;

	return 0;

stop_backing_dev:
	backing_dev_stop(pcache);
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
	if (ret == -ENOMEM || ret == -EBUSY) {
		pcache_err("requeue req: %d", ret);
		return DM_MAPIO_REQUEUE;
	} else if (ret) {
		pcache_err("failed to handle request: %d", ret);
		return DM_MAPIO_KILL;
	}

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
