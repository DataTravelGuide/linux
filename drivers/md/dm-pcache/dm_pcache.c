/*
 * dm‑pcache.c – Minimal bio-based Device‑Mapper target
 * -------------------------------------------------------------
 * This is a bio-based target that immediately completes every request with BLK_STS_OK.
 * No backing device, metadata, or DAX initialisation is performed – this is
 * just a compilable & runnable skeleton for future development.
 */

#include <linux/module.h>
#include <linux/device-mapper.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>  // Required for bio-based targets

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

        cache_dev_path = argv[0];  // Cache device path
        backing_dev_path = argv[1];  // Backing device path

        ti->per_io_data_size = sizeof(struct pcache_request);
        ti->private = pcache;

        /* Log the parsed data (for debugging) */
        pr_info("Cache device: %s\n", cache_dev_path);
        pr_info("Backing device: %s\n", backing_dev_path);

	ret = cache_dev_start(pcache, cache_dev_path, backing_dev_path);

	pr_err("ret of dev_start: %d", ret);

	ret = backing_dev_start(pcache, backing_dev_path);

	pr_err("ret of backing start: %d", ret);

	ret = pcache_cache_start(pcache, true);

	return ret;
}

static void dm_pcache_dtr(struct dm_target *ti)
{
	struct dm_pcache *pcache;

	pcache = ti->private;

	pcache_cache_stop(pcache);
	backing_dev_stop(pcache);
	cache_dev_stop(pcache);
        kfree(pcache);
}

/* bio-based fast path – just succeed */
static int dm_pcache_map_bio(struct dm_target *ti, struct bio *bio)
{
	struct dm_pcache *pcache = ti->private;
	struct pcache_request *pcache_req = dm_per_bio_data(bio, sizeof(struct pcache_request));
	int ret;

	pcache_req->bio = bio;
	pcache_req->off = (u64)bio->bi_iter.bi_sector << 9;
	pcache_req->data_len = (u64)bio_sectors(bio) << 9;
	kref_init(&pcache_req->ref);
	pcache_req->ret = 0;
	ret = pcache_cache_handle_req(&pcache->cache, pcache_req);

	pcache_req_put(pcache_req, ret);
	if (ret) {
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

/* ---------------- registration ------------------------------------ */
static struct target_type dm_pcache_target = {
        .name             = "pcache",
        .version          = {0, 0, 1},
        .module           = THIS_MODULE,
        .ctr              = dm_pcache_ctr,
        .dtr              = dm_pcache_dtr,
        .map 	         = dm_pcache_map_bio,  // Updated to map_bio for bio-based targets
        .status           = dm_pcache_status,
        .message          = dm_pcache_message,
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

MODULE_DESCRIPTION("Device‑mapper pcache (bio-based, all I/O succeed)");
MODULE_AUTHOR("Dongsheng Yang");
MODULE_LICENSE("GPL v2");
