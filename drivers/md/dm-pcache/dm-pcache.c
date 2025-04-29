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

/* ------------------------------------------------------------------ */
struct dm_pcache {
        const char *cache_dev;
        const char *backing_dev;
        unsigned long sec_nr;
};

struct pcache_request {
};

/* ---------------- target callbacks -------------------------------- */
static int dm_pcache_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
        struct dm_pcache *pcache;
        const char *cache_dev, *backing_dev;
        int ret;
        dump_stack();

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

        cache_dev = argv[0];  // Cache device path
        backing_dev = argv[1];  // Backing device path

        pcache->cache_dev = cache_dev;
        pcache->backing_dev = backing_dev;

        ti->per_io_data_size = sizeof(struct pcache_request);
        ti->private = pcache;

        /* Log the parsed data (for debugging) */
        pr_info("Cache device: %s\n", cache_dev);
        pr_info("Backing device: %s\n", backing_dev);

        /* Return success */
        return 0;
}

static void dm_pcache_dtr(struct dm_target *ti)
{
        kfree(ti->private);
}

/* bio-based fast path – just succeed */
static int dm_pcache_map_bio(struct dm_target *ti, struct bio *bio)
{
        /* We simply complete the bio without doing any actual I/O */
        bio_endio(bio);  // Correct way to complete bio with success status
        return DM_MAPIO_SUBMITTED;
}

static int dm_pcache_busy(struct dm_target *ti) { return 0; }

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
        .busy             = dm_pcache_busy,
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
