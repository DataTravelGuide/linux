/*
 * dm‑pcache.c – Minimal stub Device‑Mapper target (request‑based)
 * -------------------------------------------------------------
 * A no‑op target that immediately completes every request with BLK_STS_OK.
 * No backing device, metadata, or DAX initialisation is performed – this is
 * just a compilable & runnable skeleton for future development.
 */

#include <linux/module.h>
#include <linux/device-mapper.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>

/* ------------------------------------------------------------------ */
struct dm_pcache { /* empty for now */ };

/* ---------------- target callbacks -------------------------------- */
static int dm_pcache_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
        struct dm_pcache *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
        if (!ctx)
                return -ENOMEM;
        ti->private = ctx;
        return 0;
}

static void dm_pcache_dtr(struct dm_target *ti)
{
        kfree(ti->private);
}

/* Request‑based fast path – just succeed */
static int dm_pcache_clone_and_map_rq(struct dm_target *ti,
                                      struct request *rq,
                                      union map_info *map_ctx,
                                      struct request **clone)
{
        blk_mq_end_request(rq, BLK_STS_OK);
        *clone = NULL;                 /* nothing was dispatched */
        return DM_MAPIO_SUBMITTED;
}

static void dm_pcache_release_clone_rq(struct request *clone,
                                       union map_info *map_ctx) {}

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
        .clone_and_map_rq = dm_pcache_clone_and_map_rq,
        .release_clone_rq = dm_pcache_release_clone_rq,
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

MODULE_DESCRIPTION("Device‑mapper pcache (stub – all I/O succeed)");
MODULE_AUTHOR("Dongsheng Yang");
MODULE_LICENSE("GPL v2");
