// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/blkdev.h>

#include "pcache_internal.h"
#include "cache_dev.h"
#include "backing_dev.h"
#include "cache.h"
#include "dm_pcache.h"

static void backing_dev_destroy(struct pcache_backing_dev *backing_dev)
{
	kmem_cache_destroy(backing_dev->backing_req_cache);
}

static void req_submit_fn(struct work_struct *work);
static void req_complete_fn(struct work_struct *work);
static int backing_dev_init(struct dm_pcache *pcache)
{
	struct pcache_backing_dev *backing_dev = &pcache->backing_dev;
	int ret;

	backing_dev->backing_req_cache = KMEM_CACHE(pcache_backing_dev_req, 0);
	if (!backing_dev->backing_req_cache) {
		ret = -ENOMEM;
		goto err;
	}

	INIT_LIST_HEAD(&backing_dev->submit_list);
	INIT_LIST_HEAD(&backing_dev->complete_list);
	spin_lock_init(&backing_dev->submit_lock);
	spin_lock_init(&backing_dev->complete_lock);
	INIT_WORK(&backing_dev->req_submit_work, req_submit_fn);
	INIT_WORK(&backing_dev->req_complete_work, req_complete_fn);

	return 0;
err:
	return ret;
}

static int backing_dev_open(struct pcache_backing_dev *backing_dev, const char *path)
{
	struct dm_pcache *pcache = BACKING_DEV_TO_PCACHE(backing_dev);
	int ret;

	ret = dm_get_device(pcache->ti, path,
			BLK_OPEN_READ | BLK_OPEN_WRITE, &backing_dev->dm_dev);
	if (ret) {
		pcache_err("failed to open dm_dev: %s: %d", path, ret);
		goto err;
	}

	backing_dev->bdev_file = backing_dev->dm_dev->bdev_file;
	backing_dev->bdev = backing_dev->dm_dev->bdev;
	backing_dev->dev_size = bdev_nr_sectors(backing_dev->bdev);

	ret = bioset_init(&backing_dev->bioset, 1024, 0, BIOSET_NEED_BVECS);
	if (ret)
		goto put_dev;

	return 0;

put_dev:
	dm_put_device(pcache->ti, backing_dev->dm_dev);
err:
	return ret;
}

static int backing_dev_close(struct pcache_backing_dev *backing_dev)
{
	struct dm_pcache *pcache = BACKING_DEV_TO_PCACHE(backing_dev);

	bioset_exit(&backing_dev->bioset);
	dm_put_device(pcache->ti, backing_dev->dm_dev);

	return 0;
}

int backing_dev_start(struct dm_pcache *pcache, const char *backing_dev_path)
{
	struct pcache_backing_dev *backing_dev = &pcache->backing_dev;
	int ret;

	/* Check if path starts with "/dev/" */
	if (strncmp(backing_dev_path, "/dev/", 5) != 0)
		return -EINVAL;

	ret = backing_dev_init(pcache);
	if (ret)
		goto err;

	ret = backing_dev_open(backing_dev, backing_dev_path);
	if (ret)
		goto destroy_backing_dev;

	return 0;

destroy_backing_dev:
	backing_dev_destroy(backing_dev);
err:
	return ret;
}

void backing_dev_stop(struct dm_pcache *pcache)
{
	struct pcache_backing_dev *backing_dev = &pcache->backing_dev;

	backing_dev_close(backing_dev);
	backing_dev_destroy(backing_dev);
}

/* pcache_backing_dev_req functions */
void backing_dev_req_end(struct pcache_backing_dev_req *backing_req)
{
	struct pcache_backing_dev *backing_dev = backing_req->backing_dev;

	if (backing_req->end_req)
		backing_req->end_req(backing_req, backing_req->ret);

	kmem_cache_free(backing_dev->backing_req_cache, backing_req);
}

static void req_complete_fn(struct work_struct *work)
{
	struct pcache_backing_dev *backing_dev = container_of(work, struct pcache_backing_dev, req_complete_work);
	struct pcache_backing_dev_req *backing_req;
	unsigned long flags;
	LIST_HEAD(tmp_list);

	spin_lock_irqsave(&backing_dev->complete_lock, flags);
	list_splice_init(&backing_dev->complete_list, &tmp_list);
	spin_unlock_irqrestore(&backing_dev->complete_lock, flags);

	while (!list_empty(&tmp_list)) {
		backing_req = list_first_entry(&tmp_list,
					    struct pcache_backing_dev_req, node);
		list_del_init(&backing_req->node);
		backing_dev_req_end(backing_req);
	}
}

static void end_req(struct kref *ref)
{
	struct pcache_backing_dev_req *backing_req = container_of(ref, struct pcache_backing_dev_req, ref);
	struct pcache_backing_dev *backing_dev = backing_req->backing_dev;

	spin_lock(&backing_dev->complete_lock);
	list_move_tail(&backing_req->node, &backing_dev->complete_list);
	spin_unlock(&backing_dev->complete_lock);

	queue_work(BACKING_DEV_TO_PCACHE(backing_dev)->task_wq, &backing_dev->req_complete_work);
}

static void backing_dev_bio_end(struct bio *bio)
{
	struct pcache_backing_dev_req *backing_req = bio->bi_private;
	int ret = bio->bi_status;

	if (ret && !backing_req->ret)
		backing_req->ret = ret;

	kref_put(&backing_req->ref, end_req);
	bio_put(bio);
}

static void req_submit_fn(struct work_struct *work)
{
	struct pcache_backing_dev *backing_dev = container_of(work, struct pcache_backing_dev, req_submit_work);
	struct pcache_backing_dev_req *backing_req;
	unsigned long flags;
	LIST_HEAD(tmp_list);

	spin_lock(&backing_dev->submit_lock);
	list_splice_init(&backing_dev->submit_list, &tmp_list);
	spin_unlock(&backing_dev->submit_lock);

	while (!list_empty(&tmp_list)) {
		backing_req = list_first_entry(&tmp_list,
					    struct pcache_backing_dev_req, node);
		list_del_init(&backing_req->node);
		submit_bio_noacct(backing_req->bio);

		local_irq_save(flags);
		kref_put(&backing_req->ref, end_req);
		local_irq_restore(flags);
	}
}

void backing_dev_req_submit(struct pcache_backing_dev_req *backing_req)
{
	struct pcache_backing_dev *backing_dev = backing_req->backing_dev;

	kref_get(&backing_req->ref);

	spin_lock(&backing_dev->submit_lock);
	list_add_tail(&backing_req->node, &backing_dev->submit_list);
	spin_unlock(&backing_dev->submit_lock);

	queue_work(BACKING_DEV_TO_PCACHE(backing_dev)->task_wq, &backing_dev->req_submit_work);
}

static struct pcache_backing_dev_req *req_type_req_create(struct pcache_backing_dev *backing_dev,
							struct pcache_request *pcache_req,
							u32 off, u32 len,
							backing_req_end_fn_t end_fn)
{
	struct pcache_backing_dev_req *backing_req;
	struct bio *clone, *orig = pcache_req->bio;

	backing_req = kmem_cache_zalloc(backing_dev->backing_req_cache, GFP_ATOMIC);
	if (!backing_req)
		return NULL;

	clone = bio_alloc_clone(NULL, orig, GFP_ATOMIC, &backing_dev->bioset);
	if (!clone)
		goto err_free_req;

	BUG_ON(off & SECTOR_MASK);
	BUG_ON(len & SECTOR_MASK);
	bio_trim(clone, off >> SECTOR_SHIFT, len >> SECTOR_SHIFT);

	bio_set_dev(clone, backing_dev->bdev);
	clone->bi_opf = bio_op(orig);
	clone->bi_iter.bi_sector = (pcache_req->off + off) >> SECTOR_SHIFT;
	clone->bi_private = backing_req;
	clone->bi_end_io = backing_dev_bio_end;

	backing_req->backing_dev = backing_dev;
	INIT_LIST_HEAD(&backing_req->node);
	kref_init(&backing_req->ref);
	backing_req->bio_off     = off;
	backing_req->bio         = clone;
	backing_req->end_req     = end_fn;

	pcache_req_get(pcache_req);
	backing_req->upper_req = pcache_req;

	return backing_req;

err_free_req:
	kmem_cache_free(backing_dev->backing_req_cache, backing_req);
	return NULL;
}

struct pcache_backing_dev_req *backing_dev_req_create(struct pcache_backing_dev *backing_dev,
						struct pcache_backing_dev_req_opts *opts)
{
	if (opts->type == BACKING_DEV_REQ_TYPE_REQ)
		return req_type_req_create(backing_dev, opts->req.upper_req, opts->req.req_off, opts->req.len, opts->end_fn);

	return NULL;
}
