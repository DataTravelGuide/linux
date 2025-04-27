// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/blkdev.h>

#include "pcache_internal.h"
#include "cache_dev.h"
#include "backing_dev.h"
#include "cache.h"
#include "dm_pcache.h"

static void backing_dev_destroy(struct pcache_backing_dev *backing_dev)
{
	drain_workqueue(backing_dev->task_wq);
	destroy_workqueue(backing_dev->task_wq);
	kmem_cache_destroy(backing_dev->backing_req_cache);
	kfree(backing_dev);
}

static void req_submit_fn(struct work_struct *work);
static void req_complete_fn(struct work_struct *work);
static struct pcache_backing_dev *backing_dev_init(struct dm_pcache *pcache)
{
	struct pcache_backing_dev *backing_dev = &pcache->backing_dev;

	backing_dev->backing_req_cache = KMEM_CACHE(pcache_backing_dev_req, 0);
	if (!backing_dev->backing_req_cache)
		goto free_backing_dev;

	backing_dev->task_wq = alloc_workqueue("pcache-backing-wq",  WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
	if (!backing_dev->task_wq)
		goto destroy_io_cache;

	backing_dev->cache_segs = pcache->cache_dev.seg_num;

	INIT_LIST_HEAD(&backing_dev->submit_list);
	INIT_LIST_HEAD(&backing_dev->complete_list);
	spin_lock_init(&backing_dev->submit_lock);
	spin_lock_init(&backing_dev->complete_lock);
	INIT_WORK(&backing_dev->req_submit_work, req_submit_fn);
	INIT_WORK(&backing_dev->req_complete_work, req_complete_fn);

	return backing_dev;

destroy_io_cache:
	kmem_cache_destroy(backing_dev->backing_req_cache);
free_backing_dev:
	kfree(backing_dev);
	return NULL;
}

static int backing_dev_open(struct pcache_backing_dev *backing_dev, char *path)
{
	bool new_backing;
	int ret;

	backing_dev->bdev_file = bdev_file_open_by_path(path,
			BLK_OPEN_READ | BLK_OPEN_WRITE, backing_dev, NULL);
	if (IS_ERR(backing_dev->bdev_file)) {
		pcache_err("failed to open bdev: %d", (int)PTR_ERR(backing_dev->bdev_file));
		ret = PTR_ERR(backing_dev->bdev_file);
		goto err;
	}

	backing_dev->bdev = file_bdev(backing_dev->bdev_file);
	backing_dev->dev_size = bdev_nr_sectors(backing_dev->bdev);

	ret = bioset_init(&backing_dev->bioset, 1024, 0, BIOSET_NEED_BVECS);
	if (ret)
		goto close_bdev;

	return 0;

close_bdev:
	fput(backing_dev->bdev_file);
err:
	return ret;
}

static int backing_dev_close(struct pcache_backing_dev *backing_dev)
{
	bioset_exit(&backing_dev->bioset);
	fput(backing_dev->bdev_file);

	return 0;
}

int backing_dev_start(struct dm_pcache *pcache, char *backing_dev_path)
{
	struct pcache_backing_dev *backing_dev;
	int ret;

	/* Check if path starts with "/dev/" */
	if (strncmp(backing_dev_path, "/dev/", 5) != 0)
		return -EINVAL;

	backing_dev = backing_dev_init(pcache);
	if (!backing_dev)
		return -ENOMEM;

	ret = backing_dev_open(backing_dev, backing_dev_path);
	if (ret)
		goto destroy_backing_dev;

	return 0;

destroy_backing_dev:
	backing_dev_destroy(backing_dev);

	return ret;
}

int backing_dev_stop(struct dm_pcache *pcache)
{
	struct pcache_backing_dev *backing_dev = &pcache->backing_dev;

	backing_dev_close(backing_dev);
	backing_dev_destroy(backing_dev);

	return 0;
}

/* pcache_backing_dev_req functions */
static void end_req(struct kref *ref)
{
	struct pcache_backing_dev_req *backing_req = container_of(ref, struct pcache_backing_dev_req, ref);
	struct pcache_backing_dev *backing_dev = backing_req->backing_dev;

	spin_lock(&backing_dev->complete_lock);
	list_move_tail(&backing_req->node, &backing_dev->complete_list);
	spin_unlock(&backing_dev->complete_lock);

	queue_work(backing_dev->task_wq, &backing_dev->req_complete_work);
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

struct pcache_backing_dev_req *backing_dev_req_create(struct pcache_backing_dev *backing_dev,
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

	bio_trim(clone, off, len);

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

void backing_dev_req_submit(struct pcache_backing_dev_req *backing_req)
{
	struct pcache_backing_dev *backing_dev = backing_req->backing_dev;

	kref_get(&backing_req->ref);

	spin_lock(&backing_dev->submit_lock);
	list_add_tail(&backing_req->node, &backing_dev->submit_list);
	spin_unlock(&backing_dev->submit_lock);

	queue_work(backing_dev->task_wq, &backing_dev->req_submit_work);
}

void backing_dev_req_end(struct pcache_backing_dev_req *backing_req)
{
	struct pcache_backing_dev *backing_dev = backing_req->backing_dev;

	if (backing_req->end_req)
		backing_req->end_req(backing_req, backing_req->ret);

	kmem_cache_free(backing_dev->backing_req_cache, backing_req);
}
