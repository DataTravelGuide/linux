// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/blkdev.h>

#include "../dm-core.h"
#include "pcache_internal.h"
#include "cache_dev.h"
#include "backing_dev.h"
#include "cache.h"
#include "dm_pcache.h"

static void backing_dev_exit(struct pcache_backing_dev *backing_dev)
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

int backing_dev_start(struct dm_pcache *pcache)
{
	struct pcache_backing_dev *backing_dev = &pcache->backing_dev;
	int ret;

	ret = backing_dev_init(pcache);
	if (ret)
		return ret;

	backing_dev->dev_size = bdev_nr_sectors(backing_dev->dm_dev->bdev);

	return 0;
}

void backing_dev_stop(struct dm_pcache *pcache)
{
	struct pcache_backing_dev *backing_dev = &pcache->backing_dev;

	flush_work(&backing_dev->req_submit_work);
	flush_work(&backing_dev->req_complete_work);

	/* There should be no inflight backing_dev_request */
	BUG_ON(!list_empty(&backing_dev->submit_list));
	BUG_ON(!list_empty(&backing_dev->complete_list));

	backing_dev_exit(backing_dev);
}

/* pcache_backing_dev_req functions */
void backing_dev_req_end(struct pcache_backing_dev_req *backing_req)
{
	struct pcache_backing_dev *backing_dev = backing_req->backing_dev;

	if (backing_req->end_req)
		backing_req->end_req(backing_req, backing_req->ret);

	switch (backing_req->type) {
	case BACKING_DEV_REQ_TYPE_REQ:
		pcache_req_put(backing_req->req.upper_req, backing_req->ret);
		break;
	case BACKING_DEV_REQ_TYPE_KMEM:
		if (backing_req->kmem.bvecs != backing_req->kmem.inline_bvecs)
			kfree(backing_req->kmem.bvecs);
		break;
	default:
		BUG();
	}

	kmem_cache_free(backing_dev->backing_req_cache, backing_req);
}

static void req_complete_fn(struct work_struct *work)
{
	struct pcache_backing_dev *backing_dev = container_of(work, struct pcache_backing_dev, req_complete_work);
	struct pcache_backing_dev_req *backing_req;
	LIST_HEAD(tmp_list);

	spin_lock_irq(&backing_dev->complete_lock);
	list_splice_init(&backing_dev->complete_list, &tmp_list);
	spin_unlock_irq(&backing_dev->complete_lock);

	while (!list_empty(&tmp_list)) {
		backing_req = list_first_entry(&tmp_list,
					    struct pcache_backing_dev_req, node);
		list_del_init(&backing_req->node);
		backing_dev_req_end(backing_req);
	}
}

static void backing_dev_bio_end(struct bio *bio)
{
	struct pcache_backing_dev_req *backing_req = bio->bi_private;
	struct pcache_backing_dev *backing_dev = backing_req->backing_dev;
	unsigned long flags;

	backing_req->ret = bio->bi_status;

	spin_lock_irqsave(&backing_dev->complete_lock, flags);
	list_move_tail(&backing_req->node, &backing_dev->complete_list);
	queue_work(BACKING_DEV_TO_PCACHE(backing_dev)->task_wq, &backing_dev->req_complete_work);
	spin_unlock_irqrestore(&backing_dev->complete_lock, flags);
}

static void req_submit_fn(struct work_struct *work)
{
	struct pcache_backing_dev *backing_dev = container_of(work, struct pcache_backing_dev, req_submit_work);
	struct pcache_backing_dev_req *backing_req;
	LIST_HEAD(tmp_list);

	spin_lock(&backing_dev->submit_lock);
	list_splice_init(&backing_dev->submit_list, &tmp_list);
	spin_unlock(&backing_dev->submit_lock);

	while (!list_empty(&tmp_list)) {
		backing_req = list_first_entry(&tmp_list,
					    struct pcache_backing_dev_req, node);
		list_del_init(&backing_req->node);
		submit_bio_noacct(&backing_req->bio);
	}
}

void backing_dev_req_submit(struct pcache_backing_dev_req *backing_req, bool direct)
{
	struct pcache_backing_dev *backing_dev = backing_req->backing_dev;

	if (direct) {
		submit_bio_noacct(&backing_req->bio);
		return;
	}

	spin_lock(&backing_dev->submit_lock);
	list_add_tail(&backing_req->node, &backing_dev->submit_list);
	queue_work(BACKING_DEV_TO_PCACHE(backing_dev)->task_wq, &backing_dev->req_submit_work);
	spin_unlock(&backing_dev->submit_lock);
}

static struct pcache_backing_dev_req *req_type_req_create(struct pcache_backing_dev *backing_dev,
							struct pcache_backing_dev_req_opts *opts)
{
	struct pcache_request *pcache_req = opts->req.upper_req;
	struct pcache_backing_dev_req *backing_req;
	struct bio *clone, *orig = pcache_req->bio;
	u32 off = opts->req.req_off;
	u32 len = opts->req.len;
	int ret;

	backing_req = kmem_cache_zalloc(backing_dev->backing_req_cache, opts->gfp_mask);
	if (!backing_req)
		return NULL;

	ret = bio_init_clone(backing_dev->dm_dev->bdev, &backing_req->bio, orig, opts->gfp_mask);
	if (ret)
		goto err_free_req;

	backing_req->type = BACKING_DEV_REQ_TYPE_REQ;

	clone = &backing_req->bio;
	BUG_ON(off & SECTOR_MASK);
	BUG_ON(len & SECTOR_MASK);
	bio_trim(clone, off >> SECTOR_SHIFT, len >> SECTOR_SHIFT);

	clone->bi_iter.bi_sector = (pcache_req->off + off) >> SECTOR_SHIFT;
	clone->bi_private = backing_req;
	clone->bi_end_io = backing_dev_bio_end;

	backing_req->backing_dev = backing_dev;
	INIT_LIST_HEAD(&backing_req->node);
	backing_req->end_req     = opts->end_fn;

	pcache_req_get(pcache_req);
	backing_req->req.upper_req	= pcache_req;
	backing_req->req.bio_off	= off;

	return backing_req;

err_free_req:
	kmem_cache_free(backing_dev->backing_req_cache, backing_req);
	return NULL;
}

static void bio_map(struct bio *bio, void *base, size_t size)
{
	struct page *page;
	unsigned int offset;
	unsigned int len;

	if (!is_vmalloc_addr(base)) {
		page = virt_to_page(base);
		offset = offset_in_page(base);

		BUG_ON(!bio_add_page(bio, page, size, offset));
		return;
	}

	flush_kernel_vmap_range(base, size);
	while (size) {
		page = vmalloc_to_page(base);
		offset = offset_in_page(base);
		len = min_t(size_t, PAGE_SIZE - offset, size);

		BUG_ON(!bio_add_page(bio, page, len, offset));
		size -= len;
		base += len;
	}
}

static u32 get_n_vecs(void *data, u32 len)
{
	if (!is_vmalloc_addr(data))
		return 1;

	return DIV_ROUND_UP(len, PAGE_SIZE);
}

static struct pcache_backing_dev_req *kmem_type_req_create(struct pcache_backing_dev *backing_dev,
						struct pcache_backing_dev_req_opts *opts)
{
	struct pcache_backing_dev_req *backing_req;
	struct bio *backing_bio;
	u32 n_vecs = get_n_vecs(opts->kmem.data, opts->kmem.len);

	backing_req = kmem_cache_zalloc(backing_dev->backing_req_cache, opts->gfp_mask);
	if (!backing_req)
		return NULL;

	if (n_vecs > BACKING_DEV_REQ_INLINE_BVECS) {
		backing_req->kmem.bvecs = kmalloc_array(n_vecs, sizeof(struct bio_vec), opts->gfp_mask);
		if (!backing_req->kmem.bvecs)
			goto err_free_req;
	} else {
		backing_req->kmem.bvecs = backing_req->kmem.inline_bvecs;
	}

	backing_req->type = BACKING_DEV_REQ_TYPE_KMEM;

	bio_init(&backing_req->bio, backing_dev->dm_dev->bdev, backing_req->kmem.bvecs,
			n_vecs, opts->kmem.opf);

	backing_bio = &backing_req->bio;
	bio_map(backing_bio, opts->kmem.data, opts->kmem.len);

	backing_bio->bi_iter.bi_sector = (opts->kmem.backing_off) >> SECTOR_SHIFT;
	backing_bio->bi_private = backing_req;
	backing_bio->bi_end_io = backing_dev_bio_end;

	backing_req->backing_dev = backing_dev;
	INIT_LIST_HEAD(&backing_req->node);
	backing_req->end_req	= opts->end_fn;
	backing_req->priv_data	= opts->priv_data;

	return backing_req;

err_free_req:
	kmem_cache_free(backing_dev->backing_req_cache, backing_req);
	return NULL;
}

struct pcache_backing_dev_req *backing_dev_req_create(struct pcache_backing_dev *backing_dev,
						struct pcache_backing_dev_req_opts *opts)
{
	if (opts->type == BACKING_DEV_REQ_TYPE_REQ)
		return req_type_req_create(backing_dev, opts);
	else if (opts->type == BACKING_DEV_REQ_TYPE_KMEM)
		return kmem_type_req_create(backing_dev, opts);

	return NULL;
}

void backing_dev_flush(struct pcache_backing_dev *backing_dev)
{
	blkdev_issue_flush(backing_dev->dm_dev->bdev);
}
