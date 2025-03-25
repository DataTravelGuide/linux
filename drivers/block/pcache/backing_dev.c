// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/blkdev.h>

#include "pcache_internal.h"
#include "cache_dev.h"
#include "cache.h"
#include "backing_dev.h"
#include "logic_dev.h"
#include "meta_segment.h"

void backing_dev_info_write(struct pcache_backing_dev *backing_dev)
{
	struct pcache_backing_dev_info *info;
	struct pcache_meta_header *meta;

	mutex_lock(&backing_dev->info_lock);

	meta = &backing_dev->backing_dev_info.header;
	meta->seq++;

	info = pcache_meta_find_oldest(&backing_dev->backing_dev_info_addr->header, PCACHE_BACKING_DEV_INFO_SIZE);
	memcpy(info, &backing_dev->backing_dev_info, sizeof(struct pcache_backing_dev_info));
	info->header.crc = pcache_meta_crc(&info->header, PCACHE_BACKING_DEV_INFO_SIZE);

	cache_dev_flush(backing_dev->cache_dev, info, PCACHE_BACKING_DEV_INFO_SIZE);
	mutex_unlock(&backing_dev->info_lock);
}

static int backing_dev_info_load(struct pcache_backing_dev *backing_dev)
{
	struct pcache_backing_dev_info *info;
	int ret = 0;

	mutex_lock(&backing_dev->info_lock);

	info = pcache_meta_find_latest(&backing_dev->backing_dev_info_addr->header, PCACHE_BACKING_DEV_INFO_SIZE);
	if (!info) {
		ret = -EIO;
		goto unlock;
	}

	memcpy(&backing_dev->backing_dev_info, info, sizeof(struct pcache_backing_dev_info));
unlock:
	mutex_unlock(&backing_dev->info_lock);
	return ret;
}

static void backing_dev_free(struct pcache_backing_dev *backing_dev)
{
	drain_workqueue(backing_dev->task_wq);
	destroy_workqueue(backing_dev->task_wq);
	kmem_cache_destroy(backing_dev->backing_req_cache);
	kfree(backing_dev);
}

static void req_submit_fn(struct work_struct *work);
static void req_complete_fn(struct work_struct *work);
static struct pcache_backing_dev *backing_dev_alloc(struct pcache_cache_dev *cache_dev)
{
	struct pcache_backing_dev *backing_dev;

	backing_dev = kzalloc(sizeof(struct pcache_backing_dev), GFP_KERNEL);
	if (!backing_dev)
		return NULL;

	backing_dev->backing_req_cache = KMEM_CACHE(pcache_backing_dev_req, 0);
	if (!backing_dev->backing_req_cache)
		goto free_backing_dev;

	backing_dev->task_wq = alloc_workqueue("pcache-submit-wq",  WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
	if (!backing_dev->task_wq)
		goto destroy_io_cache;

	backing_dev->cache_dev = cache_dev;

	mutex_init(&backing_dev->info_lock);
	INIT_LIST_HEAD(&backing_dev->node);
	INIT_LIST_HEAD(&backing_dev->submit_list);
	INIT_LIST_HEAD(&backing_dev->complete_list);
	spin_lock_init(&backing_dev->lock);
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

static int backing_dev_cache_init(struct pcache_backing_dev *backing_dev,
		u32 queues, u32 cache_segs, bool new_backing_dev)
{
	struct pcache_cache_opts cache_opts = { 0 };
	int ret;

	backing_dev->cache_segs = cache_segs;
	cache_opts.cache_info = &backing_dev->backing_dev_info.cache_info;
	cache_opts.n_segs = cache_segs;
	cache_opts.n_paral = queues;
	cache_opts.new_cache = new_backing_dev;
	cache_opts.bdev_file = backing_dev->bdev_file;
	cache_opts.dev_size = backing_dev->dev_size;

	backing_dev->cache = pcache_cache_alloc(backing_dev, &cache_opts);
	if (!backing_dev->cache) {
		ret = -ENOMEM;
		goto err;
	}

	return 0;

err:
	return ret;
}

static void backing_dev_cache_destroy(struct pcache_backing_dev *backing_dev)
{
	if (backing_dev->cache)
		pcache_cache_destroy(backing_dev->cache);
}

static int backing_dev_init(struct pcache_backing_dev *backing_dev, char *path, u32 queues, u32 cache_segs)
{
	struct pcache_cache_dev *cache_dev = backing_dev->cache_dev;
	bool new_backing;
	int ret;

	memcpy(backing_dev->backing_dev_info.path, path, PCACHE_PATH_LEN);

	backing_dev->bdev_file = bdev_file_open_by_path(backing_dev->backing_dev_info.path,
			BLK_OPEN_READ | BLK_OPEN_WRITE, backing_dev, NULL);
	if (IS_ERR(backing_dev->bdev_file)) {
		backing_dev_err(backing_dev, "failed to open bdev: %d", (int)PTR_ERR(backing_dev->bdev_file));
		ret = PTR_ERR(backing_dev->bdev_file);
		goto err;
	}

	backing_dev->bdev = file_bdev(backing_dev->bdev_file);
	backing_dev->dev_size = bdev_nr_sectors(backing_dev->bdev);

	ret = bioset_init(&backing_dev->bioset, 1024, 0, BIOSET_NEED_BVECS);
	if (ret)
		goto close_bdev;

	ret = cache_dev_find_backing_info(cache_dev, backing_dev, &new_backing);
	if (ret)
		goto bioset_exit;

	if (!new_backing)
		backing_dev_info_load(backing_dev);

	ret = backing_dev_cache_init(backing_dev, queues, cache_segs, new_backing);
	if (ret)
		goto bioset_exit;

	ret = logic_dev_start(backing_dev, queues);
	if (ret)
		goto destroy_cache;

	backing_dev->backing_dev_info.state = PCACHE_BACKING_STATE_RUNNING;
	backing_dev->backing_dev_info.backing_dev_id = backing_dev->backing_dev_id;
	backing_dev_info_write(backing_dev);

	cache_dev_add_backing(cache_dev, backing_dev);

	return 0;

destroy_cache:
	backing_dev_cache_destroy(backing_dev);
bioset_exit:
	bioset_exit(&backing_dev->bioset);
close_bdev:
	fput(backing_dev->bdev_file);
err:
	return ret;
}

static int backing_dev_destroy(struct pcache_backing_dev *backing_dev)
{
	logic_dev_stop(backing_dev->logic_dev);
	backing_dev->backing_dev_info.state = PCACHE_BACKING_STATE_NONE;
	backing_dev_info_write(backing_dev);
	backing_dev_cache_destroy(backing_dev);
	bioset_exit(&backing_dev->bioset);
	fput(backing_dev->bdev_file);

	return 0;
}

int backing_dev_start(struct pcache_cache_dev *cache_dev, char *path, u32 queues, u32 cache_segs)
{
	struct pcache_backing_dev *backing_dev;
	int ret;

	/* Check if path starts with "/dev/" */
	if (strncmp(path, "/dev/", 5) != 0)
		return -EINVAL;

	backing_dev = backing_dev_alloc(cache_dev);
	if (!backing_dev)
		return -ENOMEM;

	ret = backing_dev_init(backing_dev, path, queues, cache_segs);
	if (ret)
		goto destroy_backing_dev;

	return 0;

destroy_backing_dev:
	backing_dev_free(backing_dev);

	return ret;
}

int backing_dev_stop(struct pcache_cache_dev *cache_dev, u32 backing_dev_id)
{
	struct pcache_backing_dev *backing_dev;

	backing_dev = cache_dev_fetch_backing(cache_dev, backing_dev_id);
	if (!backing_dev)
		return -ENOENT;

	backing_dev_destroy(backing_dev);
	backing_dev_free(backing_dev);

	return 0;
}

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

static int map_bio_pages(struct bio *bio, struct request *req, u32 req_off, u32 len)
{
	struct bio_vec src_bvec;
	struct bvec_iter src_iter;
	size_t mapped = 0, offset = 0;
	struct bio *src_bio;

	src_bio = req->bio;

next_bio:
	bio_for_each_segment(src_bvec, src_bio, src_iter) {
		struct page *page = src_bvec.bv_page;
		size_t page_off = src_bvec.bv_offset;
		size_t page_len = src_bvec.bv_len;
		
		if (offset + page_len <= req_off) {
			offset += page_len;
			continue;
		}

		size_t start = (req_off > offset) ? (req_off - offset) : 0;
		size_t map_len = min(len - mapped, page_len - start);

		if (bio_add_page(bio, page, map_len, page_off + start) != map_len) {
			pr_err("Failed to map page to bio\n");
			break;
		}

		mapped += map_len;
		if (mapped >= len)
			goto out;

		offset += page_len;
	}

	if (src_bio->bi_next) {
		src_bio = src_bio->bi_next;
		goto next_bio;
	}
out:
	return 0;
}

struct pcache_backing_dev_req *backing_dev_req_create(struct pcache_backing_dev *backing_dev, struct pcache_request *pcache_req,
			u32 off, u32 len, backing_req_end_fn_t end_req)
{
	struct pcache_backing_dev_req *backing_req;
	u32 mapped_len = 0;
	struct bio *bio;

	backing_req = kmem_cache_zalloc(backing_dev->backing_req_cache, GFP_ATOMIC);
	if (!backing_req)
		return NULL;

	backing_req->backing_dev = backing_dev;
	INIT_LIST_HEAD(&backing_req->node);
	kref_init(&backing_req->ref);
	backing_req->end_req = end_req;
	backing_req->bio_off = off;
next_bio:
	bio = bio_alloc_bioset(backing_dev->bdev,
					BIO_MAX_VECS,
					req_op(pcache_req->req),
					GFP_ATOMIC, &backing_dev->bioset);
	if (!bio)
		goto free_backing_req;

	bio->bi_iter.bi_sector = (pcache_req->off + off + mapped_len) >> SECTOR_SHIFT;
	bio->bi_iter.bi_size = 0;
	bio->bi_private = backing_req;
	bio->bi_end_io = backing_dev_bio_end;
	kref_get(&backing_req->ref);

	if (backing_req->bio)
		bio->bi_next = backing_req->bio;
	backing_req->bio = bio;

	map_bio_pages(bio, pcache_req->req, off + mapped_len, len - mapped_len);
	mapped_len += bio->bi_iter.bi_size;
	if (mapped_len < len)
		goto next_bio;

	pcache_req_get(pcache_req);
	backing_req->upper_req = pcache_req;

	return backing_req;

free_backing_req:
	while (backing_req->bio) {
		bio = backing_req->bio;
		backing_req->bio = bio->bi_next;
		bio_put(bio);
	}
	kmem_cache_free(backing_dev->backing_req_cache, backing_req);

	return NULL;
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
		while (backing_req->bio) {
			struct bio *bio = backing_req->bio;

			backing_req->bio = bio->bi_next;
			submit_bio_noacct(bio);
		}
		kref_put(&backing_req->ref, end_req);
	}
}

static void req_complete_fn(struct work_struct *work)
{
	struct pcache_backing_dev *backing_dev = container_of(work, struct pcache_backing_dev, req_complete_work);
	struct pcache_backing_dev_req *backing_req;
	LIST_HEAD(tmp_list);

	spin_lock(&backing_dev->complete_lock);
	list_splice_init(&backing_dev->complete_list, &tmp_list);
	spin_unlock(&backing_dev->complete_lock);

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
