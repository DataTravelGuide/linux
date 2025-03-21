// SPDX-License-Identifier: GPL-2.0-or-later
#include "pcache_internal.h"
#include "cache.h"
#include "backing_dev.h"
#include "logic_dev.h"

static int pcache_major;
static DEFINE_IDA(pcache_mapped_id_ida);

static int minor_to_pcache_mapped_id(int minor)
{
	return minor >> PCACHE_PART_SHIFT;
}

static int logic_dev_open(struct gendisk *disk, blk_mode_t mode)
{
	struct pcache_logic_dev *logic_dev = disk->private_data;

	mutex_lock(&logic_dev->lock);
	logic_dev->open_count++;
	mutex_unlock(&logic_dev->lock);

	return 0;
}

static void logic_dev_release(struct gendisk *disk)
{
	struct pcache_logic_dev *logic_dev = disk->private_data;

	mutex_lock(&logic_dev->lock);
	logic_dev->open_count--;
	mutex_unlock(&logic_dev->lock);
}

static const struct block_device_operations logic_dev_bd_ops = {
	.owner			= THIS_MODULE,
	.open			= logic_dev_open,
	.release		= logic_dev_release,
};

static inline bool pcache_req_nodata(struct pcache_request *pcache_req)
{
	switch (pcache_req->op) {
	case REQ_OP_WRITE:
	case REQ_OP_READ:
		return false;
	case REQ_OP_FLUSH:
		return true;
	default:
		BUG();
	}
}

static blk_status_t pcache_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	struct request *req = bd->rq;
	struct pcache_queue *queue = hctx->driver_data;
	struct pcache_logic_dev *logic_dev = queue->logic_dev;
	struct pcache_request *pcache_req = blk_mq_rq_to_pdu(bd->rq);
	int ret;

	memset(pcache_req, 0, sizeof(struct pcache_request));
	spin_lock_init(&pcache_req->lock);
	kref_init(&pcache_req->ref);
	blk_mq_start_request(bd->rq);

	pcache_req->queue = queue;
	pcache_req->req = req;
	pcache_req->orig_bio = req->bio;
	pcache_req->op = req_op(bd->rq);
	pcache_req->off = (u64)blk_rq_pos(bd->rq) << SECTOR_SHIFT;
	if (!pcache_req_nodata(pcache_req))
		pcache_req->data_len = blk_rq_bytes(bd->rq);
	else
		pcache_req->data_len = 0;

	if (bio_segments(req->bio) > 256)
		pr_err("req: %p op: %u orig_bio: %p orig_bio->bi_max_vecs: %u, off: %llu bytes: %u, bi_vcnt: %u, bio_segments: %u", req, req_op(bd->rq), req->bio, req->bio->bi_max_vecs, pcache_req->off, pcache_req->data_len, req->bio->bi_vcnt, bio_segments(req->bio));
	ret = pcache_cache_handle_req(logic_dev->backing_dev->cache, pcache_req);

	pcache_req_put(pcache_req, ret);

	return BLK_STS_OK;
}

static int pcache_init_hctx(struct blk_mq_hw_ctx *hctx, void *driver_data,
			unsigned int hctx_idx)
{
	struct pcache_logic_dev *logic_dev = driver_data;

	hctx->driver_data = &logic_dev->queues[hctx_idx];

	return 0;
}

const struct blk_mq_ops logic_dev_mq_ops = {
	.queue_rq	= pcache_queue_rq,
	.init_hctx	= pcache_init_hctx,
};

static int disk_start(struct pcache_logic_dev *logic_dev)
{
	struct gendisk *disk;
	struct queue_limits lim = {
		.max_hw_sectors			= BIO_MAX_VECS * PAGE_SECTORS,
		.io_min				= 4096,
		.io_opt				= 4096,
		.max_segments			= BIO_MAX_VECS,
		.max_segment_size		= PAGE_SIZE,
		.discard_granularity		= 0,
		.max_hw_discard_sectors		= 0,
		.max_write_zeroes_sectors	= 0
	};
	int ret;

	memset(&logic_dev->tag_set, 0, sizeof(logic_dev->tag_set));
	logic_dev->tag_set.ops = &logic_dev_mq_ops;
	logic_dev->tag_set.queue_depth = 128;
	logic_dev->tag_set.numa_node = NUMA_NO_NODE;
	logic_dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE | BLK_MQ_F_NO_SCHED;
	logic_dev->tag_set.nr_hw_queues = logic_dev->num_queues;
	logic_dev->tag_set.cmd_size = sizeof(struct pcache_request);
	logic_dev->tag_set.timeout = 0;
	logic_dev->tag_set.driver_data = logic_dev;

	ret = blk_mq_alloc_tag_set(&logic_dev->tag_set);
	if (ret) {
		logic_dev_err(logic_dev, "failed to alloc tag set %d", ret);
		goto err;
	}

	disk = blk_mq_alloc_disk(&logic_dev->tag_set, &lim, logic_dev);
	if (IS_ERR(disk)) {
		ret = PTR_ERR(disk);
		logic_dev_err(logic_dev, "failed to alloc disk");
		goto out_tag_set;
	}

	snprintf(disk->disk_name, sizeof(disk->disk_name), "pcache%d",
		 logic_dev->mapped_id);

	disk->major = pcache_major;
	disk->first_minor = logic_dev->mapped_id << PCACHE_PART_SHIFT;
	disk->minors = (1 << PCACHE_PART_SHIFT);
	disk->fops = &logic_dev_bd_ops;
	disk->private_data = logic_dev;

	logic_dev->disk = disk;

	set_capacity(logic_dev->disk, logic_dev->dev_size);
	set_disk_ro(logic_dev->disk, false);

	/* Register the disk with the system */
	ret = add_disk(logic_dev->disk);
	if (ret)
		goto put_disk;

	return 0;

del_disk:
	del_gendisk(logic_dev->disk);
put_disk:
	put_disk(logic_dev->disk);
out_tag_set:
	blk_mq_free_tag_set(&logic_dev->tag_set);
err:
	return ret;
}

static void disk_stop(struct pcache_logic_dev *logic_dev)
{
	sysfs_remove_link(&disk_to_dev(logic_dev->disk)->kobj, "logic_dev");
	del_gendisk(logic_dev->disk);
	put_disk(logic_dev->disk);
	blk_mq_free_tag_set(&logic_dev->tag_set);
}

static struct pcache_logic_dev *logic_dev_alloc(struct pcache_backing_dev *backing_dev)
{
	struct pcache_logic_dev *logic_dev;
	int ret;

	logic_dev = kzalloc(sizeof(struct pcache_logic_dev), GFP_KERNEL);
	if (!logic_dev)
		return NULL;

	logic_dev->backing_dev = backing_dev;
	logic_dev->cache_dev = backing_dev->cache_dev;
	mutex_init(&logic_dev->lock);
	INIT_LIST_HEAD(&logic_dev->node);

	logic_dev->mapped_id = ida_simple_get(&pcache_mapped_id_ida, 0,
					 minor_to_pcache_mapped_id(1 << MINORBITS),
					 GFP_KERNEL);
	if (logic_dev->mapped_id < 0) {
		ret = -ENOENT;
		goto logic_dev_free;
	}

	return logic_dev;

ida_remove:
	ida_simple_remove(&pcache_mapped_id_ida, logic_dev->mapped_id);
logic_dev_free:
	kfree(logic_dev);

	return NULL;
}

static void logic_dev_free(struct pcache_logic_dev *logic_dev)
{
	ida_simple_remove(&pcache_mapped_id_ida, logic_dev->mapped_id);
	kfree(logic_dev);
}

static void logic_dev_destroy_queues(struct pcache_logic_dev *logic_dev)
{
	struct pcache_queue *queue;
	int i;

	/* Stop each queue associated with the block device */
	for (i = 0; i < logic_dev->num_queues; i++) {
		queue = &logic_dev->queues[i];
		if (queue->state == PCACHE_QUEUE_STATE_NONE)
			continue;

		bioset_exit(&queue->bioset);
	}

	/* Free the memory allocated for the queues */
	kfree(logic_dev->queues);
}

/**
 * logic_dev_create_queues - Create and initialize queues for the block device
 * @backing_dev: Pointer to the block device structure
 * @channels: Array of channel identifiers for each queue
 *
 * Note: The backing_dev_destroy_queues function checks the state of each queue.
 *       Only queues that have been started will be stopped in the error path.
 *       Therefore, any queues that were not started will not be affected.
 */
static int logic_dev_create_queues(struct pcache_logic_dev *logic_dev)
{
	int i;
	int ret;
	struct pcache_queue *queue;

	logic_dev->queues = kcalloc(logic_dev->num_queues, sizeof(struct pcache_queue), GFP_KERNEL);
	if (!logic_dev->queues)
		return -ENOMEM;

	for (i = 0; i < logic_dev->num_queues; i++) {
		queue = &logic_dev->queues[i];
		queue->logic_dev = logic_dev;
		queue->index = i;

		ret = bioset_init(&queue->bioset, 256, 0, BIOSET_NEED_BVECS);
		if (ret)
			goto err;


		queue->state = PCACHE_QUEUE_STATE_RUNNING;
		//ret = pcache_queue_start(queue, channels[i]);
		//if (ret)
		//	goto err;
	}

	return 0;

err:
	logic_dev_destroy_queues(logic_dev);
	return ret;
}


static int logic_dev_init(struct pcache_logic_dev *logic_dev, u32 queues)
{
	int ret;

	logic_dev->num_queues = queues;
	logic_dev->dev_size = logic_dev->dev_size;

	ret = logic_dev_create_queues(logic_dev);
	if (ret < 0)
		goto err;

	return 0;
err:
	return ret;
}

static void logic_dev_destroy(struct pcache_logic_dev *logic_dev)
{
	return;
}

int logic_dev_start(struct pcache_backing_dev *backing_dev, u32 queues)
{
	struct pcache_logic_dev *logic_dev;
	int ret;

	logic_dev = logic_dev_alloc(backing_dev);
	if (!logic_dev)
		return -ENOMEM;

	logic_dev->dev_size = backing_dev->dev_size;
	ret = logic_dev_init(logic_dev, queues);
	if (ret)
		goto logic_dev_free;

	backing_dev->logic_dev = logic_dev;

	ret = disk_start(logic_dev);
	if (ret < 0)
		goto logic_dev_destroy;

	return 0;

logic_dev_destroy:
	logic_dev_destroy(logic_dev);
logic_dev_free:
	logic_dev_free(logic_dev);
	return ret;
}

int logic_dev_stop(struct pcache_logic_dev *logic_dev)
{
	mutex_lock(&logic_dev->lock);
	if (logic_dev->open_count > 0) {
		mutex_unlock(&logic_dev->lock);
		return -EBUSY;
	}
	mutex_unlock(&logic_dev->lock);

	disk_stop(logic_dev);
	logic_dev_destroy(logic_dev);
	logic_dev_free(logic_dev);

	return 0;
}

int pcache_blkdev_init(void)
{
	pcache_major = register_blkdev(0, "pcache");
	if (pcache_major < 0)
		return pcache_major;

	return 0;
}

void pcache_blkdev_exit(void)
{
	unregister_blkdev(pcache_major, "pcache");
}

/**
 * end_req - Finalize a PCACHE request and handle its completion.
 * @ref: Pointer to the kref structure that manages the reference count of the PCACHE request.
 *
 * This function is called when the reference count of the pcache_request reaches zero. It
 * contains two key operations:
 *
 * (1) If the end_req callback is set in the pcache_request, this callback will be invoked.
 *     This allows different pcache_requests to perform specific operations upon completion.
 *     For example, in the case of a backend request sent in the cache miss reading, it may require
 *     cache-related operations, such as storing data retrieved during a miss read.
 *
 * (2) If pcache_req->req is not NULL, it indicates that this pcache_request corresponds to a
 *     block layer request. The function will finalize the block layer request accordingly.
 */
static void end_req(struct kref *ref)
{
	struct pcache_request *pcache_req = container_of(ref, struct pcache_request, ref);
	struct request *req = pcache_req->req;
	int ret = pcache_req->ret;

	if (req) {
		/* Complete the block layer request based on the return status */
		if (ret == -ENOMEM || ret == -EBUSY) {
			//pr_err("requeue: %p bio: %p", req, req->bio);
			blk_mq_requeue_request(req, true);
		} else {
			//pr_err("end: req: %p, bio: %p", req, req->bio);
			blk_mq_end_request(req, errno_to_blk_status(ret));
		}
	}
}

void pcache_req_get(struct pcache_request *pcache_req)
{
	kref_get(&pcache_req->ref);
}

/**
 * This function decreases the reference count of the specified pcache_request. If the
 * reference count reaches zero, the end_req function is called to finalize the request.
 * Additionally, if the pcache_request has a parent and if the current request is being
 * finalized (i.e., the reference count reaches zero), the parent request will also
 * be put, potentially propagating the return status up the hierarchy.
 */
void pcache_req_put(struct pcache_request *pcache_req, int ret)
{
	/* Set the return status if it is not already set */
	if (ret && !pcache_req->ret)
		pcache_req->ret = ret;

	kref_put(&pcache_req->ref, end_req);
}

