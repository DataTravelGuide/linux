// SPDX-License-Identifier: GPL-2.0-or-later
#include "cbd_internal.h"
#include "cbd_blkdev.h"

static ssize_t blkdev_backend_id_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_blkdev_device *blkdev_dev;
	struct cbd_blkdev_info *blkdev_info;

	blkdev_dev = container_of(dev, struct cbd_blkdev_device, dev);
	blkdev_info = cbdt_blkdev_info_read(blkdev_dev->cbdt, blkdev_dev->id, NULL);
	if (!blkdev_info)
		return 0;

	if (blkdev_info->state == cbd_blkdev_state_none)
		return 0;

	return sprintf(buf, "%u\n", blkdev_info->backend_id);
}

static DEVICE_ATTR(backend_id, 0400, blkdev_backend_id_show, NULL);

static ssize_t blkdev_host_id_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_blkdev_device *blkdev_dev;
	struct cbd_blkdev_info *blkdev_info;

	blkdev_dev = container_of(dev, struct cbd_blkdev_device, dev);
	blkdev_info = cbdt_blkdev_info_read(blkdev_dev->cbdt, blkdev_dev->id, NULL);
	if (!blkdev_info)
		return 0;

	if (blkdev_info->state == cbd_blkdev_state_none)
		return 0;

	return sprintf(buf, "%u\n", blkdev_info->host_id);
}

static DEVICE_ATTR(host_id, 0400, blkdev_host_id_show, NULL);

static ssize_t blkdev_mapped_id_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_blkdev_device *blkdev_dev;
	struct cbd_blkdev_info *blkdev_info;

	blkdev_dev = container_of(dev, struct cbd_blkdev_device, dev);
	blkdev_info = cbdt_blkdev_info_read(blkdev_dev->cbdt, blkdev_dev->id, NULL);
	if (!blkdev_info)
		return 0;

	if (blkdev_info->state == cbd_blkdev_state_none)
		return 0;

	return sprintf(buf, "%u\n", blkdev_info->mapped_id);
}

static DEVICE_ATTR(mapped_id, 0400, blkdev_mapped_id_show, NULL);

static void blkdev_info_write(struct cbd_blkdev *blkdev);
static void cbd_blkdev_hb(struct cbd_blkdev *blkdev)
{
	blkdev_info_write(blkdev);
}
CBD_OBJ_HEARTBEAT(blkdev);

static struct attribute *cbd_blkdev_attrs[] = {
	&dev_attr_mapped_id.attr,
	&dev_attr_host_id.attr,
	&dev_attr_backend_id.attr,
	&dev_attr_alive.attr,
	NULL
};

static struct attribute_group cbd_blkdev_attr_group = {
	.attrs = cbd_blkdev_attrs,
};

static const struct attribute_group *cbd_blkdev_attr_groups[] = {
	&cbd_blkdev_attr_group,
	NULL
};

static void cbd_blkdev_release(struct device *dev)
{
}

const struct device_type cbd_blkdev_type = {
	.name		= "cbd_blkdev",
	.groups		= cbd_blkdev_attr_groups,
	.release	= cbd_blkdev_release,
};

const struct device_type cbd_blkdevs_type = {
	.name		= "cbd_blkdevs",
	.release	= cbd_blkdev_release,
};


static int cbd_major;
static DEFINE_IDA(cbd_mapped_id_ida);

static int minor_to_cbd_mapped_id(int minor)
{
	return minor >> CBD_PART_SHIFT;
}


static int cbd_open(struct gendisk *disk, blk_mode_t mode)
{
	struct cbd_blkdev *cbd_blkdev = disk->private_data;

	mutex_lock(&cbd_blkdev->lock);
	cbd_blkdev->open_count++;
	mutex_unlock(&cbd_blkdev->lock);

	return 0;
}

static void cbd_release(struct gendisk *disk)
{
	struct cbd_blkdev *cbd_blkdev = disk->private_data;

	mutex_lock(&cbd_blkdev->lock);
	cbd_blkdev->open_count--;
	mutex_unlock(&cbd_blkdev->lock);
}

static const struct block_device_operations cbd_bd_ops = {
	.owner			= THIS_MODULE,
	.open			= cbd_open,
	.release		= cbd_release,
};

static void cbd_blkdev_destroy_queues(struct cbd_blkdev *cbd_blkdev)
{
	int i;

	for (i = 0; i < cbd_blkdev->num_queues; i++)
		cbd_queue_stop(&cbd_blkdev->queues[i]);

	kfree(cbd_blkdev->queues);
}

/**
 * cbd_blkdev_create_queues - Create and initialize queues for the block device
 * @cbd_blkdev: Pointer to the block device structure
 * @channels: Array of channel identifiers for each queue
 *
 * This function allocates memory for the specified number of queues, initializes
 * each queue, and starts them using the provided channel identifiers. If any
 * allocation or initialization fails, it cleans up the previously created queues
 * and returns an error code.
 *
 * Returns: 0 on success, or a negative error code on failure.
 *
 * Note: The cbd_blkdev_destroy_queues function checks the state of each queue.
 *       Only queues that have been started will be stopped in the error path.
 *       Therefore, any queues that were not started will not be affected.
 */
static int cbd_blkdev_create_queues(struct cbd_blkdev *cbd_blkdev, u32 *channels)
{
	int i;
	int ret;
	struct cbd_queue *cbdq;

	/* Allocate memory for the queues associated with the block device */
	cbd_blkdev->queues = kcalloc(cbd_blkdev->num_queues, sizeof(struct cbd_queue), GFP_KERNEL);
	if (!cbd_blkdev->queues)
		return -ENOMEM;

	/* Initialize each queue */
	for (i = 0; i < cbd_blkdev->num_queues; i++) {
		cbdq = &cbd_blkdev->queues[i];
		cbdq->cbd_blkdev = cbd_blkdev;
		cbdq->index = i;

		/* Start the queue with the specified channel */
		ret = cbd_queue_start(cbdq, channels[i]);
		if (ret)
			goto err;  /* If starting the queue fails, clean up */
	}

	return 0;  /* Success */

err:
	/* Clean up by destroying the queues if initialization fails */
	cbd_blkdev_destroy_queues(cbd_blkdev);
	return ret;  /* Return the error code */
}

/**
 * disk_start - Initialize and start a block device.
 * @cbd_blkdev: Pointer to the cbd_blkdev structure representing the block device.
 *
 * This function sets up the block device's tag set for I/O operations,
 * allocates the gendisk structure, and initializes the device parameters.
 * It sets various limits for the device's I/O operations and prepares the
 * block device for use.
 *
 * Returns 0 on success, or a negative error code on failure.
 *
 * - Allocates a tag set for managing request queues.
 * - Allocates a gendisk structure for the block device.
 * - Sets device properties such as name, major and minor numbers.
 * - Adds the device to the block layer.
 * - Creates a symlink in sysfs to the device.
 *
 * On failure, cleans up previously allocated resources:
 * - Frees the tag set.
 * - Deletes the gendisk structure.
 */
static int disk_start(struct cbd_blkdev *cbd_blkdev)
{
	struct gendisk *disk;
	struct queue_limits lim = {
		.max_hw_sectors			= BIO_MAX_VECS * PAGE_SECTORS,
		.io_min				= 4096,
		.io_opt				= 4096,
		.max_segments			= USHRT_MAX,
		.max_segment_size		= UINT_MAX,
		.discard_granularity		= 0,
		.max_hw_discard_sectors		= 0,
		.max_write_zeroes_sectors	= 0
	};
	int ret;

	memset(&cbd_blkdev->tag_set, 0, sizeof(cbd_blkdev->tag_set));
	cbd_blkdev->tag_set.ops = &cbd_mq_ops;
	cbd_blkdev->tag_set.queue_depth = 128;
	cbd_blkdev->tag_set.numa_node = NUMA_NO_NODE;
	cbd_blkdev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE | BLK_MQ_F_NO_SCHED;
	cbd_blkdev->tag_set.nr_hw_queues = cbd_blkdev->num_queues;
	cbd_blkdev->tag_set.cmd_size = sizeof(struct cbd_request);
	cbd_blkdev->tag_set.timeout = 0;
	cbd_blkdev->tag_set.driver_data = cbd_blkdev;

	/* Allocate the tag set for block management */
	ret = blk_mq_alloc_tag_set(&cbd_blkdev->tag_set);
	if (ret) {
		cbd_blk_err(cbd_blkdev, "failed to alloc tag set %d", ret);
		goto err;
	}

	/* Allocate the disk structure for this block device */
	disk = blk_mq_alloc_disk(&cbd_blkdev->tag_set, &lim, cbd_blkdev);
	if (IS_ERR(disk)) {
		ret = PTR_ERR(disk);
		cbd_blk_err(cbd_blkdev, "failed to alloc disk");
		goto out_tag_set;
	}

	/* Set the disk name and properties */
	snprintf(disk->disk_name, sizeof(disk->disk_name), "cbd%d",
		 cbd_blkdev->mapped_id);

	disk->major = cbd_major;
	disk->first_minor = cbd_blkdev->mapped_id << CBD_PART_SHIFT;
	disk->minors = (1 << CBD_PART_SHIFT);
	disk->fops = &cbd_bd_ops;
	disk->private_data = cbd_blkdev;

	cbd_blkdev->disk = disk;
	cbdt_add_blkdev(cbd_blkdev->cbdt, cbd_blkdev);
	cbd_blkdev->blkdev_info.mapped_id = cbd_blkdev->blkdev_id;

	/* Set the capacity of the block device */
	set_capacity(cbd_blkdev->disk, cbd_blkdev->dev_size);
	set_disk_ro(cbd_blkdev->disk, false);

	/* Register the disk with the system */
	ret = add_disk(cbd_blkdev->disk);
	if (ret)
		goto put_disk;

	/* Create a symlink to the block device */
	ret = sysfs_create_link(&disk_to_dev(cbd_blkdev->disk)->kobj,
				&cbd_blkdev->blkdev_dev->dev.kobj, "cbd_blkdev");
	if (ret)
		goto del_disk;

	return 0;

del_disk:
	del_gendisk(cbd_blkdev->disk);
put_disk:
	put_disk(cbd_blkdev->disk);
out_tag_set:
	blk_mq_free_tag_set(&cbd_blkdev->tag_set);
err:
	return ret;
}

static void disk_stop(struct cbd_blkdev *cbd_blkdev)
{
	sysfs_remove_link(&disk_to_dev(cbd_blkdev->disk)->kobj, "cbd_blkdev");
	del_gendisk(cbd_blkdev->disk);
	put_disk(cbd_blkdev->disk);
	blk_mq_free_tag_set(&cbd_blkdev->tag_set);
}

static void blkdev_info_write(struct cbd_blkdev *blkdev)
{
	mutex_lock(&blkdev->info_lock);
	blkdev->blkdev_info.alive_ts = ktime_get_real();
	cbdt_blkdev_info_write(blkdev->cbdt, &blkdev->blkdev_info,
			       sizeof(struct cbd_blkdev_info),
			       blkdev->blkdev_id, blkdev->info_index);
	blkdev->info_index = (blkdev->info_index + 1) % CBDT_META_INDEX_MAX;
	mutex_unlock(&blkdev->info_lock);
}

static int blkdev_start_validate(struct cbd_transport *cbdt, struct cbd_backend_info *backend_info,
			     u32 backend_id, u32 queues)
{
	struct cbd_blkdev_info *blkdev_info;
	u32 backend_blkdevs = 0; /* count how many blkdevs connected to backend of backend_id */
	u32 i;

	if (!backend_info || !cbd_backend_info_is_alive(backend_info)) {
		cbdt_err(cbdt, "backend %u is not alive\n", backend_id);
		return -EINVAL;
	}

	cbd_for_each_blkdev_info(cbdt, i, blkdev_info) {
		if (!blkdev_info)
			continue;

		if (blkdev_info->state != cbd_blkdev_state_running)
			continue;

		if (blkdev_info->backend_id == backend_id)
			backend_blkdevs++;
	}

	if (backend_blkdevs >= CBDB_BLKDEV_COUNT_MAX) {
		cbdt_err(cbdt, "too many(%u) blkdevs connected to backend %u.\n", backend_blkdevs, backend_id);
		return -EBUSY;
	}

	if (queues > backend_info->n_handlers) {
		cbdt_err(cbdt, "invalid queues: %u, larger than backend handlers: %u\n",
				queues, backend_info->n_handlers);
		return -EINVAL;
	}

	return 0;
}

static struct cbd_blkdev *blkdev_alloc(struct cbd_transport *cbdt)
{
	struct cbd_blkdev *cbd_blkdev;
	int ret;

	cbd_blkdev = kzalloc(sizeof(struct cbd_blkdev), GFP_KERNEL);
	if (!cbd_blkdev)
		return NULL;

	cbd_blkdev->cbdt = cbdt;
	mutex_init(&cbd_blkdev->lock);
	mutex_init(&cbd_blkdev->info_lock);
	INIT_LIST_HEAD(&cbd_blkdev->node);
	INIT_DELAYED_WORK(&cbd_blkdev->hb_work, blkdev_hb_workfn);

	ret = cbdt_get_empty_blkdev_id(cbdt, &cbd_blkdev->blkdev_id);
	if (ret < 0)
		goto blkdev_free;

	cbd_blkdev->mapped_id = ida_simple_get(&cbd_mapped_id_ida, 0,
					 minor_to_cbd_mapped_id(1 << MINORBITS),
					 GFP_KERNEL);
	if (cbd_blkdev->mapped_id < 0) {
		ret = -ENOENT;
		goto blkdev_free;
	}

	cbd_blkdev->task_wq = alloc_workqueue("cbdt%d-d%u",  WQ_UNBOUND | WQ_MEM_RECLAIM,
					0, cbdt->id, cbd_blkdev->mapped_id);
	if (!cbd_blkdev->task_wq) {
		ret = -ENOMEM;
		goto ida_remove;
	}

	return cbd_blkdev;
ida_remove:
	ida_simple_remove(&cbd_mapped_id_ida, cbd_blkdev->mapped_id);
blkdev_free:
	kfree(cbd_blkdev);

	return NULL;
}

static void blkdev_free(struct cbd_blkdev *cbd_blkdev)
{
	drain_workqueue(cbd_blkdev->task_wq);
	destroy_workqueue(cbd_blkdev->task_wq);
	ida_simple_remove(&cbd_mapped_id_ida, cbd_blkdev->mapped_id);
	kfree(cbd_blkdev);
}

static int blkdev_cache_init(struct cbd_blkdev *cbd_blkdev)
{
	struct cbd_transport *cbdt = cbd_blkdev->cbdt;
	struct cbd_cache_opts cache_opts = { 0 };

	cache_opts.cache_info = &cbd_blkdev->cache_info;
	cache_opts.cache_id = cbd_blkdev->backend_id;
	cache_opts.owner = NULL;
	cache_opts.new_cache = false;
	cache_opts.start_writeback = false;
	cache_opts.start_gc = true;
	cache_opts.init_keys = true;
	cache_opts.dev_size = cbd_blkdev->dev_size;
	cache_opts.n_paral = cbd_blkdev->num_queues;

	cbd_blkdev->cbd_cache = cbd_cache_alloc(cbdt, &cache_opts);
	if (!cbd_blkdev->cbd_cache)
		return -ENOMEM;

	return 0;
}

static void blkdev_cache_destroy(struct cbd_blkdev *cbd_blkdev)
{
	if (cbd_blkdev->cbd_cache)
		cbd_cache_destroy(cbd_blkdev->cbd_cache);
}

static int blkdev_init(struct cbd_blkdev *cbd_blkdev, struct cbd_backend_info *backend_info,
			u32 backend_id, u32 queues)
{
	struct cbd_transport *cbdt = cbd_blkdev->cbdt;
	int ret;

	cbd_blkdev->backend_id = backend_id;
	cbd_blkdev->num_queues = queues;
	cbd_blkdev->dev_size = backend_info->dev_size;
	cbd_blkdev->blkdev_dev = &cbdt->cbd_blkdevs_dev->blkdev_devs[cbd_blkdev->blkdev_id];
	if (backend_info->host_id == cbdt->host->host_id)
		cbd_blkdev->backend = cbdt_get_backend(cbdt, backend_id);

	cbd_blkdev->blkdev_info.backend_id = backend_id;
	cbd_blkdev->blkdev_info.host_id = cbdt->host->host_id;
	cbd_blkdev->blkdev_info.state = cbd_blkdev_state_running;

	ret = cbd_blkdev_create_queues(cbd_blkdev, backend_info->handler_channels);
	if (ret < 0)
		goto err;

	if (cbd_backend_cache_on(backend_info)) {
		ret = blkdev_cache_init(cbd_blkdev);
		if (ret)
			goto destroy_queues;
	}

	blkdev_info_write(cbd_blkdev);
	queue_delayed_work(cbd_wq, &cbd_blkdev->hb_work, 0);

	return 0;
destroy_queues:
	cbd_blkdev_destroy_queues(cbd_blkdev);
err:
	return ret;
}

static void blkdev_destroy(struct cbd_blkdev *cbd_blkdev)
{
	cancel_delayed_work_sync(&cbd_blkdev->hb_work);
	blkdev_cache_destroy(cbd_blkdev);
	cbd_blkdev_destroy_queues(cbd_blkdev);
}

int cbd_blkdev_start(struct cbd_transport *cbdt, u32 backend_id, u32 queues)
{
	struct cbd_blkdev *cbd_blkdev;
	struct cbd_backend_info *backend_info;
	int ret;

	backend_info = cbdt_backend_info_read(cbdt, backend_id, NULL);
	ret = blkdev_start_validate(cbdt, backend_info, backend_id, queues);
	if (ret)
		return ret;

	cbd_blkdev = blkdev_alloc(cbdt);
	if (!cbd_blkdev)
		return -ENOMEM;

	ret = blkdev_init(cbd_blkdev, backend_info, backend_id, queues);
	if (ret)
		goto blkdev_free;

	ret = disk_start(cbd_blkdev);
	if (ret < 0)
		goto blkdev_destroy;
	return 0;

blkdev_destroy:
	blkdev_destroy(cbd_blkdev);
blkdev_free:
	blkdev_free(cbd_blkdev);
	return ret;
}

int cbd_blkdev_stop(struct cbd_transport *cbdt, u32 devid, bool force)
{
	struct cbd_blkdev *cbd_blkdev;

	cbd_blkdev = cbdt_get_blkdev(cbdt, devid);
	if (!cbd_blkdev)
		return -EINVAL;

	mutex_lock(&cbd_blkdev->lock);
	if (cbd_blkdev->open_count > 0 && !force) {
		mutex_unlock(&cbd_blkdev->lock);
		return -EBUSY;
	}

	cbdt_del_blkdev(cbdt, cbd_blkdev);
	mutex_unlock(&cbd_blkdev->lock);

	disk_stop(cbd_blkdev);
	blkdev_destroy(cbd_blkdev);
	blkdev_free(cbd_blkdev);
	cbdt_blkdev_info_clear(cbdt, devid);

	return 0;
}

int cbd_blkdev_clear(struct cbd_transport *cbdt, u32 devid)
{
	struct cbd_blkdev_info *blkdev_info;

	blkdev_info = cbdt_blkdev_info_read(cbdt, devid, NULL);
	if (!blkdev_info) {
		cbdt_err(cbdt, "all blkdev_info in blkdev_id: %u are corrupted.\n", devid);
		return -EINVAL;
	}

	if (cbd_blkdev_info_is_alive(blkdev_info)) {
		cbdt_err(cbdt, "blkdev %u is still alive\n", devid);
		return -EBUSY;
	}

	if (blkdev_info->state == cbd_blkdev_state_none)
		return 0;

	cbdt_blkdev_info_clear(cbdt, devid);

	return 0;
}

int cbd_blkdev_init(void)
{
	cbd_major = register_blkdev(0, "cbd");
	if (cbd_major < 0)
		return cbd_major;

	return 0;
}

void cbd_blkdev_exit(void)
{
	unregister_blkdev(cbd_major, "cbd");
}
