#include "cbd_internal.h"

static ssize_t blkdev_backend_id_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_blkdev_device *blkdev;
	struct cbd_blkdev_info *blkdev_info;

	blkdev = container_of(dev, struct cbd_blkdev_device, dev);
	blkdev_info = blkdev->blkdev_info;

	if (blkdev_info->state == cbd_blkdev_state_none)
		return 0;

	return sprintf(buf, "%u\n", blkdev_info->backend_id);
}

static DEVICE_ATTR(backend_id, 0400, blkdev_backend_id_show, NULL);

static ssize_t blkdev_host_id_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_blkdev_device *blkdev;
	struct cbd_blkdev_info *blkdev_info;

	blkdev = container_of(dev, struct cbd_blkdev_device, dev);
	blkdev_info = blkdev->blkdev_info;

	if (blkdev_info->state == cbd_blkdev_state_none)
		return 0;

	return sprintf(buf, "%u\n", blkdev_info->host_id);
}

static DEVICE_ATTR(host_id, 0400, blkdev_host_id_show, NULL);

static ssize_t blkdev_mapped_id_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_blkdev_device *blkdev;
	struct cbd_blkdev_info *blkdev_info;

	blkdev = container_of(dev, struct cbd_blkdev_device, dev);
	blkdev_info = blkdev->blkdev_info;

	if (blkdev_info->state == cbd_blkdev_state_none)
		return 0;

	return sprintf(buf, "%u\n", blkdev_info->mapped_id);
}

static DEVICE_ATTR(mapped_id, 0400, blkdev_mapped_id_show, NULL);

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

static void cbd_blkdev_stop_queues(struct cbd_blkdev *cbd_blkdev)
{
	int i;

	for (i = 0; i < cbd_blkdev->num_queues; i++)
		cbd_queue_stop(&cbd_blkdev->queues[i]);
}

static void cbd_blkdev_destroy_queues(struct cbd_blkdev *cbd_blkdev)
{
	cbd_blkdev_stop_queues(cbd_blkdev);
	kfree(cbd_blkdev->queues);
}

static int cbd_blkdev_create_queues(struct cbd_blkdev *cbd_blkdev)
{
	int i;
	int ret;
	struct cbd_queue *cbdq;

	cbd_blkdev->queues = kcalloc(cbd_blkdev->num_queues, sizeof(struct cbd_queue), GFP_KERNEL);
	if (!cbd_blkdev->queues)
		return -ENOMEM;

	for (i = 0; i < cbd_blkdev->num_queues; i++) {
		cbdq = &cbd_blkdev->queues[i];
		cbdq->cbd_blkdev = cbd_blkdev;
		cbdq->index = i;
		ret = cbd_queue_start(cbdq);
		if (ret)
			goto err;
	}

	return 0;
err:
	cbd_blkdev_destroy_queues(cbd_blkdev);
	return ret;
}

static int disk_start(struct cbd_blkdev *cbd_blkdev)
{
	int ret;
	struct gendisk *disk;

	memset(&cbd_blkdev->tag_set, 0, sizeof(cbd_blkdev->tag_set));
	cbd_blkdev->tag_set.ops = &cbd_mq_ops;
	cbd_blkdev->tag_set.queue_depth = 128;
	cbd_blkdev->tag_set.numa_node = NUMA_NO_NODE;
	cbd_blkdev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE | BLK_MQ_F_NO_SCHED;
	cbd_blkdev->tag_set.nr_hw_queues = cbd_blkdev->num_queues;
	cbd_blkdev->tag_set.cmd_size = sizeof(struct cbd_request);
	cbd_blkdev->tag_set.timeout = 0;
	cbd_blkdev->tag_set.driver_data = cbd_blkdev;

	ret = blk_mq_alloc_tag_set(&cbd_blkdev->tag_set);
	if (ret) {
		cbd_blk_err(cbd_blkdev, "failed to alloc tag set %d", ret);
		goto err;
	}

	disk = blk_mq_alloc_disk(&cbd_blkdev->tag_set, NULL, cbd_blkdev);
	if (IS_ERR(disk)) {
		ret = PTR_ERR(disk);
		cbd_blk_err(cbd_blkdev, "failed to alloc disk");
		goto out_tag_set;
	}

	snprintf(disk->disk_name, sizeof(disk->disk_name), "cbd%d",
		 cbd_blkdev->mapped_id);

	disk->major = cbd_major;
	disk->first_minor = cbd_blkdev->mapped_id << CBD_PART_SHIFT;
	disk->minors = (1 << CBD_PART_SHIFT);

	disk->fops = &cbd_bd_ops;
	disk->private_data = cbd_blkdev;

	/* Tell the block layer that this is not a rotational device */
	blk_queue_flag_set(QUEUE_FLAG_NONROT, disk->queue);
	blk_queue_flag_set(QUEUE_FLAG_SYNCHRONOUS, disk->queue);
	blk_queue_flag_set(QUEUE_FLAG_NOWAIT, disk->queue);

	blk_queue_physical_block_size(disk->queue, PAGE_SIZE);
	blk_queue_max_hw_sectors(disk->queue, 128);
	blk_queue_max_segments(disk->queue, USHRT_MAX);
	blk_queue_max_segment_size(disk->queue, UINT_MAX);
	blk_queue_io_min(disk->queue, 4096);
	blk_queue_io_opt(disk->queue, 4096);

	disk->queue->limits.max_sectors = queue_max_hw_sectors(disk->queue);
	/* TODO support discard */
	disk->queue->limits.discard_granularity = 0;
	blk_queue_max_discard_sectors(disk->queue, 0);
	blk_queue_max_write_zeroes_sectors(disk->queue, 0);

	cbd_blkdev->disk = disk;

	cbdt_add_blkdev(cbd_blkdev->cbdt, cbd_blkdev);
	cbd_blkdev->blkdev_info->mapped_id = cbd_blkdev->blkdev_id;
	cbd_blkdev->blkdev_info->state = cbd_blkdev_state_running;

	set_capacity(cbd_blkdev->disk, cbd_blkdev->dev_size);

	set_disk_ro(cbd_blkdev->disk, false);
	blk_queue_write_cache(cbd_blkdev->disk->queue, false, false);

	ret = add_disk(cbd_blkdev->disk);
	if (ret)
		goto put_disk;

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

int cbd_blkdev_start(struct cbd_transport *cbdt, u32 backend_id, u32 queues)
{
	struct cbd_blkdev *cbd_blkdev;
	struct cbd_backend_info *backend_info;
	u64 dev_size;
	int ret;

	backend_info = cbdt_get_backend_info(cbdt, backend_id);
	if (backend_info->blkdev_count == CBDB_BLKDEV_COUNT_MAX)
		return -EBUSY;

	if (!cbd_backend_info_is_alive(backend_info)) {
		cbdt_err(cbdt, "backend %u is not alive\n", backend_id);
		return -EINVAL;
	}

	dev_size = backend_info->dev_size;

	cbd_blkdev = kzalloc(sizeof(struct cbd_blkdev), GFP_KERNEL);
	if (!cbd_blkdev)
		return -ENOMEM;

	mutex_init(&cbd_blkdev->lock);
	atomic_set(&cbd_blkdev->state, cbd_blkdev_state_none);

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

	INIT_LIST_HEAD(&cbd_blkdev->node);
	cbd_blkdev->cbdt = cbdt;
	cbd_blkdev->backend_id = backend_id;
	cbd_blkdev->num_queues = queues;
	cbd_blkdev->dev_size = dev_size;
	cbd_blkdev->blkdev_info = cbdt_get_blkdev_info(cbdt, cbd_blkdev->blkdev_id);
	cbd_blkdev->blkdev_dev = &cbdt->cbd_blkdevs_dev->blkdev_devs[cbd_blkdev->blkdev_id];

	cbd_blkdev->blkdev_info->backend_id = backend_id;
	cbd_blkdev->blkdev_info->host_id = cbdt->host->host_id;
	cbd_blkdev->blkdev_info->state = cbd_blkdev_state_running;


	if (cbd_backend_cache_on(backend_info)) {
		struct cbd_cache_opts cache_opts = { 0 };

		cache_opts.cache_info = &backend_info->cache_info;
		cache_opts.alloc_segs = false;
		cache_opts.start_writeback = false;
		cache_opts.start_gc = true;
		cache_opts.init_keys = true;
		cbd_blkdev->cbd_cache = cbd_cache_alloc(cbdt, &cache_opts);
		if (!cbd_blkdev->cbd_cache) {
			ret = -ENOMEM;
			goto destroy_wq;
		}
	}

	ret = cbd_blkdev_create_queues(cbd_blkdev);
	if (ret < 0)
		goto destroy_cache;

	backend_info->blkdev_count++;
	atomic_set(&cbd_blkdev->state, cbd_blkdev_state_running);

	INIT_DELAYED_WORK(&cbd_blkdev->hb_work, blkdev_hb_workfn);
	queue_delayed_work(cbd_wq, &cbd_blkdev->hb_work, 0);

	ret = disk_start(cbd_blkdev);
	if (ret < 0)
		goto destroy_queues;
	return 0;

destroy_queues:
	cbd_blkdev_destroy_queues(cbd_blkdev);
destroy_cache:
	if (cbd_blkdev->cbd_cache)
		cbd_cache_destroy(cbd_blkdev->cbd_cache);
destroy_wq:
	cancel_delayed_work_sync(&cbd_blkdev->hb_work);
	cbd_blkdev->blkdev_info->state = cbd_blkdev_state_none;
	destroy_workqueue(cbd_blkdev->task_wq);
ida_remove:
	ida_simple_remove(&cbd_mapped_id_ida, cbd_blkdev->mapped_id);
blkdev_free:
	kfree(cbd_blkdev);
	return ret;
}

static void disk_stop(struct cbd_blkdev *cbd_blkdev)
{
	sysfs_remove_link(&disk_to_dev(cbd_blkdev->disk)->kobj, "cbd_blkdev");
	del_gendisk(cbd_blkdev->disk);
	put_disk(cbd_blkdev->disk);
	blk_mq_free_tag_set(&cbd_blkdev->tag_set);
}

int cbd_blkdev_stop(struct cbd_transport *cbdt, u32 devid, bool force)
{
	struct cbd_blkdev *cbd_blkdev;
	struct cbd_backend_info *backend_info;

	cbd_blkdev = cbdt_get_blkdev(cbdt, devid);
	if (!cbd_blkdev)
		return -EINVAL;

	mutex_lock(&cbd_blkdev->lock);
	if (cbd_blkdev->open_count > 0 && !force) {
		mutex_unlock(&cbd_blkdev->lock);
		return -EBUSY;
	}

	atomic_set(&cbd_blkdev->state, cbd_blkdev_state_removing);
	cbdt_del_blkdev(cbdt, cbd_blkdev);
	mutex_unlock(&cbd_blkdev->lock);

	cbd_blkdev_stop_queues(cbd_blkdev);
	disk_stop(cbd_blkdev);
	kfree(cbd_blkdev->queues);

	cancel_delayed_work_sync(&cbd_blkdev->hb_work);
	cancel_delayed_work_sync(&cbd_blkdev->hb_work);
	cbd_blkdev->blkdev_info->state = cbd_blkdev_state_none;

	drain_workqueue(cbd_blkdev->task_wq);
	destroy_workqueue(cbd_blkdev->task_wq);
	ida_simple_remove(&cbd_mapped_id_ida, cbd_blkdev->mapped_id);
	backend_info = cbdt_get_backend_info(cbdt, cbd_blkdev->backend_id);

	if (cbd_blkdev->cbd_cache) {
		cbd_cache_destroy(cbd_blkdev->cbd_cache);
	}

	kfree(cbd_blkdev);

	backend_info->blkdev_count--;

	return 0;
}

int cbd_blkdev_clear(struct cbd_transport *cbdt, u32 devid)
{
	struct cbd_blkdev_info *blkdev_info;

	blkdev_info = cbdt_get_blkdev_info(cbdt, devid);
	if (cbd_blkdev_info_is_alive(blkdev_info)) {
		cbdt_err(cbdt, "blkdev %u is still alive\n", devid);
		return -EBUSY;
	}

	if (blkdev_info->state == cbd_blkdev_state_none)
		return 0;

	blkdev_info->state = cbd_blkdev_state_none;

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
