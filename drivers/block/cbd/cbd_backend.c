// SPDX-License-Identifier: GPL-2.0-or-later

#include "cbd_internal.h"

static ssize_t backend_host_id_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_backend_device *backend;
	struct cbd_backend_info *backend_info;

	backend = container_of(dev, struct cbd_backend_device, dev);
	backend_info = backend->backend_info;

	if (backend_info->state == cbd_backend_state_none)
		return 0;

	return sprintf(buf, "%u\n", backend_info->host_id);
}

static DEVICE_ATTR(host_id, 0400, backend_host_id_show, NULL);

static ssize_t backend_path_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_backend_device *backend;
	struct cbd_backend_info *backend_info;

	backend = container_of(dev, struct cbd_backend_device, dev);
	backend_info = backend->backend_info;

	if (backend_info->state == cbd_backend_state_none)
		return 0;

	return sprintf(buf, "%s\n", backend_info->path);
}

static DEVICE_ATTR(path, 0400, backend_path_show, NULL);

CBD_OBJ_HEARTBEAT(backend);

static struct attribute *cbd_backend_attrs[] = {
	&dev_attr_path.attr,
	&dev_attr_host_id.attr,
	&dev_attr_alive.attr,
	NULL
};

static struct attribute_group cbd_backend_attr_group = {
	.attrs = cbd_backend_attrs,
};

static const struct attribute_group *cbd_backend_attr_groups[] = {
	&cbd_backend_attr_group,
	NULL
};

static void cbd_backend_release(struct device *dev)
{
}

const struct device_type cbd_backend_type = {
	.name		= "cbd_backend",
	.groups		= cbd_backend_attr_groups,
	.release	= cbd_backend_release,
};

const struct device_type cbd_backends_type = {
	.name		= "cbd_backends",
	.release	= cbd_backend_release,
};

int cbdb_add_handler(struct cbd_backend *cbdb, struct cbd_handler *handler)
{
	int ret = 0;

	spin_lock(&cbdb->lock);
	if (cbdb->backend_info->state == cbd_backend_state_removing) {
		ret = -EFAULT;
		goto out;
	}
	hash_add(cbdb->handlers_hash, &handler->hash_node, handler->channel.seg_id);
out:
	spin_unlock(&cbdb->lock);
	return ret;
}

void cbdb_del_handler(struct cbd_backend *cbdb, struct cbd_handler *handler)
{
	spin_lock(&cbdb->lock);
	hash_del(&handler->hash_node);
	spin_unlock(&cbdb->lock);
}

static struct cbd_handler *cbdb_get_handler(struct cbd_backend *cbdb, u32 seg_id)
{
	struct cbd_handler *handler;
	bool found = false;

	spin_lock(&cbdb->lock);
	hash_for_each_possible(cbdb->handlers_hash, handler,
			       hash_node, seg_id) {
		if (handler->channel.seg_id == seg_id) {
			found = true;
			break;
		}
	}
	spin_unlock(&cbdb->lock);

	if (found)
		return handler;

	return NULL;
}

static void state_work_fn(struct work_struct *work)
{
	struct cbd_backend *cbdb = container_of(work, struct cbd_backend, state_work.work);
	struct cbd_transport *cbdt = cbdb->cbdt;
	struct cbd_segment_info *segment_info;
	struct cbd_channel_info *channel_info;
	u32 blkdev_state, backend_state, backend_id;
	int ret;
	int i;

	for (i = 0; i < cbdt->transport_info->segment_num; i++) {
		segment_info = cbdt_get_segment_info(cbdt, i);
		if (segment_info->type != cbds_type_channel)
			continue;

		channel_info = (struct cbd_channel_info *)segment_info;

		blkdev_state = channel_info->blkdev_state;
		backend_state = channel_info->backend_state;
		backend_id = channel_info->backend_id;

		if (blkdev_state == cbdc_blkdev_state_running &&
				backend_state == cbdc_backend_state_none &&
				backend_id == cbdb->backend_id) {

			ret = cbd_handler_create(cbdb, i);
			if (ret) {
				cbdb_err(cbdb, "create handler for %u error", i);
				continue;
			}
		}

		if (blkdev_state == cbdc_blkdev_state_none &&
				backend_state == cbdc_backend_state_running &&
				backend_id == cbdb->backend_id) {
			struct cbd_handler *handler;

			handler = cbdb_get_handler(cbdb, i);
			if (!handler)
				continue;
			cbd_handler_destroy(handler);
		}
	}

	queue_delayed_work(cbd_wq, &cbdb->state_work, 1 * HZ);
}

static int cbd_backend_init(struct cbd_backend *cbdb, bool new_backend)
{
	struct cbd_backend_info *b_info;
	struct cbd_transport *cbdt = cbdb->cbdt;
	int ret;

	b_info = cbdt_get_backend_info(cbdt, cbdb->backend_id);
	cbdb->backend_info = b_info;

	b_info->host_id = cbdb->cbdt->host->host_id;

	cbdb->backend_io_cache = KMEM_CACHE(cbd_backend_io, 0);
	if (!cbdb->backend_io_cache) {
		ret = -ENOMEM;
		goto err;
	}

	cbdb->task_wq = alloc_workqueue("cbdt%d-b%u",  WQ_UNBOUND | WQ_MEM_RECLAIM,
					0, cbdt->id, cbdb->backend_id);
	if (!cbdb->task_wq) {
		ret = -ENOMEM;
		goto destroy_io_cache;
	}

	cbdb->bdev_file = bdev_file_open_by_path(cbdb->path,
			BLK_OPEN_READ | BLK_OPEN_WRITE, cbdb, NULL);
	if (IS_ERR(cbdb->bdev_file)) {
		cbdt_err(cbdt, "failed to open bdev: %d", (int)PTR_ERR(cbdb->bdev_file));
		ret = PTR_ERR(cbdb->bdev_file);
		goto destroy_wq;
	}

	cbdb->bdev = file_bdev(cbdb->bdev_file);
	if (new_backend) {
		b_info->dev_size = bdev_nr_sectors(cbdb->bdev);
	} else {
		if (b_info->dev_size != bdev_nr_sectors(cbdb->bdev)) {
			cbdt_err(cbdt, "Unexpected backend size: %llu, expected: %llu\n",
				 bdev_nr_sectors(cbdb->bdev), b_info->dev_size);
			ret = -EINVAL;
			goto close_file;
		}
	}

	INIT_DELAYED_WORK(&cbdb->state_work, state_work_fn);
	INIT_DELAYED_WORK(&cbdb->hb_work, backend_hb_workfn);
	hash_init(cbdb->handlers_hash);
	cbdb->backend_device = &cbdt->cbd_backends_dev->backend_devs[cbdb->backend_id];

	spin_lock_init(&cbdb->lock);

	b_info->state = cbd_backend_state_running;

	queue_delayed_work(cbd_wq, &cbdb->state_work, 0);
	queue_delayed_work(cbd_wq, &cbdb->hb_work, 0);

	return 0;

close_file:
	fput(cbdb->bdev_file);
destroy_wq:
	destroy_workqueue(cbdb->task_wq);
destroy_io_cache:
	kmem_cache_destroy(cbdb->backend_io_cache);
err:
	return ret;
}

extern struct device_type cbd_cache_type;

int cbd_backend_start(struct cbd_transport *cbdt, char *path, u32 backend_id, u32 cache_segs)
{
	struct cbd_backend *backend;
	struct cbd_backend_info *backend_info;
	struct cbd_cache_info *cache_info;
	bool new_backend = false;
	int ret;
	int i;

	if (backend_id == U32_MAX)
		new_backend = true;

	if (new_backend) {
		ret = cbdt_get_empty_backend_id(cbdt, &backend_id);
		if (ret)
			return ret;

		backend_info = cbdt_get_backend_info(cbdt, backend_id);
		for (i = 0; i < CBDB_BLKDEV_COUNT_MAX; i++)
			backend_info->blkdevs[i] = UINT_MAX;

		cache_info = &backend_info->cache_info;
		cache_info->n_segs = cache_segs;
	} else {
		backend_info = cbdt_get_backend_info(cbdt, backend_id);
		if (cbd_backend_info_is_alive(backend_info))
			return -EBUSY;
		cache_info = &backend_info->cache_info;
	}

	backend = kzalloc(sizeof(*backend), GFP_KERNEL);
	if (!backend)
		return -ENOMEM;

	strscpy(backend->path, path, CBD_PATH_LEN);
	memcpy(backend_info->path, backend->path, CBD_PATH_LEN);
	INIT_LIST_HEAD(&backend->node);
	backend->backend_id = backend_id;
	backend->cbdt = cbdt;

	ret = cbd_backend_init(backend, new_backend);
	if (ret) {
		kfree(backend);
		return ret;
	}

	cbdt_add_backend(cbdt, backend);

	if (cache_info->n_segs) {
		struct cbd_cache_opts cache_opts = { 0 };

		cache_opts.cache_info = cache_info;
		cache_opts.alloc_segs = new_backend;
		cache_opts.start_writeback = true;
		cache_opts.start_gc = false;
		cache_opts.init_keys = false;
		cache_opts.bdev_file = backend->bdev_file;
		cache_opts.dev_size = backend_info->dev_size;
		backend->cbd_cache = cbd_cache_alloc(cbdt, &cache_opts);
		if (!backend->cbd_cache) {
			ret = -ENOMEM;
			goto backend_stop;
		}

		device_initialize(&backend->cache_dev);
		device_set_pm_not_required(&backend->cache_dev);
		dev_set_name(&backend->cache_dev, "cache");
		backend->cache_dev.parent = &backend->backend_device->dev;
		backend->cache_dev.type = &cbd_cache_type;
		ret = device_add(&backend->cache_dev);
		if (ret)
			goto backend_stop;
		backend->cache_dev_registered = true;
	}

	return 0;

backend_stop:
	cbd_backend_stop(cbdt, backend_id);

	return ret;
}

int cbd_backend_stop(struct cbd_transport *cbdt, u32 backend_id)
{
	struct cbd_backend *cbdb;
	struct cbd_backend_info *backend_info;

	cbdb = cbdt_get_backend(cbdt, backend_id);
	if (!cbdb)
		return -ENOENT;

	spin_lock(&cbdb->lock);
	if (!hash_empty(cbdb->handlers_hash)) {
		spin_unlock(&cbdb->lock);
		return -EBUSY;
	}

	if (cbdb->backend_info->state == cbd_backend_state_removing) {
		spin_unlock(&cbdb->lock);
		return -EBUSY;
	}

	cbdb->backend_info->state = cbd_backend_state_removing;
	spin_unlock(&cbdb->lock);

	cbdt_del_backend(cbdt, cbdb);

	if (cbdb->cbd_cache) {
		if (cbdb->cache_dev_registered)
			device_unregister(&cbdb->cache_dev);
		cbd_cache_destroy(cbdb->cbd_cache);
	}

	cancel_delayed_work_sync(&cbdb->hb_work);
	cancel_delayed_work_sync(&cbdb->state_work);

	backend_info = cbdt_get_backend_info(cbdt, cbdb->backend_id);
	backend_info->state = cbd_backend_state_none;
	backend_info->alive_ts = 0;

	drain_workqueue(cbdb->task_wq);
	destroy_workqueue(cbdb->task_wq);

	kmem_cache_destroy(cbdb->backend_io_cache);

	fput(cbdb->bdev_file);
	kfree(cbdb);

	return 0;
}

int cbd_backend_clear(struct cbd_transport *cbdt, u32 backend_id)
{
	struct cbd_backend_info *backend_info;
	int i;

	backend_info = cbdt_get_backend_info(cbdt, backend_id);
	if (cbd_backend_info_is_alive(backend_info)) {
		cbdt_err(cbdt, "backend %u is still alive\n", backend_id);
		return -EBUSY;
	}

	if (backend_info->state == cbd_backend_state_none)
		return 0;

	for (i = 0; i < CBDB_BLKDEV_COUNT_MAX; i++) {
		if (backend_info->blkdevs[i] != UINT_MAX) {
			cbdt_err(cbdt, "blkdev %u is connected to backend %u\n", i, backend_id);
			return -EBUSY;
		}
	}

	for (i = 0; i < cbdt->transport_info->segment_num; i++) {
		struct cbd_segment_info *seg_info;
		struct cbd_channel_info *channel_info;
		struct cbd_cache_seg_info *cache_seg_info;

		seg_info = cbdt_get_segment_info(cbdt, i);
		if (seg_info->type == cbds_type_channel) {
			channel_info = (struct cbd_channel_info *)seg_info;
			if (channel_info->blkdev_state != cbdc_backend_state_running)
				continue;

			/* release the channels backend is using */
			if (channel_info->backend_id != backend_id)
				continue;

			if (channel_info->blkdev_state == cbdc_blkdev_state_none) {
				cbd_segment_clear(cbdt, i);
				continue;
			}

			channel_info->backend_state = cbdc_backend_state_none;
		}

		if (seg_info->type == cbds_type_cache) {
			cache_seg_info = (struct cbd_cache_seg_info *)seg_info;

			/* clear cache segments */
			if (cache_seg_info->backend_id == backend_id)
				cbd_segment_clear(cbdt, i);
		}
	}

	backend_info->state = cbd_backend_state_none;

	return 0;
}

bool cbd_backend_cache_on(struct cbd_backend_info *backend_info)
{
	return (backend_info->cache_info.n_segs != 0);
}

void cbd_backend_notify(struct cbd_backend *cbdb, u32 seg_id)
{
	struct cbd_handler *handler;

	handler = cbdb_get_handler(cbdb, seg_id);
	/*
	 * If the handler is not ready, return directly and
	 * wait handler to queue the handle_work in creating
	 */
	if (!handler)
		return;
	cbd_handler_notify(handler);
}
