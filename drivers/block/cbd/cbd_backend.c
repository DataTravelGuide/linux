// SPDX-License-Identifier: GPL-2.0-or-later

#include "cbd_internal.h"

static ssize_t backend_host_id_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_backend_device *backend;
	struct cbd_backend_info *backend_info, *latest_info;

	backend = container_of(dev, struct cbd_backend_device, dev);

	latest_info = cbdt_backend_info_read(backend->cbdt, backend->id, NULL);
	if (!latest_info)
		return 0;

	if (latest_info->state == cbd_backend_state_none)
		return 0;

	return sprintf(buf, "%u\n", latest_info->host_id);
}

static DEVICE_ATTR(host_id, 0400, backend_host_id_show, NULL);

static ssize_t backend_path_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_backend_device *backend;
	struct cbd_backend_info *backend_info, *latest_info;

	backend = container_of(dev, struct cbd_backend_device, dev);

	latest_info = cbdt_backend_info_read(backend->cbdt, backend->id, NULL);
	if (!latest_info)
		return 0;

	if (latest_info->state == cbd_backend_state_none)
		return 0;

	return sprintf(buf, "%s\n", latest_info->path);
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
	if (cbdb->backend_info.state == cbd_backend_state_removing) {
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
	if (hlist_unhashed(&handler->hash_node))
		return;

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

static void destroy_handlers(struct cbd_backend *cbdb)
{
	struct cbd_handler *handler;
	struct hlist_node *tmp;
	int i;

	hash_for_each_safe(cbdb->handlers_hash, i, tmp, handler, hash_node) {
		hash_del(&handler->hash_node);
		cbd_handler_destroy(handler);
	}
}

static int create_handlers(struct cbd_backend *cbdb, bool new_backend)
{
	struct cbd_backend_info *backend_info;
	u32 channel_id;
	int ret;
	int i;

	backend_info = &cbdb->backend_info;

	for (i = 0; i < backend_info->n_handlers; i++) {
		if (new_backend) {
			ret = cbd_get_empty_channel_id(cbdb->cbdt, &channel_id);
			if (ret < 0) {
				cbdb_err(cbdb, "failed find available channel_id.\n");
				goto destroy_handlers;
			}
			backend_info->handler_channels[i] = channel_id;
		} else {
			channel_id = backend_info->handler_channels[i];
		}

		ret = cbd_handler_create(cbdb, channel_id, new_backend);
		if (ret) {
			cbdb_err(cbdb, "failed to create handler: %d\n", ret);
			goto destroy_handlers;
		}
	}

	return 0;

destroy_handlers:
	destroy_handlers(cbdb);

	return ret;
}

extern struct device_type cbd_cache_type;

static int backend_open_bdev(struct cbd_backend *cbdb, bool new_backend)
{
	int ret;

	cbdb->bdev_file = bdev_file_open_by_path(cbdb->backend_info.path,
			BLK_OPEN_READ | BLK_OPEN_WRITE, cbdb, NULL);
	if (IS_ERR(cbdb->bdev_file)) {
		cbdb_err(cbdb, "failed to open bdev: %d", (int)PTR_ERR(cbdb->bdev_file));
		ret = PTR_ERR(cbdb->bdev_file);
		goto err;
	}

	cbdb->bdev = file_bdev(cbdb->bdev_file);

	if (new_backend) {
		cbdb->backend_info.dev_size = bdev_nr_sectors(cbdb->bdev);
	} else {
		if (cbdb->backend_info.dev_size != bdev_nr_sectors(cbdb->bdev)) {
			cbdb_err(cbdb, "Unexpected backend size: %llu, expected: %llu\n",
				 bdev_nr_sectors(cbdb->bdev), cbdb->backend_info.dev_size);
			ret = -EINVAL;
			goto close_file;
		}
	}

	return 0;

close_file:
	fput(cbdb->bdev_file);
err:
	return ret;
}

static void backend_close_bdev(struct cbd_backend *cbdb)
{
	fput(cbdb->bdev_file);
}

static int backend_cache_init(struct cbd_backend *cbdb, u32 cache_segs, bool new_backend)
{
	struct cbd_cache_opts cache_opts = { 0 };
	int ret;

	cache_opts.cache_info = &cbdb->backend_info.cache_info;
	cache_opts.cache_id = cbdb->backend_id;
	cache_opts.backend = cbdb;
	cache_opts.n_segs = cache_segs;
	cache_opts.new_cache = new_backend;
	cache_opts.start_writeback = true;
	cache_opts.start_gc = false;
	cache_opts.init_keys = false;
	cache_opts.bdev_file = cbdb->bdev_file;
	cache_opts.dev_size = cbdb->backend_info.dev_size;
	cbdb->cbd_cache = cbd_cache_alloc(cbdb->cbdt, &cache_opts);
	if (!cbdb->cbd_cache) {
		ret = -ENOMEM;
		goto err;
	}

	device_initialize(&cbdb->cache_dev);
	device_set_pm_not_required(&cbdb->cache_dev);
	dev_set_name(&cbdb->cache_dev, "cache");
	cbdb->cache_dev.parent = &cbdb->backend_device->dev;
	cbdb->cache_dev.type = &cbd_cache_type;
	ret = device_add(&cbdb->cache_dev);
	if (ret)
		goto destroy_cache;

	return 0;

destroy_cache:
	cbd_cache_destroy(cbdb->cbd_cache);
err:
	return ret;
}

static void backend_cache_destroy(struct cbd_backend *cbdb)
{
	if (cbdb->cbd_cache) {
		device_unregister(&cbdb->cache_dev);
		cbd_cache_destroy(cbdb->cbd_cache);
	}
}

static int cbd_backend_info_init(struct cbd_backend *cbdb, char *path,
				 u32 handlers, u32 cache_segs)
{
	struct cbd_transport *cbdt = cbdb->cbdt;
	u32 backend_id;
	int ret;

	ret = cbdt_get_empty_backend_id(cbdt, &backend_id);
	if (ret)
		goto err;

	pr_err("get empty backend: %u\n", backend_id);
	cbdb->backend_id = backend_id;
	cbdb->backend_info.meta_header.version = 0;
	cbdb->backend_info.host_id = cbdb->host_id;
	cbdb->backend_info.n_handlers = handlers;

	strscpy(cbdb->backend_info.path, path, CBD_PATH_LEN);

	return 0;
err:
	return ret;
}

static int cbd_backend_info_load(struct cbd_backend *cbdb, u32 backend_id);
static int cbd_backend_init(struct cbd_backend *cbdb, char *path, u32 backend_id,
			    u32 handlers, u32 cache_segs)
{
	struct cbd_transport *cbdt = cbdb->cbdt;
	bool new_backend = false;
	int ret;

	if (backend_id == U32_MAX)
		new_backend = true;

	if (new_backend) {
		/* new backend */
		ret = cbd_backend_info_init(cbdb, path, handlers, cache_segs);
		if (ret)
			goto err;
	} else {
		/* attach backend, this could happend after an unexpected power off */
		cbdt_info(cbdt, "attach backend to backend_id: %u\n", backend_id);
		cbdb->backend_id = backend_id;
		ret = cbd_backend_info_load(cbdb, cbdb->backend_id);
		if (ret)
			goto err;
	}

	cbdb->backend_device = &cbdt->cbd_backends_dev->backend_devs[cbdb->backend_id];
	pr_err("backend_id: %u\n", cbdb->backend_id);

	ret = backend_open_bdev(cbdb, new_backend);
	if (ret)
		goto err;

	ret = create_handlers(cbdb, new_backend);
	if (ret)
		goto close_bdev;

	if (cache_segs) {
		ret = backend_cache_init(cbdb, cache_segs, new_backend);
		if (ret)
			goto destroy_handlers;
	}

	cbdb->backend_info.state = cbd_backend_state_running;
	cbdt_add_backend(cbdt, cbdb);

	return 0;

destroy_handlers:
	destroy_handlers(cbdb);
close_bdev:
	backend_close_bdev(cbdb);
err:
	return ret;
}

static u32 cbd_backend_info_crc(struct cbd_backend_info *backend_info)
{
	return crc32(0, (void *)backend_info + 4, sizeof(*backend_info) - 4);
}

void cbd_backend_info_write(struct cbd_backend *cbdb)
{
	struct cbd_backend_info *backend_info;

	mutex_lock(&cbdb->info_lock);
	cbdb->backend_info.alive_ts = ktime_get_real();
	cbdt_backend_info_write(cbdb->cbdt, &cbdb->backend_info, sizeof(struct cbd_backend_info),
				cbdb->backend_id, cbdb->backend_info_index);
	cbdb->backend_info_index = (cbdb->backend_info_index + 1) % CBDT_META_INDEX_MAX;
	mutex_unlock(&cbdb->info_lock);
}

static int cbd_backend_info_load(struct cbd_backend *cbdb, u32 backend_id)
{
	struct cbd_backend_info *backend_info;
	int ret = 0;

	mutex_lock(&cbdb->info_lock);
	backend_info = cbdt_backend_info_read(cbdb->cbdt, backend_id, &cbdb->backend_info_index);
	if (!backend_info) {
		cbdt_err(cbdb->cbdt, "can't read info from backend id %u.\n",
				cbdb->backend_id);
		ret = -EINVAL;
		goto out;
	}

	if (cbd_backend_info_is_alive(backend_info)) {
		cbdt_err(cbdb->cbdt, "backend %u is alive\n");
		ret = -EBUSY;
		goto out;
	}

	if (backend_info->host_id != cbdb->host_id) {
		cbdt_err(cbdb->cbdt, "backend_id: %u is on host %u but not on host %u\n",
				cbdb->backend_id, backend_info->host_id, cbdb->host_id);
		ret = -EINVAL;
		goto out;
	}

	memcpy(&cbdb->backend_info, backend_info, sizeof(struct cbd_backend_info));
out:
	mutex_unlock(&cbdb->info_lock);
	return ret;
}

static struct cbd_backend *cbd_backend_alloc(struct cbd_transport *cbdt)
{
	struct cbd_backend *cbdb;

	cbdb = kzalloc(sizeof(*cbdb), GFP_KERNEL);
	if (!cbdb)
		return NULL;

	cbdb->backend_io_cache = KMEM_CACHE(cbd_backend_io, 0);
	if (!cbdb->backend_io_cache) {
		goto free_cbdb;
	}

	cbdb->task_wq = alloc_workqueue("cbdt%d-b%u",  WQ_UNBOUND | WQ_MEM_RECLAIM,
					0, cbdt->id, cbdb->backend_id);
	if (!cbdb->task_wq) {
		goto destroy_io_cache;
	}


	cbdb->cbdt = cbdt;
	cbdb->host_id = cbdt->host->host_id;

	mutex_init(&cbdb->info_lock);
	INIT_LIST_HEAD(&cbdb->node);
	INIT_DELAYED_WORK(&cbdb->hb_work, backend_hb_workfn);
	hash_init(cbdb->handlers_hash);
	spin_lock_init(&cbdb->lock);

	return cbdb;

destroy_io_cache:
	kmem_cache_destroy(cbdb->backend_io_cache);
free_cbdb:
	kfree(cbdb);
	return NULL;
}

static void cbd_backend_destroy(struct cbd_backend *cbdb)
{
	drain_workqueue(cbdb->task_wq);
	destroy_workqueue(cbdb->task_wq);

	kmem_cache_destroy(cbdb->backend_io_cache);

	kfree(cbdb);
}

int cbd_backend_start(struct cbd_transport *cbdt, char *path, u32 backend_id,
		      u32 handlers, u32 cache_segs)
{
	struct cbd_backend *cbdb;
	struct cbd_backend_info *backend_info;
	struct cbd_cache_info *cache_info;
	bool new_backend = false;
	int ret;

	cbdb = cbd_backend_alloc(cbdt);
	if (!cbdb)
		return -ENOMEM;

	ret = cbd_backend_init(cbdb, path, backend_id, handlers, cache_segs);
	if (ret) {
		goto destroy_cbdb;
	}

	cbd_backend_info_write(cbdb);
	queue_delayed_work(cbd_wq, &cbdb->hb_work, CBD_HB_INTERVAL);

	return 0;

destroy_cbdb:
	cbd_backend_destroy(cbdb);;

	return ret;
}

int cbd_backend_stop(struct cbd_transport *cbdt, u32 backend_id)
{
	struct cbd_backend *cbdb;
	struct cbd_backend_info *backend_info;
	struct cbd_blkdev_info *blkdev_info;
	int i;

	cbdb = cbdt_get_backend(cbdt, backend_id);
	if (!cbdb)
		return -ENOENT;

	cbd_for_each_blkdev_info(cbdt, i, blkdev_info) {
		if (!blkdev_info)
			continue;

		if (blkdev_info->state != cbd_blkdev_state_running)
			continue;

		cbdb_err(cbdb, "blkdev %u blkdev->backend_id: %u, backend_id: %u\n", i, blkdev_info->backend_id, backend_id);
		if (blkdev_info->backend_id == backend_id) {
			cbdt_err(cbdt, "blkdev %u is connected to backend %u\n", i, backend_id);
			return -EBUSY;
		}
	}

	spin_lock(&cbdb->lock);
	if (cbdb->backend_info.state == cbd_backend_state_removing) {
		spin_unlock(&cbdb->lock);
		return -EBUSY;
	}

	cbdb->backend_info.state = cbd_backend_state_removing;
	spin_unlock(&cbdb->lock);

	cbdt_del_backend(cbdt, cbdb);

	if (cbdb->cbd_cache) {
		device_unregister(&cbdb->cache_dev);
		cbd_cache_destroy(cbdb->cbd_cache);
	}

	cancel_delayed_work_sync(&cbdb->hb_work);

	destroy_handlers(cbdb);
	pr_err("after destroy handler\n");

	cbdt_backend_info_clear(cbdb->cbdt, cbdb->backend_id);

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
	struct cbd_blkdev_info *blkdev_info;
	int i;

	backend_info = cbdt_backend_info_read(cbdt, backend_id, NULL);
	if (!backend_info) {
		cbdt_err(cbdt, "all backend_info in backend_id: %u are corrupted.\n", backend_id);
		return -EINVAL;
	}

	if (cbd_backend_info_is_alive(backend_info)) {
		cbdt_err(cbdt, "backend %u is still alive\n", backend_id);
		return -EBUSY;
	}

	if (backend_info->state == cbd_backend_state_none)
		return 0;

	cbd_for_each_blkdev_info(cbdt, i, blkdev_info) {
		if (blkdev_info->state != cbd_blkdev_state_running)
			continue;

		if (blkdev_info->backend_id == backend_id) {
			cbdt_err(cbdt, "blkdev %u is connected to backend %u\n", i, backend_id);
			return -EBUSY;
		}
	}

	for (i = 0; i < cbdt->transport_info->segment_num; i++) {
		struct cbd_segment_info *seg_info;
		struct cbd_channel_seg_info *channel_info;
		struct cbd_cache_seg_info *cache_seg_info;

		seg_info = cbdt_segment_info_read(cbdt, i, NULL);
		if (!seg_info)
			continue;

		if (seg_info->type == cbds_type_channel) {
			channel_info = (struct cbd_channel_seg_info *)seg_info;
			/* release the channels backend is using */
			if (channel_info->backend_id == backend_id)
				cbd_segment_clear(cbdt, i);
		}

		if (seg_info->type == cbds_type_cache) {
			cache_seg_info = (struct cbd_cache_seg_info *)seg_info;

			/* clear cache segments */
			if (cache_seg_info->backend_id == backend_id)
				cbd_segment_clear(cbdt, i);
		}
	}

	cbdt_backend_info_clear(cbdt, backend_id);

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

void cbd_backend_hb(struct cbd_backend *cbdb)
{
	cbd_backend_info_write(cbdb);
}
