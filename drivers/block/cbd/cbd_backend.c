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

void cbdb_add_handler(struct cbd_backend *cbdb, struct cbd_handler *handler)
{
	mutex_lock(&cbdb->lock);
	list_add(&handler->handlers_node, &cbdb->handlers);
	mutex_unlock(&cbdb->lock);
}

void cbdb_del_handler(struct cbd_backend *cbdb, struct cbd_handler *handler)
{
	mutex_lock(&cbdb->lock);
	list_del_init(&handler->handlers_node);
	mutex_unlock(&cbdb->lock);
}

static struct cbd_handler *cbdb_get_handler(struct cbd_backend *cbdb, u32 seg_id)
{
	struct cbd_handler *handler, *handler_next;
	bool found = false;

	mutex_lock(&cbdb->lock);
	list_for_each_entry_safe(handler, handler_next,
				 &cbdb->handlers, handlers_node) {
		if (handler->channel.seg_id == seg_id) {
			found = true;
			break;
		}
	}
	mutex_unlock(&cbdb->lock);

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

static int cbd_backend_init(struct cbd_backend *cbdb)
{
	struct cbd_backend_info *b_info;
	struct cbd_transport *cbdt = cbdb->cbdt;

	b_info = cbdt_get_backend_info(cbdt, cbdb->backend_id);
	cbdb->backend_info = b_info;

	b_info->host_id = cbdb->cbdt->host->host_id;

	cbdb->backend_io_cache = KMEM_CACHE(cbd_backend_io, 0);
	if (!cbdb->backend_io_cache)
		return -ENOMEM;

	cbdb->task_wq = alloc_workqueue("cbdt%d-b%u",  WQ_UNBOUND | WQ_MEM_RECLAIM,
					0, cbdt->id, cbdb->backend_id);
	if (!cbdb->task_wq) {
		kmem_cache_destroy(cbdb->backend_io_cache);
		return -ENOMEM;
	}

	cbdb->bdev_file = bdev_file_open_by_path(cbdb->path,
			BLK_OPEN_READ | BLK_OPEN_WRITE, cbdb, NULL);
	if (IS_ERR(cbdb->bdev_file)) {
		cbdt_err(cbdt, "failed to open bdev: %d", (int)PTR_ERR(cbdb->bdev_file));
		destroy_workqueue(cbdb->task_wq);
		kmem_cache_destroy(cbdb->backend_io_cache);
		return PTR_ERR(cbdb->bdev_file);
	}
	cbdb->bdev = file_bdev(cbdb->bdev_file);
	b_info->dev_size = bdev_nr_sectors(cbdb->bdev);

	INIT_DELAYED_WORK(&cbdb->state_work, state_work_fn);
	INIT_DELAYED_WORK(&cbdb->hb_work, backend_hb_workfn);
	INIT_LIST_HEAD(&cbdb->handlers);
	cbdb->backend_device = &cbdt->cbd_backends_dev->backend_devs[cbdb->backend_id];

	mutex_init(&cbdb->lock);

	queue_delayed_work(cbd_wq, &cbdb->state_work, 0);
	queue_delayed_work(cbd_wq, &cbdb->hb_work, 0);

	return 0;
}

int cbd_backend_start(struct cbd_transport *cbdt, char *path, u32 backend_id, u32 cache_segs)
{
	struct cbd_backend *backend;
	struct cbd_backend_info *backend_info;
	struct cbd_cache_info *cache_info;
	struct cbd_segment_info *prev_seg_info = NULL;
	struct cbd_segment *segment;
	u32 seg_id;
	bool alloc_backend = false;
	int ret;
	int i;

	if (backend_id == U32_MAX)
		alloc_backend = true;

	if (alloc_backend) {
		ret = cbdt_get_empty_backend_id(cbdt, &backend_id);
		if (ret)
			return ret;

		backend_info = cbdt_get_backend_info(cbdt, backend_id);
		cache_info = &backend_info->cache_info;
		cache_info->n_segs = cache_segs;
	} else {
		backend_info = cbdt_get_backend_info(cbdt, backend_id);
		cache_info = &backend_info->cache_info;
	}

	backend = kzalloc(sizeof(*backend), GFP_KERNEL);
	if (!backend)
		return -ENOMEM;

	if (cache_info->n_segs) {
		backend->cbd_cache = cbd_cache_alloc(cache_info);
		if (!backend->cbd_cache) {
			ret = -ENOMEM;
			goto backend_free;
		}

		for (i = 0; i < cache_info->n_segs; i++) {
			ret = cbdt_get_empty_segment_id(cbdt, &seg_id);
			if (ret)
				goto segments_exit;

			pr_err("get seg: %u", seg_id);
			segment = &backend->cbd_cache->segments[i];
			cbd_segment_init(segment, cbdt, seg_id, cbds_type_cache);

			if (prev_seg_info) {
				prev_seg_info->next_seg = seg_id;
			} else {
				cache_info->seg_id = seg_id;
			}
			prev_seg_info = cbdt_get_segment_info(cbdt, seg_id);
		}
	}

	strscpy(backend->path, path, CBD_PATH_LEN);
	memcpy(backend_info->path, backend->path, CBD_PATH_LEN);
	INIT_LIST_HEAD(&backend->node);
	backend->backend_id = backend_id;
	backend->cbdt = cbdt;

	ret = cbd_backend_init(backend);
	if (ret)
		goto segments_exit;

	backend_info->state = cbd_backend_state_running;

	cbdt_add_backend(cbdt, backend);

	return 0;

segments_exit:
	if (backend->cbd_cache) {
		for (i = 0; i < backend->cbd_cache->n_segs; i++)
			cbd_segment_exit(&backend->cbd_cache->segments[i]);

		cbd_cache_destroy(backend->cbd_cache);
	}
backend_free:
	kfree(backend);

	return ret;
}

int cbd_backend_stop(struct cbd_transport *cbdt, u32 backend_id, bool force)
{
	struct cbd_backend *cbdb;
	struct cbd_backend_info *backend_info;
	struct cbd_handler *handler, *next;

	cbdb = cbdt_get_backend(cbdt, backend_id);
	if (!cbdb)
		return -ENOENT;

	mutex_lock(&cbdb->lock);
	if (!list_empty(&cbdb->handlers) && !force) {
		mutex_unlock(&cbdb->lock);
		return -EBUSY;
	}
	cbdt_del_backend(cbdt, cbdb);

	cancel_delayed_work_sync(&cbdb->hb_work);
	cancel_delayed_work_sync(&cbdb->state_work);

	mutex_unlock(&cbdb->lock);
	list_for_each_entry_safe(handler, next, &cbdb->handlers, handlers_node) {
		cbd_handler_destroy(handler);
	}
	mutex_lock(&cbdb->lock);

	backend_info = cbdt_get_backend_info(cbdt, cbdb->backend_id);
	backend_info->state = cbd_backend_state_none;
	mutex_unlock(&cbdb->lock);

	drain_workqueue(cbdb->task_wq);
	destroy_workqueue(cbdb->task_wq);

	kmem_cache_destroy(cbdb->backend_io_cache);

	if (cbdb->cbd_cache) {
		int i;

		for (i = 0; i < cbdb->cbd_cache->n_segs; i++)
			cbd_segment_exit(&cbdb->cbd_cache->segments[i]);

		cbd_cache_destroy(cbdb->cbd_cache);
	}

	fput(cbdb->bdev_file);
	kfree(cbdb);

	return 0;
}

int cbd_backend_clear(struct cbd_transport *cbdt, u32 backend_id)
{
	struct cbd_backend_info *backend_info;

	backend_info = cbdt_get_backend_info(cbdt, backend_id);
	if (cbd_backend_info_is_alive(backend_info)) {
		cbdt_err(cbdt, "backend %u is still alive\n", backend_id);
		return -EBUSY;
	}

	if (backend_info->state == cbd_backend_state_none)
		return 0;

	backend_info->state = cbd_backend_state_none;

	return 0;
}

bool cbd_backend_cache_on(struct cbd_backend_info *backend_info)
{
	return (backend_info->cache_info.n_segs != 0);
}
