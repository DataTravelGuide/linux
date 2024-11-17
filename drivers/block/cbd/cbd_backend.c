// SPDX-License-Identifier: GPL-2.0-or-later

#include "cbd_internal.h"
#include "cbd_transport.h"
#include "cbd_host.h"
#include "cbd_segment.h"
#include "cbd_channel.h"
#include "cbd_cache/cbd_cache.h"
#include "cbd_handler.h"
#include "cbd_backend.h"

static ssize_t host_id_show(struct device *dev,
			    struct device_attribute *attr,
			    char *buf)
{
	struct cbd_backend_device *backend;
	struct cbd_backend_info *latest_info;

	backend = container_of(dev, struct cbd_backend_device, dev);
	latest_info = cbdt_backend_info_read(backend->cbdt, backend->id);
	if (!latest_info || latest_info->state == CBD_BACKEND_STATE_NONE)
		return 0;

	return sprintf(buf, "%u\n", latest_info->host_id);
}
static DEVICE_ATTR_ADMIN_RO(host_id);

static ssize_t path_show(struct device *dev,
			 struct device_attribute *attr,
			 char *buf)
{
	struct cbd_backend_device *backend;
	struct cbd_backend_info *latest_info;

	backend = container_of(dev, struct cbd_backend_device, dev);
	latest_info = cbdt_backend_info_read(backend->cbdt, backend->id);
	if (!latest_info || latest_info->state == CBD_BACKEND_STATE_NONE)
		return 0;

	return sprintf(buf, "%s\n", latest_info->path);
}
static DEVICE_ATTR_ADMIN_RO(path);

/* sysfs for cache */
static ssize_t cache_segs_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_backend_device *backend;
	struct cbd_backend_info *latest_info;

	backend = container_of(dev, struct cbd_backend_device, dev);
	latest_info = cbdt_backend_info_read(backend->cbdt, backend->id);
	if (!latest_info || latest_info->state == CBD_BACKEND_STATE_NONE)
		return 0;

	return sprintf(buf, "%u\n", latest_info->cache_info.n_segs);
}
static DEVICE_ATTR_ADMIN_RO(cache_segs);

static ssize_t cache_used_segs_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_backend_device *backend;
	struct cbd_backend_info *latest_info;
	u32 used_segs = 0;

	backend = container_of(dev, struct cbd_backend_device, dev);
	latest_info = cbdt_backend_info_read(backend->cbdt, backend->id);
	if (!latest_info || latest_info->state == CBD_BACKEND_STATE_NONE)
		return 0;

	if (!latest_info->cache_info.n_segs)
		goto out;

	used_segs = cache_info_used_segs(backend->cbdt, &latest_info->cache_info);
out:
	return sprintf(buf, "%u\n", used_segs);
}
static DEVICE_ATTR_ADMIN_RO(cache_used_segs);

static ssize_t cache_gc_percent_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_backend_device *backend;
	struct cbd_backend_info *latest_info;

	backend = container_of(dev, struct cbd_backend_device, dev);
	latest_info = cbdt_backend_info_read(backend->cbdt, backend->id);
	if (!latest_info || latest_info->state == CBD_BACKEND_STATE_NONE)
		return 0;

	return sprintf(buf, "%u\n", latest_info->cache_info.gc_percent);
}

static void __backend_info_write(struct cbd_backend *cbdb);
static ssize_t cache_gc_percent_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf,
				size_t size)
{
	struct cbd_backend_device *backend;
	struct cbd_backend *cbdb;
	unsigned long val;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	backend = container_of(dev, struct cbd_backend_device, dev);
	ret = kstrtoul(buf, 10, &val);
	if (ret)
		return ret;

	if (val < CBD_CACHE_GC_PERCENT_MIN ||
	    val > CBD_CACHE_GC_PERCENT_MAX)
		return -EINVAL;

	cbdb = cbdt_get_backend(backend->cbdt, backend->id);
	if (!cbdb) {
		cbdt_err(backend->cbdt, "gc_percent is only allowed to set in backend node.\n");
		return -EINVAL;
	}

	mutex_lock(&cbdb->info_lock);
	if (cbdb->backend_info.cache_info.n_segs == 0) {
		mutex_unlock(&cbdb->info_lock);
		return -EINVAL;
	}

	cbdb->backend_info.cache_info.gc_percent = val;
	__backend_info_write(cbdb);
	mutex_unlock(&cbdb->info_lock);

	return size;
}
static DEVICE_ATTR_ADMIN_RW(cache_gc_percent);

static void cbd_backend_hb(struct cbd_backend *cbdb)
{
	cbd_backend_info_write(cbdb);
}
CBD_OBJ_HEARTBEAT(backend);

static struct attribute *cbd_backend_attrs[] = {
	&dev_attr_path.attr,
	&dev_attr_host_id.attr,
	&dev_attr_alive.attr,
	&dev_attr_cache_segs.attr,
	&dev_attr_cache_gc_percent.attr,
	&dev_attr_cache_used_segs.attr,
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
	if (cbdb->backend_info.state == CBD_BACKEND_STATE_STOPPING) {
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
			ret = cbdt_get_empty_segment_id(cbdb->cbdt, &channel_id);
			if (ret < 0) {
				cbdb_err(cbdb, "failed find available channel_id.\n");
				goto destroy_handlers;
			}
			/* clear all channel segment before using it */
			cbd_segment_clear(cbdb->cbdt, channel_id);
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
	cache_opts.owner = cbdb;
	cache_opts.n_segs = cache_segs;
	cache_opts.n_paral = cbdb->backend_info.n_handlers;
	cache_opts.new_cache = new_backend;
	cache_opts.start_writeback = true;
	cache_opts.start_gc = false;
	cache_opts.init_req_keys = false;
	cache_opts.bdev_file = cbdb->bdev_file;
	cache_opts.dev_size = cbdb->backend_info.dev_size;

	/* Allocate the cache with specified options. */
	cbdb->cbd_cache = cbd_cache_alloc(cbdb->cbdt, &cache_opts);
	if (!cbdb->cbd_cache) {
		ret = -ENOMEM;
		goto err;
	}

	return 0;

err:
	return ret;
}

static void backend_cache_destroy(struct cbd_backend *cbdb)
{
	if (cbdb->cbd_cache)
		cbd_cache_destroy(cbdb->cbd_cache);
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

	cbdb->backend_id = backend_id;
	cbdb->backend_info.meta_header.version = 0;
	cbdb->backend_info.host_id = cbdb->host_id;
	cbdb->backend_info.n_handlers = handlers;

	strscpy(cbdb->backend_info.path, path, CBD_PATH_LEN);

	cbd_cache_info_init(&cbdb->backend_info.cache_info, cache_segs);

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
		/* attach backend, this could happen after an unexpected power off */
		cbdt_info(cbdt, "attach backend to backend_id: %u\n", backend_id);
		cbdb->backend_id = backend_id;
		ret = cbd_backend_info_load(cbdb, cbdb->backend_id);
		if (ret)
			goto err;
	}

	cbdb->backend_device = &cbdt->cbd_backends_dev->backend_devs[cbdb->backend_id];

	ret = backend_open_bdev(cbdb, new_backend);
	if (ret)
		goto err;

	ret = create_handlers(cbdb, new_backend);
	if (ret)
		goto close_bdev;

	if (cbdb->backend_info.cache_info.n_segs) {
		ret = backend_cache_init(cbdb, cbdb->backend_info.cache_info.n_segs, new_backend);
		if (ret)
			goto destroy_handlers;
	}

	cbdb->backend_info.state = CBD_BACKEND_STATE_RUNNING;
	cbdt_add_backend(cbdt, cbdb);

	return 0;

destroy_handlers:
	destroy_handlers(cbdb);
close_bdev:
	backend_close_bdev(cbdb);
err:
	return ret;
}

static void cbd_backend_destroy(struct cbd_backend *cbdb)
{
	struct cbd_transport *cbdt = cbdb->cbdt;

	cbdt_del_backend(cbdt, cbdb);
	backend_cache_destroy(cbdb);
	destroy_handlers(cbdb);
	backend_close_bdev(cbdb);
}

static void __backend_info_write(struct cbd_backend *cbdb)
{
	cbdb->backend_info.alive_ts = ktime_get_real();
	cbdt_backend_info_write(cbdb->cbdt, &cbdb->backend_info, sizeof(struct cbd_backend_info),
				cbdb->backend_id);
}

void cbd_backend_info_write(struct cbd_backend *cbdb)
{
	mutex_lock(&cbdb->info_lock);
	__backend_info_write(cbdb);
	mutex_unlock(&cbdb->info_lock);
}

static int cbd_backend_info_load(struct cbd_backend *cbdb, u32 backend_id)
{
	struct cbd_backend_info *backend_info;
	int ret = 0;

	mutex_lock(&cbdb->info_lock);
	backend_info = cbdt_backend_info_read(cbdb->cbdt, backend_id);
	if (!backend_info) {
		cbdt_err(cbdb->cbdt, "can't read info from backend id %u.\n",
				cbdb->backend_id);
		ret = -EINVAL;
		goto out;
	}

	if (cbd_backend_info_is_alive(backend_info)) {
		cbdt_err(cbdb->cbdt, "backend %u is alive\n", backend_id);
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
	if (!cbdb->backend_io_cache)
		goto free_cbdb;

	cbdb->task_wq = alloc_workqueue("cbdt%d-b%u",  WQ_UNBOUND | WQ_MEM_RECLAIM,
					0, cbdt->id, cbdb->backend_id);
	if (!cbdb->task_wq)
		goto destroy_io_cache;

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

static void cbd_backend_free(struct cbd_backend *cbdb)
{
	drain_workqueue(cbdb->task_wq);
	destroy_workqueue(cbdb->task_wq);
	kmem_cache_destroy(cbdb->backend_io_cache);
	kfree(cbdb);
}

static int backend_validate(struct cbd_transport *cbdt, char *path,
			    u32 *backend_id, u32 handlers, u32 cache_segs)
{
	u32 host_id = cbdt->host->host_id;
	int ret;

	/* Check if path starts with "/dev/" */
	if (strncmp(path, "/dev/", 5) != 0)
		return -EINVAL;

	/* Validate backend_id */
	if (*backend_id == U32_MAX) {
		ret = cbd_backend_find_id_by_path(cbdt, host_id, path, backend_id);
		if (!ret)
			cbdt_info(cbdt, "found backend_id: %u for host_id: %u, path: %s\n",
					*backend_id, host_id, path);
	} else {
		u32 backend_id_tmp;

		if (*backend_id != U32_MAX && *backend_id >= cbdt->transport_info.backend_num)
			return -EINVAL;

		ret = cbd_backend_find_id_by_path(cbdt, host_id, path, &backend_id_tmp);
		if (!ret && (*backend_id != backend_id_tmp)) {
			cbdt_err(cbdt, "duplicated backend path: %s with backend_id: %u\n",
					path, backend_id_tmp);
			return -EINVAL;
		}
	}

	/* Ensure handlers count is within valid range */
	if (handlers == 0 || handlers >= CBD_HANDLERS_MAX)
		return -EINVAL;

	/* All checks passed */
	return 0;
}

int cbd_backend_start(struct cbd_transport *cbdt, char *path, u32 backend_id,
		      u32 handlers, u32 cache_segs)
{
	struct cbd_backend *cbdb;
	int ret;

	ret = backend_validate(cbdt, path, &backend_id, handlers, cache_segs);
	if (ret)
		return ret;

	cbdb = cbd_backend_alloc(cbdt);
	if (!cbdb)
		return -ENOMEM;

	ret = cbd_backend_init(cbdb, path, backend_id, handlers, cache_segs);
	if (ret)
		goto destroy_cbdb;

	cbd_backend_info_write(cbdb);
	queue_delayed_work(cbd_wq, &cbdb->hb_work, CBD_HB_INTERVAL);

	return 0;

destroy_cbdb:
	cbd_backend_free(cbdb);

	return ret;
}

static bool backend_blkdevs_stopped(struct cbd_transport *cbdt, u32 backend_id)
{
	struct cbd_blkdev_info *blkdev_info;
	int i;

	cbd_for_each_blkdev_info(cbdt, i, blkdev_info) {
		if (!blkdev_info)
			continue;

		if (blkdev_info->state != CBD_BLKDEV_STATE_RUNNING)
			continue;

		if (blkdev_info->backend_id == backend_id) {
			cbdt_err(cbdt, "blkdev %u is connected to backend %u\n",
					i, backend_id);
			return false;
		}
	}

	return true;
}

int cbd_backend_stop(struct cbd_transport *cbdt, u32 backend_id)
{
	struct cbd_backend *cbdb;

	cbdb = cbdt_get_backend(cbdt, backend_id);
	if (!cbdb)
		return -ENOENT;

	if (!backend_blkdevs_stopped(cbdt, backend_id))
		return -EBUSY;

	spin_lock(&cbdb->lock);
	if (cbdb->backend_info.state == CBD_BACKEND_STATE_STOPPING) {
		spin_unlock(&cbdb->lock);
		return -EBUSY;
	}

	cbdb->backend_info.state = CBD_BACKEND_STATE_STOPPING;
	spin_unlock(&cbdb->lock);

	cancel_delayed_work_sync(&cbdb->hb_work);
	cbd_backend_destroy(cbdb);
	cbd_backend_free(cbdb);

	cbdt_backend_info_clear(cbdt, backend_id);

	return 0;
}

static void backend_segs_clear(struct cbd_transport *cbdt, u32 backend_id)
{
	struct cbd_segment_info *seg_info;
	u32 i;

	cbd_for_each_segment_info(cbdt, i, seg_info) {
		if (!seg_info)
			continue;

		if (seg_info->backend_id == backend_id)
			cbdt_segment_info_clear(cbdt, i);
	}
}

int cbd_backend_clear(struct cbd_transport *cbdt, u32 backend_id)
{
	struct cbd_backend_info *backend_info;

	backend_info = cbdt_backend_info_read(cbdt, backend_id);
	if (!backend_info) {
		cbdt_err(cbdt, "all backend_info in backend_id: %u are corrupted.\n", backend_id);
		return -EINVAL;
	}

	if (cbd_backend_info_is_alive(backend_info)) {
		cbdt_err(cbdt, "backend %u is still alive\n", backend_id);
		return -EBUSY;
	}

	if (backend_info->state == CBD_BACKEND_STATE_NONE)
		return 0;

	if (!backend_blkdevs_stopped(cbdt, backend_id))
		return -EBUSY;

	backend_segs_clear(cbdt, backend_id);
	cbdt_backend_info_clear(cbdt, backend_id);

	return 0;
}

bool cbd_backend_cache_on(struct cbd_backend_info *backend_info)
{
	return (backend_info->cache_info.n_segs != 0);
}

/**
 * cbd_backend_notify - Notify the backend to handle an I/O request.
 * @cbdb: Pointer to the cbd_backend structure.
 * @seg_id: Segment ID associated with the request.
 *
 * This function is called in a single-host scenario after a block device
 * sends an I/O request. It retrieves the corresponding handler for the
 * given segment ID and, if the handler is ready, notifies it to proceed
 * with handling the request. If the handler is not ready, the function
 * returns immediately, allowing the handler to queue the handle_work
 * while being created.
 */
void cbd_backend_notify(struct cbd_backend *cbdb, u32 seg_id)
{
	struct cbd_handler *handler;

	handler = cbdb_get_handler(cbdb, seg_id);
	/*
	 * If the handler is not ready, return directly and
	 * wait for the handler to queue the handle_work during creation.
	 */
	if (!handler)
		return;

	cbd_handler_notify(handler);
}

void cbd_backend_mgmt_notify(struct cbd_backend *cbdb, u32 seg_id)
{
	struct cbd_handler *handler;

	handler = cbdb_get_handler(cbdb, seg_id);
	if (!handler)
		return;

	cbd_handler_mgmt_notify(handler);
}
