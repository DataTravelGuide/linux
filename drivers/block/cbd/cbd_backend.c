// SPDX-License-Identifier: GPL-2.0-or-later

#include "cbd_internal.h"
#include "cbd_transport.h"
#include "cbd_host.h"
#include "cbd_segment.h"
#include "cbd_channel.h"
#include "cbd_cache/cbd_cache.h"
#include "cbd_handler.h"
#include "cbd_backend.h"

static ssize_t backend_host_id_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_backend_device *backend;
	struct cbd_backend_info *latest_info;

	backend = container_of(dev, struct cbd_backend_device, dev);

	latest_info = cbdt_backend_info_read(backend->cbdt, backend->id, NULL);
	if (!latest_info || latest_info->state == cbd_backend_state_none)
		return 0;

	return sprintf(buf, "%u\n", latest_info->host_id);
}
static DEVICE_ATTR(host_id, 0400, backend_host_id_show, NULL);

static ssize_t backend_path_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_backend_device *backend;
	struct cbd_backend_info *latest_info;

	backend = container_of(dev, struct cbd_backend_device, dev);

	latest_info = cbdt_backend_info_read(backend->cbdt, backend->id, NULL);
	if (!latest_info || latest_info->state == cbd_backend_state_none)
		return 0;

	return sprintf(buf, "%s\n", latest_info->path);
}
static DEVICE_ATTR(path, 0400, backend_path_show, NULL);

/**
 * cbd_backend_hb - Update the backend information as part of the heartbeat.
 * @cbdb: Pointer to the cbd_backend structure.
 *
 * This function is invoked as part of the heartbeat work (hb_work).
 * It updates the backend information, specifically the alive timestamp
 * (alive_ts), ensuring that the backend is marked as alive and responsive.
 */
static void cbd_backend_hb(struct cbd_backend *cbdb)
{
	cbd_backend_info_write(cbdb);
}

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

/**
 * cbdb_add_handler - Add a handler to the backend's handler hash table.
 * @cbdb: Pointer to the cbd_backend structure.
 * @handler: Pointer to the cbd_handler structure to be added.
 *
 * This function adds a handler to the hash table of handlers associated
 * with the backend. The hash map is used for quick lookup of handlers
 * by their ID in single-host scenarios, where a block device sends a
 * request to the backend and subsequently calls a notify function.
 *
 * If the backend is in the process of being removed, the handler will
 * not be added, and an error will be returned.
 *
 * Return: 0 on success, or -EFAULT if the backend state is removing.
 */
int cbdb_add_handler(struct cbd_backend *cbdb, struct cbd_handler *handler)
{
	int ret = 0;

	spin_lock(&cbdb->lock);
	if (cbdb->backend_info.state == cbd_backend_state_stopping) {
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

/**
 * cbdb_get_handler - Retrieve a handler from the backend's handler hash table.
 * @cbdb: Pointer to the cbd_backend structure.
 * @seg_id: Segment ID of the handler to retrieve.
 *
 * This function searches for a handler in the backend's hash table using
 * the provided segment ID. It uses a hash table for efficient lookup.
 *
 * Return: Pointer to the cbd_handler structure if found, or NULL if not found.
 */
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

/**
 * create_handlers - Create handler structures for the backend.
 * @cbdb: Pointer to the cbd_backend structure.
 * @new_backend: Boolean indicating if this is a new backend.
 *
 * This function creates handlers for the backend. If it's a new backend,
 * it allocates new channel IDs for each handler. If it's not a new backend,
 * it uses existing channel IDs stored in the backend_info.
 *
 * The function iterates through the number of handlers specified in
 * backend_info. For each handler, it either retrieves an available
 * channel ID or uses the existing one, and then attempts to create
 * the handler using cbd_handler_create.
 *
 * If any operation fails, it calls destroy_handlers to clean up
 * any already created handlers before returning an error code.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
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

extern struct device_type cbd_cache_type;

/**
 * backend_open_bdev - Open a block device file and validate its size.
 * @cbdb: Pointer to the backend structure.
 * @new_backend: Boolean indicating if this is a new backend.
 *
 * This function attempts to open a block device file specified by the
 * backend's path. If it's a new backend, it retrieves the device size.
 * If it's an existing backend, it checks that the device size matches
 * the expected size. Returns 0 on success or a negative error code on failure.
 */
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

/**
 * backend_cache_init - Initialize the backend cache.
 * @cbdb: Pointer to the cbd_backend structure.
 * @cache_segs: Number of cache segments to allocate.
 * @new_backend: Indicates if this is a new backend.
 *
 * This function initializes the cache for the backend. It allocates
 * cache resources and sets up the corresponding device structure.
 * If the allocation or setup fails, appropriate cleanup is performed.
 *
 * Returns 0 on success, or a negative error code on failure.
 */
static int backend_cache_init(struct cbd_backend *cbdb, u32 cache_segs, bool new_backend)
{
	struct cbd_cache_opts cache_opts = { 0 };
	int ret;

	cache_opts.cache_info = &cbdb->backend_info.cache_info;
	cache_opts.cache_id = cbdb->backend_id;
	cache_opts.owner = cbdb;
	cache_opts.n_segs = cache_segs;
	cache_opts.new_cache = new_backend;
	cache_opts.start_writeback = true;
	cache_opts.start_gc = false;
	cache_opts.init_keys = false;
	cache_opts.bdev_file = cbdb->bdev_file;
	cache_opts.dev_size = cbdb->backend_info.dev_size;

	/* Allocate the cache with specified options. */
	cbdb->cbd_cache = cbd_cache_alloc(cbdb->cbdt, &cache_opts);
	if (!cbdb->cbd_cache) {
		ret = -ENOMEM;
		goto err; /* Cleanup and return error. */
	}

	device_initialize(&cbdb->cache_dev);
	device_set_pm_not_required(&cbdb->cache_dev);
	dev_set_name(&cbdb->cache_dev, "cache");
	cbdb->cache_dev.parent = &cbdb->backend_device->dev;
	cbdb->cache_dev.type = &cbd_cache_type;

	/* Add the cache device to the system. */
	ret = device_add(&cbdb->cache_dev);
	if (ret)
		goto destroy_cache;

	return 0; /* Success. */

destroy_cache:
	cbd_cache_destroy(cbdb->cbd_cache); /* Cleanup on failure. */
err:
	return ret; /* Return error code. */
}

/**
 * backend_cache_destroy - Destroy the backend cache.
 * @cbdb: Pointer to the cbd_backend structure.
 *
 * This function cleans up and releases resources allocated for
 * the backend cache. It unregisters the device and destroys the
 * cache if it exists.
 */
static void backend_cache_destroy(struct cbd_backend *cbdb)
{
	if (cbdb->cbd_cache) {
		device_unregister(&cbdb->cache_dev); /* Unregister the device. */
		cbd_cache_destroy(cbdb->cbd_cache); /* Destroy the cache. */
	}
}

/**
 * cbd_backend_info_init - Initialize the backend information.
 * @cbdb: Pointer to the backend structure.
 * @path: Path to the backend device.
 * @handlers: Number of handlers for the backend.
 * @cache_segs: Number of cache segments to allocate.
 *
 * This function initializes the backend information structure with the provided
 * parameters. It retrieves an empty backend ID and sets up the metadata for the
 * backend, including the path and number of handlers.
 *
 * Returns 0 on success or a negative error code on failure.
 */
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

	return 0;
err:
	return ret;
}

static int cbd_backend_info_load(struct cbd_backend *cbdb, u32 backend_id);
/**
 * cbd_backend_init - Initialize a backend structure.
 * @cbdb: Pointer to the backend structure to initialize.
 * @path: Path to the backend device.
 * @backend_id: Identifier for the backend.
 * @handlers: Number of handlers for the backend.
 * @cache_segs: Number of cache segments to allocate.
 *
 * This function initializes the backend structure based on the provided parameters.
 * If the backend ID is U32_MAX, it initializes a new backend; otherwise, it attaches
 * an existing backend. The function handles opening the block device, creating handlers,
 * and initializing the cache if specified.
 *
 * Returns 0 on success or a negative error code on failure.
 */
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

static void cbd_backend_destroy(struct cbd_backend *cbdb)
{
	struct cbd_transport *cbdt = cbdb->cbdt;

	cbdt_del_backend(cbdt, cbdb);
	backend_cache_destroy(cbdb);
	destroy_handlers(cbdb);
	backend_close_bdev(cbdb);
}

/**
 * cbd_backend_info_write - Write backend information to the transport layer.
 * @cbdb: Pointer to the backend structure containing information to write.
 *
 * This function updates the alive timestamp for the backend and writes the backend
 * information to the transport layer. It uses a mutex to ensure thread safety while
 * accessing the backend info structure. The backend info index is incremented and
 * wrapped around to a maximum value defined by CBDT_META_INDEX_MAX.
 */
void cbd_backend_info_write(struct cbd_backend *cbdb)
{
	mutex_lock(&cbdb->info_lock);
	cbdb->backend_info.alive_ts = ktime_get_real();
	cbdt_backend_info_write(cbdb->cbdt, &cbdb->backend_info, sizeof(struct cbd_backend_info),
				cbdb->backend_id, cbdb->backend_info_index);
	cbdb->backend_info_index = (cbdb->backend_info_index + 1) % CBDT_META_INDEX_MAX;
	mutex_unlock(&cbdb->info_lock);
}

/**
 * cbd_backend_info_load - Load backend metadata for a given backend ID.
 * @cbdb: Pointer to the backend structure to load information into.
 * @backend_id: Identifier of the backend to load information for.
 *
 * This function is called when attaching a backend to load its metadata.
 * It reads the backend information from the transport layer and checks if
 * the backend is alive. If the backend is alive, an error (-EBUSY) is returned.
 * The function also verifies that the host ID of the loaded backend matches
 * the current host ID. If they do not match, an error (-EINVAL) is returned.
 * On successful loading, the backend information is copied into the provided
 * backend structure.
 *
 * Returns 0 on success, or a negative error code on failure.
 */
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

/**
 * cbd_backend_alloc - Allocate and initialize a cbd_backend structure.
 * @cbdt: Pointer to the cbd_transport structure associated with the backend.
 *
 * This function allocates memory for a new cbd_backend structure and initializes
 * its members. It sets up necessary caches, workqueues, and locks. If any allocation
 * fails, it cleans up previously allocated resources and returns NULL.
 *
 * Returns a pointer to the allocated cbd_backend structure on success, or NULL
 * on failure.
 */
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

/**
 * cbd_backend_start - Main function to start a backend.
 * @cbdt: Pointer to the cbd_transport structure associated with the backend.
 * @path: Path to the backend storage.
 * @backend_id: Identifier for the backend.
 * @handlers: Number of handler instances to create.
 * @cache_segs: Number of cache segments to allocate.
 *
 * This function orchestrates the entire process of starting a backend. It allocates
 * the backend structure, initializes it with the provided parameters, writes the
 * backend info, and starts the heartbeat work. If any step fails, it cleans up
 * and frees the allocated resources before returning an error code.
 *
 * Returns 0 on success, or a negative error code on failure.
 */
int cbd_backend_start(struct cbd_transport *cbdt, char *path, u32 backend_id,
		      u32 handlers, u32 cache_segs)
{
	struct cbd_backend *cbdb;
	int ret;

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

/**
 * backend_blkdevs_stopped - Check if all block devices are stopped for a given backend.
 * @cbdt: Pointer to the cbd_transport structure.
 * @backend_id: ID of the backend to check.
 *
 * This function iterates through all block device information entries
 * associated with the given backend ID. If any block device is found
 * to be in the running state, it logs an error message and returns false.
 * If all block devices are stopped, it returns true.
 */
static bool backend_blkdevs_stopped(struct cbd_transport *cbdt, u32 backend_id)
{
	struct cbd_blkdev_info *blkdev_info;
	int i;

	cbd_for_each_blkdev_info(cbdt, i, blkdev_info) {
		if (!blkdev_info)
			continue;

		if (blkdev_info->state != cbd_blkdev_state_running)
			continue;

		if (blkdev_info->backend_id == backend_id) {
			cbdt_err(cbdt, "blkdev %u is connected to backend %u\n",
					i, backend_id);
			return false;
		}
	}

	return true;
}

/**
 * cbd_backend_stop - Main function to stop a backend.
 * @cbdt: Pointer to the cbd_transport structure associated with the backend.
 * @backend_id: Identifier for the backend to be stopped.
 *
 * This function handles the process of stopping a backend. It first checks if the
 * specified backend is valid and ensures that no block devices are currently
 * connected to it. If the backend is already in the process of stopping, it returns
 * -EBUSY. Otherwise, it sets the backend state to stopping, cleans up associated
 * resources, and updates the backend info.
 *
 * Returns 0 on success, or a negative error code on failure.
 */
int cbd_backend_stop(struct cbd_transport *cbdt, u32 backend_id)
{
	struct cbd_backend *cbdb;

	cbdb = cbdt_get_backend(cbdt, backend_id);
	if (!cbdb)
		return -ENOENT;

	if (!backend_blkdevs_stopped(cbdt, backend_id))
		return -EBUSY;

	spin_lock(&cbdb->lock);
	if (cbdb->backend_info.state == cbd_backend_state_stopping) {
		spin_unlock(&cbdb->lock);
		return -EBUSY;
	}

	cbdb->backend_info.state = cbd_backend_state_stopping;
	spin_unlock(&cbdb->lock);

	cancel_delayed_work_sync(&cbdb->hb_work);
	cbd_backend_destroy(cbdb);
	cbd_backend_free(cbdb);

	cbdt_backend_info_clear(cbdt, backend_id);

	return 0;
}

/**
 * backend_segs_clear - Clear segments associated with a specific backend.
 * @cbdt: Pointer to the cbd_transport structure.
 * @backend_id: ID of the backend whose segments are to be cleared.
 *
 * This function iterates through all segment information entries in the
 * cbd_transport. For each segment, it checks its type. If the segment is
 * of type channel and is associated with the specified backend, it calls
 * cbd_segment_clear to release it. Similarly, if the segment is of type
 * cache and is associated with the backend, it also clears that segment.
 */
static void backend_segs_clear(struct cbd_transport *cbdt, u32 backend_id)
{
	struct cbd_segment_info *seg_info;
	struct cbd_channel_seg_info *channel_info;
	struct cbd_cache_seg_info *cache_seg_info;
	u32 i;

	for (i = 0; i < cbdt->transport_info->segment_num; i++) {
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
}

/**
 * cbd_backend_clear - Clear a backend's resources.
 * @cbdt: Pointer to the cbd_transport structure.
 * @backend_id: ID of the backend to be cleared.
 *
 * This function handles the clearing of a backend that cannot be recovered.
 * This function checks if the backend's metadata can be read. If the
 * metadata is corrupted, it means this backend was cleared.
 *
 * It then verifies if the backend is still alive; if so, it returns an
 * error indicating that the backend is busy. If the backend's state is none,
 * it indicates there are no resources to clear, and the function returns success.
 *
 * Before clearing the backend, it checks if all block devices
 * associated with the backend have stopped. If any are still running,
 * it returns an error indicating the backend is busy.
 *
 * Finally, it clears the segments associated with the backend and
 * removes the backend's metadata from the transport.
 */
int cbd_backend_clear(struct cbd_transport *cbdt, u32 backend_id)
{
	struct cbd_backend_info *backend_info;

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

	if (!backend_blkdevs_stopped(cbdt, backend_id))
		return -EBUSY;

	backend_segs_clear(cbdt, backend_id);
	cbdt_backend_info_clear(cbdt, backend_id);

	return 0;
}

/**
 * cbd_backend_cache_on - Check if the backend has an active cache.
 * @backend_info: Pointer to the cbd_backend_info structure of the backend.
 *
 * This function determines if the specified backend has an active cache
 * by checking the number of cache segments. In a single-host scenario,
 * this is useful for block devices to ascertain if the corresponding
 * backend utilizes caching.
 *
 * Returns true if the backend has one or more cache segments, false otherwise.
 */
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
