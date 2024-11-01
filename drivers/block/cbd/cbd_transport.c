// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/dax.h>
#include <linux/pfn_t.h>
#include <linux/parser.h>

#include "cbd_transport.h"
#include "cbd_host.h"
#include "cbd_segment.h"
#include "cbd_backend.h"
#include "cbd_blkdev.h"

/*
 * This macro defines and manages four types of objects within the CBD transport:
 * host, backend, blkdev, and segment. Each object type is associated with its own
 * information structure (`cbd_<OBJ>_info`), which includes a meta header. The meta
 * header incorporates a sequence number and CRC, ensuring data integrity. This
 * integrity mechanism allows consistent and reliable access to object information
 * within the CBD transport.
 */
#define CBDT_OBJ(OBJ, OBJ_SIZE, OBJ_STRIDE)					\
static int cbd_##OBJ##s_init(struct cbd_transport *cbdt)			\
{										\
	struct cbd_##OBJ##s_device *devs;					\
	struct cbd_##OBJ##_device *cbd_dev;					\
	struct device *dev;							\
	int i;									\
	int ret;								\
										\
	u32 memsize = struct_size(devs, OBJ##_devs,				\
			cbdt->transport_info->OBJ##_num);			\
	devs = kzalloc(memsize, GFP_KERNEL);					\
	if (!devs) {								\
		return -ENOMEM;							\
	}									\
										\
	dev = &devs->OBJ##s_dev;						\
	device_initialize(dev);							\
	device_set_pm_not_required(dev);					\
	dev_set_name(dev, "cbd_" #OBJ "s");					\
	dev->parent = &cbdt->device;						\
	dev->type = &cbd_##OBJ##s_type;						\
	ret = device_add(dev);							\
	if (ret) {								\
		goto devs_free;							\
	}									\
										\
	for (i = 0; i < cbdt->transport_info->OBJ##_num; i++) {			\
		cbd_dev = &devs->OBJ##_devs[i];					\
		dev = &cbd_dev->dev;						\
										\
		cbd_dev->cbdt = cbdt;						\
		cbd_dev->id = i;						\
		device_initialize(dev);						\
		device_set_pm_not_required(dev);				\
		dev_set_name(dev, #OBJ "%u", i);				\
		dev->parent = &devs->OBJ##s_dev;				\
		dev->type = &cbd_##OBJ##_type;					\
										\
		ret = device_add(dev);						\
		if (ret) {							\
			i--;							\
			goto del_device;					\
		}								\
	}									\
	cbdt->cbd_##OBJ##s_dev = devs;						\
										\
	return 0;								\
del_device:									\
	for (; i >= 0; i--) {							\
		cbd_dev = &devs->OBJ##_devs[i];					\
		dev = &cbd_dev->dev;						\
		device_del(dev);						\
	}									\
devs_free:									\
	kfree(devs);								\
	return ret;								\
}										\
										\
static void cbd_##OBJ##s_exit(struct cbd_transport *cbdt)			\
{										\
	struct cbd_##OBJ##s_device *devs = cbdt->cbd_##OBJ##s_dev;		\
	struct device *dev;							\
	int i;									\
										\
	if (!devs)								\
		return;								\
										\
	for (i = 0; i < cbdt->transport_info->OBJ##_num; i++) {			\
		struct cbd_##OBJ##_device *cbd_dev = &devs->OBJ##_devs[i];	\
		dev = &cbd_dev->dev;						\
										\
		device_del(dev);						\
	}									\
										\
	device_del(&devs->OBJ##s_dev);						\
										\
	kfree(devs);								\
	cbdt->cbd_##OBJ##s_dev = NULL;						\
										\
	return;									\
}										\
										\
static inline struct cbd_##OBJ##_info						\
*__get_##OBJ##_info(struct cbd_transport *cbdt, u32 id)				\
{										\
	struct cbd_transport_info *info = cbdt->transport_info;			\
	void *start = cbdt->transport_info;					\
										\
	BUG_ON(id >= info->OBJ##_num);						\
										\
	start += info->OBJ##_area_off;						\
										\
	return start + ((u64)OBJ_STRIDE * id);					\
}										\
										\
struct cbd_##OBJ##_info								\
*cbdt_get_##OBJ##_info(struct cbd_transport *cbdt, u32 id)			\
{										\
	struct cbd_##OBJ##_info *info;						\
										\
	mutex_lock(&cbdt->lock);						\
	info = __get_##OBJ##_info(cbdt, id);					\
	mutex_unlock(&cbdt->lock);						\
										\
	return info;								\
}										\
										\
int cbdt_get_empty_##OBJ##_id(struct cbd_transport *cbdt, u32 *id)		\
{										\
	struct cbd_transport_info *info = cbdt->transport_info;			\
	struct cbd_##OBJ##_info *_info, *latest;				\
	int ret = 0;								\
	int i;									\
										\
	mutex_lock(&cbdt->lock);						\
	for (i = 0; i < info->OBJ##_num; i++) {					\
		_info = __get_##OBJ##_info(cbdt, i);				\
		latest = cbd_meta_find_latest(&_info->meta_header,		\
					      OBJ_SIZE,				\
					      NULL);				\
		if (!latest || latest->state == cbd_##OBJ##_state_none) {	\
			cbdt_zero_range(cbdt, _info, OBJ_STRIDE);		\
			*id = i;						\
			goto out;						\
		}								\
	}									\
										\
	cbdt_err(cbdt, "No available " #OBJ "_id found.");			\
	ret = -ENOENT;								\
out:										\
	mutex_unlock(&cbdt->lock);						\
										\
	return ret;								\
}										\
										\
struct cbd_##OBJ##_info *cbdt_##OBJ##_info_read(struct cbd_transport *cbdt,	\
						u32 id,				\
						u32 *info_index)		\
{										\
	struct cbd_##OBJ##_info *info, *latest = NULL;				\
										\
	info = cbdt_get_##OBJ##_info(cbdt, id);					\
										\
	latest = cbd_meta_find_latest(&info->meta_header,			\
				      OBJ_SIZE,					\
				      info_index);				\
	if (!latest)								\
		return NULL;							\
										\
	return latest;								\
}										\
										\
void cbdt_##OBJ##_info_write(struct cbd_transport *cbdt,			\
				    void *data,					\
				    u32 data_size,				\
				    u32 id,					\
				    u32 info_index)				\
{										\
	struct cbd_##OBJ##_info *info;						\
	struct cbd_meta_header *meta;						\
										\
	mutex_lock(&cbdt->lock);						\
	/* seq is u8 and we compare it with cbd_meta_seq_after() */		\
	meta = (struct cbd_meta_header *)data;					\
	meta->seq++;								\
										\
	info = __get_##OBJ##_info(cbdt, id);					\
										\
	info = (void *)info + (info_index * OBJ_SIZE);				\
	memcpy(info, data, data_size);						\
										\
	info->meta_header.crc = cbd_meta_crc(&info->meta_header, OBJ_SIZE);	\
	mutex_unlock(&cbdt->lock);						\
}										\
										\
void cbdt_##OBJ##_info_clear(struct cbd_transport *cbdt, u32 id)		\
{										\
	struct cbd_##OBJ##_info *info;						\
										\
	mutex_lock(&cbdt->lock);						\
	info = __get_##OBJ##_info(cbdt, id);					\
	cbdt_zero_range(cbdt, info, OBJ_SIZE * CBDT_META_INDEX_MAX);		\
	mutex_unlock(&cbdt->lock);						\
}

CBDT_OBJ(host, CBDT_HOST_INFO_SIZE, CBDT_HOST_INFO_STRIDE);
CBDT_OBJ(backend, CBDT_BACKEND_INFO_SIZE, CBDT_BACKEND_INFO_STRIDE);
CBDT_OBJ(blkdev, CBDT_BLKDEV_INFO_SIZE, CBDT_BLKDEV_INFO_STRIDE);
CBDT_OBJ(segment, CBDT_SEG_INFO_SIZE, CBDT_SEG_INFO_STRIDE);

static struct cbd_transport *cbd_transports[CBD_TRANSPORT_MAX];
static DEFINE_IDA(cbd_transport_id_ida);
static DEFINE_MUTEX(cbd_transport_mutex);

static ssize_t cbdt_host_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_transport *cbdt;
	struct cbd_host *host;

	cbdt = container_of(dev, struct cbd_transport, device);

	host = cbdt->host;
	if (!host)
		return 0;

	return sprintf(buf, "%d\n", host->host_id);
}

static DEVICE_ATTR(host_id, 0400, cbdt_host_show, NULL);

enum {
	CBDT_ADM_OPT_ERR		= 0,
	CBDT_ADM_OPT_OP,
	CBDT_ADM_OPT_FORCE,
	CBDT_ADM_OPT_PATH,
	CBDT_ADM_OPT_BID,
	CBDT_ADM_OPT_HANDLERS,
	CBDT_ADM_OPT_DID,
	CBDT_ADM_OPT_QUEUES,
	CBDT_ADM_OPT_HID,
	CBDT_ADM_OPT_CACHE_SIZE,
};

enum {
	CBDT_ADM_OP_B_START,
	CBDT_ADM_OP_B_STOP,
	CBDT_ADM_OP_B_CLEAR,
	CBDT_ADM_OP_DEV_START,
	CBDT_ADM_OP_DEV_STOP,
	CBDT_ADM_OP_DEV_CLEAR,
	CBDT_ADM_OP_H_CLEAR,
};

static const char *const adm_op_names[] = {
	[CBDT_ADM_OP_B_START] = "backend-start",
	[CBDT_ADM_OP_B_STOP] = "backend-stop",
	[CBDT_ADM_OP_B_CLEAR] = "backend-clear",
	[CBDT_ADM_OP_DEV_START] = "dev-start",
	[CBDT_ADM_OP_DEV_STOP] = "dev-stop",
	[CBDT_ADM_OP_DEV_CLEAR] = "dev-clear",
	[CBDT_ADM_OP_H_CLEAR] = "host-clear",
};

static const match_table_t adm_opt_tokens = {
	{ CBDT_ADM_OPT_OP,		"op=%s"	},
	{ CBDT_ADM_OPT_FORCE,		"force=%u" },
	{ CBDT_ADM_OPT_PATH,		"path=%s" },
	{ CBDT_ADM_OPT_BID,		"backend_id=%u" },
	{ CBDT_ADM_OPT_HANDLERS,	"handlers=%u" },
	{ CBDT_ADM_OPT_DID,		"dev_id=%u" },
	{ CBDT_ADM_OPT_QUEUES,		"queues=%u" },
	{ CBDT_ADM_OPT_HID,		"host_id=%u" },
	{ CBDT_ADM_OPT_CACHE_SIZE,	"cache_size=%u" },	/* unit is MiB */
	{ CBDT_ADM_OPT_ERR,		NULL	}
};


struct cbd_adm_options {
	u16 op;
	u16 force:1;
	u32 backend_id;
	union {
		struct host_options {
			u32 hid;
		} host;
		struct backend_options {
			char path[CBD_PATH_LEN];
			u32 handlers;
			u64 cache_size_M;
		} backend;
		struct segment_options {
			u32 sid;
		} segment;
		struct blkdev_options {
			u32 devid;
			u32 queues;
		} blkdev;
	};
};

static int parse_adm_options(struct cbd_transport *cbdt,
		char *buf,
		struct cbd_adm_options *opts)
{
	substring_t args[MAX_OPT_ARGS];
	char *o, *p;
	int token, ret = 0;

	o = buf;

	while ((p = strsep(&o, ",\n")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, adm_opt_tokens, args);
		switch (token) {
		case CBDT_ADM_OPT_OP:
			ret = match_string(adm_op_names, ARRAY_SIZE(adm_op_names), args[0].from);
			if (ret < 0) {
				cbdt_err(cbdt, "unknown op: '%s'\n", args[0].from);
				ret = -EINVAL;
				break;
			}
			opts->op = ret;
			break;
		case CBDT_ADM_OPT_PATH:
			if (match_strlcpy(opts->backend.path, &args[0],
				CBD_PATH_LEN) == 0) {
				ret = -EINVAL;
				break;
			}
			break;
		case CBDT_ADM_OPT_FORCE:
			if (match_uint(args, &token) || token != 1) {
				ret = -EINVAL;
				goto out;
			}
			opts->force = 1;
			break;
		case CBDT_ADM_OPT_BID:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}

			if (token >= cbdt->transport_info->backend_num) {
				cbdt_err(cbdt, "invalid backend_id: %u, larger than backend_num %u\n",
						token, cbdt->transport_info->backend_num);
				ret = -EINVAL;
				goto out;
			}
			opts->backend_id = token;
			break;
		case CBDT_ADM_OPT_HANDLERS:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}

			if (token > CBD_HANDLERS_MAX) {
				cbdt_err(cbdt, "invalid handlers: %u, larger than max %u\n",
						token, CBD_HANDLERS_MAX);
			}
			opts->backend.handlers = token;
			break;
		case CBDT_ADM_OPT_DID:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}

			if (token >= cbdt->transport_info->blkdev_num) {
				cbdt_err(cbdt, "invalid dev_id: %u, larger than blkdev_num %u\n",
						token, cbdt->transport_info->blkdev_num);
				ret = -EINVAL;
				goto out;
			}
			opts->blkdev.devid = token;
			break;
		case CBDT_ADM_OPT_QUEUES:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}

			if (token > CBD_QUEUES_MAX) {
				cbdt_err(cbdt, "invalid queues: %u, larger than max %u\n",
						token, CBD_QUEUES_MAX);
			}
			opts->blkdev.queues = token;
			break;
		case CBDT_ADM_OPT_HID:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}

			if (token >= cbdt->transport_info->host_num) {
				cbdt_err(cbdt, "invalid host_id: %u, larger than max %u\n",
						token, cbdt->transport_info->host_num);
			}
			opts->host.hid = token;
			break;
		case CBDT_ADM_OPT_CACHE_SIZE:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}
			opts->backend.cache_size_M = token;
			break;
		default:
			cbdt_err(cbdt, "unknown parameter or missing value '%s'\n", p);
			ret = -EINVAL;
			goto out;
		}
	}

out:
	return ret;
}

/**
 * cbdt_flush - Flush a specified range of data to persistent storage.
 * @cbdt: Pointer to the CBD transport structure.
 * @pos: Pointer to the starting address of the data range to flush.
 * @size: Size of the data range to flush.
 *
 * This function ensures that the data in the specified address range
 * is persisted to storage. It handles the following scenarios:
 *
 * - If using NVDIMM in a single-host scenario with ADR support,
 *   then after calling dax_flush, the data will be persistent.
 *   For more information on ADR, refer to:
 *   https://pmem.io/glossary/#adr
 *
 * - If using CXL persistent memory, the function should comply with
 *   Global Persistent Flush (GPF) as described in section 9.8 of
 *   the CXL SPEC 3.1. In this case, dax_flush is also sufficient
 *   to ensure data persistence.
 */
void cbdt_flush(struct cbd_transport *cbdt, void *pos, u32 size)
{
	dax_flush(cbdt->dax_dev, pos, size);
}

void cbdt_zero_range(struct cbd_transport *cbdt, void *pos, u32 size)
{
	memset(pos, 0, size);
	cbdt_flush(cbdt, pos, size);
}

static bool hosts_stopped(struct cbd_transport *cbdt)
{
	struct cbd_host_info *host_info;
	u32 i;

	cbd_for_each_host_info(cbdt, i, host_info) {
		if (cbd_host_info_is_alive(host_info)) {
			cbdt_err(cbdt, "host %u is still alive\n", i);
			return false;
		}
	}

	return true;
}

/*
 * format_validate - Validate the transport device format for CBD transport
 * @cbdt: Pointer to the CBD transport structure containing transport info
 * @force: Boolean flag to force format validation
 *
 * This function checks the following conditions:
 * 1. If the magic number indicates that the transport format already exists,
 *    return -EEXIST if it does and force is not set.
 * 2. If the transport is currently in use (if the magic number matches and
 *    hosts are not stopped), return -EBUSY if it is.
 * 3. Validate the size of the device, ensuring it meets the minimum size
 *    requirement. If the size is below the minimum, log an error and
 *    return -ENOSPC.
 *
 * Return: 0 on success, negative error codes on failure indicating specific
 *         validation issues.
 */
static int format_validate(struct cbd_transport *cbdt, bool force)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	u64 transport_dev_size;
	u64 magic;

	magic = le64_to_cpu(info->magic);
	if (magic && !force)
		return -EEXIST;

	if (magic == CBD_TRANSPORT_MAGIC && !hosts_stopped(cbdt))
		return -EBUSY;

	transport_dev_size = bdev_nr_bytes(file_bdev(cbdt->bdev_file));
	if (transport_dev_size < CBD_TRASNPORT_SIZE_MIN) {
		cbdt_err(cbdt, "dax device is too small, required at least %u",
				CBD_TRASNPORT_SIZE_MIN);
		return -ENOSPC;
	}

	return 0;
}

/*
 * format_transport_info - Initialize the transport info structure for CBD transport
 * @cbdt: Pointer to the CBD transport structure
 *
 * This function initializes the cbd_transport_info structure with relevant
 * metadata for the transport. It sets the magic number and version, and
 * determines the flags.
 *
 * The magic, version, and flags fields are stored in little-endian format to
 * ensure compatibility across different platforms. This allows for correct
 * identification of transport information and helps determine if it is suitable
 * for registration on the local machine.
 *
 * The function calculates the size and offsets for various sections within
 * the transport device based on the available device size, assuming a
 * 1:1 mapping of hosts, block devices, backends, and segments.
 */
static void format_transport_info(struct cbd_transport *cbdt)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	u64 transport_dev_size;
	u32 seg_size;
	u32 nr_segs;
	u16 flags = 0;

	cbdt_zero_range(cbdt, info, sizeof(struct cbd_transport_info));

	info->magic = cpu_to_le64(CBD_TRANSPORT_MAGIC);
	info->version = cpu_to_le16(CBD_TRANSPORT_VERSION);

#if defined(__BYTE_ORDER) ? (__BIG_ENDIAN == __BYTE_ORDER) : defined(__BIG_ENDIAN)
	flags |= CBDT_INFO_F_BIGENDIAN;
#endif

#ifdef CONFIG_CBD_CHANNEL_CRC
	flags |= CBDT_INFO_F_CHANNEL_CRC;
#endif

#ifdef CONFIG_CBD_CHANNEL_DATA_CRC
	flags |= CBDT_INFO_F_CHANNEL_DATA_CRC;
#endif

#ifdef CONFIG_CBD_CACHE_DATA_CRC
	flags |= CBDT_INFO_F_CACHE_DATA_CRC;
#endif

#ifdef CONFIG_CBD_MULTIHOST
	flags |= CBDT_INFO_F_MULTIHOST;
#endif

	info->flags = cpu_to_le16(flags);
	/*
	 * Try to fully utilize all available space,
	 * assuming host:blkdev:backend:segment = 1:1:1:1
	 */
	seg_size = (CBDT_HOST_INFO_STRIDE + CBDT_BACKEND_INFO_STRIDE +
			CBDT_BLKDEV_INFO_STRIDE + CBDT_SEG_SIZE);
	transport_dev_size = bdev_nr_bytes(file_bdev(cbdt->bdev_file));
	nr_segs = (transport_dev_size - CBDT_INFO_STRIDE) / seg_size;

	info->host_area_off = CBDT_INFO_OFF + CBDT_INFO_STRIDE;
	info->host_info_size = CBDT_HOST_INFO_SIZE;
	info->host_num = min(nr_segs, CBDT_HOSTS_MAX);

	info->backend_area_off = info->host_area_off + (CBDT_HOST_INFO_STRIDE * info->host_num);
	info->backend_info_size = CBDT_BACKEND_INFO_SIZE;
	info->backend_num = nr_segs;

	info->blkdev_area_off = info->backend_area_off + (CBDT_BACKEND_INFO_STRIDE * info->backend_num);
	info->blkdev_info_size = CBDT_BLKDEV_INFO_SIZE;
	info->blkdev_num = nr_segs;

	info->segment_area_off = info->blkdev_area_off + (CBDT_BLKDEV_INFO_STRIDE * info->blkdev_num);
	info->segment_size = CBDT_SEG_SIZE;
	info->segment_num = nr_segs;
}

static void segments_format(struct cbd_transport *cbdt)
{
	u32 i;

	for (i = 0; i < cbdt->transport_info->segment_num; i++)
		cbdt_segment_info_clear(cbdt, i);
}

/*
 * cbd_transport_format - Format the CBD transport structure
 * @cbdt: Pointer to the CBD transport structure
 * @force: Flag to force formatting even if the transport is already initialized
 *
 * This function formats the CBD transport by validating the current state,
 * initializing the transport information structure, and preparing the transport
 * for use. It ensures that all necessary space is allocated and initialized
 * before the transport can be registered or used.
 *
 * Steps:
 * 1. Validate the format by calling `format_validate()`, which checks if the
 *    transport is already initialized and if the size is sufficient. If the
 *    validation fails, an error code is returned.
 * 2. Initialize the transport info structure using `format_transport_info()`,
 *    which sets up the magic number, version, flags, and calculates offsets
 *    and sizes for various sections of the transport.
 * 3. Zero out all area of objects infos in transport info to ensure no stale data remains.
 * 4. Call `segments_format()` to format the segment structures, which
 *    initializes the segments based on the previously computed parameters.
 *
 * The function returns 0 on success or a negative error code if an error
 * occurred during validation or formatting.
 */
static int cbd_transport_format(struct cbd_transport *cbdt, bool force)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	int ret;

	ret = format_validate(cbdt, force);
	if (ret)
		return ret;

	format_transport_info(cbdt);

	cbdt_zero_range(cbdt, (void *)info + info->host_area_off,
			     info->segment_area_off - info->host_area_off);

	segments_format(cbdt);

	return 0;
}

/*
 * This function handles administrative operations for the CBD transport device.
 * It processes various commands related to backend management, device control,
 * and host operations. All transport metadata allocation or reclamation
 * should occur within this function to ensure proper control flow and exclusivity.
 *
 * The function performs the following tasks:
 * 1. Checks for administrative permissions.
 * 2. Duplicates the input buffer containing administrative options.
 * 3. Parses the administrative options from the buffer.
 * 4. Acquires a mutex lock to ensure mutual exclusion while performing
 *    operations related to the CBD transport.
 * 5. Switches based on the specified operation, executing corresponding
 *    backend or device management functions.
 * 6. Releases the mutex lock after completing the operation.
 *
 * Note: For single-host scenarios, the `adm_lock` mutex is sufficient
 * to manage mutual exclusion. However, in multi-host scenarios,
 * a distributed locking mechanism is necessary to guarantee
 * exclusivity across all `adm_store` calls.
 *
 * TODO: Investigate potential locking mechanisms for the CXL shared memory device.
 */
static ssize_t adm_store(struct device *dev,
			struct device_attribute *attr,
			const char *ubuf,
			size_t size)
{
	int ret;
	char *buf;
	struct cbd_adm_options opts = { 0 };
	struct cbd_transport *cbdt;

	opts.backend_id = U32_MAX;
	opts.backend.handlers = 1;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	cbdt = container_of(dev, struct cbd_transport, device);

	buf = kmemdup(ubuf, size + 1, GFP_KERNEL);
	if (IS_ERR(buf)) {
		cbdt_err(cbdt, "failed to dup buf for adm option: %d", (int)PTR_ERR(buf));
		return PTR_ERR(buf);
	}
	buf[size] = '\0';
	ret = parse_adm_options(cbdt, buf, &opts);
	if (ret < 0) {
		kfree(buf);
		return ret;
	}
	kfree(buf);

	mutex_lock(&cbdt->adm_lock);
	switch (opts.op) {
	case CBDT_ADM_OP_B_START:
		u32 cache_segs = 0;

		if (opts.backend.cache_size_M > 0)
			cache_segs = DIV_ROUND_UP(opts.backend.cache_size_M,
					cbdt->transport_info->segment_size / CBD_MB);

		ret = cbd_backend_start(cbdt, opts.backend.path, opts.backend_id, opts.backend.handlers, cache_segs);
		break;
	case CBDT_ADM_OP_B_STOP:
		ret = cbd_backend_stop(cbdt, opts.backend_id);
		break;
	case CBDT_ADM_OP_B_CLEAR:
		ret = cbd_backend_clear(cbdt, opts.backend_id);
		break;
	case CBDT_ADM_OP_DEV_START:
		if (opts.blkdev.queues > CBD_QUEUES_MAX) {
			mutex_unlock(&cbdt->adm_lock);
			cbdt_err(cbdt, "invalid queues = %u, larger than max %u\n",
					opts.blkdev.queues, CBD_QUEUES_MAX);
			return -EINVAL;
		}
		ret = cbd_blkdev_start(cbdt, opts.backend_id, opts.blkdev.queues);
		break;
	case CBDT_ADM_OP_DEV_STOP:
		ret = cbd_blkdev_stop(cbdt, opts.blkdev.devid);
		break;
	case CBDT_ADM_OP_DEV_CLEAR:
		ret = cbd_blkdev_clear(cbdt, opts.blkdev.devid);
		break;
	case CBDT_ADM_OP_H_CLEAR:
		ret = cbd_host_clear(cbdt, opts.host.hid);
		break;
	default:
		mutex_unlock(&cbdt->adm_lock);
		cbdt_err(cbdt, "invalid op: %d\n", opts.op);
		return -EINVAL;
	}
	mutex_unlock(&cbdt->adm_lock);

	if (ret < 0)
		return ret;

	return size;
}

static DEVICE_ATTR_WO(adm);

static ssize_t cbd_transport_info(struct cbd_transport *cbdt, char *buf)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	ssize_t ret;

	mutex_lock(&cbdt->lock);
	info = cbdt->transport_info;
	mutex_unlock(&cbdt->lock);

	ret = sprintf(buf, "magic: 0x%llx\n"
			"version: %u\n"
			"flags: %x\n\n"
			"host_area_off: %llu\n"
			"bytes_per_host_info: %u\n"
			"host_num: %u\n\n"
			"backend_area_off: %llu\n"
			"bytes_per_backend_info: %u\n"
			"backend_num: %u\n\n"
			"blkdev_area_off: %llu\n"
			"bytes_per_blkdev_info: %u\n"
			"blkdev_num: %u\n\n"
			"segment_area_off: %llu\n"
			"bytes_per_segment: %u\n"
			"segment_num: %u\n",
			le64_to_cpu(info->magic),
			le16_to_cpu(info->version),
			le16_to_cpu(info->flags),
			info->host_area_off,
			info->host_info_size,
			info->host_num,
			info->backend_area_off,
			info->backend_info_size,
			info->backend_num,
			info->blkdev_area_off,
			info->blkdev_info_size,
			info->blkdev_num,
			info->segment_area_off,
			info->segment_size,
			info->segment_num);

	return ret;
}

static ssize_t cbd_info_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_transport *cbdt;

	cbdt = container_of(dev, struct cbd_transport, device);

	return cbd_transport_info(cbdt, buf);
}
static DEVICE_ATTR(info, 0400, cbd_info_show, NULL);

static struct attribute *cbd_transport_attrs[] = {
	&dev_attr_adm.attr,
	&dev_attr_info.attr,
	&dev_attr_host_id.attr,
	NULL
};

static struct attribute_group cbd_transport_attr_group = {
	.attrs = cbd_transport_attrs,
};

static const struct attribute_group *cbd_transport_attr_groups[] = {
	&cbd_transport_attr_group,
	NULL
};

static void cbd_transport_release(struct device *dev)
{
}

const struct device_type cbd_transport_type = {
	.name		= "cbd_transport",
	.groups		= cbd_transport_attr_groups,
	.release	= cbd_transport_release,
};

static int cbd_dax_notify_failure(struct dax_device *dax_dev, u64 offset,
				  u64 len, int mf_flags)
{

	pr_err("%s: dax_dev %llx offset %llx len %lld mf_flags %x\n",
	       __func__, (u64)dax_dev, (u64)offset, (u64)len, mf_flags);
	return -EOPNOTSUPP;
}

const struct dax_holder_operations cbd_dax_holder_ops = {
	.notify_failure		= cbd_dax_notify_failure,
};

/*
 * transport_info_validate - Validate the transport information structure
 * @cbdt: Pointer to the CBD transport structure
 *
 * This function validates the transport information contained within the
 * cbd_transport structure. It checks for the correctness of the magic number,
 * endianness, and various feature flags specified in the transport info.
 *
 * Steps:
 * 1. Check the magic number to ensure it matches the expected value,
 *    CBD_TRANSPORT_MAGIC. If it does not match, an error is logged, and
 *    -EINVAL is returned.
 * 2. Retrieve and convert the flags field from the transport info to
 *    host-endian format.
 * 3. Verify the endianness of the transport matches the system's endianness:
 *    - If the system is big-endian, the transport should indicate it is
 *      big-endian (CBDT_INFO_F_BIGENDIAN).
 *    - If the system is little-endian, the transport should not indicate
 *      big-endian. If there is a mismatch, an error is logged, and
 *      -EINVAL is returned.
 * 4. Check if the necessary CRC features are enabled in the kernel
 *    configuration based on the flags:
 *    - If CBDT_INFO_F_CHANNEL_CRC is set and CONFIG_CBD_CHANNEL_CRC is not
 *      defined, an error is logged, and -EOPNOTSUPP is returned.
 *    - If CBDT_INFO_F_CHANNEL_DATA_CRC is set and CONFIG_CBD_CHANNEL_DATA_CRC
 *      is not defined, an error is logged, and -EOPNOTSUPP is returned.
 *    - If CBDT_INFO_F_CACHE_DATA_CRC is set and CONFIG_CBD_CACHE_DATA_CRC is
 *      not defined, an error is logged, and -EOPNOTSUPP is returned.
 * 5. If CBDT_INFO_F_MULTIHOST is set and CONFIG_CBD_MULTIHOST is not
 *      defined, an error is logged, and -EOPNOTSUPP is returned.
 *
 * The function returns 0 on success or a negative error code if any
 * validation fails.
 */
static int transport_info_validate(struct cbd_transport *cbdt)
{
	u16 flags;

	if (le64_to_cpu(cbdt->transport_info->magic) != CBD_TRANSPORT_MAGIC) {
		cbdt_err(cbdt, "unexpected magic: %llx\n",
				le64_to_cpu(cbdt->transport_info->magic));
		return -EINVAL;
	}

	flags = le16_to_cpu(cbdt->transport_info->flags);
	flags = le16_to_cpu(cbdt->transport_info->flags);

#if defined(__BYTE_ORDER) ? (__BIG_ENDIAN == __BYTE_ORDER) : defined(__BIG_ENDIAN)
	/* Ensure transport matches the system's endianness */
	if (!(flags & CBDT_INFO_F_BIGENDIAN)) {
		cbdt_err(cbdt, "transport is not big endian\n");
		return -EINVAL;
	}
#else
	if (flags & CBDT_INFO_F_BIGENDIAN) {
		cbdt_err(cbdt, "transport is big endian\n");
		return -EINVAL;
	}
#endif

#ifndef CONFIG_CBD_CHANNEL_CRC
	if (flags & CBDT_INFO_F_CHANNEL_CRC) {
		cbdt_err(cbdt, "transport expects CBD_CHANNEL_CRC enabled.\n");
		return -EOPNOTSUPP;
	}
#endif

#ifndef CONFIG_CBD_CHANNEL_DATA_CRC
	if (flags & CBDT_INFO_F_CHANNEL_DATA_CRC) {
		cbdt_err(cbdt, "transport expects CBD_CHANNEL_DATA_CRC enabled.\n");
		return -EOPNOTSUPP;
	}
#endif

#ifndef CONFIG_CBD_CACHE_DATA_CRC
	if (flags & CBDT_INFO_F_CACHE_DATA_CRC) {
		cbdt_err(cbdt, "transport expects CBD_CACHE_DATA_CRC enabled.\n");
		return -EOPNOTSUPP;
	}
#endif

#ifndef CONFIG_CBD_MULTIHOST
	if (flags & CBDT_INFO_F_MULTIHOST) {
		cbdt_err(cbdt, "transport expects CBD_MULTIHOST enabled.\n");
		return -EOPNOTSUPP;
	}
#endif
	return 0;
}

static struct cbd_transport *transport_alloc(void)
{
	struct cbd_transport *cbdt;
	int ret;

	cbdt = kzalloc(sizeof(struct cbd_transport), GFP_KERNEL);
	if (!cbdt)
		return NULL;

	mutex_init(&cbdt->lock);
	mutex_init(&cbdt->adm_lock);
	INIT_LIST_HEAD(&cbdt->backends);
	INIT_LIST_HEAD(&cbdt->devices);

	ret = ida_simple_get(&cbd_transport_id_ida, 0, CBD_TRANSPORT_MAX,
				GFP_KERNEL);
	if (ret < 0)
		goto transport_free;

	cbdt->id = ret;
	cbd_transports[cbdt->id] = cbdt;

	return cbdt;

transport_free:
	kfree(cbdt);
	return NULL;
}

static void transport_free(struct cbd_transport *cbdt)
{
	cbd_transports[cbdt->id] = NULL;
	ida_simple_remove(&cbd_transport_id_ida, cbdt->id);
	kfree(cbdt);
}

/*
 * transport_dax_init - Initialize the DAX transport
 * @cbdt: Pointer to the CBD transport structure
 * @path: Path to the block device file
 *
 * This function initializes the DAX (Direct Access) transport for the
 * specified block device. It opens the block device, obtains a DAX device
 * associated with it, and sets up the transport structure with the necessary
 * information for direct access.
 *
 * Steps:
 * 1. Open the block device specified by the given path with read and write
 *    access. If the operation fails, log the error and clean up.
 * 2. Get the DAX device associated with the opened block device. If this
 *    operation fails, log the error and clean up the opened file.
 * 3. Acquire a read lock on the DAX device to ensure safe access to its
 *    memory. It uses dax_direct_access to obtain the kaddr at offset 0,
 *    which corresponds to the address of cbdt->transport_info for subsequent
 *    transport information initialization.
 * 4. If the direct access is successful, store the opened block device file
 *    pointer, the DAX device pointer, and the address of the transport info
 *    structure in the CBD transport structure.
 * 5. Release the read lock after successful setup.
 *
 * Returns:
 * - 0 on success.
 * - Negative error code on failure.
 */
static int transport_dax_init(struct cbd_transport *cbdt, char *path)
{
	struct dax_device *dax_dev = NULL;
	struct file *bdev_file = NULL;
	long access_size;
	void *kaddr;
	u64 start_off = 0;
	int ret;
	int id;

	bdev_file = bdev_file_open_by_path(path, BLK_OPEN_READ | BLK_OPEN_WRITE, cbdt, NULL);
	if (IS_ERR(bdev_file)) {
		cbdt_err(cbdt, "%s: failed blkdev_get_by_path(%s)\n", __func__, path);
		ret = PTR_ERR(bdev_file);
		goto err;
	}

	dax_dev = fs_dax_get_by_bdev(file_bdev(bdev_file), &start_off,
				     cbdt,
				     &cbd_dax_holder_ops);
	if (IS_ERR(dax_dev)) {
		cbdt_err(cbdt, "%s: unable to get daxdev from bdev_file\n", __func__);
		ret = -ENODEV;
		goto fput;
	}

	id = dax_read_lock();
	access_size = dax_direct_access(dax_dev, 0, 1, DAX_ACCESS, &kaddr, NULL);
	if (access_size != 1) {
		dax_read_unlock(id);
		ret = -EINVAL;
		goto dax_put;
	}

	cbdt->bdev_file = bdev_file;
	cbdt->dax_dev = dax_dev;
	cbdt->transport_info = (struct cbd_transport_info *)kaddr;
	dax_read_unlock(id);

	return 0;

dax_put:
	fs_put_dax(dax_dev, cbdt);
fput:
	fput(bdev_file);
err:
	return ret;
}

static void transport_dax_exit(struct cbd_transport *cbdt)
{
	if (cbdt->dax_dev)
		fs_put_dax(cbdt->dax_dev, cbdt);

	if (cbdt->bdev_file)
		fput(cbdt->bdev_file);
}

static int transport_init(struct cbd_transport *cbdt,
			  struct cbdt_register_options *opts)
{
	struct device *dev;
	int ret;

	ret = transport_info_validate(cbdt);
	if (ret)
		goto err;

	dev = &cbdt->device;
	device_initialize(dev);
	device_set_pm_not_required(dev);
	dev->bus = &cbd_bus_type;
	dev->type = &cbd_transport_type;
	dev->parent = &cbd_root_dev;
	dev_set_name(&cbdt->device, "transport%d", cbdt->id);
	ret = device_add(&cbdt->device);
	if (ret)
		goto err;

	ret = cbd_host_register(cbdt, opts->hostname, opts->host_id);
	if (ret)
		goto dev_unregister;

	if (cbd_hosts_init(cbdt) || cbd_backends_init(cbdt) ||
	    cbd_segments_init(cbdt) || cbd_blkdevs_init(cbdt)) {
		ret = -ENOMEM;
		goto devs_exit;
	}

	return 0;

devs_exit:
	cbd_blkdevs_exit(cbdt);
	cbd_segments_exit(cbdt);
	cbd_backends_exit(cbdt);
	cbd_hosts_exit(cbdt);

	cbd_host_unregister(cbdt);
dev_unregister:
	device_unregister(&cbdt->device);
err:
	return ret;
}

static void transport_exit(struct cbd_transport *cbdt)
{
	cbd_blkdevs_exit(cbdt);
	cbd_segments_exit(cbdt);
	cbd_backends_exit(cbdt);
	cbd_hosts_exit(cbdt);

	cbd_host_unregister(cbdt);
	device_unregister(&cbdt->device);
}

int cbdt_unregister(u32 tid)
{
	struct cbd_transport *cbdt;

	cbdt = cbd_transports[tid];
	if (!cbdt) {
		pr_err("tid: %u, is not registered\n", tid);
		return -EINVAL;
	}

	mutex_lock(&cbdt->lock);
	if (!list_empty(&cbdt->backends) || !list_empty(&cbdt->devices)) {
		mutex_unlock(&cbdt->lock);
		return -EBUSY;
	}
	mutex_unlock(&cbdt->lock);

	transport_exit(cbdt);
	transport_dax_exit(cbdt);
	transport_free(cbdt);
	module_put(THIS_MODULE);

	return 0;
}

/*
 * cbdt_register - Register a new CBD transport instance
 * @opts: Pointer to the registration options
 *
 * This function registers a new CBD transport instance based on the
 * provided options. It ensures that the specified path corresponds to a
 * persistent memory device, initializes the transport for direct access,
 * and formats it if required.
 *
 * Returns:
 * - 0 on success.
 * - Negative error code on failure.
 */
int cbdt_register(struct cbdt_register_options *opts)
{
	struct cbd_transport *cbdt;
	int ret;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	if (!strstr(opts->path, "/dev/pmem")) {
		pr_err("%s: path (%s) is not pmem\n",
		       __func__, opts->path);
		ret = -EINVAL;
		goto module_put;
	}

	cbdt = transport_alloc();
	if (!cbdt) {
		ret = -ENOMEM;
		goto module_put;
	}

	ret = transport_dax_init(cbdt, opts->path);
	if (ret)
		goto transport_free;

	if (opts->format) {
		ret = cbd_transport_format(cbdt, opts->force);
		if (ret < 0)
			goto dax_release;
	}

	ret = transport_init(cbdt, opts);
	if (ret)
		goto dax_release;

	return 0;
dax_release:
	transport_dax_exit(cbdt);
transport_free:
	transport_free(cbdt);
module_put:
	module_put(THIS_MODULE);

	return ret;
}

void cbdt_add_backend(struct cbd_transport *cbdt, struct cbd_backend *cbdb)
{
	mutex_lock(&cbdt->lock);
	list_add(&cbdb->node, &cbdt->backends);
	mutex_unlock(&cbdt->lock);
}

void cbdt_del_backend(struct cbd_transport *cbdt, struct cbd_backend *cbdb)
{
	if (list_empty(&cbdb->node))
		return;

	mutex_lock(&cbdt->lock);
	list_del_init(&cbdb->node);
	mutex_unlock(&cbdt->lock);
}

struct cbd_backend *cbdt_get_backend(struct cbd_transport *cbdt, u32 id)
{
	struct cbd_backend *backend;

	mutex_lock(&cbdt->lock);
	list_for_each_entry(backend, &cbdt->backends, node) {
		if (backend->backend_id == id)
			goto out;
	}
	backend = NULL;
out:
	mutex_unlock(&cbdt->lock);
	return backend;
}

void cbdt_add_blkdev(struct cbd_transport *cbdt, struct cbd_blkdev *blkdev)
{
	mutex_lock(&cbdt->lock);
	list_add(&blkdev->node, &cbdt->devices);
	mutex_unlock(&cbdt->lock);
}

void cbdt_del_blkdev(struct cbd_transport *cbdt, struct cbd_blkdev *blkdev)
{
	if (list_empty(&blkdev->node))
		return;

	mutex_lock(&cbdt->lock);
	list_del_init(&blkdev->node);
	mutex_unlock(&cbdt->lock);
}

struct cbd_blkdev *cbdt_get_blkdev(struct cbd_transport *cbdt, u32 id)
{
	struct cbd_blkdev *dev;

	mutex_lock(&cbdt->lock);
	list_for_each_entry(dev, &cbdt->devices, node) {
		if (dev->blkdev_id == id)
			goto out;
	}
	dev = NULL;
out:
	mutex_unlock(&cbdt->lock);
	return dev;
}

struct page *cbdt_page(struct cbd_transport *cbdt, u64 transport_off, u32 *page_off)
{
	long access_size;
	pfn_t pfn;

	access_size = dax_direct_access(cbdt->dax_dev, transport_off >> PAGE_SHIFT,
					1, DAX_ACCESS, NULL, &pfn);
	if (access_size < 0)
		return NULL;

	if (page_off)
		*page_off = transport_off & PAGE_MASK;

	return pfn_t_to_page(pfn);
}
