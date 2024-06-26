#include <linux/pfn_t.h>
#include "cbd_internal.h"

#define CBDT_OBJ(OBJ, OBJ_SIZE)							\
extern struct device_type cbd_##OBJ##_type;					\
extern struct device_type cbd_##OBJ##s_type;					\
										\
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
		cbd_dev->OBJ##_info = cbdt_get_##OBJ##_info(cbdt, i);		\
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
	start += info->OBJ##_area_off;						\
										\
	return start + (info->OBJ_SIZE * id);					\
}										\
										\
struct cbd_##OBJ##_info							\
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
	struct cbd_##OBJ##_info *_info;						\
	int ret = 0;								\
	int i;									\
										\
	mutex_lock(&cbdt->lock);						\
	for (i = 0; i < info->OBJ##_num; i++) {					\
		_info = __get_##OBJ##_info(cbdt, i);				\
		if (_info->state == cbd_##OBJ##_state_none) {			\
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
}

CBDT_OBJ(host, host_info_size);
CBDT_OBJ(backend, backend_info_size);
CBDT_OBJ(blkdev, blkdev_info_size);
CBDT_OBJ(channel, channel_size);

static struct cbd_transport *cbd_transports[CBD_TRANSPORT_MAX];
static DEFINE_IDA(cbd_transport_id_ida);
static DEFINE_MUTEX(cbd_transport_mutex);

extern struct bus_type cbd_bus_type;
extern struct device cbd_root_dev;

static ssize_t cbd_myhost_show(struct device *dev,
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

static DEVICE_ATTR(my_host_id, 0400, cbd_myhost_show, NULL);

enum {
	CBDT_ADM_OPT_ERR		= 0,
	CBDT_ADM_OPT_OP,
	CBDT_ADM_OPT_FORCE,
	CBDT_ADM_OPT_PATH,
	CBDT_ADM_OPT_BID,
	CBDT_ADM_OPT_DID,
	CBDT_ADM_OPT_QUEUES,
	CBDT_ADM_OPT_HID,
	CBDT_ADM_OPT_CID,
};

enum {
	CBDT_ADM_OP_B_START,
	CBDT_ADM_OP_B_STOP,
	CBDT_ADM_OP_B_CLEAR,
	CBDT_ADM_OP_DEV_START,
	CBDT_ADM_OP_DEV_STOP,
	CBDT_ADM_OP_DEV_CLEAR,
	CBDT_ADM_OP_H_CLEAR,
	CBDT_ADM_OP_C_CLEAR,
};

static const char *const adm_op_names[] = {
	[CBDT_ADM_OP_B_START] = "backend-start",
	[CBDT_ADM_OP_B_STOP] = "backend-stop",
	[CBDT_ADM_OP_B_CLEAR] = "backend-clear",
	[CBDT_ADM_OP_DEV_START] = "dev-start",
	[CBDT_ADM_OP_DEV_STOP] = "dev-stop",
	[CBDT_ADM_OP_DEV_CLEAR] = "dev-clear",
	[CBDT_ADM_OP_H_CLEAR] = "host-clear",
	[CBDT_ADM_OP_C_CLEAR] = "channel-clear",
};

static const match_table_t adm_opt_tokens = {
	{ CBDT_ADM_OPT_OP,		"op=%s"	},
	{ CBDT_ADM_OPT_FORCE,		"force=%u" },
	{ CBDT_ADM_OPT_PATH,		"path=%s" },
	{ CBDT_ADM_OPT_BID,		"backend_id=%u" },
	{ CBDT_ADM_OPT_DID,		"dev_id=%u" },
	{ CBDT_ADM_OPT_QUEUES,		"queues=%u" },
	{ CBDT_ADM_OPT_HID,		"host_id=%u" },
	{ CBDT_ADM_OPT_CID,		"channel_id=%u" },
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
		} backend;
		struct channel_options {
			u32 cid;
		} channel;
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
			opts->backend_id = token;
			break;
		case CBDT_ADM_OPT_DID:
			if (match_uint(args, &token)) {
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
			opts->blkdev.queues = token;
			break;
		case CBDT_ADM_OPT_HID:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}
			opts->host.hid = token;
			break;
		case CBDT_ADM_OPT_CID:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}
			opts->channel.cid = token;
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

static void transport_zero_range(struct cbd_transport *cbdt, void *pos, u64 size)
{
	memset(pos, 0, size);
}

static void channels_format(struct cbd_transport *cbdt)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	struct cbd_channel_info *channel_info;
	int i;

	for (i = 0; i < info->channel_num; i++) {
		channel_info = __get_channel_info(cbdt, i);
		transport_zero_range(cbdt, channel_info, CBDC_META_SIZE);
	}
}

static int cbd_transport_format(struct cbd_transport *cbdt, bool force)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	u64 magic;

	magic = le64_to_cpu(info->magic);
	if (magic && !force)
		return -EEXIST;

	/* TODO make these configureable */
	info->magic = cpu_to_le64(CBD_TRANSPORT_MAGIC);
	info->version = cpu_to_le16(CBD_TRANSPORT_VERSION);
#if defined(__BYTE_ORDER) ? __BYTE_ORDER == __BIG_ENDIAN : defined(__BIG_ENDIAN)
	info->flags = cpu_to_le16(CBDT_INFO_F_BIGENDIAN);
#endif
	info->host_area_off = CBDT_HOST_AREA_OFF;
	info->host_info_size = CBDT_HOST_INFO_SIZE;
	info->host_num = CBDT_HOST_NUM;

	info->backend_area_off = CBDT_BACKEND_AREA_OFF;
	info->backend_info_size = CBDT_BACKEND_INFO_SIZE;
	info->backend_num = CBDT_BACKEND_NUM;

	info->blkdev_area_off = CBDT_BLKDEV_AREA_OFF;
	info->blkdev_info_size = CBDT_BLKDEV_INFO_SIZE;
	info->blkdev_num = CBDT_BLKDEV_NUM;

	info->channel_area_off = CBDT_CHANNEL_AREA_OFF;
	info->channel_size = CBDT_CHANNEL_SIZE;
	info->channel_num = CBDT_CHANNEL_NUM;

	transport_zero_range(cbdt, (void *)info + info->host_area_off,
			     info->channel_area_off - info->host_area_off);

	channels_format(cbdt);

	return 0;
}



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

	switch (opts.op) {
	case CBDT_ADM_OP_B_START:
		ret = cbd_backend_start(cbdt, opts.backend.path, opts.backend_id);
		if (ret < 0)
			return ret;
		break;
	case CBDT_ADM_OP_B_STOP:
		ret = cbd_backend_stop(cbdt, opts.backend_id, opts.force);
		if (ret < 0)
			return ret;
		break;
	case CBDT_ADM_OP_B_CLEAR:
		ret = cbd_backend_clear(cbdt, opts.backend_id);
		if (ret < 0)
			return ret;
		break;
	case CBDT_ADM_OP_DEV_START:
		if (opts.blkdev.queues > CBD_QUEUES_MAX) {
			cbdt_err(cbdt, "invalid queues = %u, larger than max %u\n",
					opts.blkdev.queues, CBD_QUEUES_MAX);
			return -EINVAL;
		}
		ret = cbd_blkdev_start(cbdt, opts.backend_id, opts.blkdev.queues);
		if (ret < 0)
			return ret;
		break;
	case CBDT_ADM_OP_DEV_STOP:
		ret = cbd_blkdev_stop(cbdt, opts.blkdev.devid, opts.force);
		if (ret < 0)
			return ret;
		break;
	case CBDT_ADM_OP_DEV_CLEAR:
		ret = cbd_blkdev_clear(cbdt, opts.blkdev.devid);
		if (ret < 0)
			return ret;
		break;
	case CBDT_ADM_OP_H_CLEAR:
		ret = cbd_host_clear(cbdt, opts.host.hid);
		if (ret < 0)
			return ret;
		break;
	case CBDT_ADM_OP_C_CLEAR:
		ret = cbd_channel_clear(cbdt, opts.channel.cid);
		if (ret < 0)
			return ret;
		break;
	default:
		cbdt_err(cbdt, "invalid op: %d\n", opts.op);
		return -EINVAL;
	}

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
			"channel_area_off: %llu\n"
			"bytes_per_channel: %llu\n"
			"channel_num: %u\n",
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
			info->channel_area_off,
			info->channel_size,
			info->channel_num);

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
	&dev_attr_my_host_id.attr,
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

static int
cbd_dax_notify_failure(
	struct dax_device	*dax_devp,
	u64			offset,
	u64			len,
	int			mf_flags)
{

	pr_err("%s: dax_devp %llx offset %llx len %lld mf_flags %x\n",
	       __func__, (u64)dax_devp, (u64)offset, (u64)len, mf_flags);
	return -EOPNOTSUPP;
}

const struct dax_holder_operations cbd_dax_holder_ops = {
	.notify_failure		= cbd_dax_notify_failure,
};

static struct cbd_transport *cbdt_alloc(void)
{
	struct cbd_transport *cbdt;
	int ret;

	cbdt = kzalloc(sizeof(struct cbd_transport), GFP_KERNEL);
	if (!cbdt)
		return NULL;

	ret = ida_simple_get(&cbd_transport_id_ida, 0, CBD_TRANSPORT_MAX,
				GFP_KERNEL);
	if (ret < 0)
		goto cbdt_free;

	cbdt->id = ret;
	cbd_transports[cbdt->id] = cbdt;

	return cbdt;

cbdt_free:
	kfree(cbdt);
	return NULL;
}

static void cbdt_destroy(struct cbd_transport *cbdt)
{
	cbd_transports[cbdt->id] = NULL;
	ida_simple_remove(&cbd_transport_id_ida, cbdt->id);
	kfree(cbdt);
}

static int cbdt_dax_init(struct cbd_transport *cbdt, char *path)
{
	struct dax_device *dax_dev = NULL;
	struct file *bdev_file = NULL;
	long access_size;
	void *kaddr;
	u64 nr_pages = CBD_TRASNPORT_SIZE >> PAGE_SHIFT;
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
	access_size = dax_direct_access(dax_dev, 0, nr_pages, DAX_ACCESS, &kaddr, NULL);
	if (access_size != nr_pages) {
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

static void cbdt_dax_release(struct cbd_transport *cbdt)
{
	if (cbdt->dax_dev)
		fs_put_dax(cbdt->dax_dev, cbdt);

	if (cbdt->bdev_file)
		fput(cbdt->bdev_file);
}

static int cbd_transport_init(struct cbd_transport *cbdt)
{
	struct device *dev;

	mutex_init(&cbdt->lock);
	INIT_LIST_HEAD(&cbdt->backends);
	INIT_LIST_HEAD(&cbdt->devices);

	dev = &cbdt->device;
	device_initialize(dev);
	device_set_pm_not_required(dev);
	dev->bus = &cbd_bus_type;
	dev->type = &cbd_transport_type;
	dev->parent = &cbd_root_dev;

	dev_set_name(&cbdt->device, "transport%d", cbdt->id);

	return device_add(&cbdt->device);
}


static int cbdt_validate(struct cbd_transport *cbdt)
{
	u16 flags;

	if (le64_to_cpu(cbdt->transport_info->magic) != CBD_TRANSPORT_MAGIC)
		return -EINVAL;

	flags = le16_to_cpu(cbdt->transport_info->flags);
#if defined(__BYTE_ORDER) ? __BYTE_ORDER == __BIG_ENDIAN : defined(__BIG_ENDIAN)
	if (!(flags & CBDT_INFO_F_BIGENDIAN))
		return -EINVAL;
#else
	if ((flags & CBDT_INFO_F_BIGENDIAN))
		return -EINVAL;
#endif

	return 0;
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

	cbd_blkdevs_exit(cbdt);
	cbd_channels_exit(cbdt);
	cbd_backends_exit(cbdt);
	cbd_hosts_exit(cbdt);

	cbd_host_unregister(cbdt);
	device_unregister(&cbdt->device);
	cbdt_dax_release(cbdt);
	cbdt_destroy(cbdt);
	module_put(THIS_MODULE);

	return 0;
}


int cbdt_register(struct cbdt_register_options *opts)
{
	struct cbd_transport *cbdt;
	int ret;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	/* TODO support /dev/dax */
	if (!strstr(opts->path, "/dev/pmem")) {
		pr_err("%s: path (%s) is not pmem\n",
		       __func__, opts->path);
		ret = -EINVAL;
		goto module_put;
	}

	cbdt = cbdt_alloc();
	if (!cbdt) {
		ret = -ENOMEM;
		goto module_put;
	}

	ret = cbdt_dax_init(cbdt, opts->path);
	if (ret)
		goto cbdt_destroy;

	if (opts->format) {
		ret = cbd_transport_format(cbdt, opts->force);
		if (ret < 0)
			goto dax_release;
	}

	ret = cbdt_validate(cbdt);
	if (ret)
		goto dax_release;

	ret = cbd_transport_init(cbdt);
	if (ret)
		goto dax_release;

	ret = cbd_host_register(cbdt, opts->hostname);
	if (ret)
		goto dev_unregister;

	if (cbd_hosts_init(cbdt) || cbd_backends_init(cbdt) ||
	    cbd_channels_init(cbdt) || cbd_blkdevs_init(cbdt)) {
		ret = -ENOMEM;
		goto devs_exit;
	}

	return 0;

devs_exit:
	cbd_blkdevs_exit(cbdt);
	cbd_channels_exit(cbdt);
	cbd_backends_exit(cbdt);
	cbd_hosts_exit(cbdt);

	cbd_host_unregister(cbdt);
dev_unregister:
	device_unregister(&cbdt->device);
dax_release:
	cbdt_dax_release(cbdt);
cbdt_destroy:
	cbdt_destroy(cbdt);
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
