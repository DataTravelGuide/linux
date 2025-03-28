// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(C) 2025, Dongsheng Yang <dongsheng.yang@linux.dev>
 */

#include <linux/capability.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/parser.h>

#include "pcache_internal.h"
#include "cache_dev.h"
#include "logic_dev.h"

enum {
	PCACHE_REG_OPT_ERR		= 0,
	PCACHE_REG_OPT_FORCE,
	PCACHE_REG_OPT_FORMAT,
	PCACHE_REG_OPT_PATH,
};

static const match_table_t register_opt_tokens = {
	{ PCACHE_REG_OPT_FORCE,		"force=%u" },
	{ PCACHE_REG_OPT_FORMAT,	"format=%u" },
	{ PCACHE_REG_OPT_PATH,		"path=%s" },
	{ PCACHE_REG_OPT_ERR,		NULL	}
};

static int parse_register_options(char *buf,
		struct pcache_cache_dev_register_options *opts)
{
	substring_t args[MAX_OPT_ARGS];
	char *o, *p;
	int token, ret = 0;

	o = buf;

	while ((p = strsep(&o, ",\n")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, register_opt_tokens, args);
		switch (token) {
		case PCACHE_REG_OPT_PATH:
			if (match_strlcpy(opts->path, &args[0],
				PCACHE_PATH_LEN) == 0) {
				ret = -EINVAL;
				break;
			}
			break;
		case PCACHE_REG_OPT_FORCE:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}
			opts->force = (token != 0);
			break;
		case PCACHE_REG_OPT_FORMAT:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}
			opts->format = (token != 0);
			break;
		default:
			pr_err("unknown parameter or missing value '%s'\n", p);
			ret = -EINVAL;
			goto out;
		}
	}

out:
	return ret;
}

static ssize_t cache_dev_unregister_store(const struct bus_type *bus, const char *ubuf,
				      size_t size)
{
	u32 cache_dev_id;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (sscanf(ubuf, "cache_dev_id=%u", &cache_dev_id) != 1)
		return -EINVAL;

	ret = cache_dev_unregister(cache_dev_id);
	if (ret < 0)
		return ret;

	return size;
}

static ssize_t cache_dev_register_store(const struct bus_type *bus, const char *ubuf,
				      size_t size)
{
	struct pcache_cache_dev_register_options opts = { 0 };
	char *buf;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	buf = kmemdup(ubuf, size + 1, GFP_KERNEL);
	if (IS_ERR(buf)) {
		pr_err("failed to dup buf for adm option: %d", (int)PTR_ERR(buf));
		return PTR_ERR(buf);
	}
	buf[size] = '\0';

	ret = parse_register_options(buf, &opts);
	if (ret < 0) {
		kfree(buf);
		return ret;
	}
	kfree(buf);

	ret = cache_dev_register(&opts);
	if (ret < 0)
		return ret;

	return size;
}

static BUS_ATTR_WO(cache_dev_unregister);
static BUS_ATTR_WO(cache_dev_register);

static struct attribute *pcache_bus_attrs[] = {
	&bus_attr_cache_dev_unregister.attr,
	&bus_attr_cache_dev_register.attr,
	NULL,
};

static const struct attribute_group pcache_bus_group = {
	.attrs = pcache_bus_attrs,
};
__ATTRIBUTE_GROUPS(pcache_bus);

const struct bus_type pcache_bus_type = {
	.name		= "pcache",
	.bus_groups	= pcache_bus_groups,
};

static void pcache_root_dev_release(struct device *dev)
{
}

struct device pcache_root_dev = {
	.init_name =    "pcache",
	.release =      pcache_root_dev_release,
};

static int __init pcache_init(void)
{
	int ret;

	ret = device_register(&pcache_root_dev);
	if (ret < 0) {
		put_device(&pcache_root_dev);
		goto err;
	}

	ret = bus_register(&pcache_bus_type);
	if (ret < 0)
		goto device_unregister;

	ret = pcache_blkdev_init();
	if (ret < 0)
		goto bus_unregister;

	return 0;

bus_unregister:
	bus_unregister(&pcache_bus_type);
device_unregister:
	device_unregister(&pcache_root_dev);
err:

	return ret;
}

static void pcache_exit(void)
{
	pcache_blkdev_exit();
	bus_unregister(&pcache_bus_type);
	device_unregister(&pcache_root_dev);
}

MODULE_AUTHOR("Dongsheng Yang <dongsheng.yang@linux.dev>");
MODULE_DESCRIPTION("PMem for Cache of block device");
MODULE_LICENSE("GPL v2");
module_init(pcache_init);
module_exit(pcache_exit);
