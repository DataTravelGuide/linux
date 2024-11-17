// SPDX-License-Identifier: GPL-2.0-or-later

#include "cbd_host.h"
#include "cbd_blkdev.h"
#include "cbd_backend.h"

static ssize_t hostname_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_host_device *host_dev;
	struct cbd_host_info *host_info;

	host_dev = container_of(dev, struct cbd_host_device, dev);
	host_info = cbdt_host_info_read(host_dev->cbdt, host_dev->id);
	if (!host_info)
		return 0;

	if (host_info->state == CBD_HOST_STATE_NONE)
		return 0;

	return sprintf(buf, "%s\n", host_info->hostname);
}
static DEVICE_ATTR_ADMIN_RO(hostname);

static void host_info_write(struct cbd_host *host);
static void cbd_host_hb(struct cbd_host *host)
{
	host_info_write(host);
}
CBD_OBJ_HEARTBEAT(host);

static struct attribute *cbd_host_attrs[] = {
	&dev_attr_hostname.attr,
	&dev_attr_alive.attr,
	NULL
};

static struct attribute_group cbd_host_attr_group = {
	.attrs = cbd_host_attrs,
};

static const struct attribute_group *cbd_host_attr_groups[] = {
	&cbd_host_attr_group,
	NULL
};

static void cbd_host_release(struct device *dev)
{
}

const struct device_type cbd_host_type = {
	.name		= "cbd_host",
	.groups		= cbd_host_attr_groups,
	.release	= cbd_host_release,
};

const struct device_type cbd_hosts_type = {
	.name		= "cbd_hosts",
	.release	= cbd_host_release,
};

static void host_info_write(struct cbd_host *host)
{
	mutex_lock(&host->info_lock);
	host->host_info.alive_ts = ktime_get_real();
	cbdt_host_info_write(host->cbdt, &host->host_info, sizeof(struct cbd_host_info),
			     host->host_id);
	mutex_unlock(&host->info_lock);
}

static int host_register_validate(struct cbd_transport *cbdt, char *hostname, u32 *host_id)
{
	struct cbd_host_info *host_info;
	u32 host_id_tmp;
	int ret;
	u32 i;

	if (cbdt->host)
		return -EEXIST;

	if (strlen(hostname) == 0) {
		cbdt_err(cbdt, "hostname is empty\n");
		return -EINVAL;
	}

	if (*host_id == UINT_MAX) {
		ret = cbd_host_find_id_by_name(cbdt, hostname, host_id);
		if (!ret)
			goto host_id_found;

		/* In single-host case, set the host_id to 0 */
		if (cbdt_is_single_host(cbdt)) {
			*host_id = 0;
		} else {
			ret = cbdt_get_empty_host_id(cbdt, host_id);
			if (ret) {
				cbdt_err(cbdt, "no available host id found.\n");
				return -EBUSY;
			}
		}
	}

host_id_found:
	if (*host_id >= cbdt->transport_info.host_num) {
		cbdt_err(cbdt, "host_id: %u is too large, host_num: %u\n",
			       *host_id, cbdt->transport_info.host_num);
		return -EINVAL;
	}

	/* check for duplicated hostname */
	ret = cbd_host_find_id_by_name(cbdt, hostname, &host_id_tmp);
	if (!ret && (host_id_tmp != *host_id)) {
		cbdt_err(cbdt, "duplicated hostname: %s with host: %u\n", hostname, i);
		return -EINVAL;
	}

	host_info = cbdt_host_info_read(cbdt, *host_id);
	if (host_info && cbd_host_info_is_alive(host_info)) {
		pr_err("host id %u is still alive\n", *host_id);
		return -EBUSY;
	}

	return 0;
}

int cbd_host_register(struct cbd_transport *cbdt, char *hostname, u32 host_id)
{
	struct cbd_host *host;
	int ret;

	ret = host_register_validate(cbdt, hostname, &host_id);
	if (ret)
		return ret;

	host = kzalloc(sizeof(struct cbd_host), GFP_KERNEL);
	if (!host)
		return -ENOMEM;

	host->cbdt = cbdt;
	host->host_id = host_id;
	mutex_init(&host->info_lock);
	INIT_DELAYED_WORK(&host->hb_work, host_hb_workfn);

	host->host_info.state = CBD_HOST_STATE_RUNNING;
	memcpy(host->host_info.hostname, hostname, CBD_NAME_LEN);

	cbdt->host = host;

	host_info_write(host);
	queue_delayed_work(cbd_wq, &host->hb_work, 0);

	return 0;
}

static bool host_backends_stopped(struct cbd_transport *cbdt, u32 host_id)
{
	struct cbd_backend_info *backend_info;
	u32 i;

	cbd_for_each_backend_info(cbdt, i, backend_info) {
		if (!backend_info || backend_info->state != CBD_BACKEND_STATE_RUNNING)
			continue;

		if (backend_info->host_id == host_id) {
			cbdt_err(cbdt, "backend %u is still on host %u\n", i, host_id);
			return false;
		}
	}

	return true;
}

static bool host_blkdevs_stopped(struct cbd_transport *cbdt, u32 host_id)
{
	struct cbd_blkdev_info *blkdev_info;
	int i;

	cbd_for_each_blkdev_info(cbdt, i, blkdev_info) {
		if (!blkdev_info || blkdev_info->state != CBD_BLKDEV_STATE_RUNNING)
			continue;

		if (blkdev_info->host_id == host_id) {
			cbdt_err(cbdt, "blkdev %u is still on host %u\n", i, host_id);
			return false;
		}
	}

	return true;
}

void cbd_host_unregister(struct cbd_transport *cbdt)
{
	struct cbd_host *host = cbdt->host;

	if (!host) {
		cbd_err("This host is not registered.");
		return;
	}

	cancel_delayed_work_sync(&host->hb_work);
	cbdt_host_info_clear(cbdt, host->host_id);
	cbdt->host = NULL;
	kfree(host);
}

int cbd_host_clear(struct cbd_transport *cbdt, u32 host_id)
{
	struct cbd_host_info *host_info;

	host_info = cbdt_get_host_info(cbdt, host_id);
	if (cbd_host_info_is_alive(host_info)) {
		cbdt_err(cbdt, "host %u is still alive\n", host_id);
		return -EBUSY;
	}

	if (host_info->state == CBD_HOST_STATE_NONE)
		return 0;

	if (!host_blkdevs_stopped(cbdt, host_id) ||
			!host_backends_stopped(cbdt, host_id))
		return -EBUSY;

	cbdt_host_info_clear(cbdt, host_id);

	return 0;
}
