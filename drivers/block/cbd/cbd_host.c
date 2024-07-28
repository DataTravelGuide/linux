#include "cbd_internal.h"

static ssize_t cbd_host_name_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_host_device *host;
	struct cbd_host_info *host_info;

	host = container_of(dev, struct cbd_host_device, dev);
	host_info = host->host_info;

	if (host_info->state == cbd_host_state_none)
		return 0;

	return sprintf(buf, "%s\n", host_info->hostname);
}

static DEVICE_ATTR(hostname, 0400, cbd_host_name_show, NULL);

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

int cbd_host_register(struct cbd_transport *cbdt, char *hostname)
{
	struct cbd_host *host;
	struct cbd_host_info *host_info;
	u32 host_id;
	int ret;

	if (cbdt->host)
		return -EEXIST;

	if (strlen(hostname) == 0)
		return -EINVAL;

	ret = cbdt_get_empty_host_id(cbdt, &host_id);
	if (ret < 0)
		return ret;

	host = kzalloc(sizeof(struct cbd_host), GFP_KERNEL);
	if (!host)
		return -ENOMEM;

	host->host_id = host_id;
	host->cbdt = cbdt;
	INIT_DELAYED_WORK(&host->hb_work, host_hb_workfn);

	host_info = cbdt_get_host_info(cbdt, host_id);
	host_info->state = cbd_host_state_running;
	memcpy(host_info->hostname, hostname, CBD_NAME_LEN);

	host->host_info = host_info;
	cbdt->host = host;

	queue_delayed_work(cbd_wq, &host->hb_work, 0);

	return 0;
}

int cbd_host_unregister(struct cbd_transport *cbdt)
{
	struct cbd_host *host = cbdt->host;
	struct cbd_host_info *host_info;

	if (!host) {
		cbd_err("This host is not registered.");
		return 0;
	}

	host->host_info->state = cbd_host_state_removing;
	cancel_delayed_work_sync(&host->hb_work);
	cancel_delayed_work_sync(&host->hb_work);
	host_info = host->host_info;
	memset(host_info->hostname, 0, CBD_NAME_LEN);
	host_info->alive_ts = 0;
	host_info->state = cbd_host_state_none;

	cbdt->host = NULL;
	kfree(cbdt->host);

	return 0;
}

int cbd_host_clear(struct cbd_transport *cbdt, u32 host_id)
{
	struct cbd_host_info *host_info;

	host_info = cbdt_get_host_info(cbdt, host_id);
	if (cbd_host_info_is_alive(host_info)) {
		cbdt_err(cbdt, "host %u is still alive\n", host_id);
		return -EBUSY;
	}

	if (host_info->state == cbd_host_state_none)
		return 0;

	host_info->state = cbd_host_state_none;

	return 0;
}
