// SPDX-License-Identifier: GPL-2.0-or-later

#include "cbd_host.h"
#include "cbd_blkdev.h"
#include "cbd_backend.h"

static ssize_t cbd_host_name_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_host_device *host_dev;
	struct cbd_host_info *host_info;

	host_dev = container_of(dev, struct cbd_host_device, dev);
	host_info = cbdt_host_info_read(host_dev->cbdt, host_dev->id, NULL);
	if (!host_info)
		return 0;

	if (host_info->state == cbd_host_state_none)
		return 0;

	return sprintf(buf, "%s\n", host_info->hostname);
}

static DEVICE_ATTR(hostname, 0400, cbd_host_name_show, NULL);

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
			     host->host_id, host->info_index);
	host->info_index = (host->info_index + 1) % CBDT_META_INDEX_MAX;
	mutex_unlock(&host->info_lock);
}

/**
 * host_register_validate - Validate host registration parameters
 * @cbdt: Pointer to the CBD transport structure
 * @hostname: Pointer to the hostname string
 * @host_id: Pointer to the host ID to be validated and potentially updated
 *
 * This function validates if a host can be registered based on the
 * provided parameters. If the host has already been registered (cbdt->host
 * is non-NULL), it returns -EEXIST. It also checks the validity of
 * @hostname and ensures it is non-empty, returning -EINVAL if invalid.
 *
 * If *host_id is set to UINT_MAX, it assigns a new host ID based on the
 * transport's configuration. For single-host cases, the host ID is set to 0.
 * In multi-host setups, it attempts to find an available host ID with
 * cbdt_get_empty_host_id(). If no ID is available, it logs an error and
 * returns -EBUSY.
 *
 * After determining a host ID, the function verifies that no active host
 * exists with that ID by reading the host info with cbdt_host_info_read()
 * and checking its state with cbd_host_info_is_alive(). If an active host
 * exists, it logs the error and returns -EBUSY.
 *
 * Return:
 * * 0 on successful validation and ID assignment
 * * -EEXIST if the host is already registered
 * * -EINVAL if the hostname is empty
 * * -EBUSY if no available ID is found or if the host ID is in use
 */
static int host_register_validate(struct cbd_transport *cbdt, char *hostname, u32 *host_id)
{
	struct cbd_host_info *host_info;
	int ret;

	if (cbdt->host)
		return -EEXIST;

	if (strlen(hostname) == 0)
		return -EINVAL;

	if (*host_id == UINT_MAX) {
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

	host_info = cbdt_host_info_read(cbdt, *host_id, NULL);
	if (host_info && cbd_host_info_is_alive(host_info)) {
		pr_err("host id %u is still alive\n", *host_id);
		return -EBUSY;
	}

	return 0;
}

/**
 * cbd_host_register - Register a new host with the specified host ID
 * @cbdt: Pointer to the CBD transport structure
 * @hostname: Pointer to the hostname string for the new host
 * @host_id: Host ID to be assigned to the new host
 *
 * This function registers a new host with the specified host ID by
 * performing a validation check using host_register_validate(). If the
 * validation is successful, memory is allocated for the new host structure
 * and initialized with the given parameters. This includes setting the
 * CBD transport pointer, host ID, and initializing synchronization primitives.
 *
 * The hostname is stored in the host_info structure to help identify the
 * host. This allows for quick identification of the physical server
 * associated with the `host_id`, streamlining maintenance and data tracking.
 *
 * The host is marked as running, and the host information is then saved
 * with host_info_write(). A delayed heartbeat work item is also queued to
 * monitor the host's state.
 *
 * Return:
 * * 0 on successful registration
 * * -EEXIST if the host has already been registered
 * * -EINVAL if the hostname is empty
 * * -EBUSY if the host ID is already in use
 * * -ENOMEM if memory allocation for the host structure fails
 */
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
	host->info_index = 0;
	mutex_init(&host->info_lock);
	INIT_DELAYED_WORK(&host->hb_work, host_hb_workfn);

	host->host_info.state = cbd_host_state_running;
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
		if (!backend_info || backend_info->state != cbd_backend_state_running)
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
		if (!blkdev_info || blkdev_info->state != cbd_blkdev_state_running)
			continue;

		if (blkdev_info->host_id == host_id) {
			cbdt_err(cbdt, "blkdev %u is still on host %u\n", i, host_id);
			return false;
		}
	}

	return true;
}

/**
 * cbd_host_unregister - Unregister the host from the CBD transport
 * @cbdt: Pointer to the CBD transport structure
 *
 * This function unregisters a host that has been registered to the given
 * CBD transport. It first checks if a host is currently registered. If not,
 * it logs an error message and returns 0.
 *
 * If a host is registered, it verifies that all block devices and backends
 * associated with the host ID are stopped. If either are still active,
 * it returns -EBUSY to indicate the host cannot be unregistered at this time.
 *
 * If all checks pass, the function proceeds to cancel the heartbeat
 * delayed work and clear the host's info from the CBD transport. It then
 * frees the memory associated with the host structure.
 *
 * Return:
 * * 0 on successful unregistration or if no host is registered
 * * -EBUSY if block devices or backends are still active
 */
int cbd_host_unregister(struct cbd_transport *cbdt)
{
	struct cbd_host *host = cbdt->host;

	if (!host) {
		cbd_err("This host is not registered.");
		return 0;
	}

	if (!host_blkdevs_stopped(cbdt, host->host_id) ||
			!host_backends_stopped(cbdt, host->host_id))
		return -EBUSY;

	cancel_delayed_work_sync(&host->hb_work);
	cbdt_host_info_clear(cbdt, host->host_id);
	cbdt->host = NULL;
	kfree(host);

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

	if (!host_blkdevs_stopped(cbdt, host_id) ||
			!host_backends_stopped(cbdt, host_id))
		return -EBUSY;

	cbdt_host_info_clear(cbdt, host_id);

	return 0;
}
