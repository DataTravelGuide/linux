/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _CBD_HOST_H
#define _CBD_HOST_H

#include "cbd_internal.h"
#include "cbd_transport.h"

CBD_DEVICE(host);

enum cbd_host_state {
	cbd_host_state_none	= 0,
	cbd_host_state_running,
	cbd_host_state_removing
};

struct cbd_host_info {
	struct cbd_meta_header meta_header;
	u32	crc;
	u8	version;
	u8	res;
	u16	res2;

	u8	state;
	u64	alive_ts;
	char	hostname[CBD_NAME_LEN];
};

struct cbd_host {
	u32			host_id;
	struct cbd_transport	*cbdt;

	struct cbd_host_device	*dev;

	struct cbd_host_info	host_info;
	struct mutex		info_lock;
	u32			info_index;

	struct delayed_work	hb_work; /* heartbeat work */
};

int cbd_host_register(struct cbd_transport *cbdt, char *hostname, u32 host_id);
int cbd_host_unregister(struct cbd_transport *cbdt);
int cbd_host_clear(struct cbd_transport *cbdt, u32 host_id);
bool cbd_host_info_is_alive(struct cbd_host_info *info);

#define cbd_for_each_host_info(cbdt, i, host_info)				\
	for (i = 0;								\
	     i < cbdt->transport_info->host_num &&				\
	     (host_info = cbdt_host_info_read(cbdt, i, NULL));			\
	     i++)

#endif /* _CBD_HOST_H */
