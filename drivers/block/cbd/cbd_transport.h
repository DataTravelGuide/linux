/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _CBD_TRANSPORT_H
#define _CBD_TRANSPORT_H

#include <linux/device.h>

#include "cbd_internal.h"

#define cbdt_err(transport, fmt, ...)						\
	cbd_err("cbd_transport%u: " fmt,					\
		 transport->id, ##__VA_ARGS__)
#define cbdt_info(transport, fmt, ...)						\
	cbd_info("cbd_transport%u: " fmt,					\
		 transport->id, ##__VA_ARGS__)
#define cbdt_debug(transport, fmt, ...)						\
	cbd_debug("cbd_transport%u: " fmt,					\
		 transport->id, ##__VA_ARGS__)

/* Info section offsets and sizes */
#define CBDT_INFO_OFF                   0                       /* Offset for transport info */
#define CBDT_INFO_SIZE                  PAGE_SIZE               /* Size of transport info section (1 page) */
#define CBDT_INFO_STRIDE                (CBDT_INFO_SIZE * CBDT_META_INDEX_MAX) /* Stride for alternating metadata copies */

#define CBDT_HOST_INFO_SIZE             round_up(sizeof(struct cbd_host_info), PAGE_SIZE)
#define CBDT_HOST_INFO_STRIDE           (CBDT_HOST_INFO_SIZE * CBDT_META_INDEX_MAX)

#define CBDT_BACKEND_INFO_SIZE          round_up(sizeof(struct cbd_backend_info), PAGE_SIZE)
#define CBDT_BACKEND_INFO_STRIDE        (CBDT_BACKEND_INFO_SIZE * CBDT_META_INDEX_MAX)

#define CBDT_BLKDEV_INFO_SIZE           round_up(sizeof(struct cbd_blkdev_info), PAGE_SIZE)
#define CBDT_BLKDEV_INFO_STRIDE         (CBDT_BLKDEV_INFO_SIZE * CBDT_META_INDEX_MAX)

#define CBDT_SEG_INFO_SIZE              round_up(sizeof(struct cbd_segment_info), PAGE_SIZE)
#define CBDT_SEG_INFO_STRIDE            CBDT_SEG_SIZE

#define CBD_TRASNPORT_SIZE_MIN          (512 * 1024 * 1024)     /* Minimum size for CBD transport (512 MB) */

/*
 * CBD transport flags configured during formatting
 *
 * The CBDT_INFO_F_xxx flags define registration requirements based on transport
 * formatting. For a machine to register a transport:
 * - CBDT_INFO_F_BIGENDIAN: Requires a big-endian machine.
 * - CBDT_INFO_F_CHANNEL_CRC: Requires CBD_CHANNEL_CRC enabled.
 * - CBDT_INFO_F_CHANNEL_DATA_CRC: Requires CBD_CHANNEL_DATA_CRC enabled.
 * - CBDT_INFO_F_CACHE_DATA_CRC: Requires CBD_CACHE_DATA_CRC enabled.
 * - CBDT_INFO_F_MULTIHOST: Requires CBD_MULTIHOST enabled for multi-host access.
 */
#define CBDT_INFO_F_BIGENDIAN			(1 << 0)
#define CBDT_INFO_F_CHANNEL_CRC			(1 << 1)
#define CBDT_INFO_F_CHANNEL_DATA_CRC		(1 << 2)
#define CBDT_INFO_F_CACHE_DATA_CRC		(1 << 3)
#define CBDT_INFO_F_MULTIHOST			(1 << 4)

/*
 * Maximum number of hosts supported in the transport.
 * Limited to 1 if CONFIG_CBD_MULTIHOST is not enabled.
 */
#ifdef CONFIG_CBD_MULTIHOST
#define CBDT_HOSTS_MAX                  16
#else
#define CBDT_HOSTS_MAX                  1
#endif /* CONFIG_CBD_MULTIHOST */

struct cbd_transport_info {
	__le64 magic;
	__le16 version;
	__le16 flags;

	u64 host_area_off;
	u32 host_info_size;
	u32 host_num;

	u64 backend_area_off;
	u32 backend_info_size;
	u32 backend_num;

	u64 blkdev_area_off;
	u32 blkdev_info_size;
	u32 blkdev_num;

	u64 segment_area_off;
	u32 segment_size;
	u32 segment_num;
};

struct cbd_transport {
	u16	id;
	struct device device;
	struct mutex lock;
	struct mutex adm_lock;

	struct cbd_transport_info *transport_info_addr;
	struct cbd_transport_info transport_info;

	struct cbd_host *host;
	struct list_head backends;
	struct list_head devices;

	u32 host_hint;
	u32 backend_hint;
	u32 blkdev_hint;
	u32 segment_hint;

	struct cbd_hosts_device *cbd_hosts_dev;
	struct cbd_segments_device *cbd_segments_dev;
	struct cbd_backends_device *cbd_backends_dev;
	struct cbd_blkdevs_device *cbd_blkdevs_dev;

	char path[CBD_PATH_LEN];
	struct dax_device *dax_dev;
	struct file *bdev_file;
};

struct cbdt_register_options {
	char hostname[CBD_NAME_LEN];
	char path[CBD_PATH_LEN];
	u32 host_id;
	u16 format:1;
	u16 force:1;
	u16 unused:14;
};

struct cbd_blkdev;
struct cbd_backend;
struct cbd_backend_io;
struct cbd_cache;

int cbdt_register(struct cbdt_register_options *opts);
int cbdt_unregister(u32 transport_id);

#define CBDT_OBJ_DECLARE(OBJ)								\
extern const struct device_type cbd_##OBJ##_type;					\
extern const struct device_type cbd_##OBJ##s_type;					\
struct cbd_##OBJ##_info	*cbdt_get_##OBJ##_info(struct cbd_transport *cbdt, u32 id);	\
int cbdt_get_empty_##OBJ##_id(struct cbd_transport *cbdt, u32 *id);			\
struct cbd_##OBJ##_info *cbdt_##OBJ##_info_read(struct cbd_transport *cbdt,		\
						u32 id);				\
void cbdt_##OBJ##_info_write(struct cbd_transport *cbdt,				\
			     void *data,						\
			     u32 data_size,						\
			     u32 id);							\
void cbdt_##OBJ##_info_clear(struct cbd_transport *cbdt, u32 id)

CBDT_OBJ_DECLARE(host);
CBDT_OBJ_DECLARE(backend);
CBDT_OBJ_DECLARE(blkdev);
CBDT_OBJ_DECLARE(segment);

extern const struct bus_type cbd_bus_type;
extern struct device cbd_root_dev;

void cbdt_add_backend(struct cbd_transport *cbdt, struct cbd_backend *cbdb);
void cbdt_del_backend(struct cbd_transport *cbdt, struct cbd_backend *cbdb);
struct cbd_backend *cbdt_get_backend(struct cbd_transport *cbdt, u32 id);
void cbdt_add_blkdev(struct cbd_transport *cbdt, struct cbd_blkdev *blkdev);
void cbdt_del_blkdev(struct cbd_transport *cbdt, struct cbd_blkdev *blkdev);
struct cbd_blkdev *cbdt_get_blkdev(struct cbd_transport *cbdt, u32 id);

struct page *cbdt_page(struct cbd_transport *cbdt, u64 transport_off, u32 *page_off);
void cbdt_zero_range(struct cbd_transport *cbdt, void *pos, u32 size);
void cbdt_flush(struct cbd_transport *cbdt, void *pos, u32 size);

static inline bool cbdt_is_single_host(struct cbd_transport *cbdt)
{
	return (cbdt->transport_info.host_num == 1);
}

#endif /* _CBD_TRANSPORT_H */
