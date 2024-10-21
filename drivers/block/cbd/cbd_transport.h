/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CBD_TRANSPORT_H
#define _CBD_TRANSPORT_H

/* cbd_transport */
#define CBDT_INFO_F_BIGENDIAN		(1 << 0)
#define CBDT_INFO_F_CRC			(1 << 1)
#define CBDT_INFO_F_MULTIHOST		(1 << 2)

#ifdef CONFIG_CBD_MULTIHOST
#define CBDT_HOSTS_MAX			16
#else
#define CBDT_HOSTS_MAX			1
#endif /*CONFIG_CBD_MULTIHOST*/

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

	struct cbd_transport_info *transport_info;

	struct cbd_host *host;
	struct list_head backends;
	struct list_head devices;

	struct cbd_hosts_device *cbd_hosts_dev;
	struct cbd_segments_device *cbd_segments_dev;
	struct cbd_backends_device *cbd_backends_dev;
	struct cbd_blkdevs_device *cbd_blkdevs_dev;

	struct dax_device *dax_dev;
	struct file *bdev_file;
};

struct cbdt_register_options {
	char hostname[CBD_NAME_LEN];
	char path[CBD_PATH_LEN];
	u32 host_id;
	u16 format:1;
	u16 force:1;
	u16 unused:15;
};

struct cbd_blkdev;
struct cbd_backend;
struct cbd_backend_io;
struct cbd_cache;

int cbdt_register(struct cbdt_register_options *opts);
int cbdt_unregister(u32 transport_id);

#define CBDT_OBJ_DECLARE(OBJ)								\
struct cbd_##OBJ##_info	*cbdt_get_##OBJ##_info(struct cbd_transport *cbdt, u32 id);	\
int cbdt_get_empty_##OBJ##_id(struct cbd_transport *cbdt, u32 *id);			\
struct cbd_##OBJ##_info *cbdt_##OBJ##_info_read(struct cbd_transport *cbdt,		\
	       					u32 id,					\
						u32 *info_index);			\
void cbdt_##OBJ##_info_write(struct cbd_transport *cbdt,				\
			     void *data,						\
			     u32 data_size,						\
			     u32 id,							\
			     u32 info_index);						\
void cbdt_##OBJ##_info_clear(struct cbd_transport *cbdt, u32 id);

CBDT_OBJ_DECLARE(host);
CBDT_OBJ_DECLARE(backend);
CBDT_OBJ_DECLARE(blkdev);
CBDT_OBJ_DECLARE(segment);

static inline struct cbd_channel_seg_info *cbdt_get_channel_info(struct cbd_transport *cbdt, u32 id)
{
	return (struct cbd_channel_seg_info *)cbdt_get_segment_info(cbdt, id);
}

void cbdt_add_backend(struct cbd_transport *cbdt, struct cbd_backend *cbdb);
void cbdt_del_backend(struct cbd_transport *cbdt, struct cbd_backend *cbdb);
struct cbd_backend *cbdt_get_backend(struct cbd_transport *cbdt, u32 id);
void cbdt_add_blkdev(struct cbd_transport *cbdt, struct cbd_blkdev *blkdev);
void cbdt_del_blkdev(struct cbd_transport *cbdt, struct cbd_blkdev *blkdev);
struct cbd_blkdev *cbdt_get_blkdev(struct cbd_transport *cbdt, u32 id);

struct page *cbdt_page(struct cbd_transport *cbdt, u64 transport_off, u32 *page_off);
void cbdt_zero_range(struct cbd_transport *cbdt, void *pos, u32 size);

#endif /* _CBD_TRANSPORT_H */
