/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CBD_INTERNAL_H
#define _CBD_INTERNAL_H

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/blk-mq.h>
#include <asm/byteorder.h>
#include <asm/types.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/dax.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/parser.h>
#include <linux/idr.h>
#include <linux/workqueue.h>
#include <linux/uuid.h>
#include <linux/bitfield.h>
#include <linux/crc32.h>
#include <linux/hashtable.h>

/*
 * CBD (CXL Block Device) provides two usage scenarios: single-host and multi-hosts.
 *
 * (1) Single-host scenario, CBD can use a pmem device as a cache for block devices,
 * providing a caching mechanism specifically designed for persistent memory.
 *
 *	+-----------------------------------------------------------------+
 *	|                         single-host                             |
 *	+-----------------------------------------------------------------+
 *	|                                                                 |
 *	|                                                                 |
 *	|                                                                 |
 *	|                                                                 |
 *	|                                                                 |
 *	|                        +-----------+     +------------+         |
 *	|                        | /dev/cbd0 |     | /dev/cbd1  |         |
 *	|                        |           |     |            |         |
 *	|  +---------------------|-----------|-----|------------|-------+ |
 *	|  |                     |           |     |            |       | |
 *	|  |      /dev/pmem0     | cbd0 cache|     | cbd1 cache |       | |
 *	|  |                     |           |     |            |       | |
 *	|  +---------------------|-----------|-----|------------|-------+ |
 *	|                        |+---------+|     |+----------+|         |
 *	|                        ||/dev/sda ||     || /dev/sdb ||         |
 *	|                        |+---------+|     |+----------+|         |
 *	|                        +-----------+     +------------+         |
 *	+-----------------------------------------------------------------+
 *
 * (2) Multi-hosts scenario, CBD also provides a cache while taking advantage of
 * shared memory features, allowing users to access block devices on other nodes across
 * different hosts.
 *
 * As shared memory is supported in CXL3.0 spec, we can transfer data via CXL shared memory.
 * CBD use CXL shared memory to transfer data between node-1 and node-2.
 *
 *	+--------------------------------------------------------------------------------------------------------+
 *	|                                           multi-hosts                                                  |
 *	+--------------------------------------------------------------------------------------------------------+
 *	|                                                                                                        |
 *	|                                                                                                        |
 *	| +-------------------------------+                               +------------------------------------+ |
 *	| |          node-1               |                               |              node-2                | |
 *	| +-------------------------------+                               +------------------------------------+ |
 *	| |                               |                               |                                    | |
 *	| |                       +-------+                               +---------+                          | |
 *	| |                       | cbd0  |                               | backend0+------------------+       | |
 *	| |                       +-------+                               +---------+                  |       | |
 *	| |                       | pmem0 |                               | pmem0   |                  v       | |
 *	| |               +-------+-------+                               +---------+----+     +---------------+ |
 *	| |               |    cxl driver |                               | cxl driver   |     |  /dev/sda     | |
 *	| +---------------+--------+------+                               +-----+--------+-----+---------------+ |
 *	|                          |                                            |                                |
 *	|                          |                                            |                                |
 *	|                          |        CXL                         CXL     |                                |
 *	|                          +----------------+               +-----------+                                |
 *	|                                           |               |                                            |
 *	|                                           |               |                                            |
 *	|                                           |               |                                            |
 *	|                 +-------------------------+---------------+--------------------------+                 |
 *	|                 |                         +---------------+                          |                 |
 *	|                 | shared memory device    |  cbd0 cache   |                          |                 |
 *	|                 |                         +---------------+                          |                 |
 *	|                 +--------------------------------------------------------------------+                 |
 *	|                                                                                                        |
 *	+--------------------------------------------------------------------------------------------------------+
 */

#define cbd_err(fmt, ...)							\
	pr_err("cbd: %s:%u " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define cbd_info(fmt, ...)							\
	pr_info("cbd: %s:%u " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define cbd_debug(fmt, ...)							\
	pr_debug("cbd: %s:%u " fmt, __func__, __LINE__, ##__VA_ARGS__)

#define cbdt_err(transport, fmt, ...)						\
	cbd_err("cbd_transport%u: " fmt,					\
		 transport->id, ##__VA_ARGS__)
#define cbdt_info(transport, fmt, ...)						\
	cbd_info("cbd_transport%u: " fmt,					\
		 transport->id, ##__VA_ARGS__)
#define cbdt_debug(transport, fmt, ...)						\
	cbd_debug("cbd_transport%u: " fmt,					\
		 transport->id, ##__VA_ARGS__)

#define cbdb_err(backend, fmt, ...)						\
	cbdt_err(backend->cbdt, "backend%d: " fmt,				\
		 backend->backend_id, ##__VA_ARGS__)
#define cbdb_info(backend, fmt, ...)						\
	cbdt_info(backend->cbdt, "backend%d: " fmt,				\
		 backend->backend_id, ##__VA_ARGS__)
#define cbdbdebug(backend, fmt, ...)						\
	cbdt_debug(backend->cbdt, "backend%d: " fmt,				\
		 backend->backend_id, ##__VA_ARGS__)

#define cbd_handler_err(handler, fmt, ...)					\
	cbdb_err(handler->cbdb, "handler%d: " fmt,				\
		 handler->channel.seg_id, ##__VA_ARGS__)
#define cbd_handler_info(handler, fmt, ...)					\
	cbdb_info(handler->cbdb, "handler%d: " fmt,				\
		 handler->channel.seg_id, ##__VA_ARGS__)
#define cbd_handler_debug(handler, fmt, ...)					\
	cbdb_debug(handler->cbdb, "handler%d: " fmt,				\
		 handler->channel.seg_id, ##__VA_ARGS__)

#define cbd_blk_err(dev, fmt, ...)						\
	cbdt_err(dev->cbdt, "cbd%d: " fmt,					\
		 dev->mapped_id, ##__VA_ARGS__)
#define cbd_blk_info(dev, fmt, ...)						\
	cbdt_info(dev->cbdt, "cbd%d: " fmt,					\
		 dev->mapped_id, ##__VA_ARGS__)
#define cbd_blk_debug(dev, fmt, ...)						\
	cbdt_debug(dev->cbdt, "cbd%d: " fmt,					\
		 dev->mapped_id, ##__VA_ARGS__)

#define cbd_queue_err(queue, fmt, ...)						\
	cbd_blk_err(queue->cbd_blkdev, "queue%d: " fmt,			\
		     queue->channel.seg_id, ##__VA_ARGS__)
#define cbd_queue_info(queue, fmt, ...)						\
	cbd_blk_info(queue->cbd_blkdev, "queue%d: " fmt,			\
		     queue->channel.seg_id, ##__VA_ARGS__)
#define cbd_queue_debug(queue, fmt, ...)					\
	cbd_blk_debug(queue->cbd_blkdev, "queue%d: " fmt,			\
		     queue->channel.seg_id, ##__VA_ARGS__)

#define cbd_channel_err(channel, fmt, ...)					\
	cbdt_err(channel->cbdt, "channel%d: " fmt,				\
		 channel->seg_id, ##__VA_ARGS__)
#define cbd_channel_info(channel, fmt, ...)					\
	cbdt_info(channel->cbdt, "channel%d: " fmt,				\
		 channel->seg_id, ##__VA_ARGS__)
#define cbd_channel_debug(channel, fmt, ...)					\
	cbdt_debug(channel->cbdt, "channel%d: " fmt,				\
		 channel->seg_id, ##__VA_ARGS__)

#define cbd_cache_err(cache, fmt, ...)						\
	cbdt_err(cache->cbdt, "cache%d: " fmt,					\
		 cache->cache_id, ##__VA_ARGS__)
#define cbd_cache_info(cache, fmt, ...)						\
	cbdt_info(cache->cbdt, "cache%d: " fmt,					\
		 cache->cache_id, ##__VA_ARGS__)
#define cbd_cache_debug(cache, fmt, ...)					\
	cbdt_debug(cache->cbdt, "cache%d: " fmt,				\
		 cache->cache_id, ##__VA_ARGS__)

#define CBD_KB	(1024)
#define CBD_MB	(CBD_KB * CBD_KB)

#define CBD_TRANSPORT_MAX	1024
#define CBD_PATH_LEN	512
#define CBD_NAME_LEN	32

#define CBD_QUEUES_MAX		128

#define CBD_PART_SHIFT 4
#define CBD_DRV_NAME "cbd"
#define CBD_DEV_NAME_LEN 32

#define CBD_HB_INTERVAL		msecs_to_jiffies(5000) /* 5s */
#define CBD_HB_TIMEOUT		(30 * 1000) /* 30s */

/*
 * CBD transport layout:
 *
 *	+-------------------------------------------------------------------------------------------------------------------------------+
 *	|                           cbd transport                                                                                       |
 *	+--------------------+-----------------------+-----------------------+----------------------+-----------------------------------+
 *	|                    |       hosts           |      backends         |       blkdevs        |        channels                   |
 *	| cbd transport info +----+----+----+--------+----+----+----+--------+----+----+----+-------+-------+-------+-------+-----------+
 *	|                    |    |    |    |  ...   |    |    |    |  ...   |    |    |    |  ...  |       |       |       |   ...     |
 *	+--------------------+----+----+----+--------+----+----+----+--------+----+----+----+-------+---+---+---+---+-------+-----------+
 *	                                                                                                |       |
 *	                                                                                                |       |
 *	                                                                                                |       |
 *	                                                                                                |       |
 *	          +-------------------------------------------------------------------------------------+       |
 *	          |                                                                                             |
 *	          |                                                                                             |
 *	          v                                                                                             |
 *	    +-----------------------------------------------------------+                                       |
 *	    |                 channel segment                           |                                       |
 *	    +--------------------+--------------------------------------+                                       |
 *	    |    channel meta    |              channel data            |                                       |
 *	    +---------+----------+--------------------------------------+                                       |
 *	              |                                                                                         |
 *	              |                                                                                         |
 *	              |                                                                                         |
 *	              v                                                                                         |
 *	    +----------------------------------------------------------+                                        |
 *	    |                 channel meta                             |                                        |
 *	    +-----------+--------------+-------------------------------+                                        |
 *	    | meta ctrl |  comp ring   |       cmd ring                |                                        |
 *	    +-----------+--------------+-------------------------------+                                        |
 *	                                                                                                        |
 *	                                                                                                        |
 *	                                                                                                        |
 *	           +--------------------------------------------------------------------------------------------+
 *	           |
 *	           |
 *	           |
 *	           v
 *	     +----------------------------------------------------------+
 *	     |                cache segment                             |
 *	     +-----------+----------------------------------------------+
 *	     |   info    |               data                           |
 *	     +-----------+----------------------------------------------+
 */

/* cbd segment */
#define CBDT_SEG_SIZE		(16 * 1024 * 1024)

/* cbd channel seg */
#define CBDC_META_SIZE		(4 * 1024 * 1024)
#define CBDC_SUBMR_RESERVED	sizeof(struct cbd_se)
#define CBDC_CMPR_RESERVED	sizeof(struct cbd_ce)

#define CBDC_DATA_ALIGH		4096
#define CBDC_DATA_RESERVED	CBDC_DATA_ALIGH

#define CBDC_CTRL_OFF		0
#define CBDC_CTRL_SIZE		PAGE_SIZE
#define CBDC_COMPR_OFF		(CBDC_CTRL_OFF + CBDC_CTRL_SIZE)
#define CBDC_COMPR_SIZE		(sizeof(struct cbd_ce) * 1024)
#define CBDC_SUBMR_OFF		(CBDC_COMPR_OFF + CBDC_COMPR_SIZE)
#define CBDC_SUBMR_SIZE		(CBDC_META_SIZE - CBDC_SUBMR_OFF)

#define CBDC_DATA_OFF		CBDC_META_SIZE
#define CBDC_DATA_SIZE		(CBDT_SEG_SIZE - CBDC_META_SIZE)

#define CBDC_UPDATE_SUBMR_HEAD(head, used, size) (head = ((head % size) + used) % size)
#define CBDC_UPDATE_SUBMR_TAIL(tail, used, size) (tail = ((tail % size) + used) % size)

#define CBDC_UPDATE_COMPR_HEAD(head, used, size) (head = ((head % size) + used) % size)
#define CBDC_UPDATE_COMPR_TAIL(tail, used, size) (tail = ((tail % size) + used) % size)

/* cbd transport */
#define CBD_TRANSPORT_MAGIC		0x65B05EFA96C596EFULL
#define CBD_TRANSPORT_VERSION		1

#define CBDT_INFO_OFF			0
#define CBDT_INFO_SIZE			PAGE_SIZE

#define CBDT_HOST_INFO_SIZE		round_up(sizeof(struct cbd_host_info), PAGE_SIZE)
#define CBDT_BACKEND_INFO_SIZE		round_up(sizeof(struct cbd_backend_info), PAGE_SIZE)
#define CBDT_BLKDEV_INFO_SIZE		round_up(sizeof(struct cbd_blkdev_info), PAGE_SIZE)

#define CBD_TRASNPORT_SIZE_MIN		(512 * 1024 * 1024)

/*
 * CBD structure diagram:
 *
 *	                                        +--------------+
 *	                                        | cbd_transport|                                               +----------+
 *	                                        +--------------+                                               | cbd_host |
 *	                                        |              |                                               +----------+
 *	                                        |   host       +---------------------------------------------->|          |
 *	                   +--------------------+   backends   |                                               | hostname |
 *	                   |                    |   devices    +------------------------------------------+    |          |
 *	                   |                    |              |                                          |    +----------+
 *	                   |                    +--------------+                                          |
 *	                   |                                                                              |
 *	                   |                                                                              |
 *	                   |                                                                              |
 *	                   |                                                                              |
 *	                   |                                                                              |
 *	                   v                                                                              v
 *	             +------------+     +-----------+     +------+                                  +-----------+      +-----------+     +------+
 *	             | cbd_backend+---->|cbd_backend+---->| NULL |                                  | cbd_blkdev+----->| cbd_blkdev+---->| NULL |
 *	             +------------+     +-----------+     +------+                                  +-----------+      +-----------+     +------+
 *	+------------+  cbd_cache |     |  handlers |                                        +------+  queues   |      |  queues   |
 *	|            |            |     +-----------+                                        |      |           |      +-----------+
 *	|     +------+  handlers  |                                                          |      |           |
 *	|     |      +------------+                                                          |      | cbd_cache +-------------------------------------+
 *	|     |                                                                              |      +-----------+                                     |
 *	|     |                                                                              |                                                        |
 *	|     |      +-------------+       +-------------+           +------+                |      +-----------+      +-----------+     +------+     |
 *	|     +----->| cbd_handler +------>| cbd_handler +---------->| NULL |                +----->| cbd_queue +----->| cbd_queue +---->| NULL |     |
 *	|            +-------------+       +-------------+           +------+                       +-----------+      +-----------+     +------+     |
 *	|     +------+ channel     |       |   channel   |                                   +------+  channel  |      |  channel  |                  |
 *	|     |      +-------------+       +-------------+                                   |      +-----------+      +-----------+                  |
 *	|     |                                                                              |                                                        |
 *	|     |                                                                              |                                                        |
 *	|     |                                                                              |                                                        |
 *	|     |                                                                              v                                                        |
 *	|     |                                                        +-----------------------+                                                      |
 *	|     +------------------------------------------------------->|      cbd_channel      |                                                      |
 *	|                                                              +-----------------------+                                                      |
 *	|                                                              | channel_id            |                                                      |
 *	|                                                              | cmdr (cmd ring)       |                                                      |
 *	|                                                              | compr (complete ring) |                                                      |
 *	|                                                              | data (data area)      |                                                      |
 *	|                                                              |                       |                                                      |
 *	|                                                              +-----------------------+                                                      |
 *	|                                                                                                                                             |
 *	|                                                 +-----------------------------+                                                             |
 *	+------------------------------------------------>|         cbd_cache           |<------------------------------------------------------------+
 *	                                                  +-----------------------------+
 *	                                                  |     cache_wq                |
 *	                                                  |     cache_tree              |
 *	                                                  |     segments[]              |
 *	                                                  +-----------------------------+
 */

#define CBD_DEVICE(OBJ)					\
struct cbd_## OBJ ##_device {				\
	struct device dev;				\
	struct cbd_transport *cbdt;			\
	struct cbd_## OBJ ##_info *OBJ##_info;		\
};							\
							\
struct cbd_## OBJ ##s_device {				\
	struct device OBJ ##s_dev;			\
	struct cbd_## OBJ ##_device OBJ ##_devs[];	\
}

/* cbd_worker_cfg*/
struct cbd_worker_cfg {
	u32			busy_retry_cur;
	u32			busy_retry_count;
	u32			busy_retry_max;
	u32			busy_retry_min;
	u64			busy_retry_interval;
};

static inline void cbdwc_init(struct cbd_worker_cfg *cfg)
{
	/* init cbd_worker_cfg with default values */
	cfg->busy_retry_cur = 0;
	cfg->busy_retry_count = 100;
	cfg->busy_retry_max = cfg->busy_retry_count * 2;
	cfg->busy_retry_min = 0;
	cfg->busy_retry_interval = 1;			/* 1us */
}

/* reset retry_cur and increase busy_retry_count */
static inline void cbdwc_hit(struct cbd_worker_cfg *cfg)
{
	u32 delta;

	cfg->busy_retry_cur = 0;

	if (cfg->busy_retry_count == cfg->busy_retry_max)
		return;

	/* retry_count increase by 1/16 */
	delta = cfg->busy_retry_count >> 4;
	if (!delta)
		delta = (cfg->busy_retry_max + cfg->busy_retry_min) >> 1;

	cfg->busy_retry_count += delta;

	if (cfg->busy_retry_count > cfg->busy_retry_max)
		cfg->busy_retry_count = cfg->busy_retry_max;
}

/* reset retry_cur and decrease busy_retry_count */
static inline void cbdwc_miss(struct cbd_worker_cfg *cfg)
{
	u32 delta;

	cfg->busy_retry_cur = 0;

	if (cfg->busy_retry_count == cfg->busy_retry_min)
		return;

	/* retry_count decrease by 1/16 */
	delta = cfg->busy_retry_count >> 4;
	if (!delta)
		delta = cfg->busy_retry_count;

	cfg->busy_retry_count -= delta;
}

static inline bool cbdwc_need_retry(struct cbd_worker_cfg *cfg)
{
	if (++cfg->busy_retry_cur < cfg->busy_retry_count) {
		cpu_relax();
		fsleep(cfg->busy_retry_interval);
		return true;
	}

	return false;
}

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

struct cbd_host_info *cbdt_get_host_info(struct cbd_transport *cbdt, u32 id);
struct cbd_backend_info *cbdt_get_backend_info(struct cbd_transport *cbdt, u32 id);
struct cbd_blkdev_info *cbdt_get_blkdev_info(struct cbd_transport *cbdt, u32 id);
struct cbd_segment_info *cbdt_get_segment_info(struct cbd_transport *cbdt, u32 id);
static inline struct cbd_channel_info *cbdt_get_channel_info(struct cbd_transport *cbdt, u32 id)
{
	return (struct cbd_channel_info *)cbdt_get_segment_info(cbdt, id);
}

int cbdt_get_empty_host_id(struct cbd_transport *cbdt, u32 *id);
int cbdt_get_empty_backend_id(struct cbd_transport *cbdt, u32 *id);
int cbdt_get_empty_blkdev_id(struct cbd_transport *cbdt, u32 *id);
int cbdt_get_empty_segment_id(struct cbd_transport *cbdt, u32 *id);

void cbdt_add_backend(struct cbd_transport *cbdt, struct cbd_backend *cbdb);
void cbdt_del_backend(struct cbd_transport *cbdt, struct cbd_backend *cbdb);
struct cbd_backend *cbdt_get_backend(struct cbd_transport *cbdt, u32 id);
void cbdt_add_blkdev(struct cbd_transport *cbdt, struct cbd_blkdev *blkdev);
void cbdt_del_blkdev(struct cbd_transport *cbdt, struct cbd_blkdev *blkdev);
struct cbd_blkdev *cbdt_get_blkdev(struct cbd_transport *cbdt, u32 id);

struct page *cbdt_page(struct cbd_transport *cbdt, u64 transport_off, u32 *page_off);
void cbdt_zero_range(struct cbd_transport *cbdt, void *pos, u32 size);

/* cbd_host */
CBD_DEVICE(host);

enum cbd_host_state {
	cbd_host_state_none	= 0,
	cbd_host_state_running,
	cbd_host_state_removing
};

struct cbd_host_info {
	u8	state;
	u64	alive_ts;
	char	hostname[CBD_NAME_LEN];
};

struct cbd_host {
	u32			host_id;
	struct cbd_transport	*cbdt;

	struct cbd_host_device	*dev;
	struct cbd_host_info	*host_info;
	struct delayed_work	hb_work; /* heartbeat work */
};

int cbd_host_register(struct cbd_transport *cbdt, char *hostname, u32 host_id);
int cbd_host_unregister(struct cbd_transport *cbdt);
int cbd_host_clear(struct cbd_transport *cbdt, u32 host_id);
bool cbd_host_info_is_alive(struct cbd_host_info *info);

/* cbd_segment */
CBD_DEVICE(segment);

enum cbd_segment_state {
	cbd_segment_state_none		= 0,
	cbd_segment_state_running,
};

enum cbd_seg_type {
	cbds_type_none = 0,
	cbds_type_channel,
	cbds_type_cache
};

static inline const char *cbds_type_str(enum cbd_seg_type type)
{
	if (type == cbds_type_channel)
		return "channel";
	else if (type == cbds_type_cache)
		return "cache";

	return "Unknown";
}

struct cbd_segment_info {
	u8 state;
	u8 type;
	u8 ref;
	u32 next_seg;
	u64 alive_ts;
};

struct cbd_seg_pos {
	struct cbd_segment *segment;
	u32 off;
};

struct cbd_seg_ops {
	void (*sanitize_pos)(struct cbd_seg_pos *pos);
};

struct cbds_init_options {
	u32 seg_id;
	enum cbd_seg_type type;
	u32 data_off;
	struct cbd_seg_ops *seg_ops;
	void *priv_data;
};

struct cbd_segment {
	struct cbd_transport		*cbdt;
	struct cbd_segment		*next;

	u32				seg_id;
	struct cbd_segment_info		*segment_info;
	struct cbd_seg_ops		*seg_ops;

	void				*data;
	u32				data_size;

	void				*priv_data;

	struct delayed_work		hb_work; /* heartbeat work */
};

int cbd_segment_clear(struct cbd_transport *cbdt, u32 segment_id);
void cbd_segment_init(struct cbd_transport *cbdt, struct cbd_segment *segment,
		      struct cbds_init_options *options);
void cbd_segment_exit(struct cbd_segment *segment);
bool cbd_segment_info_is_alive(struct cbd_segment_info *info);
void cbds_copy_to_bio(struct cbd_segment *segment,
		u32 data_off, u32 data_len, struct bio *bio, u32 bio_off);
void cbds_copy_from_bio(struct cbd_segment *segment,
		u32 data_off, u32 data_len, struct bio *bio, u32 bio_off);
u32 cbd_seg_crc(struct cbd_segment *segment, u32 data_off, u32 data_len);
int cbds_map_pages(struct cbd_segment *segment, struct cbd_backend_io *io);
int cbds_pos_advance(struct cbd_seg_pos *seg_pos, u32 len);
void cbds_copy_data(struct cbd_seg_pos *dst_pos,
		struct cbd_seg_pos *src_pos, u32 len);

/* cbd_channel */

enum cbdc_blkdev_state {
	cbdc_blkdev_state_none		= 0,
	cbdc_blkdev_state_running,
};

enum cbdc_backend_state {
	cbdc_backend_state_none		= 0,
	cbdc_backend_state_running,
};

struct cbd_channel_info {
	struct cbd_segment_info seg_info;	/* must be the first member */
	u8	blkdev_state;
	u32	blkdev_id;

	u8	backend_state;
	u32	backend_id;

	u32	polling:1;

	u32	submr_head;
	u32	submr_tail;

	u32	compr_head;
	u32	compr_tail;
};

struct cbd_channel {
	u32				seg_id;
	struct cbd_segment		segment;

	struct cbd_channel_info		*channel_info;

	struct cbd_transport		*cbdt;

	void				*submr;
	void				*compr;

	u32				submr_size;
	u32				compr_size;

	u32				data_size;
	u32				data_head;
	u32				data_tail;

	spinlock_t			submr_lock;
	spinlock_t			compr_lock;
};

void cbd_channel_init(struct cbd_channel *channel, struct cbd_transport *cbdt, u32 seg_id);
void cbd_channel_exit(struct cbd_channel *channel);
void cbdc_copy_from_bio(struct cbd_channel *channel,
		u32 data_off, u32 data_len, struct bio *bio, u32 bio_off);
void cbdc_copy_to_bio(struct cbd_channel *channel,
		u32 data_off, u32 data_len, struct bio *bio, u32 bio_off);
u32 cbd_channel_crc(struct cbd_channel *channel, u32 data_off, u32 data_len);
int cbdc_map_pages(struct cbd_channel *channel, struct cbd_backend_io *io);
int cbd_get_empty_channel_id(struct cbd_transport *cbdt, u32 *id);
ssize_t cbd_channel_seg_detail_show(struct cbd_channel_info *channel_info, char *buf);

/* cbd cache */
struct cbd_cache_seg_info {
	struct cbd_segment_info segment_info;	/* first member */
	u32 backend_id;
	u32 flags;
	u32 next_cache_seg_id;		/* index in cache->segments */
	u64 gen;
};

#define CBD_CACHE_SEG_FLAGS_HAS_NEXT	(1 << 0)
#define CBD_CACHE_SEG_FLAGS_WB_DONE	(1 << 1)
#define CBD_CACHE_SEG_FLAGS_GC_DONE	(1 << 2)

struct cbd_cache_segment {
	struct cbd_cache	*cache;
	u32			cache_seg_id;	/* index in cache->segments */
	u32			used;
	spinlock_t		gen_lock;
	struct cbd_cache_seg_info *cache_seg_info;
	struct cbd_segment	segment;
	atomic_t		refs;
};

struct cbd_cache_pos {
	struct cbd_cache_segment *cache_seg;
	u32		seg_off;
};

struct cbd_cache_pos_onmedia {
	u32 cache_seg_id;
	u32 seg_off;
};

struct cbd_cache_info {
	u8	blkdev_state;
	u32	blkdev_id;

	u32	seg_id;
	u32	n_segs;

	u32	used_segs;
	u16	gc_percent;

	struct cbd_cache_pos_onmedia key_tail_pos;
	struct cbd_cache_pos_onmedia dirty_tail_pos;
};

struct cbd_cache_tree {
	struct rb_root			root;
	spinlock_t			tree_lock;
};

struct cbd_cache_data_head {
	spinlock_t			data_head_lock;
	struct cbd_cache_pos		head_pos;
};

struct cbd_cache_key {
	struct cbd_cache *cache;
	struct cbd_cache_tree *cache_tree;
	struct kref ref;

	struct rb_node rb_node;
	struct list_head list_node;

	u64		off;
	u32		len;
	u64		flags;

	struct cbd_cache_pos	cache_pos;

	u64		seg_gen;
#ifdef CONFIG_CBD_CRC
	u32	data_crc;
#endif
};

#define CBD_CACHE_KEY_FLAGS_EMPTY	(1 << 0)
#define CBD_CACHE_KEY_FLAGS_CLEAN	(1 << 1)

struct cbd_cache_key_onmedia {
	u64	off;
	u32	len;

	u32	flags;

	u32	cache_seg_id;
	u32	cache_seg_off;

	u64	seg_gen;
#ifdef CONFIG_CBD_CRC
	u32	data_crc;
#endif
};

struct cbd_cache_kset_onmedia {
	u32	crc;
	u64	magic;
	u64	flags;
	u32	key_num;
	struct cbd_cache_key_onmedia	data[];
};

#define CBD_KSET_FLAGS_LAST	(1 << 0)

#define CBD_KSET_MAGIC		0x676894a64e164f1aULL

struct cbd_cache_kset {
	struct cbd_cache		*cache;
	spinlock_t			kset_lock;
	struct delayed_work		flush_work;
	struct cbd_cache_kset_onmedia	kset_onmedia;
};

enum cbd_cache_state {
	cbd_cache_state_none = 0,
	cbd_cache_state_running,
	cbd_cache_state_stopping
};

struct cbd_cache {
	struct cbd_transport		*cbdt;
	struct cbd_cache_info		*cache_info;
	u32				cache_id;	/* same with related backend->backend_id */

	u32				n_heads;
	struct cbd_cache_data_head	*data_heads;

	spinlock_t			key_head_lock;
	struct cbd_cache_pos		key_head;
	u32				n_ksets;
	struct cbd_cache_kset		*ksets;

	struct cbd_cache_pos		key_tail;
	struct cbd_cache_pos		dirty_tail;

	struct kmem_cache		*key_cache;
	u32				n_trees;
	struct cbd_cache_tree		*cache_trees;
	struct work_struct		clean_work;

	spinlock_t			miss_read_reqs_lock;
	struct list_head		miss_read_reqs;
	struct work_struct		miss_read_end_work;

	struct workqueue_struct		*cache_wq;

	struct file			*bdev_file;
	u64				dev_size;
	struct delayed_work		writeback_work;
	struct delayed_work		gc_work;
	struct bio_set			*bioset;

	struct kmem_cache		*req_cache;

	u32				state:8;
	u32				init_keys:1;
	u32				start_writeback:1;
	u32				start_gc:1;

	u32				n_segs;
	unsigned long			*seg_map;
	u32				last_cache_seg;
	spinlock_t			seg_map_lock;
	struct cbd_cache_segment	segments[]; /* should be the last member */
};

struct cbd_request;
struct cbd_cache_opts {
	struct cbd_cache_info *cache_info;
	bool alloc_segs;
	bool start_writeback;
	bool start_gc;
	bool init_keys;
	u64 dev_size;
	u32 n_paral;
	struct file *bdev_file;	/* needed for start_writeback is true */
};

struct cbd_cache *cbd_cache_alloc(struct cbd_transport *cbdt,
				  struct cbd_cache_opts *opts);
void cbd_cache_destroy(struct cbd_cache *cache);
int cbd_cache_handle_req(struct cbd_cache *cache, struct cbd_request *cbd_req);

/* cbd_handler */
struct cbd_handler {
	struct cbd_backend	*cbdb;
	struct cbd_channel_info *channel_info;

	struct cbd_channel	channel;
	spinlock_t		compr_lock;

	u32			se_to_handle;
	u64			req_tid_expected;

	u32			polling:1;

	struct delayed_work	handle_work;
	struct cbd_worker_cfg	handle_worker_cfg;

	struct hlist_node	hash_node;
	struct bio_set		bioset;
};

void cbd_handler_destroy(struct cbd_handler *handler);
int cbd_handler_create(struct cbd_backend *cbdb, u32 seg_id);
void cbd_handler_notify(struct cbd_handler *handler);

/* cbd_backend */
CBD_DEVICE(backend);

enum cbd_backend_state {
	cbd_backend_state_none	= 0,
	cbd_backend_state_running,
	cbd_backend_state_removing
};

#define CBDB_BLKDEV_COUNT_MAX	1

struct cbd_backend_info {
	u8			state;
	u32			host_id;
	u64			alive_ts;
	u64			dev_size; /* nr_sectors */
	struct cbd_cache_info	cache_info;

	u32			blkdevs[CBDB_BLKDEV_COUNT_MAX];
	char			path[CBD_PATH_LEN];
};

struct cbd_backend_io {
	struct cbd_se		*se;
	u64			off;
	u32			len;
	struct bio		*bio;
	struct cbd_handler	*handler;
};

#define CBD_BACKENDS_HANDLER_BITS	7

struct cbd_backend {
	u32			backend_id;
	char			path[CBD_PATH_LEN];
	struct cbd_transport	*cbdt;
	struct cbd_backend_info *backend_info;
	spinlock_t		lock;

	struct block_device	*bdev;
	struct file		*bdev_file;

	struct workqueue_struct	*task_wq;
	struct delayed_work	state_work;
	struct delayed_work	hb_work; /* heartbeat work */

	struct list_head	node; /* cbd_transport->backends */
	DECLARE_HASHTABLE(handlers_hash, CBD_BACKENDS_HANDLER_BITS);

	struct cbd_backend_device *backend_device;

	struct kmem_cache	*backend_io_cache;

	struct cbd_cache	*cbd_cache;
	struct device		cache_dev;
	bool			cache_dev_registered;
};

int cbd_backend_start(struct cbd_transport *cbdt, char *path, u32 backend_id, u32 cache_segs);
int cbd_backend_stop(struct cbd_transport *cbdt, u32 backend_id);
int cbd_backend_clear(struct cbd_transport *cbdt, u32 backend_id);
int cbdb_add_handler(struct cbd_backend *cbdb, struct cbd_handler *handler);
void cbdb_del_handler(struct cbd_backend *cbdb, struct cbd_handler *handler);
bool cbd_backend_info_is_alive(struct cbd_backend_info *info);
bool cbd_backend_cache_on(struct cbd_backend_info *backend_info);
void cbd_backend_notify(struct cbd_backend *cbdb, u32 seg_id);

/* cbd_queue */
enum cbd_op {
	CBD_OP_WRITE = 0,
	CBD_OP_READ,
	CBD_OP_FLUSH,
};

struct cbd_se {
#ifdef CONFIG_CBD_CRC
	u32			se_crc;		/* should be the first member */
	u32			data_crc;
#endif
	u32			op;
	u32			flags;
	u64			req_tid;

	u64			offset;
	u32			len;

	u32			data_off;
	u32			data_len;
};

struct cbd_ce {
#ifdef CONFIG_CBD_CRC
	u32		ce_crc;		/* should be the first member */
	u32		data_crc;
#endif
	u64		req_tid;
	u32		result;
	u32		flags;
};

#ifdef CONFIG_CBD_CRC
static inline u32 cbd_se_crc(struct cbd_se *se)
{
	return crc32(0, (void *)se + 4, sizeof(*se) - 4);
}

static inline u32 cbd_ce_crc(struct cbd_ce *ce)
{
	return crc32(0, (void *)ce + 4, sizeof(*ce) - 4);
}
#endif

struct cbd_request {
	struct cbd_queue	*cbdq;

	struct cbd_se		*se;
	struct cbd_ce		*ce;
	struct request		*req;

	u64			off;
	struct bio		*bio;
	u32			bio_off;
	spinlock_t		lock; /* race between cache and complete_work to access bio */

	enum cbd_op		op;
	u64			req_tid;
	struct list_head	inflight_reqs_node;

	u32			data_off;
	u32			data_len;

	struct work_struct	work;

	struct kref		ref;
	int			ret;
	struct cbd_request	*parent;

	void			*priv_data;
	void (*end_req)(struct cbd_request *cbd_req, void *priv_data);
};

struct cbd_cache_req {
	struct cbd_cache	*cache;
	enum cbd_op		op;
	struct work_struct	work;
};

#define CBD_SE_FLAGS_DONE	1

static inline bool cbd_se_flags_test(struct cbd_se *se, u32 bit)
{
	return (se->flags & bit);
}

static inline void cbd_se_flags_set(struct cbd_se *se, u32 bit)
{
	se->flags |= bit;
}

enum cbd_queue_state {
	cbd_queue_state_none	= 0,
	cbd_queue_state_running,
	cbd_queue_state_removing
};

struct cbd_queue {
	struct cbd_blkdev	*cbd_blkdev;
	u32			index;
	struct list_head	inflight_reqs;
	spinlock_t		inflight_reqs_lock;
	u64			req_tid;

	u64			*released_extents;

	struct cbd_channel_info	*channel_info;
	struct cbd_channel	channel;

	atomic_t		state;

	struct delayed_work	complete_work;
	struct cbd_worker_cfg	complete_worker_cfg;
};

int cbd_queue_start(struct cbd_queue *cbdq);
void cbd_queue_stop(struct cbd_queue *cbdq);
extern const struct blk_mq_ops cbd_mq_ops;
int cbd_queue_req_to_backend(struct cbd_request *cbd_req);
void cbd_req_get(struct cbd_request *cbd_req);
void cbd_req_put(struct cbd_request *cbd_req, int ret);
void cbd_queue_advance(struct cbd_queue *cbdq, struct cbd_request *cbd_req);

/* cbd_blkdev */
CBD_DEVICE(blkdev);

enum cbd_blkdev_state {
	cbd_blkdev_state_none	= 0,
	cbd_blkdev_state_running,
};

struct cbd_blkdev_info {
	u8	state;
	u64	alive_ts;
	u32	backend_id;
	u32	host_id;
	u32	mapped_id;
	u32	devid_in_backend;
};

struct cbd_blkdev {
	u32			blkdev_id; /* index in transport blkdev area */
	u32			backend_id;
	int			mapped_id; /* id in block device such as: /dev/cbd0 */

	struct cbd_backend	*backend; /* reference to backend if blkdev and backend on the same host */

	int			major;		/* blkdev assigned major */
	int			minor;
	struct gendisk		*disk;		/* blkdev's gendisk and rq */

	struct mutex		lock;
	unsigned long		open_count;	/* protected by lock */

	struct list_head	node;
	struct delayed_work	hb_work; /* heartbeat work */

	/* Block layer tags. */
	struct blk_mq_tag_set	tag_set;

	uint32_t		num_queues;
	struct cbd_queue	*queues;

	u64			dev_size;

	struct workqueue_struct	*task_wq;

	struct cbd_blkdev_device *blkdev_dev;
	struct cbd_blkdev_info *blkdev_info;

	struct cbd_transport *cbdt;

	struct cbd_cache	*cbd_cache;
};

int cbd_blkdev_init(void);
void cbd_blkdev_exit(void);
int cbd_blkdev_start(struct cbd_transport *cbdt, u32 backend_id, u32 queues);
int cbd_blkdev_stop(struct cbd_transport *cbdt, u32 devid, bool force);
int cbd_blkdev_clear(struct cbd_transport *cbdt, u32 devid);
bool cbd_blkdev_info_is_alive(struct cbd_blkdev_info *info);

extern struct workqueue_struct	*cbd_wq;

#define cbd_setup_device(DEV, PARENT, TYPE, fmt, ...)		\
do {								\
	device_initialize(DEV);					\
	device_set_pm_not_required(DEV);			\
	dev_set_name(DEV, fmt, ##__VA_ARGS__);			\
	DEV->parent = PARENT;					\
	DEV->type = TYPE;					\
								\
	ret = device_add(DEV);					\
} while (0)

#define CBD_OBJ_HEARTBEAT(OBJ)								\
static void OBJ##_hb_workfn(struct work_struct *work)					\
{											\
	struct cbd_##OBJ *obj = container_of(work, struct cbd_##OBJ, hb_work.work);	\
	struct cbd_##OBJ##_info *info = obj->OBJ##_info;				\
											\
	info->alive_ts = ktime_get_real();						\
											\
	queue_delayed_work(cbd_wq, &obj->hb_work, CBD_HB_INTERVAL);			\
}											\
											\
bool cbd_##OBJ##_info_is_alive(struct cbd_##OBJ##_info *info)				\
{											\
	ktime_t oldest, ts;								\
											\
	ts = info->alive_ts;								\
	oldest = ktime_sub_ms(ktime_get_real(), CBD_HB_TIMEOUT);			\
											\
	if (ktime_after(ts, oldest))							\
		return true;								\
											\
	return false;									\
}											\
											\
static ssize_t cbd_##OBJ##_alive_show(struct device *dev,				\
			       struct device_attribute *attr,				\
			       char *buf)						\
{											\
	struct cbd_##OBJ##_device *_dev;						\
											\
	_dev = container_of(dev, struct cbd_##OBJ##_device, dev);			\
											\
	if (cbd_##OBJ##_info_is_alive(_dev->OBJ##_info))				\
		return sprintf(buf, "true\n");						\
											\
	return sprintf(buf, "false\n");							\
}											\
											\
static DEVICE_ATTR(alive, 0400, cbd_##OBJ##_alive_show, NULL)

#endif /* _CBD_INTERNAL_H */
