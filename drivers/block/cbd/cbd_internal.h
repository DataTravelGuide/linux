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

/*
 * As shared memory is supported in CXL3.0 spec, we can transfer data via CXL shared memory.
 * CBD means CXL block device, it use CXL shared memory to transport command and data to
 * access block device in different host, as shown below:
 *
 *    +-------------------------------+                               +------------------------------------+
 *    |          node-1               |                               |              node-2                |
 *    +-------------------------------+                               +------------------------------------+
 *    |                               |                               |                                    |
 *    |                       +-------+                               +---------+                          |
 *    |                       | cbd0  |                               | backend0+------------------+       |
 *    |                       +-------+                               +---------+                  |       |
 *    |                       | pmem0 |                               | pmem0   |                  v       |
 *    |               +-------+-------+                               +---------+----+     +---------------+
 *    |               |    cxl driver |                               | cxl driver   |     |   /dev/sda    |
 *    +---------------+--------+------+                               +-----+--------+-----+---------------+
 *                             |                                            |
 *                             |                                            |
 *                             |        CXL                         CXL     |
 *                             +----------------+               +-----------+
 *                                              |               |
 *                                              |               |
 *                                              |               |
 *                                          +---+---------------+-----+
 *                                          |   shared memory device  |
 *                                          +-------------------------+
 * any read/write to cbd0 on node-1 will be transferred to node-2 /dev/sda. It works similar with
 * nbd (network block device), but it transfer data via CXL shared memory rather than network.
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
	cbd_blk_err(queue->cbd_blkdev, "queue-%d: " fmt,			\
		     queue->index, ##__VA_ARGS__)
#define cbd_queue_info(queue, fmt, ...)						\
	cbd_blk_info(queue->cbd_blkdev, "queue-%d: " fmt,			\
		     queue->index, ##__VA_ARGS__)
#define cbd_queue_debug(queue, fmt, ...)					\
	cbd_blk_debug(queue->cbd_blkdev, "queue-%d: " fmt,			\
		     queue->index, ##__VA_ARGS__)

#define cbd_channel_err(channel, fmt, ...)					\
	cbdt_err(channel->cbdt, "channel%d: " fmt,				\
		 channel->seg_id, ##__VA_ARGS__)
#define cbd_channel_info(channel, fmt, ...)					\
	cbdt_info(channel->cbdt, "channel%d: " fmt,				\
		 channel->seg_id, ##__VA_ARGS__)
#define cbd_channel_debug(channel, fmt, ...)					\
	cbdt_debug(channel->cbdt, "channel%d: " fmt,				\
		 channel->seg_id, ##__VA_ARGS__)

#define KB	(1024)
#define MB	(KB * KB)

#define CBD_TRANSPORT_MAX	1024
#define CBD_PATH_LEN	512
#define CBD_NAME_LEN	32

/* TODO support multi queue */
#define CBD_QUEUES_MAX		1

#define CBD_PART_SHIFT 4
#define CBD_DRV_NAME "cbd"
#define CBD_DEV_NAME_LEN 32

#define CBD_HB_INTERVAL		msecs_to_jiffies(5000) /* 5s */
#define CBD_HB_TIMEOUT		(30 * 1000) /* 30s */

/*
 * CBD transport layout:
 *
 *      +-------------------------------------------------------------------------------------------------------------------------------+
 *      |                           cbd transport                                                                                       |
 *      +--------------------+-----------------------+-----------------------+----------------------+-----------------------------------+
 *      |                    |       hosts           |      backends         |       blkdevs        |        segments                   |
 *      | cbd transport info +----+----+----+--------+----+----+----+--------+----+----+----+-------+-------+-------+-------+-----------+
 *      |                    |    |    |    |  ...   |    |    |    |  ...   |    |    |    |  ...  |       |       |       |   ...     |
 *      +--------------------+----+----+----+--------+----+----+----+--------+----+----+----+-------+---+---+-------+-------+-----------+
 *                                                                                                      |
 *                                                                                                      |
 *                                                                                                      |
 *                                                                                                      |
 *                +-------------------------------------------------------------------------------------+
 *                |
 *                |
 *                v
 *          +-----------------------------------------------------------+
 *          |                     channel seg                           |
 *          +--------------------+--------------------------------------+
 *          |    channel meta    |              channel data            |
 *          +---------+----------+--------------------------------------+
 *                    |
 *                    |
 *                    |
 *                    v
 *          +----------------------------------------------------------+
 *          |                 channel meta                             |
 *          +-----------+--------------+-------------------------------+
 *          | meta ctrl |  comp ring   |       subm ring               |
 *          +-----------+--------------+-------------------------------+
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

#define CBDC_UPDATE_SUBMR_HEAD(head, used, size) smp_store_release(&head, ((head % size) + used) % size)
#define CBDC_UPDATE_SUBMR_TAIL(tail, used, size) smp_store_release(&tail, ((tail % size) + used) % size)

#define CBDC_UPDATE_COMPR_HEAD(head, used, size) smp_store_release(&head, ((head % size) + used) % size)
#define CBDC_UPDATE_COMPR_TAIL(tail, used, size) smp_store_release(&tail, ((tail % size) + used) % size)

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
 *                                        +--------------+
 *                                        | cbd_transport|                                               +----------+
 *                                        +--------------+                                               | cbd_host |
 *                                        |              |                                               +----------+
 *                                        |   host       +---------------------------------------------->|          |
 *                   +--------------------+   backends   |                                               | hostname |
 *                   |                    |   devices    +------------------------------------------+    |          |
 *                   |                    |              |                                          |    +----------+
 *                   |                    +--------------+                                          |
 *                   |                                                                              |
 *                   |                                                                              |
 *                   |                                                                              |
 *                   |                                                                              |
 *                   |                                                                              |
 *                   v                                                                              v
 *             +------------+     +-----------+     +------+                                  +-----------+      +-----------+     +------+
 *             | cbd_backend+---->|cbd_backend+---->| NULL |                                  | cbd_blkdev+----->| cbd_blkdev+---->| NULL |
 *             +------------+     +-----------+     +------+                                  +-----------+      +-----------+     +------+
 *      +------+  handlers  |     |  handlers |                                        +------+  queues   |      |  queues   |
 *      |      +------------+     +-----------+                                        |      +-----------+      +-----------+
 *      |                                                                              |
 *      |                                                                              |
 *      |                                                                              |
 *      |                                                                              |
 *      |      +-------------+       +-------------+           +------+                |      +-----------+      +-----------+     +------+
 *      +----->| cbd_handler +------>| cbd_handler +---------->| NULL |                +----->| cbd_queue +----->| cbd_queue +---->| NULL |
 *             +-------------+       +-------------+           +------+                       +-----------+      +-----------+     +------+
 *      +------+ channel     |       |   channel   |                                   +------+  channel  |      |  channel  |
 *      |      +-------------+       +-------------+                                   |      +-----------+      +-----------+
 *      |                                                                              |
 *      |                                                                              |
 *      |                                                                              |
 *      |                                                                              v
 *      |                                                        +-----------------------+
 *      +------------------------------------------------------->|      cbd_channel      |
 *                                                               +-----------------------+
 *                                                               | seg_id                |
 *                                                               | submr (submit ring)   |
 *                                                               | compr (complete ring) |
 *                                                               | data (data area)      |
 *                                                               |                       |
 *                                                               +-----------------------+
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
	cbd_host_state_running
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

int cbd_host_register(struct cbd_transport *cbdt, char *hostname);
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
		u32 data_off, u32 data_len, struct bio *bio);
void cbds_copy_from_bio(struct cbd_segment *segment,
		u32 data_off, u32 data_len, struct bio *bio);
u32 cbd_seg_crc(struct cbd_segment *segment, u32 data_off, u32 data_len);
int cbds_map_pages(struct cbd_segment *segment, struct cbd_backend_io *io);

/* cbd_channel */

enum cbdc_blkdev_state {
	cbdc_blkdev_state_none		= 0,
	cbdc_blkdev_state_running,
	cbdc_blkdev_state_stopped,
};

enum cbdc_backend_state {
	cbdc_backend_state_none		= 0,
	cbdc_backend_state_running,
	cbdc_backend_state_stopped,
};

struct cbd_channel_info {
	struct cbd_segment_info seg_info;	/* must be the first member */
	u8	blkdev_state;
	u32	blkdev_id;

	u8	backend_state;
	u32	backend_id;

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
		u32 data_off, u32 data_len, struct bio *bio);
void cbdc_copy_to_bio(struct cbd_channel *channel,
		u32 data_off, u32 data_len, struct bio *bio);
u32 cbd_channel_crc(struct cbd_channel *channel, u32 data_off, u32 data_len);
int cbdc_map_pages(struct cbd_channel *channel, struct cbd_backend_io *io);
int cbd_get_empty_channel_id(struct cbd_transport *cbdt, u32 *id);
ssize_t cbd_channel_seg_detail_show(struct cbd_channel_info *channel_info, char *buf);

/* cbd cache */
struct cbd_cache_seg_info {
	struct cbd_segment_info segment_info;	/* first member */
};

enum cbd_cache_blkdev_state {
	cbd_cache_blkdev_state_none = 0,
	cbd_cache_blkdev_state_running
};

struct cbd_cache_pos {
	u32	cache_seg_id;	/* index in cache->segments */
	u32	seg_off;
};

struct cbd_cache_info {
	u8	blkdev_state;
	u32	blkdev_id;

	u32	seg_id;
	u32	n_segs;

	struct cbd_cache_pos key_tail_pos;
	struct cbd_cache_pos dirty_tail_pos;
	u32	lats_key_epoch;
};

struct cbd_cache {
	struct cbd_transport		*cbdt;
	struct cbd_cache_info		*cache_info;

	struct cbd_cache_pos		data_head;
	struct cbd_cache_pos		key_head;

	struct kmem_cache		*key_cache;
	struct rb_root			cache_tree;

	u32				n_segs;
	unsigned long			*seg_map;
	spinlock_t			seg_map_lock;
	struct cbd_segment		segments[];
};

struct cbd_request;
struct cbd_cache *cbd_cache_alloc(struct cbd_transport *cbdt,
				  struct cbd_cache_info *cache_info,
				  bool alloc_seg);
void cbd_cache_destroy(struct cbd_cache *cache);
int cbd_cache_handle_req(struct cbd_cache *cache, struct cbd_request *cbd_req);

/* cbd_handler */
struct cbd_handler {
	struct cbd_backend	*cbdb;
	struct cbd_channel_info *channel_info;

	struct cbd_channel	channel;

	u32			se_to_handle;
	u64			req_tid_expected;

	struct delayed_work	handle_work;
	struct cbd_worker_cfg	handle_worker_cfg;

	struct list_head	handlers_node;
	struct bio_set		bioset;
};

void cbd_handler_destroy(struct cbd_handler *handler);
int cbd_handler_create(struct cbd_backend *cbdb, u32 seg_id);

/* cbd_backend */
CBD_DEVICE(backend);

enum cbd_backend_state {
	cbd_backend_state_none	= 0,
	cbd_backend_state_running,
};

#define CBDB_BLKDEV_COUNT_MAX	1

struct cbd_backend_info {
	u8			state;
	u32			host_id;
	u32			blkdev_count;
	u64			alive_ts;
	u64			dev_size; /* nr_sectors */
	struct cbd_cache_info	cache_info;

	char			path[CBD_PATH_LEN];
};

struct cbd_backend_io {
	struct cbd_se		*se;
	u64			off;
	u32			len;
	struct bio		*bio;
	struct cbd_handler	*handler;
};

struct cbd_backend {
	u32			backend_id;
	char			path[CBD_PATH_LEN];
	struct cbd_transport	*cbdt;
	struct cbd_backend_info *backend_info;
	struct mutex		lock;

	struct block_device	*bdev;
	struct file		*bdev_file;

	struct workqueue_struct	*task_wq;
	struct delayed_work	state_work;
	struct delayed_work	hb_work; /* heartbeat work */

	struct list_head	node; /* cbd_transport->backends */
	struct list_head	handlers;

	struct cbd_backend_device *backend_device;

	struct kmem_cache	*backend_io_cache;

	struct cbd_cache	*cbd_cache;
};

int cbd_backend_start(struct cbd_transport *cbdt, char *path, u32 backend_id, u32 cache_segs);
int cbd_backend_stop(struct cbd_transport *cbdt, u32 backend_id, bool force);
int cbd_backend_clear(struct cbd_transport *cbdt, u32 backend_id);
void cbdb_add_handler(struct cbd_backend *cbdb, struct cbd_handler *handler);
void cbdb_del_handler(struct cbd_backend *cbdb, struct cbd_handler *handler);
bool cbd_backend_info_is_alive(struct cbd_backend_info *info);
bool cbd_backend_cache_on(struct cbd_backend_info *backend_info);

/* cbd_queue */
enum cbd_op {
	CBD_OP_WRITE = 0,
	CBD_OP_READ,
	CBD_OP_DISCARD,
	CBD_OP_WRITE_ZEROES,
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

	enum cbd_op		op;
	u64			req_tid;
	struct list_head	inflight_reqs_node;

	u32			data_off;
	u32			data_len;

	struct work_struct	work;

	struct kref		ref;
	int			ret;
	struct cbd_request	*parent;
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

	int			index;

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

/* cbd_blkdev */
CBD_DEVICE(blkdev);

enum cbd_blkdev_state {
	cbd_blkdev_state_none	= 0,
	cbd_blkdev_state_running,
	cbd_blkdev_state_removing
};

struct cbd_blkdev_info {
	u8	state;
	u64	alive_ts;
	u32	backend_id;
	u32	host_id;
	u32	mapped_id;
};

struct cbd_blkdev {
	u32			blkdev_id; /* index in transport blkdev area */
	u32			backend_id;
	int			mapped_id; /* id in block device such as: /dev/cbd0 */

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

	atomic_t		state;

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
