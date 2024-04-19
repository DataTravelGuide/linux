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

/*
 * As shared memory is supported in CXL3.0 spec, we can transfer data via CXL shared memory.
 * CBD means CXL block device, it use CXL shared memory to transport command and data to
 * access block device in different host, as shown below:
 *
 *    ┌───────────────────────────────┐                               ┌────────────────────────────────────┐
 *    │          node-1               │                               │              node-2                │
 *    ├───────────────────────────────┤                               ├────────────────────────────────────┤
 *    │                               │                               │                                    │
 *    │                       ┌───────┤                               ├─────────┐                          │
 *    │                       │ cbd0  │                               │ backend0├──────────────────┐       │
 *    │                       ├───────┤                               ├─────────┤                  │       │
 *    │                       │ pmem0 │                               │ pmem0   │                  ▼       │
 *    │               ┌───────┴───────┤                               ├─────────┴────┐     ┌───────────────┤
 *    │               │    cxl driver │                               │ cxl driver   │     │  /dev/sda     │
 *    └───────────────┴────────┬──────┘                               └─────┬────────┴─────┴───────────────┘
 *                             │                                            │
 *                             │                                            │
 *                             │        CXL                         CXL     │
 *                             └────────────────┐               ┌───────────┘
 *                                              │               │
 *                                              │               │
 *                                              │               │
 *                                          ┌───┴───────────────┴─────┐
 *                                          │   shared memory device  │
 *                                          └─────────────────────────┘
 *
 * any read/write to cbd0 on node-1 will be transferred to node-2 /dev/sda. It works similar with
 * nbd (network block device), but it transfer data via CXL shared memory rather than network.
 */

/* printk */
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

#define cbd_backend_err(backend, fmt, ...)					\
	cbdt_err(backend->cbdt, "backend%d: " fmt,				\
		 backend->backend_id, ##__VA_ARGS__)
#define cbd_backend_info(backend, fmt, ...)					\
	cbdt_info(backend->cbdt, "backend%d: " fmt,				\
		 backend->backend_id, ##__VA_ARGS__)
#define cbd_backend_debug(backend, fmt, ...)					\
	cbdt_debug(backend->cbdt, "backend%d: " fmt,				\
		 backend->backend_id, ##__VA_ARGS__)

#define cbd_handler_err(handler, fmt, ...)					\
	cbd_backend_err(handler->cbdb, "handler%d: " fmt,			\
		 handler->channel.channel_id, ##__VA_ARGS__)
#define cbd_handler_info(handler, fmt, ...)					\
	cbd_backend_info(handler->cbdb, "handler%d: " fmt,			\
		 handler->channel.channel_id, ##__VA_ARGS__)
#define cbd_handler_debug(handler, fmt, ...)					\
	cbd_backend_debug(handler->cbdb, "handler%d: " fmt,			\
		 handler->channel.channel_id, ##__VA_ARGS__)

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
		 channel->channel_id, ##__VA_ARGS__)
#define cbd_channel_info(channel, fmt, ...)					\
	cbdt_info(channel->cbdt, "channel%d: " fmt,				\
		 channel->channel_id, ##__VA_ARGS__)
#define cbd_channel_debug(channel, fmt, ...)					\
	cbdt_debug(channel->cbdt, "channel%d: " fmt,				\
		 channel->channel_id, ##__VA_ARGS__)

#define CBD_PAGE_SHIFT		12
#define CBD_PAGE_SIZE		(1 << CBD_PAGE_SHIFT)
#define CBD_PAGE_MASK		(CBD_PAGE_SIZE - 1)

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
 *      |                    |       hosts           |      backends         |       blkdevs        |        channels                   |
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
 *          |                     channel                               |
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
 *          | meta ctrl |  comp ring   |       cmd ring                |
 *          +-----------+--------------+-------------------------------+
 */

/* cbd channel */
#define CBD_OP_ALIGN_SIZE	sizeof(u64)
#define CBDC_META_SIZE		(1024 * CBD_PAGE_SIZE)
#define CBDC_CMDR_RESERVED	CBD_OP_ALIGN_SIZE
#define CBDC_CMPR_RESERVED	sizeof(struct cbd_ce)

#define CBDC_CTRL_OFF		0
#define CBDC_CTRL_SIZE		CBD_PAGE_SIZE
#define CBDC_COMPR_OFF		(CBDC_CTRL_OFF + CBDC_CTRL_SIZE)
#define CBDC_COMPR_SIZE		(sizeof(struct cbd_ce) * 1024)
#define CBDC_CMDR_OFF		(CBDC_COMPR_OFF + CBDC_COMPR_SIZE)
#define CBDC_CMDR_SIZE		(CBDC_META_SIZE - CBDC_CMDR_OFF)

#define CBDC_DATA_OFF		(CBDC_CMDR_OFF + CBDC_CMDR_SIZE)
#define CBDC_DATA_SIZE		(16 * 1024 * 1024)
#define CBDC_DATA_MASK		0xFFFFFF

#define CBDC_UPDATE_CMDR_HEAD(head, used, size) (head = ((head % size) + used) % size)
#define CBDC_UPDATE_CMDR_TAIL(tail, used, size) (tail = ((tail % size) + used) % size)

#define CBDC_UPDATE_COMPR_HEAD(head, used, size) (head = ((head % size) + used) % size)
#define CBDC_UPDATE_COMPR_TAIL(tail, used, size) (tail = ((tail % size) + used) % size)

/* cbd transport */
#define CBD_TRANSPORT_MAGIC		0x9a6c676896C596EFULL
#define CBD_TRANSPORT_VERSION		1

#define CBDT_INFO_OFF			0
#define CBDT_INFO_SIZE			CBD_PAGE_SIZE

#define CBDT_HOST_AREA_OFF		(CBDT_INFO_OFF + CBDT_INFO_SIZE)
#define CBDT_HOST_INFO_SIZE		CBD_PAGE_SIZE
#define CBDT_HOST_NUM			16

#define CBDT_BACKEND_AREA_OFF		(CBDT_HOST_AREA_OFF + (CBDT_HOST_INFO_SIZE * CBDT_HOST_NUM))
#define CBDT_BACKEND_INFO_SIZE		CBD_PAGE_SIZE
#define CBDT_BACKEND_NUM		16

#define CBDT_BLKDEV_AREA_OFF		(CBDT_BACKEND_AREA_OFF + (CBDT_BACKEND_INFO_SIZE * CBDT_BACKEND_NUM))
#define CBDT_BLKDEV_INFO_SIZE		CBD_PAGE_SIZE
#define CBDT_BLKDEV_NUM			16

#define CBDT_CHANNEL_AREA_OFF		(CBDT_BLKDEV_AREA_OFF + (CBDT_BLKDEV_INFO_SIZE * CBDT_BLKDEV_NUM))
#define CBDT_CHANNEL_SIZE		(CBDC_META_SIZE + CBDC_DATA_SIZE)
#define CBDT_CHANNEL_NUM		16

#define CBD_TRASNPORT_SIZE		(CBDT_CHANNEL_AREA_OFF + CBDT_CHANNEL_SIZE * CBDT_CHANNEL_NUM)

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
 *                                                               | channel_id            |
 *                                                               | cmdr (cmd ring)       |
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
};


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

	return;
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

	return;
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
#define CBDT_INFO_F_BIGENDIAN		1 << 0

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

	u64 channel_area_off;
	u32 channel_size;
	u32 channel_num;
};

struct cbd_transport {
	u16	id;
	struct device device;
	struct mutex lock;

	struct cbd_transport_info *transport_info;

	struct cbd_host *host;
	struct list_head backends;
	struct list_head devices;

	struct cbd_hosts_device *cbd_hosts_dev;
	struct cbd_channels_device *cbd_channels_dev;
	struct cbd_backends_device *cbd_backends_dev;
	struct cbd_blkdevs_device *cbd_blkdevs_dev;

	struct dax_device *dax_dev;
	struct bdev_handle   *bdev_handle;
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

int cbdt_register(struct cbdt_register_options *opts);
int cbdt_unregister(u32 transport_id);

struct cbd_host_info *cbdt_get_host_info(struct cbd_transport *cbdt, u32 id);
struct cbd_backend_info *cbdt_get_backend_info(struct cbd_transport *cbdt, u32 id);
struct cbd_blkdev_info *cbdt_get_blkdev_info(struct cbd_transport *cbdt, u32 id);
struct cbd_channel_info *cbdt_get_channel_info(struct cbd_transport *cbdt, u32 id);

int cbdt_get_empty_host_id(struct cbd_transport *cbdt, u32 *id);
int cbdt_get_empty_backend_id(struct cbd_transport *cbdt, u32 *id);
int cbdt_get_empty_blkdev_id(struct cbd_transport *cbdt, u32 *id);
int cbdt_get_empty_channel_id(struct cbd_transport *cbdt, u32 *id);

void cbdt_add_backend(struct cbd_transport *cbdt, struct cbd_backend *cbdb);
void cbdt_del_backend(struct cbd_transport *cbdt, struct cbd_backend *cbdb);
struct cbd_backend *cbdt_get_backend(struct cbd_transport *cbdt, u32 id);
void cbdt_add_blkdev(struct cbd_transport *cbdt, struct cbd_blkdev *blkdev);
struct cbd_blkdev *cbdt_fetch_blkdev(struct cbd_transport *cbdt, u32 id);

struct page *cbdt_page(struct cbd_transport *cbdt, u64 transport_off);
void cbdt_flush_range(struct cbd_transport *cbdt, void *pos, u64 size);

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

/* cbd_channel */
CBD_DEVICE(channel);

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

enum cbd_channel_state {
	cbd_channel_state_none		= 0,
	cbd_channel_state_running,
};

struct cbd_channel_info {
	u8	state;

	u8	blkdev_state;
	u32	blkdev_id;

	u8	backend_state;
	u32	backend_id;

	u32	cmdr_off;
	u32 	cmdr_size;
	u32 	cmd_head;
	u32 	cmd_tail;

	u32 	compr_head;
	u32 	compr_tail;
	u32 	compr_off;
	u32 	compr_size;
};

struct cbd_channel {
	u32				channel_id;
	struct cbd_channel_deivce	*dev;
	struct cbd_channel_info		*channel_info;

	struct cbd_transport		*cbdt;

	struct page			*ctrl_page;

	void				*cmdr;
	void				*compr;
	void				*data;

	u32				data_size;
	u32				data_head;
	u32				data_tail;

	spinlock_t			cmdr_lock;
	spinlock_t			compr_lock;
};

void cbd_channel_init(struct cbd_channel *channel, struct cbd_transport *cbdt, u32 channel_id);
void cbdc_copy_from_bio(struct cbd_channel *channel,
		u32 data_off, u32 data_len, struct bio *bio);
void cbdc_copy_to_bio(struct cbd_channel *channel,
		u32 data_off, u32 data_len, struct bio *bio);
void cbdc_flush_ctrl(struct cbd_channel *channel);

/* cbd_handler */
struct cbd_handler {
	struct cbd_backend	*cbdb;
	struct cbd_channel_info *channel_info;

	struct cbd_channel	channel;

	u32			se_to_handle;

	struct delayed_work	handle_work;
	struct cbd_worker_cfg	handle_worker_cfg;

	struct list_head	handlers_node;
	struct bio_set		bioset;
	struct workqueue_struct *handle_wq;
};

void cbd_handler_destroy(struct cbd_handler *handler);
int cbd_handler_create(struct cbd_backend *cbdb, u32 channel_id);

/* cbd_backend */
CBD_DEVICE(backend);

enum cbd_backend_state {
	cbd_backend_state_none	= 0,
	cbd_backend_state_running,
};

#define CBDB_BLKDEV_COUNT_MAX	1

struct cbd_backend_info {
	u8	state;
	u32	host_id;
	u32	blkdev_count;
	u64	alive_ts;
	u64	dev_size; /* nr_sectors */
	char	path[CBD_PATH_LEN];
};

struct cbd_backend {
	u32			backend_id;
	char			path[CBD_PATH_LEN];
	struct cbd_transport	*cbdt;
	struct cbd_backend_info *backend_info;
	struct mutex 		lock;

	struct block_device	*bdev;
	struct bdev_handle	*bdev_handle;

	struct workqueue_struct	*task_wq;  /* workqueue for request work */
	struct delayed_work	state_work;
	struct delayed_work	hb_work; /* heartbeat work */

	struct list_head	node; /* cbd_transport->backends */
	struct list_head	handlers;

	struct cbd_backend_device *backend_device;
};

int cbd_backend_start(struct cbd_transport *cbdt, char *path);
int cbd_backend_stop(struct cbd_transport *cbdt, u32 backend_id);
void cbdb_add_handler(struct cbd_backend *cbdb, struct cbd_handler *handler);
void cbdb_del_handler(struct cbd_backend *cbdb, struct cbd_handler *handler);

/* cbd_queue */
enum cbd_op {
	CBD_OP_PAD = 0,
	CBD_OP_WRITE,
	CBD_OP_READ,
	CBD_OP_DISCARD,
	CBD_OP_WRITE_ZEROS,
	CBD_OP_FLUSH,
};

struct cbd_se_hdr {
	u32 len_op;
	u32 flags;

};

struct cbd_se {
	struct cbd_se_hdr	header;
	u64			priv_data;	// pointer to cbd_request

	u64			offset;
	u32			len;

	u32			data_off;
	u32			data_len;
};


struct cbd_ce {
	u64		priv_data;	// copied from submit entry
	u32		result;
	u32		flags;
};


struct cbd_request {
	struct cbd_queue	*cbdq;

	struct cbd_se		*se;
	struct cbd_ce		*ce;
	struct request		*req;

	enum cbd_op		op;
	u64			req_tid;
	struct list_head	inflight_reqs_node;

	u32			data_off;
	u32			data_len;

	struct work_struct	work;
};

#define CBD_OP_MASK 0xff
#define CBD_OP_SHIFT 8

static inline enum cbd_op cbd_se_hdr_get_op(__le32 len_op)
{
       return (enum cbd_op)(len_op & CBD_OP_MASK);
}

static inline void cbd_se_hdr_set_op(u32 *len_op, enum cbd_op op)
{
       *len_op &= ~CBD_OP_MASK;
       *len_op |= (op & CBD_OP_MASK);
}

static inline u32 cbd_se_hdr_get_len(u32 len_op)
{
	return len_op >> CBD_OP_SHIFT;
}

static inline void cbd_se_hdr_set_len(u32 *len_op, u32 len)
{
	*len_op &= CBD_OP_MASK;
	*len_op |= (len << CBD_OP_SHIFT);
}

#define CBD_SE_HDR_DONE	1

static inline bool cbd_se_hdr_flags_test(struct cbd_se *se, u32 bit)
{
	return (se->header.flags & bit);
}

static inline void cbd_se_hdr_flags_set(struct cbd_se *se, u32 bit)
{
	se->header.flags |= bit;
}

enum cbd_queue_state {
	cbd_queue_state_none	= 0,
	cbd_queue_state_running
};

struct cbd_queue {
	struct cbd_blkdev	*cbd_blkdev;

	bool			inited;
	int			index;

	struct list_head	inflight_reqs;
	spinlock_t		inflight_reqs_lock;
	u64			req_tid;

	u32			*released_extents;

	u32			channel_id;
	struct cbd_channel_info	*channel_info;
	struct cbd_channel	channel;
	struct workqueue_struct	*task_wq;  /* workqueue for request work */

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
	cbd_blkdev_state_running
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

	spinlock_t		lock;		/* open_count */
	struct list_head	node;
	struct mutex		state_lock;
	struct delayed_work	hb_work; /* heartbeat work */

	/* Block layer tags. */
	struct blk_mq_tag_set	tag_set;

	unsigned long		open_count;	/* protected by lock */

	uint32_t		num_queues;
	struct cbd_queue	*queues;

	u64			dev_size;
	u64			dev_features;
	u32			io_timeout;

	u8			state;
	u32			state_flags;
	struct kref		kref;

	void			*cmdr;
	void			*compr;
	spinlock_t		cmdr_lock;
	spinlock_t		compr_lock;
	void			*data;

	struct cbd_blkdev_device *blkdev_dev;
	struct cbd_blkdev_info *blkdev_info;

	struct cbd_transport *cbdt;
};

int cbd_blkdev_init(void);
void cbd_blkdev_exit(void);
int cbd_blkdev_start(struct cbd_transport *cbdt, u32 backend_id, u32 queues);
int cbd_blkdev_stop(struct cbd_transport *cbdt, u32 devid);

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
	cbdt_flush_range(obj->cbdt, info, sizeof(*info));				\
											\
	queue_delayed_work(cbd_wq, &obj->hb_work, CBD_HB_INTERVAL);			\
}											\
											\
static bool OBJ##_info_is_alive(struct cbd_##OBJ##_info *info)				\
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
	cbdt_flush_range(_dev->cbdt, _dev->OBJ##_info, sizeof(*_dev->OBJ##_info));	\
	if (OBJ##_info_is_alive(_dev->OBJ##_info))					\
		return sprintf(buf, "true\n");						\
											\
	return sprintf(buf, "false\n");							\
}											\
											\
static DEVICE_ATTR(alive, 0400, cbd_##OBJ##_alive_show, NULL);				\

#endif /* _CBD_INTERNAL_H */
