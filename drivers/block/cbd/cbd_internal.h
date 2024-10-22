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
#define cbdb_debug(backend, fmt, ...)						\
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

#define cbd_segment_err(segment, fmt, ...)					\
	cbdt_err(segment->cbdt, "segment%d: " fmt,				\
		 segment->seg_id, ##__VA_ARGS__)
#define cbd_segment_info(segment, fmt, ...)					\
	cbdt_info(segment->cbdt, "segment%d: " fmt,				\
		 segment->seg_id, ##__VA_ARGS__)
#define cbd_segment_debug(segment, fmt, ...)					\
	cbdt_debug(segment->cbdt, "segment%d: " fmt,				\
		 segment->seg_id, ##__VA_ARGS__)

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
#define CBD_PATH_LEN	128
#define CBD_NAME_LEN	32

#define CBD_QUEUES_MAX		128
#define CBD_HANDLERS_MAX		128

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

#define CBDC_CTRL_OFF		(CBDT_SEG_INFO_SIZE * CBDT_META_INDEX_MAX)
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

#define CBDT_META_INDEX_MAX		2

#define CBDT_INFO_OFF			0
#define CBDT_INFO_SIZE			PAGE_SIZE
#define CBDT_INFO_STRIDE		(CBDT_INFO_SIZE * CBDT_META_INDEX_MAX)

#define CBDT_HOST_INFO_SIZE			round_up(sizeof(struct cbd_host_info), PAGE_SIZE)
#define CBDT_HOST_INFO_STRIDE			(CBDT_HOST_INFO_SIZE * CBDT_META_INDEX_MAX)
#define CBDT_BACKEND_INFO_SIZE			round_up(sizeof(struct cbd_backend_info), PAGE_SIZE)
#define CBDT_BACKEND_INFO_STRIDE		(CBDT_BACKEND_INFO_SIZE * CBDT_META_INDEX_MAX)
#define CBDT_BLKDEV_INFO_SIZE			round_up(sizeof(struct cbd_blkdev_info), PAGE_SIZE)
#define CBDT_BLKDEV_INFO_STRIDE			(CBDT_BLKDEV_INFO_SIZE * CBDT_META_INDEX_MAX)
#define CBDT_SEG_INFO_SIZE			round_up(sizeof(struct cbd_segment_info), PAGE_SIZE)
#define CBDT_SEG_INFO_STRIDE			CBDT_SEG_SIZE

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
	u32 id;						\
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

/* cbd metadata */
struct cbd_meta_header {
	u32			crc;
	u8			seq;
	u8			version;
	u16			res;
};

static inline u32 cbd_meta_crc(struct cbd_meta_header *header,
			       u32 meta_size)
{
	return crc32(0, (void *)header + 4, meta_size - 4);
}

static inline bool cbd_meta_seq_after(u8 seq1, u8 seq2)
{
	return (s8)(seq1 - seq2) > 0;
}

static inline void *cbd_meta_find_latest(struct cbd_meta_header *header,
					 u32 meta_size, u32 *index)
{
	struct cbd_meta_header *meta, *latest = NULL;
	u32 i;

	for (i = 0; i < CBDT_META_INDEX_MAX; i++) {
		meta = (void *)header + (i * meta_size);
		if (meta->crc != cbd_meta_crc(meta, meta_size)) {
			pr_err("crc: %u, info_crc: %u\n", meta->crc, cbd_meta_crc(meta, meta_size));
			continue;
		}

		if (!latest) {
			latest = meta;
			if (index)
				*index = i;
			continue;
		}

		if (cbd_meta_seq_after(meta->seq, latest->seq)) {
			latest = meta;
			if (index)
				*index = i;
		}
	}

	return latest;
}

static inline struct cbd_meta_header *cbd_meta_find_oldest(struct cbd_meta_header *header,
							   u32 meta_size)
{
	struct cbd_meta_header *meta, *oldest = NULL;
	u32 i;

	for (i = 0; i < CBDT_META_INDEX_MAX; i++) {
		meta = (void *)header + (meta_size * i);
		if (meta->crc != cbd_meta_crc(meta, meta_size)) {
			oldest = meta;
			break;
		}

		if (!oldest) {
			oldest = meta;
			continue;
		}

		if (cbd_meta_seq_after(oldest->seq, meta->seq))
			oldest = meta;
	}

	return oldest;
}

#include "cbd_transport.h"

#include "cbd_host.h"
#include "cbd_segment.h"
#include "cbd_channel.h"

#include "cbd_cache.h"

#include "cbd_handler.h"
#include "cbd_backend.h"

#include "cbd_queue.h"
#include "cbd_blkdev.h"

void cbd_blkdev_hb(struct cbd_blkdev *blkdev);
void cbd_backend_hb(struct cbd_backend *cbdb);
void cbd_host_hb(struct cbd_host *host);

/* sysfs device related macros */
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
											\
	cbd_##OBJ##_hb(obj);								\
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
	struct cbd_##OBJ##_info *info;							\
											\
	_dev = container_of(dev, struct cbd_##OBJ##_device, dev);			\
	info = cbdt_##OBJ##_info_read(_dev->cbdt, _dev->id, NULL);			\
	if (!info)									\
		goto out;								\
											\
	if (cbd_##OBJ##_info_is_alive(info))						\
		return sprintf(buf, "true\n");						\
											\
out:											\
	return sprintf(buf, "false\n");							\
}											\
											\
static DEVICE_ATTR(alive, 0400, cbd_##OBJ##_alive_show, NULL)

#endif /* _CBD_INTERNAL_H */
