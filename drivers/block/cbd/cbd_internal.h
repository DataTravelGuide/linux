/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CBD_INTERNAL_H
#define _CBD_INTERNAL_H

#include <linux/delay.h>
#include <linux/crc32.h>

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

#define CBD_KB                  (1024)                      /* 1 Kilobyte in bytes */
#define CBD_MB                  (CBD_KB * CBD_KB)           /* 1 Megabyte in bytes */

#define CBD_TRANSPORT_MAX       1024                        /* Maximum number of transport instances */
#define CBD_PATH_LEN            128                         /* Maximum path length for device names */
#define CBD_NAME_LEN            32                          /* Maximum length for a name string */

#define CBD_QUEUES_MAX          128                         /* Maximum number of I/O queues */
#define CBD_HANDLERS_MAX        128                         /* Maximum number of handlers */

#define CBD_PART_SHIFT          4                           /* Bit shift for partition identifier */
#define CBD_DRV_NAME            "cbd"                       /* Default driver name for CBD */
#define CBD_DEV_NAME_LEN        32                          /* Maximum device name length */

#define CBD_HB_INTERVAL         msecs_to_jiffies(5000)      /* Heartbeat interval in jiffies (5 seconds) */
#define CBD_HB_TIMEOUT          (30 * 1000)                 /* Heartbeat timeout in milliseconds (30 seconds) */

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
#define CBDT_SEG_SIZE           (16 * 1024 * 1024)                  /* Size of each CBD segment (16 MB) */

/* cbd transport */
#define CBD_TRANSPORT_MAGIC             0x65B05EFA96C596EFULL  /* Unique identifier for CBD transport layer */
#define CBD_TRANSPORT_VERSION           1                      /* Version number for CBD transport layer */

/* Maximum number of metadata indices */
#define CBDT_META_INDEX_MAX             2                      

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

/* cbd_worker_cfg - Structure to manage retry configurations for a worker */
struct cbd_worker_cfg {
	u32			busy_retry_cur;     /* Current retry count */
	u32			busy_retry_count;   /* Dynamic retry threshold */
	u32			busy_retry_max;     /* Maximum retry threshold */
	u32			busy_retry_min;     /* Minimum retry threshold */
	u64			busy_retry_interval; /* Time interval between retries in microseconds */
};

/**
 * cbdwc_init - Initialize cbd_worker_cfg with default values.
 * @cfg: Pointer to the cbd_worker_cfg structure to initialize.
 */
static inline void cbdwc_init(struct cbd_worker_cfg *cfg)
{
	cfg->busy_retry_cur = 0;
	cfg->busy_retry_count = 100;
	cfg->busy_retry_max = cfg->busy_retry_count * 2;
	cfg->busy_retry_min = 0;
	cfg->busy_retry_interval = 1; /* 1 microsecond */
}

/**
 * cbdwc_hit - Reset retry counter and increase busy_retry_count on success.
 * @cfg: Pointer to the cbd_worker_cfg structure to update.
 *
 * Increases busy_retry_count by 1/16 of its current value,
 * unless it's already at the maximum.
 */
static inline void cbdwc_hit(struct cbd_worker_cfg *cfg)
{
	u32 delta;

	cfg->busy_retry_cur = 0;

	if (cfg->busy_retry_count == cfg->busy_retry_max)
		return;

	delta = cfg->busy_retry_count >> 4;
	if (!delta)
		delta = (cfg->busy_retry_max + cfg->busy_retry_min) >> 1;

	cfg->busy_retry_count += delta;

	if (cfg->busy_retry_count > cfg->busy_retry_max)
		cfg->busy_retry_count = cfg->busy_retry_max;
}

/**
 * cbdwc_miss - Reset retry counter and decrease busy_retry_count on failure.
 * @cfg: Pointer to the cbd_worker_cfg structure to update.
 *
 * Decreases busy_retry_count by 1/16 of its current value,
 * unless it's already at the minimum.
 */
static inline void cbdwc_miss(struct cbd_worker_cfg *cfg)
{
	u32 delta;

	cfg->busy_retry_cur = 0;

	if (cfg->busy_retry_count == cfg->busy_retry_min)
		return;

	delta = cfg->busy_retry_count >> 4;
	if (!delta)
		delta = cfg->busy_retry_count;

	cfg->busy_retry_count -= delta;
}

/**
 * cbdwc_need_retry - Determine if another retry attempt should be made.
 * @cfg: Pointer to the cbd_worker_cfg structure to check.
 *
 * Increments busy_retry_cur and compares it to busy_retry_count.
 * If retry is needed, yields CPU and waits for busy_retry_interval.
 *
 * Return: true if retry is allowed, false if retry limit reached.
 */
static inline bool cbdwc_need_retry(struct cbd_worker_cfg *cfg)
{
	if (++cfg->busy_retry_cur < cfg->busy_retry_count) {
		cpu_relax();
		fsleep(cfg->busy_retry_interval);
		return true;
	}

	return false;
}

/* 
 * struct cbd_meta_header - CBD metadata header structure 
 * @crc: CRC checksum for validating metadata integrity.
 * @seq: Sequence number to track metadata updates.
 * @version: Metadata version.
 * @res: Reserved space for future use.
 */
struct cbd_meta_header {
	u32 crc;
	u8  seq;
	u8  version;
	u16 res;
};

/*
 * cbd_meta_crc - Calculate CRC for the given metadata header.
 * @header: Pointer to the metadata header.
 * @meta_size: Size of the metadata structure.
 *
 * Returns the CRC checksum calculated by excluding the CRC field itself.
 */
static inline u32 cbd_meta_crc(struct cbd_meta_header *header, u32 meta_size)
{
	return crc32(0, (void *)header + 4, meta_size - 4);  /* CRC calculated starting after the crc field */
}

/*
 * cbd_meta_seq_after - Check if a sequence number is more recent, accounting for overflow.
 * @seq1: First sequence number.
 * @seq2: Second sequence number.
 *
 * Determines if @seq1 is more recent than @seq2 by calculating the signed
 * difference between them. This approach allows handling sequence number
 * overflow correctly because the difference wraps naturally, and any value
 * greater than zero indicates that @seq1 is "after" @seq2. This method
 * assumes 8-bit unsigned sequence numbers, where the difference wraps
 * around if seq1 overflows past seq2.
 *
 * Returns:
 *   - true if @seq1 is more recent than @seq2, indicating it comes "after."
 *   - false otherwise.
 */
static inline bool cbd_meta_seq_after(u8 seq1, u8 seq2)
{
	return (s8)(seq1 - seq2) > 0;
}

/*
 * cbd_meta_find_latest - Find the latest valid metadata.
 * @header: Pointer to the metadata header.
 * @meta_size: Size of each metadata block.
 * @index: Optional pointer to store the index of the latest metadata.
 *
 * Finds the latest valid metadata by checking sequence numbers. If a
 * valid entry with the highest sequence number is found, its pointer
 * is returned. Returns NULL if no valid metadata is found.
 */
static inline void *cbd_meta_find_latest(struct cbd_meta_header *header,
					 u32 meta_size, u32 *index)
{
	struct cbd_meta_header *meta, *latest = NULL;
	u32 i;

	for (i = 0; i < CBDT_META_INDEX_MAX; i++) {
		meta = (void *)header + (i * meta_size);

		/* Skip if CRC check fails */
		if (meta->crc != cbd_meta_crc(meta, meta_size))
			continue;

		/* Update latest if a more recent sequence is found */
		if (!latest || cbd_meta_seq_after(meta->seq, latest->seq)) {
			latest = meta;
			if (index)
				*index = i;
		}
	}

	return latest;
}

/*
 * cbd_meta_find_oldest - Find the oldest valid metadata.
 * @header: Pointer to the metadata header.
 * @meta_size: Size of each metadata block.
 *
 * Returns the oldest valid metadata by comparing sequence numbers.
 * If an entry with the lowest sequence number is found, its pointer
 * is returned. Returns NULL if no valid metadata is found.
 */
static inline void *cbd_meta_find_oldest(struct cbd_meta_header *header,
					 u32 meta_size)
{
	struct cbd_meta_header *meta, *oldest = NULL;
	u32 i;

	for (i = 0; i < CBDT_META_INDEX_MAX; i++) {
		meta = (void *)header + (meta_size * i);

		/* Mark as oldest if CRC check fails */
		if (meta->crc != cbd_meta_crc(meta, meta_size)) {
			oldest = meta;
			break;
		}

		/* Update oldest if an older sequence is found */
		if (!oldest || cbd_meta_seq_after(oldest->seq, meta->seq))
			oldest = meta;
	}

	return oldest;
}

/*
 * cbd_meta_get_next_seq - Get the next sequence number for metadata.
 * @header: Pointer to the metadata header.
 * @meta_size: Size of each metadata block.
 *
 * Returns the next sequence number based on the latest metadata entry.
 * If no latest metadata is found, returns 0.
 */
static inline u32 cbd_meta_get_next_seq(struct cbd_meta_header *header,
					u32 meta_size)
{
	struct cbd_meta_header *latest;

	latest = cbd_meta_find_latest(header, meta_size, NULL);
	if (!latest)
		return 0;

	return (latest->seq + 1);
}

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
