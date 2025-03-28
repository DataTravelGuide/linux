/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _PCACHE_INTERNAL_H
#define _PCACHE_INTERNAL_H

#include <linux/delay.h>
#include <linux/crc32.h>

#define pcache_err(fmt, ...)							\
	pr_err("pcache: %s:%u " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define pcache_info(fmt, ...)							\
	pr_info("pcache: %s:%u " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define pcache_debug(fmt, ...)							\
	pr_debug("pcache: %s:%u " fmt, __func__, __LINE__, ##__VA_ARGS__)

#define PCACHE_KB			(1024ULL)			/* 1 Kilobyte in bytes */
#define PCACHE_MB			(1024ULL * PCACHE_KB)		/* 1 Megabyte in bytes */

#define PCACHE_CACHE_DEV_MAX		1024				/* Maximum number of cache_dev instances */
#define PCACHE_PATH_LEN			128

#define PCACHE_QUEUES_MAX		128				/* Maximum number of I/O queues */

#define PCACHE_PART_SHIFT		4				/* Bit shift for partition identifier */

/* pcache segment */
#define PCACHE_SEG_SIZE			(16 * 1024 * 1024ULL)		/* Size of each PCACHE segment (16 MB) */

#define PCACHE_MAGIC			0x65B05EFA96C596EFULL		/* Unique identifier for PCACHE cache dev */
#define PCACHE_VERSION			1

/* Maximum number of metadata indices */
#define PCACHE_META_INDEX_MAX			2

#define PCACHE_SB_OFF				4096
#define PCACHE_SB_SIZE				PAGE_SIZE

#define PCACHE_CACHE_DEV_INFO_OFF		(PCACHE_SB_OFF + PCACHE_SB_SIZE)
#define PCACHE_CACHE_DEV_INFO_SIZE		PAGE_SIZE
#define PCACHE_CACHE_DEV_INFO_STRIDE		(PCACHE_CACHE_DEV_INFO_SIZE * PCACHE_META_INDEX_MAX)

#define PCACHE_SEGMENTS_OFF			(PCACHE_CACHE_DEV_INFO_OFF + PCACHE_CACHE_DEV_INFO_STRIDE)
#define PCACHE_SEG_INFO_SIZE			PAGE_SIZE

#define PCACHE_BACKING_DEV_INFO_SIZE		PAGE_SIZE

#define PCACHE_CACHE_DEV_SIZE_MIN		(512 * 1024 * 1024)	 /* 512 MB */

#define CACHE_DEV_SEGMENTS(cache_dev)		((void *)cache_dev->sb_addr + PCACHE_SEGMENTS_OFF)
#define CACHE_DEV_SEGMENT(cache_dev, id)	((void *)CACHE_DEV_SEGMENTS(cache_dev) + (u64)id * PCACHE_SEG_SIZE)

#define BACKING_DEV_INFO_SEG_ID			0
#define CACHE_DEV_BACKING_SEG(cache_dev)	(CACHE_DEV_SEGMENT(cache_dev, BACKING_DEV_INFO_SEG_ID))

/*
 * struct pcache_meta_header - PCACHE metadata header structure
 * @crc: CRC checksum for validating metadata integrity.
 * @seq: Sequence number to track metadata updates.
 * @version: Metadata version.
 * @res: Reserved space for future use.
 */
struct pcache_meta_header {
	u32 crc;
	u8  seq;
	u8  version;
	u16 res;
};

/*
 * pcache_meta_crc - Calculate CRC for the given metadata header.
 * @header: Pointer to the metadata header.
 * @meta_size: Size of the metadata structure.
 *
 * Returns the CRC checksum calculated by excluding the CRC field itself.
 */
static inline u32 pcache_meta_crc(struct pcache_meta_header *header, u32 meta_size)
{
	return crc32(0, (void *)header + 4, meta_size - 4);  /* CRC calculated starting after the crc field */
}

/*
 * pcache_meta_seq_after - Check if a sequence number is more recent, accounting for overflow.
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
 *   - true if @seq1 is more recent than @seq2, indicating it comes "after"
 *   - false otherwise.
 */
static inline bool pcache_meta_seq_after(u8 seq1, u8 seq2)
{
	return (s8)(seq1 - seq2) > 0;
}

/*
 * pcache_meta_find_latest - Find the latest valid metadata.
 * @header: Pointer to the metadata header.
 * @meta_size: Size of each metadata block.
 *
 * Finds the latest valid metadata by checking sequence numbers. If a
 * valid entry with the highest sequence number is found, its pointer
 * is returned. Returns NULL if no valid metadata is found.
 */
static inline void *pcache_meta_find_latest(struct pcache_meta_header *header,
					 u32 meta_size)
{
	struct pcache_meta_header *meta, *latest = NULL;
	u32 i;

	for (i = 0; i < PCACHE_META_INDEX_MAX; i++) {
		meta = (void *)header + (i * meta_size);

		/* Skip if CRC check fails */
		if (meta->crc != pcache_meta_crc(meta, meta_size))
			continue;

		/* Update latest if a more recent sequence is found */
		if (!latest || pcache_meta_seq_after(meta->seq, latest->seq))
			latest = meta;
	}

	return latest;
}

/*
 * pcache_meta_find_oldest - Find the oldest valid metadata.
 * @header: Pointer to the metadata header.
 * @meta_size: Size of each metadata block.
 *
 * Returns the oldest valid metadata by comparing sequence numbers.
 * If an entry with the lowest sequence number is found, its pointer
 * is returned. Returns NULL if no valid metadata is found.
 */
static inline void *pcache_meta_find_oldest(struct pcache_meta_header *header,
					 u32 meta_size)
{
	struct pcache_meta_header *meta, *oldest = NULL;
	u32 i;

	for (i = 0; i < PCACHE_META_INDEX_MAX; i++) {
		meta = (void *)header + (meta_size * i);

		/* Mark as oldest if CRC check fails */
		if (meta->crc != pcache_meta_crc(meta, meta_size)) {
			oldest = meta;
			break;
		}

		/* Update oldest if an older sequence is found */
		if (!oldest || pcache_meta_seq_after(oldest->seq, meta->seq))
			oldest = meta;
	}

	BUG_ON(!oldest);

	return oldest;
}

/*
 * pcache_meta_get_next_seq - Get the next sequence number for metadata.
 * @header: Pointer to the metadata header.
 * @meta_size: Size of each metadata block.
 *
 * Returns the next sequence number based on the latest metadata entry.
 * If no latest metadata is found, returns 1.
 */
static inline u32 pcache_meta_get_next_seq(struct pcache_meta_header *header,
					u32 meta_size)
{
	struct pcache_meta_header *latest;

	latest = pcache_meta_find_latest(header, meta_size);
	if (!latest)
		return 1;

	return (latest->seq + 1);
}

#endif /* _PCACHE_INTERNAL_H */
