// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/bio.h>

#include "cbd_cache_internal.h"

/**
 * is_cache_clean - Check if the cache is clean by validating the dirty tail.
 * @cache: Pointer to the cbd_cache structure.
 *
 * This function determines if the cache is clean by verifying the integrity
 * of the dirty tail. If the dirty tail has an invalid magic number or CRC
 * checksum, it indicates that the dirty tail is incomplete, meaning there
 * are no more valid dirty ksets, and thus the cache is clean.
 *
 * Returns:
 * true if the cache is clean (no more valid dirty ksets),
 * false if the cache has valid dirty ksets (dirty and requires flushing).
 */
static inline bool is_cache_clean(struct cbd_cache *cache)
{
	struct cbd_cache_kset_onmedia *kset_onmedia;
	struct cbd_cache_pos *pos;
	void *addr;

	pos = &cache->dirty_tail;
	addr = cache_pos_addr(pos);
	kset_onmedia = (struct cbd_cache_kset_onmedia *)addr;

	/* Check if the magic number matches the expected value */
	if (kset_onmedia->magic != CBD_KSET_MAGIC) {
		cbd_cache_debug(cache, "dirty_tail: %u:%u magic: %llx, not expected: %llx\n",
				pos->cache_seg->cache_seg_id, pos->seg_off,
				kset_onmedia->magic, CBD_KSET_MAGIC);
		return true; /* Incomplete dirty tail, cache is clean */
	}

	/* Verify the CRC checksum for data integrity */
	if (kset_onmedia->crc != cache_kset_crc(kset_onmedia)) {
		cbd_cache_debug(cache, "dirty_tail: %u:%u crc: %x, not expected: %x\n",
				pos->cache_seg->cache_seg_id, pos->seg_off,
				cache_kset_crc(kset_onmedia), kset_onmedia->crc);
		return true; /* Incomplete dirty tail, cache is clean */
	}

	return false; /* Complete dirty kset found, cache is not clean */
}

/**
 * cache_writeback_exit - Clean up writeback resources for a cache.
 * @cache: Pointer to the cbd_cache structure.
 *
 * This function ensures that all outstanding writeback operations have
 * completed and frees associated resources. It first flushes any remaining
 * data in the cache, then waits for the cache to become clean, and finally
 * cancels any pending delayed writeback work.
 */
void cache_writeback_exit(struct cbd_cache *cache)
{
	/* Flush any pending cache operations to ensure data consistency */
	cache_flush(cache);

	/* Wait until the cache is fully clean */
	while (!is_cache_clean(cache))
		schedule_timeout(HZ);

	/* Cancel any delayed writeback work, ensuring no jobs remain */
	cancel_delayed_work_sync(&cache->writeback_work);

	/* Release bioset resources and free the bioset structure */
	bioset_exit(cache->bioset);
	kfree(cache->bioset);
}

/**
 * cache_writeback_init - Initialize writeback resources for a cache.
 * @cache: Pointer to the cbd_cache structure.
 *
 * Allocates and initializes the bioset structure required for writeback
 * operations. Sets up delayed work for handling writebacks in the background.
 *
 * Return: 0 on success, -ENOMEM if memory allocation fails, or another
 *         error code from bioset_init on failure.
 */
int cache_writeback_init(struct cbd_cache *cache)
{
	int ret;

	/* Allocate memory for bioset and check for allocation failure */
	cache->bioset = kzalloc(sizeof(*cache->bioset), GFP_KERNEL);
	if (!cache->bioset) {
		ret = -ENOMEM;
		goto err;
	}

	/* Initialize bioset with specified parameters; handle failure */
	ret = bioset_init(cache->bioset, 256, 0, BIOSET_NEED_BVECS);
	if (ret) {
		kfree(cache->bioset);  /* Free bioset if init fails */
		cache->bioset = NULL;  /* Nullify pointer to avoid use-after-free */
		goto err;
	}

	/* Queue delayed work to start writeback handling */
	queue_delayed_work(cache->cache_wq, &cache->writeback_work, 0);

	return 0;

err:
	return ret;  /* Return error code on failure */
}

/**
 * cache_key_writeback - Write back a cache key's data to the underlying storage.
 * @cache: Pointer to the cbd_cache structure containing cache configuration.
 * @key: Pointer to the cbd_cache_key structure containing the data to be written back.
 *
 * This function synchronously writes back data associated with a cache key to the
 * backing storage. It ensures that overwrites are applied in the correct sequence
 * to prevent data corruption. If the data is already clean (i.e., no modifications),
 * the function returns without performing any writeback.
 *
 * Unlike traditional approaches where each key write is followed by a data flush,
 * here we defer flushing. Instead, once an entire kset (a set of keys) completes
 * its writeback, we perform a `sync` operation to ensure data consistency and
 * durability on disk.
 *
 * Return: 0 on success, or -EIO on write failure.
 */
static int cache_key_writeback(struct cbd_cache *cache, struct cbd_cache_key *key)
{
	struct cbd_cache_pos *pos;
	void *addr;
	ssize_t written;
	u32 seg_remain;
	u64 off;

	/* Check if the cache key is already clean; if so, skip writeback */
	if (cache_key_clean(key))
		return 0;

	pos = &key->cache_pos;

	/* Get remaining segment size and check if it can contain the key's data */
	seg_remain = cache_seg_remain(pos);
	/* All data within one key must fit within the same segment */
	BUG_ON(seg_remain < key->len);

	/* Get the address within the cache position for writing */
	addr = cache_pos_addr(pos);
	off = key->off;

	/* Perform synchronous writeback to maintain overwrite sequence.
	 * Ensures data consistency by writing in order. For instance, if K1 writes
	 * data to the range 0-4K and then K2 writes to the same range, K1's write
	 * must complete before K2's.
	 *
	 * Note: We defer flushing data immediately after each key's writeback.
	 * Instead, a `sync` operation is issued once the entire kset (group of keys)
	 * has completed writeback, ensuring all data from the kset is safely persisted
	 * to disk while reducing the overhead of frequent flushes.
	 */
	written = kernel_write(cache->bdev_file, addr, key->len, &off);
	if (written != key->len)
		return -EIO;

	return 0;
}

/**
 * cache_kset_writeback - Write back a set of cache keys to the backing storage.
 * @cache: Pointer to the cbd_cache structure for cache context.
 * @kset_onmedia: Pointer to the cbd_cache_kset_onmedia structure, containing
 *                the set of keys to be written back.
 *
 * This function writes back each key in a kset to ensure data consistency in the
 * backing storage. Each key is allocated, decoded, written back, and then released
 * sequentially. After processing all keys in the kset, the function calls `vfs_fsync`
 * to sync data to disk, ensuring that the entire kset is durably stored.
 *
 * Return: 0 on success, -ENOMEM if memory allocation fails for a key,
 *         or another error code from cache_key_writeback on failure.
 */
static int cache_kset_writeback(struct cbd_cache *cache,
		struct cbd_cache_kset_onmedia *kset_onmedia)
{
	struct cbd_cache_key_onmedia *key_onmedia;
	struct cbd_cache_key *key;
	int ret;
	u32 i;

	/* Iterate through all keys in the kset and write each back to storage */
	for (i = 0; i < kset_onmedia->key_num; i++) {
		key_onmedia = &kset_onmedia->data[i];

		/* Allocate memory for the cache key structure */
		key = cache_key_alloc(cache);
		if (!key) {
			cbd_cache_err(cache, "writeback error: failed to allocate key\n");
			return -ENOMEM;
		}

		/* Decode on-media key data into the in-memory cache key structure */
		cache_key_decode(key_onmedia, key);

		/* Write back the key data to the backing storage */
		ret = cache_key_writeback(cache, key);

		/* Release the key after writeback, regardless of success or failure */
		cache_key_put(key);

		/* If writeback failed, log the error and return immediately */
		if (ret) {
			cbd_cache_err(cache, "writeback error: %d\n", ret);
			return ret;
		}
	}

	/* Sync the entire kset's data to disk to ensure durability */
	vfs_fsync(cache->bdev_file, 1);

	return 0;
}

/**
 * last_kset_writeback - Handle the final kset of a cache key segment.
 * @cache: Pointer to the cbd_cache structure containing cache state.
 * @last_kset_onmedia: Pointer to the last kset in a segment, which stores metadata
 *                     for the next segment.
 *
 * This function is called to process the last kset of a cache key segment. Unlike
 * other ksets, the last kset does not store actual keys. Instead, it contains
 * metadata pointing to the next cache key segment, allowing writeback operations
 * to proceed in sequence across segments.
 *
 * The function updates the dirty tail position to the start of the next segment,
 * ensuring that writeback can resume from the appropriate location in the cache.
 */
static void last_kset_writeback(struct cbd_cache *cache,
		struct cbd_cache_kset_onmedia *last_kset_onmedia)
{
	struct cbd_cache_segment *next_seg;

	/* Log the segment ID of the next cache segment for debugging */
	cbd_cache_debug(cache, "last kset, next: %u\n", last_kset_onmedia->next_cache_seg_id);

	/* Retrieve the next segment using the ID stored in the last kset */
	next_seg = &cache->segments[last_kset_onmedia->next_cache_seg_id];

	/* Update dirty_tail to point to the start of the next segment */
	cache->dirty_tail.cache_seg = next_seg;
	cache->dirty_tail.seg_off = 0;

	/* Encode and store the updated dirty tail position */
	cache_encode_dirty_tail(cache);
}


#ifdef CONFIG_CBD_CACHE_DATA_CRC
/**
 * kset_data_verify - Verify the integrity of each key in a kset before writeback.
 * @cache: Pointer to the cbd_cache structure, which provides context for the cache.
 * @kset_onmedia: Pointer to the cbd_cache_kset_onmedia structure containing the keys
 *                to be verified within the kset.
 *
 * This function verifies the integrity of each key in a kset by comparing its
 * computed CRC with the stored CRC value. During writeback, if a kset is found
 * and it has a valid CRC (indicating the kset itself is intact), this function
 * can be used to check the data completeness of each key within the kset.
 *
 * If any key's data CRC check fails, the function returns -EIO, preventing the
 * writeback from occurring on incomplete data. In a single-host environment,
 * incomplete data should not occur due to exclusive access. In multi-host mode,
 * if the CXL hardware provides hardware-level consistency, incomplete data is
 * also theoretically unlikely.
 *
 * Return: 0 if all keys are verified as complete, -EIO if any key's CRC check fails.
 */
static int kset_data_verify(struct cbd_cache *cache,
		struct cbd_cache_kset_onmedia *kset_onmedia)
{
	u32 i;

	/* Iterate through each key in the kset and verify data integrity */
	for (i = 0; i < kset_onmedia->key_num; i++) {
		struct cbd_cache_key key_tmp = { 0 };
		struct cbd_cache_key *key;
		struct cbd_cache_key_onmedia *key_onmedia;

		/* Initialize a temporary key structure for verification */
		key = &key_tmp;
		cache_key_init(cache, key);

		/* Decode the on-media key data into the temporary key structure */
		key_onmedia = &kset_onmedia->data[i];
		cache_key_decode(key_onmedia, key);

		/* Compare computed and stored CRC values to verify data integrity */
		if (key->data_crc != cache_key_data_crc(key)) {
			cbd_cache_debug(cache, "key: %llu:%u data crc(%x) is not expected(%x), wait for data ready.\n",
					key->off, key->len, cache_key_data_crc(key), key->data_crc);
			return -EIO;
		}
	}

	return 0;
}

#endif

/**
 * cache_writeback_fn - Main function for handling writeback work in the cache.
 * @work: Pointer to the work_struct, which contains the context for the work item.
 *
 * This function is executed when the writeback work is queued. It continuously checks
 * the cache's dirty_tail for new ksets that need to be written back. The function
 * processes each kset until the cache is clean, ensuring that all dirty data is
 * properly persisted to the backing storage.
 *
 * The function performs the following steps:
 * 1. Checks if the cache is clean; if so, it exits the loop.
 * 2. Retrieves the kset_onmedia from the current dirty_tail position.
 * 3. Handles the last kset, if identified, and continues the loop.
 * 4. Verifies the data integrity of the kset using CRC, if configured.
 * 5. Performs the writeback of the kset to the backing storage.
 * 6. Advances the dirty_tail position and encodes the updated state.
 */
void cache_writeback_fn(struct work_struct *work)
{
	struct cbd_cache *cache = container_of(work, struct cbd_cache, writeback_work.work);
	struct cbd_cache_kset_onmedia *kset_onmedia;
	int ret = 0;
	void *addr;

	/* Loop until all dirty data is written back and the cache is clean */
	while (true) {
		/* Check if the cache is clean; exit if no dirty data remains */
		if (is_cache_clean(cache))
			break;

		/* Get kset_onmedia from the current dirty_tail position */
		addr = cache_pos_addr(&cache->dirty_tail);
		kset_onmedia = (struct cbd_cache_kset_onmedia *)addr;

		/* Handle the last kset, which indicates the end of a segment */
		if (kset_onmedia->flags & CBD_KSET_FLAGS_LAST) {
			last_kset_writeback(cache, kset_onmedia);
			continue;
		}

#ifdef CONFIG_CBD_CACHE_DATA_CRC
		/* Verify the data integrity of the kset using CRC */
		ret = kset_data_verify(cache, kset_onmedia);
		if (ret)
			break;  /* Exit on CRC verification failure */
#endif

		/* Write back the kset to the backing storage */
		ret = cache_kset_writeback(cache, kset_onmedia);
		if (ret)
			break;  /* Exit on writeback failure */

		/* Log the advancement of writeback progress for debugging */
		cbd_cache_debug(cache, "writeback advance: %u:%u %u\n",
			cache->dirty_tail.cache_seg->cache_seg_id,
			cache->dirty_tail.seg_off,
			get_kset_onmedia_size(kset_onmedia));

		/* Advance the dirty_tail position based on the size of the kset */
		cache_pos_advance(&cache->dirty_tail, get_kset_onmedia_size(kset_onmedia));

		/* Encode the updated dirty tail position for persistence */
		cache_encode_dirty_tail(cache);
	}

	/* Requeue the writeback work to continue processing after a delay */
	queue_delayed_work(cache->cache_wq, &cache->writeback_work, CBD_CACHE_WRITEBACK_INTERVAL);
}
