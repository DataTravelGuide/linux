/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _CBD_CACHE_H
#define _CBD_CACHE_H

#include "../cbd_transport.h"
#include "../cbd_segment.h"

/* CBD Cache Error, Info, and Debug Macros */
#define cbd_cache_err(cache, fmt, ...)                \
	cbdt_err(cache->cbdt, "cache%d: " fmt,             \
		 cache->cache_id, ##__VA_ARGS__)
#define cbd_cache_info(cache, fmt, ...)               \
	cbdt_info(cache->cbdt, "cache%d: " fmt,            \
		 cache->cache_id, ##__VA_ARGS__)
#define cbd_cache_debug(cache, fmt, ...)              \
	cbdt_debug(cache->cbdt, "cache%d: " fmt,           \
		 cache->cache_id, ##__VA_ARGS__)

/* Struct defining cache segment information */
struct cbd_cache_seg_info {
	struct cbd_segment_info segment_info;   /* First member */
	u32 backend_id;
};

/* Cache segment generation control information */
struct cbd_cache_seg_gen {
	struct cbd_meta_header header;
	u64 gen;
};

/* Cache position structure for on-media storage */
struct cbd_cache_pos_onmedia {
	struct cbd_meta_header header;
	u32 cache_seg_id;
	u32 seg_off;
};

/* Offset and size definitions for cache segment control */
#define CBDT_CACHE_SEG_CTRL_OFF     (CBDT_SEG_INFO_SIZE * CBDT_META_INDEX_MAX)
#define CBDT_CACHE_SEG_CTRL_SIZE    PAGE_SIZE

/* Control structure for cache segments */
struct cbd_cache_seg_ctrl {
	struct cbd_cache_seg_gen gen[CBDT_META_INDEX_MAX]; /* Updated by blkdev, incremented in invalidating */
};

/* CBD Cache Segment */
struct cbd_cache_segment {
	struct cbd_cache       *cache;
	u32                    cache_seg_id;   /* Index in cache->segments */
	u32                    used;
	struct cbd_segment     segment;
	atomic_t               refs;

	/* Segment info, updated only by the owner backend */
	struct cbd_cache_seg_info cache_seg_info;
	u32                    info_index;
	struct mutex           info_lock;

	spinlock_t             gen_lock;
	u64                    gen;
	struct cbd_cache_seg_ctrl *cache_seg_ctrl;
	struct mutex           ctrl_lock;
};

/* CBD Cache Position */
struct cbd_cache_pos {
	struct cbd_cache_segment *cache_seg;
	u32 seg_off;
};

/* CBD Cache Information */
struct cbd_cache_info {
	u32 seg_id;
	u32 n_segs;
	u16 gc_percent;
	u16 res;
	u32 res2;
};

/* Control offsets and sizes for the cache controller */
#define CBDT_CACHE_CTRL_OFF CBDT_SEG_INFO_SIZE
#define CBDT_CACHE_CTRL_SIZE PAGE_SIZE

/* CBD Cache Control structure */
struct cbd_cache_ctrl {
	struct cbd_cache_seg_ctrl cache_seg_ctrl;
	struct cbd_cache_pos_onmedia key_tail_pos[CBDT_META_INDEX_MAX];
	struct cbd_cache_pos_onmedia dirty_tail_pos[CBDT_META_INDEX_MAX];
};

/* Red-black tree for cache entries */
struct cbd_cache_tree {
	struct rb_root root;
	spinlock_t tree_lock;
};

/* Data head lock for CBD Cache */
struct cbd_cache_data_head {
	spinlock_t data_head_lock;
	struct cbd_cache_pos head_pos;
};

/* Cache key structure */
struct cbd_cache_key {
	struct cbd_cache        *cache;
	struct cbd_cache_tree   *cache_tree;
	struct kref             ref;
	struct rb_node          rb_node;
	struct list_head        list_node;
	u64                     off;
	u32                     len;
	u64                     flags;
	struct cbd_cache_pos    cache_pos;
	u64                     seg_gen;
#ifdef CONFIG_CBD_CACHE_DATA_CRC
	u32                     data_crc;
#endif
};

/* Cache key flags */
#define CBD_CACHE_KEY_FLAGS_EMPTY   (1 << 0)
#define CBD_CACHE_KEY_FLAGS_CLEAN   (1 << 1)

/* On-media cache key structure */
struct cbd_cache_key_onmedia {
	u64 off;
	u32 len;
	u32 flags;
	u32 cache_seg_id;
	u32 cache_seg_off;
	u64 seg_gen;
#ifdef CONFIG_CBD_CACHE_DATA_CRC
	u32 data_crc;
#endif
};

/* Cache key set on-media structure */
struct cbd_cache_kset_onmedia {
	u32 crc;
	union {
		u32 key_num;
		u32 next_cache_seg_id;
	};
	u64 magic;
	u64 flags;
	struct cbd_cache_key_onmedia data[];
};

/* Cache key set flags */
#define CBD_KSET_FLAGS_LAST (1 << 0)
#define CBD_KSET_MAGIC      0x676894a64e164f1aULL

/* Cache key set structure */
struct cbd_cache_kset {
	struct cbd_cache *cache;
	spinlock_t        kset_lock;
	struct delayed_work flush_work;
	struct cbd_cache_kset_onmedia kset_onmedia;
};

/* Cache states */
enum cbd_cache_state {
	cbd_cache_state_none = 0,
	cbd_cache_state_running,
	cbd_cache_state_stopping
};

/* CBD Cache main structure */
struct cbd_cache {
	struct cbd_transport   *cbdt;
	u32                    cache_id;  /* Same as related backend->backend_id */
	void                   *owner;    /* For backend cache side only */
	struct cbd_cache_info  *cache_info;
	struct cbd_cache_ctrl  *cache_ctrl;

	u32                    n_heads;
	struct cbd_cache_data_head *data_heads;

	spinlock_t             key_head_lock;
	struct cbd_cache_pos   key_head;
	u32                    n_ksets;
	struct cbd_cache_kset  *ksets;

	struct mutex           key_tail_lock;
	struct cbd_cache_pos   key_tail;

	struct mutex           dirty_tail_lock;
	struct cbd_cache_pos   dirty_tail;

	struct kmem_cache      *key_cache;
	u32                    n_trees;
	struct cbd_cache_tree  *cache_trees;
	struct work_struct     clean_work;

	spinlock_t             miss_read_reqs_lock;
	struct list_head       miss_read_reqs;
	struct work_struct     miss_read_end_work;

	struct workqueue_struct *cache_wq;

	struct file            *bdev_file;
	u64                    dev_size;
	struct delayed_work    writeback_work;
	struct delayed_work    gc_work;
	struct bio_set         *bioset;

	struct kmem_cache      *req_cache;

	u32                    state:8;
	u32                    init_keys:1;
	u32                    start_writeback:1;
	u32                    start_gc:1;

	u32                    n_segs;
	unsigned long          *seg_map;
	u32                    last_cache_seg;
	spinlock_t             seg_map_lock;
	struct cbd_cache_segment segments[]; /* Last member */
};

/* CBD Cache options structure */
struct cbd_cache_opts {
	u32 cache_id;
	struct cbd_cache_info *cache_info;
	void *owner;
	u32 n_segs;
	bool new_cache;
	bool start_writeback;
	bool start_gc;
	bool init_keys;
	u64 dev_size;
	u32 n_paral;
	struct file *bdev_file;
};

/* CBD Cache API function declarations */
struct cbd_cache *cbd_cache_alloc(struct cbd_transport *cbdt, struct cbd_cache_opts *opts);
void cbd_cache_destroy(struct cbd_cache *cache);

struct cbd_request;
int cbd_cache_handle_req(struct cbd_cache *cache, struct cbd_request *cbd_req);

#endif /* _CBD_CACHE_H */
