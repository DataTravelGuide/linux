/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _CBD_CACHE_H
#define _CBD_CACHE_H

#include "../cbd_transport.h"
#include "../cbd_segment.h"

#define cbd_cache_err(cache, fmt, ...)                \
	cbdt_err(cache->cbdt, "cache%d: " fmt,             \
		 cache->cache_id, ##__VA_ARGS__)
#define cbd_cache_info(cache, fmt, ...)               \
	cbdt_info(cache->cbdt, "cache%d: " fmt,            \
		 cache->cache_id, ##__VA_ARGS__)
#define cbd_cache_debug(cache, fmt, ...)              \
	cbdt_debug(cache->cbdt, "cache%d: " fmt,           \
		 cache->cache_id, ##__VA_ARGS__)

/* Garbage collection thresholds */
#define CBD_CACHE_GC_PERCENT_MIN       0                   /* Minimum GC percentage */
#define CBD_CACHE_GC_PERCENT_MAX       90                  /* Maximum GC percentage */
#define CBD_CACHE_GC_PERCENT_DEFAULT   70                  /* Default GC percentage */

struct cbd_cache_seg_info {
	struct cbd_segment_info segment_info;   /* must be first member */
};

struct cbd_cache_info {
	u32 seg_id;
	u32 n_segs;
	u16 gc_percent;
	u16 res;
	u32 res2;
};

struct cbd_cache_pos {
	struct cbd_cache_segment *cache_seg;
	u32 seg_off;
};

enum cbd_cache_seg_state {
	cbd_cache_seg_state_none	= 0,
	cbd_cache_seg_state_running
};

struct cbd_cache_segment {
	struct cbd_cache	*cache;
	u32			cache_seg_id;   /* Index in cache->segments */
	u32			used;
	struct cbd_segment	segment;
	atomic_t		refs;

	atomic_t		state;

	/* Segment info, updated only by the owner backend */
	struct cbd_cache_seg_info cache_seg_info;
	struct mutex           info_lock;

	spinlock_t             gen_lock;
	u64                    gen;
	struct cbd_cache_seg_ctrl *cache_seg_ctrl;
	struct mutex           ctrl_lock;
};

/* rbtree for cache entries */
struct cbd_cache_subtree {
	struct rb_root root;
	spinlock_t tree_lock;
};

struct cbd_cache_tree {
	struct cbd_cache		*cache;
	u32				n_subtrees;
	struct kmem_cache		*key_cache;
	struct cbd_cache_subtree	*subtrees;
};

#define CBD_CACHE_STATE_NONE		0
#define CBD_CACHE_STATE_RUNNING		1
#define CBD_CACHE_STATE_STOPPING	2

/* CBD Cache main structure */
struct cbd_cache {
	struct cbd_transport	*cbdt;
	u32			cache_id;  /* Same as related backend->backend_id */
	void			*owner;    /* For backend cache side only */
	struct cbd_cache_info	*cache_info;
	struct cbd_cache_ctrl	*cache_ctrl;

	u32			n_heads;
	struct cbd_cache_data_head *data_heads;

	spinlock_t		key_head_lock;
	struct cbd_cache_pos	key_head;
	u32			n_ksets;
	struct cbd_cache_kset	*ksets;

	struct mutex		key_tail_lock;
	struct cbd_cache_pos	key_tail;

	struct mutex		dirty_tail_lock;
	struct cbd_cache_pos	dirty_tail;

	struct cbd_cache_tree	req_key_tree;
	struct work_struct	clean_work;
	struct work_struct	used_segs_update_work;

	spinlock_t		miss_read_reqs_lock;
	struct list_head	miss_read_reqs;
	struct work_struct	miss_read_end_work;

	struct workqueue_struct	*cache_wq;

	struct file		*bdev_file;
	u64			dev_size;
	struct delayed_work	writeback_work;
	struct delayed_work	gc_work;
	struct bio_set		*bioset;

	struct kmem_cache	*req_cache;

	u32			state:8;
	u32			init_req_keys:1;
	u32			start_writeback:1;
	u32			start_gc:1;

	u32			n_segs;
	unsigned long		*seg_map;
	u32			last_cache_seg;
	spinlock_t		seg_map_lock;
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
	bool init_req_keys;
	u64 dev_size;
	u32 n_paral;
	struct file *bdev_file;
};

/* CBD Cache API function declarations */
struct cbd_cache *cbd_cache_alloc(struct cbd_transport *cbdt, struct cbd_cache_opts *opts);
void cbd_cache_destroy(struct cbd_cache *cache);
void cbd_cache_info_init(struct cbd_cache_info *cache_info, u32 cache_segs);

struct cbd_request;
int cbd_cache_handle_req(struct cbd_cache *cache, struct cbd_request *cbd_req);
u32 cache_info_used_segs(struct cbd_transport *cbdt, struct cbd_cache_info *cache_info);

#endif /* _CBD_CACHE_H */
