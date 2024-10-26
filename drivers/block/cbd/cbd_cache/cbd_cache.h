/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CBD_CACHE_H
#define _CBD_CACHE_H

/* cbd cache */
struct cbd_cache_seg_info {
	struct cbd_segment_info segment_info;	/* first member */
	u32 backend_id;
};

struct cbd_cache_seg_gen {
	struct cbd_meta_header header;
	u64 gen;
};

struct cbd_cache_pos_onmedia {
	struct cbd_meta_header header;
	u32 cache_seg_id;
	u32 seg_off;
};

#define CBDT_CACHE_SEG_CTRL_OFF		(CBDT_SEG_INFO_SIZE * CBDT_META_INDEX_MAX)
#define CBDT_CACHE_SEG_CTRL_SIZE		PAGE_SIZE

struct cbd_cache_seg_ctrl {
	/* updated by blkdev, it is increased in invalidating */
	struct cbd_cache_seg_gen gen[CBDT_META_INDEX_MAX];
};

struct cbd_cache_segment {
	struct cbd_cache		*cache;
	u32				cache_seg_id;	/* index in cache->segments */
	u32				used;
	struct cbd_segment		segment;
	atomic_t			refs;

	/* cache_seg_info is only updated by owner backend */
	struct cbd_cache_seg_info	cache_seg_info;
	u32				info_index;
	struct mutex			info_lock;

	spinlock_t			gen_lock;
	u64				gen;
	struct cbd_cache_seg_ctrl	*cache_seg_ctrl;
	struct mutex			ctrl_lock;
};

struct cbd_cache_pos {
	struct cbd_cache_segment *cache_seg;
	u32		seg_off;
};

struct cbd_cache_info {
	u32	seg_id;
	u32	n_segs;

	u16	gc_percent;
	u16	res;
	u32	res2;
};

/* put cbd cache metadata at CBD_CACHE_CTRL_OFF of first cqche segment */
#define CBDT_CACHE_CTRL_OFF	CBDT_SEG_INFO_SIZE
#define CBDT_CACHE_CTRL_SIZE	PAGE_SIZE

struct cbd_cache_ctrl {
	struct cbd_cache_seg_ctrl	cache_seg_ctrl;
	struct cbd_cache_pos_onmedia key_tail_pos[CBDT_META_INDEX_MAX];
	struct cbd_cache_pos_onmedia dirty_tail_pos[CBDT_META_INDEX_MAX];
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
	union {
		u32	key_num;
		u32	next_cache_seg_id;
	};
	u64	magic;
	u64	flags;
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
	u32				cache_id;	/* same with related backend->backend_id */

	/* ->backend is only used for cache on backend size,
	 * on the blkdev size, ->backend should be NULL */
	struct cbd_backend		*backend;

	struct cbd_cache_info		*cache_info;
	struct cbd_cache_ctrl		*cache_ctrl;

	u32				n_heads;
	struct cbd_cache_data_head	*data_heads;

	spinlock_t			key_head_lock;
	struct cbd_cache_pos		key_head;
	u32				n_ksets;
	struct cbd_cache_kset		*ksets;

	struct mutex			key_tail_lock;
	struct cbd_cache_pos		key_tail;

	struct mutex			dirty_tail_lock;
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
	u32 cache_id;
	struct cbd_cache_info *cache_info;
	struct cbd_backend *backend;
	u32 n_segs;
	bool new_cache;
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

#endif /* _CBD_CACHE_H */
