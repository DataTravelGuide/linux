/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CBD_CHANNEL_H
#define _CBD_CHANNEL_H

/* cbd_channel */
enum cbdc_blkdev_state {
	cbdc_blkdev_state_none		= 0,
	cbdc_blkdev_state_running,
};

enum cbdc_backend_state {
	cbdc_backend_state_none		= 0,
	cbdc_backend_state_running,
};

struct cbd_channel_seg_info {
	struct cbd_segment_info seg_info;	/* must be the first member */
	u32	backend_id;
};

struct cbd_channel_ctrl {
	u64	polling:1;
	u64	need_reset:1;

	u32	submr_head;
	u32	submr_tail;

	u32	compr_head;
	u32	compr_tail;
};

struct cbd_channel_init_options {
	struct cbd_transport *cbdt;
	bool	new_channel;

	u32	seg_id;
	u32	backend_id;
};

struct cbd_channel {
	u32				seg_id;
	struct cbd_segment		segment;

	struct cbd_channel_seg_info	channel_info;
	struct mutex			info_lock;
	u32				info_index;

	struct cbd_transport		*cbdt;

	struct cbd_channel_ctrl		*ctrl;
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

int cbd_channel_init(struct cbd_channel *channel, struct cbd_channel_init_options *init_opts);
void cbd_channel_exit(struct cbd_channel *channel);
void cbdc_copy_from_bio(struct cbd_channel *channel,
		u32 data_off, u32 data_len, struct bio *bio, u32 bio_off);
void cbdc_copy_to_bio(struct cbd_channel *channel,
		u32 data_off, u32 data_len, struct bio *bio, u32 bio_off);
u32 cbd_channel_crc(struct cbd_channel *channel, u32 data_off, u32 data_len);
int cbdc_map_pages(struct cbd_channel *channel, struct bio *bio, u32 off, u32 size);
int cbd_get_empty_channel_id(struct cbd_transport *cbdt, u32 *id);
ssize_t cbd_channel_seg_detail_show(struct cbd_channel_seg_info *channel_info, char *buf);

#endif /* _CBD_CHANNEL_H */
