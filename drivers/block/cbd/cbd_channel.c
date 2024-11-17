// SPDX-License-Identifier: GPL-2.0-or-later

#include "cbd_transport.h"
#include "cbd_channel.h"

int cbdc_copy_to_bio(struct cbd_channel *channel,
		u32 data_off, u32 data_len, struct bio *bio, u32 bio_off)
{
	return cbds_copy_to_bio(&channel->segment, data_off, data_len, bio, bio_off);
}

void cbdc_copy_from_bio(struct cbd_channel *channel,
		u32 data_off, u32 data_len, struct bio *bio, u32 bio_off)
{
	cbds_copy_from_bio(&channel->segment, data_off, data_len, bio, bio_off);
}

u32 cbd_channel_crc(struct cbd_channel *channel, u32 data_off, u32 data_len)
{
	return cbd_seg_crc(&channel->segment, data_off, data_len);
}

int cbdc_map_pages(struct cbd_channel *channel, struct bio *bio, u32 off, u32 size)
{
	return cbds_map_pages(&channel->segment, bio, off, size);
}

void cbd_channel_reset(struct cbd_channel *channel)
{
	/* Reset channel data head and tail pointers */
	channel->data_head = channel->data_tail = 0;

	/* Reset submr and compr control pointers */
	channel->ctrl->submr_tail = channel->ctrl->submr_head = 0;
	channel->ctrl->compr_tail = channel->ctrl->compr_head = 0;

	cbdt_zero_range(channel->cbdt, channel->submr, CBDC_SUBMR_SIZE);
	cbdt_zero_range(channel->cbdt, channel->compr, CBDC_COMPR_SIZE);
}

/*
 * cbd_channel_seg_sanitize_pos - Sanitize position within a channel segment ring
 * @pos: Position structure within the segment to sanitize
 *
 * This function ensures that the offset in the segment position wraps around
 * correctly when the channel is using a single segment in a ring structure. If
 * the offset exceeds the data size of the segment, it wraps back to the start of
 * the segment by reducing it by the segment's data size. This allows the channel
 * to reuse the segment space efficiently in a circular manner, preventing overflows.
 */
static void cbd_channel_seg_sanitize_pos(struct cbd_seg_pos *pos)
{
	struct cbd_segment *segment = pos->segment;

	/* Channel only uses one segment as a ring */
	while (pos->off >= segment->data_size)
		pos->off -= segment->data_size;
}

static struct cbd_seg_ops cbd_channel_seg_ops = {
	.sanitize_pos = cbd_channel_seg_sanitize_pos
};

static int channel_info_load(struct cbd_channel *channel)
{
	struct cbd_channel_seg_info *channel_info;
	int ret;

	mutex_lock(&channel->info_lock);
	channel_info = (struct cbd_channel_seg_info *)cbdt_segment_info_read(channel->cbdt,
							channel->seg_id);
	if (!channel_info) {
		cbd_channel_err(channel, "can't read info from segment id: %u\n",
				channel->seg_id);
		ret = -EINVAL;
		goto out;
	}
	memcpy(&channel->channel_info, channel_info, sizeof(struct cbd_channel_seg_info));
	ret = 0;
out:
	mutex_unlock(&channel->info_lock);
	return ret;
}

static void channel_info_write(struct cbd_channel *channel)
{
	mutex_lock(&channel->info_lock);
	cbdt_segment_info_write(channel->cbdt, &channel->channel_info, sizeof(struct cbd_channel_seg_info),
				channel->seg_id);
	mutex_unlock(&channel->info_lock);
}

int cbd_channel_init(struct cbd_channel *channel, struct cbd_channel_init_options *init_opts)
{
	struct cbds_init_options seg_options = { 0 };
	void *seg_addr;
	int ret;

	seg_options.seg_id = init_opts->seg_id;
	seg_options.data_off = CBDC_DATA_OFF;
	seg_options.seg_ops = &cbd_channel_seg_ops;

	cbd_segment_init(init_opts->cbdt, &channel->segment, &seg_options);

	channel->cbdt = init_opts->cbdt;
	channel->seg_id = init_opts->seg_id;
	channel->submr_size = rounddown(CBDC_SUBMR_SIZE, sizeof(struct cbd_se));
	channel->compr_size = rounddown(CBDC_COMPR_SIZE, sizeof(struct cbd_ce));
	channel->data_size = CBDC_DATA_SIZE;

	seg_addr = cbd_segment_addr(&channel->segment);
	channel->ctrl = seg_addr + CBDC_CTRL_OFF;
	channel->submr = seg_addr + CBDC_SUBMR_OFF;
	channel->compr = seg_addr + CBDC_COMPR_OFF;

	spin_lock_init(&channel->submr_lock);
	spin_lock_init(&channel->compr_lock);
	mutex_init(&channel->info_lock);

	if (init_opts->new_channel) {
		/* Initialize new channel state */
		channel->channel_info.seg_info.type = CBDS_TYPE_CHANNEL;
		channel->channel_info.seg_info.state = CBD_SEGMENT_STATE_RUNNING;
		channel->channel_info.seg_info.flags = 0;
		channel->channel_info.seg_info.backend_id = init_opts->backend_id;

		/* Persist new channel information */
		channel_info_write(channel);
	} else {
		/* Load existing channel information for reattachment or blkdev side */
		ret = channel_info_load(channel);
		if (ret)
			goto out;
	}
	ret = 0;

out:
	return ret;
}

void cbd_channel_destroy(struct cbd_channel *channel)
{
	cbdt_segment_info_clear(channel->cbdt, channel->seg_id);
}
