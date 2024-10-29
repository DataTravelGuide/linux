// SPDX-License-Identifier: GPL-2.0-or-later

#include "cbd_transport.h"
#include "cbd_channel.h"

void cbdc_copy_to_bio(struct cbd_channel *channel,
		u32 data_off, u32 data_len, struct bio *bio, u32 bio_off)
{
	cbds_copy_to_bio(&channel->segment, data_off, data_len, bio, bio_off);
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

ssize_t cbd_channel_seg_detail_show(struct cbd_segment_info *seg_info, char *buf)
{
	struct cbd_channel_seg_info *channel_info;

	channel_info = (struct cbd_channel_seg_info *)seg_info;

	return sprintf(buf, "backend id: %u\n", channel_info->backend_id);
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
							channel->seg_id, &channel->info_index);
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
				channel->seg_id, channel->info_index);
	channel->info_index = (channel->info_index + 1) % CBDT_META_INDEX_MAX;
	mutex_unlock(&channel->info_lock);
}

/*
 * cbd_channel_init - Initialize a CBD channel for backend or block device side
 * @channel: Pointer to the CBD channel structure
 * @init_opts: Initialization options for the channel
 *
 * This function initializes a channel for data transfer, which can be called
 * from both the backend and block device sides. In cases where `new_channel`
 * is specified (typically when creating a new backend), this function initializes
 * a new channel. In other scenarios, such as on the block device side or during
 * a backend attach, it loads existing channel information instead of re-initializing.
 *
 * The function begins by setting basic channel properties such as segment ID,
 * buffer sizes, and locking mechanisms. It then retrieves the segment information
 * required to locate the control, submission, and completion buffers in shared memory.
 *
 * For new channels, it initializes channel-specific information and writes this data
 * to persist the channel state. For existing channels, it loads previously saved
 * channel information to restore its configuration. This approach supports reuse of
 * channel resources in multi-threaded environments across both backend and block device contexts.
 *
 * Returns 0 on successful initialization, or a negative error code if loading
 * existing channel information fails.
 */
int cbd_channel_init(struct cbd_channel *channel, struct cbd_channel_init_options *init_opts)
{
	struct cbd_segment_info *seg_info;
	struct cbds_init_options seg_options;
	int ret;

	/* Initialize channel base properties */
	channel->cbdt = init_opts->cbdt;
	channel->seg_id = init_opts->seg_id;
	channel->submr_size = rounddown(CBDC_SUBMR_SIZE, sizeof(struct cbd_se));
	channel->compr_size = rounddown(CBDC_COMPR_SIZE, sizeof(struct cbd_ce));
	channel->data_size = CBDC_DATA_SIZE;

	/* Locate control, submission, and completion resources in shared memory */
	seg_info = cbdt_get_segment_info(channel->cbdt, channel->seg_id);
	channel->ctrl = (void *)seg_info + CBDC_CTRL_OFF;
	channel->submr = (void *)seg_info + CBDC_SUBMR_OFF;
	channel->compr = (void *)seg_info + CBDC_COMPR_OFF;

	/* Initialize locking mechanisms */
	spin_lock_init(&channel->submr_lock);
	spin_lock_init(&channel->compr_lock);
	mutex_init(&channel->info_lock);

	/* Set up channel information and segment details */
	seg_options.seg_id = init_opts->seg_id;
	seg_options.data_off = CBDC_DATA_OFF;
	seg_options.seg_ops = &cbd_channel_seg_ops;

	/* Initialize the segment with specified options */
	cbd_segment_init(init_opts->cbdt, &channel->segment, &seg_options);

	if (init_opts->new_channel) {
		/* Initialize new channel state */
		channel->channel_info.seg_info.type = cbds_type_channel;
		channel->channel_info.seg_info.state = cbd_segment_state_running;
		channel->channel_info.seg_info.flags = 0;
		channel->channel_info.backend_id = init_opts->backend_id;

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
