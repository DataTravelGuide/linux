// SPDX-License-Identifier: GPL-2.0-or-later

#include "cbd_internal.h"

static void channel_format(struct cbd_transport *cbdt, u32 id)
{
	struct cbd_channel_seg_info *channel_info = cbdt_get_channel_info(cbdt, id);

	cbdt_zero_range(cbdt, channel_info, CBDC_META_SIZE);
}

int cbd_get_empty_channel_id(struct cbd_transport *cbdt, u32 *id)
{
	int ret;

	ret = cbdt_get_empty_segment_id(cbdt, id);
	if (ret)
		return ret;

	channel_format(cbdt, *id);

	return 0;
}

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


int cbdc_map_pages(struct cbd_channel *channel, struct cbd_backend_io *io)
{
	return cbds_map_pages(&channel->segment, io);
}

ssize_t cbd_channel_seg_detail_show(struct cbd_channel_seg_info *channel_info, char *buf)
{
	return sprintf(buf, "backend id: %u\n", channel_info->backend_id);
}

static void cbd_channel_seg_sanitize_pos(struct cbd_seg_pos *pos)
{
	struct cbd_segment *segment = pos->segment;

	/* channel only use one segment as a ring */
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
	struct cbd_channel_seg_info *channel_info;

	mutex_lock(&channel->info_lock);
	cbdt_segment_info_write(channel->cbdt, &channel->channel_info, sizeof(struct cbd_channel_seg_info),
				channel->seg_id, channel->info_index);
	channel->info_index = (channel->info_index + 1) % CBDT_META_INDEX_MAX;
	mutex_unlock(&channel->info_lock);
}

void cbd_channel_init(struct cbd_channel *channel, struct cbd_transport *cbdt, u32 seg_id, bool update_info)
{
	struct cbd_channel_seg_info *channel_info = &channel->channel_info;
	struct cbd_segment *segment = &channel->segment;
	struct cbds_init_options seg_options;

	channel->cbdt = cbdt;
	channel->seg_id = seg_id;
	channel->ctrl = (void *)channel_info + CBDC_CTRL_OFF;
	channel->submr = (void *)channel_info + CBDC_SUBMR_OFF;
	channel->compr = (void *)channel_info + CBDC_COMPR_OFF;
	channel->submr_size = rounddown(CBDC_SUBMR_SIZE, sizeof(struct cbd_se));
	channel->compr_size = rounddown(CBDC_COMPR_SIZE, sizeof(struct cbd_ce));
	channel->data_size = CBDC_DATA_SIZE;

	spin_lock_init(&channel->submr_lock);
	spin_lock_init(&channel->compr_lock);
	mutex_init(&channel->info_lock);

	seg_options.seg_id = seg_id;
	seg_options.data_off = CBDC_DATA_OFF;
	seg_options.seg_ops = &cbd_channel_seg_ops;

	cbd_segment_init(cbdt, segment, &seg_options);

	if (update_info) {
		channel_info->seg_info.type = cbds_type_channel;
		channel_info->seg_info.state = cbd_segment_state_running;
		channel_info_write(channel);
	} else {
		/*TODO check ret-val*/
		channel_info_load(channel);
	}
}

void cbd_channel_exit(struct cbd_channel *channel)
{
	cbd_segment_exit(&channel->segment);
}

void cbd_channel_write(struct cbd_channel *channel)
{
	mutex_lock(&channel->info_lock);

	mutex_unlock(&channel->info_lock);
}
