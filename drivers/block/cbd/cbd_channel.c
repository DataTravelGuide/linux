// SPDX-License-Identifier: GPL-2.0-or-later

#include "cbd_internal.h"

static void channel_format(struct cbd_transport *cbdt, u32 id)
{
	struct cbd_channel_info *channel_info = cbdt_get_channel_info(cbdt, id);

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

ssize_t cbd_channel_seg_detail_show(struct cbd_channel_info *channel_info, char *buf)
{
	return sprintf(buf, "channel backend id: %u\n"
			"channel blkdev id: %u\n",
			channel_info->backend_id,
			channel_info->blkdev_id);
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

void cbd_channel_init(struct cbd_channel *channel, struct cbd_transport *cbdt, u32 seg_id)
{
	struct cbd_channel_info *channel_info = cbdt_get_channel_info(cbdt, seg_id);
	struct cbd_segment *segment = &channel->segment;
	struct cbds_init_options seg_options;

	seg_options.seg_id = seg_id;
	seg_options.type = cbds_type_channel;
	seg_options.data_off = CBDC_DATA_OFF;
	seg_options.seg_ops = &cbd_channel_seg_ops;

	cbd_segment_init(cbdt, segment, &seg_options);

	channel->cbdt = cbdt;
	channel->channel_info = channel_info;
	channel->seg_id = seg_id;
	channel->submr = (void *)channel_info + CBDC_SUBMR_OFF;
	channel->compr = (void *)channel_info + CBDC_COMPR_OFF;
	channel->submr_size = rounddown(CBDC_SUBMR_SIZE, sizeof(struct cbd_se));
	channel->compr_size = rounddown(CBDC_COMPR_SIZE, sizeof(struct cbd_ce));
	channel->data_size = CBDC_DATA_SIZE;

	spin_lock_init(&channel->submr_lock);
	spin_lock_init(&channel->compr_lock);
}

void cbd_channel_exit(struct cbd_channel *channel)
{
	cbd_segment_exit(&channel->segment);
}
