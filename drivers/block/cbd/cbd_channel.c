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
		u64 data_off, u32 data_len, struct bio *bio)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	void *src, *dst;
	u64 data_head = data_off;
	u32 to_copy, page_off = 0;

next:
	bio_for_each_segment(bv, bio, iter) {
		dst = kmap_local_page(bv.bv_page);
		page_off = bv.bv_offset;
again:
		if (data_head >= CBDC_DATA_SIZE)
			data_head %= CBDC_DATA_SIZE;

		flush_dcache_page(bv.bv_page);
		src = channel->data + data_head;
		to_copy = min(bv.bv_offset + bv.bv_len - page_off,
			      CBDC_DATA_SIZE - data_head);
		memcpy_flushcache(dst + page_off, src, to_copy);

		/* advance */
		data_head += to_copy;
		page_off += to_copy;

		/* more data in this bv page */
		if (page_off < bv.bv_offset + bv.bv_len)
			goto again;
		kunmap_local(dst);
	}

	if (bio->bi_next) {
		bio = bio->bi_next;
		goto next;
	}
}

void cbdc_copy_from_bio(struct cbd_channel *channel,
		u64 data_off, u32 data_len, struct bio *bio)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	void *src, *dst;
	u64 data_head = data_off;
	u32 to_copy, page_off = 0;

next:
	bio_for_each_segment(bv, bio, iter) {
		src = kmap_local_page(bv.bv_page);
		page_off = bv.bv_offset;
again:
		if (data_head >= CBDC_DATA_SIZE)
			data_head %= CBDC_DATA_SIZE;

		dst = channel->data + data_head;
		to_copy = min(bv.bv_offset + bv.bv_len - page_off,
			      CBDC_DATA_SIZE - data_head);

		memcpy_flushcache(dst, src + page_off, to_copy);
		flush_dcache_page(bv.bv_page);

		/* advance */
		data_head += to_copy;
		page_off += to_copy;

		/* more data in this bv page */
		if (page_off < bv.bv_offset + bv.bv_len)
			goto again;
		kunmap_local(src);
	}

	if (bio->bi_next) {
		bio = bio->bi_next;
		goto next;
	}
}

u32 cbd_channel_crc(struct cbd_channel *channel, u64 data_off, u32 data_len)
{
	u32 crc = 0;
	u32 crc_size;
	u64 data_head = data_off;

	while (data_len) {
		if (data_head >= CBDC_DATA_SIZE)
			data_head %= CBDC_DATA_SIZE;

		crc_size = min(CBDC_DATA_SIZE - data_head, data_len);

		crc = crc32(crc, channel->data + data_head, crc_size);

		data_len -= crc_size;
		data_head += crc_size;
	}

	return crc;
}

ssize_t cbd_channel_seg_detail_show(struct cbd_channel_info *channel_info, char *buf)
{
	return sprintf(buf, "channel backend id: %u\n"
			"channel blkdev id: %u\n",
			channel_info->backend_id,
			channel_info->blkdev_id);
}


void cbd_channel_init(struct cbd_channel *channel, struct cbd_transport *cbdt, u32 seg_id)
{
	struct cbd_channel_info *channel_info = cbdt_get_channel_info(cbdt, seg_id);

	cbd_segment_init(&channel->segment, cbdt, seg_id);

	channel->cbdt = cbdt;
	channel->channel_info = channel_info;
	channel->seg_id = seg_id;
	channel->submr = (void *)channel_info + CBDC_SUBMR_OFF;
	channel->compr = (void *)channel_info + CBDC_COMPR_OFF;
	channel->data = (void *)channel_info + CBDC_DATA_OFF;
	channel->data_size = CBDC_DATA_SIZE;

	spin_lock_init(&channel->submr_lock);
	spin_lock_init(&channel->compr_lock);
}

void cbd_channel_exit(struct cbd_channel *channel)
{
	cbd_segment_exit(&channel->segment);
}
