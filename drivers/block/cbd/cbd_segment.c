// SPDX-License-Identifier: GPL-2.0-or-later

#include "cbd_internal.h"

static ssize_t cbd_seg_detail_show(struct device *dev,
				   struct device_attribute *attr,
				   char *buf)
{
	struct cbd_segment_device *segment;
	struct cbd_segment_info *segment_info;

	segment = container_of(dev, struct cbd_segment_device, dev);
	segment_info = segment->segment_info;

	if (segment_info->state == cbd_segment_state_none)
		return 0;

	if (segment_info->type == cbds_type_channel)
		return cbd_channel_seg_detail_show((struct cbd_channel_info *)segment_info, buf);

	return 0;
}

static ssize_t cbd_seg_type_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct cbd_segment_device *segment;
	struct cbd_segment_info *segment_info;

	segment = container_of(dev, struct cbd_segment_device, dev);
	segment_info = segment->segment_info;

	if (segment_info->state == cbd_segment_state_none)
		return 0;

	return sprintf(buf, "%s\n", cbds_type_str(segment_info->type));
}

static DEVICE_ATTR(detail, 0400, cbd_seg_detail_show, NULL);
static DEVICE_ATTR(type, 0400, cbd_seg_type_show, NULL);

CBD_OBJ_HEARTBEAT(segment);

static struct attribute *cbd_segment_attrs[] = {
	&dev_attr_detail.attr,
	&dev_attr_type.attr,
	&dev_attr_alive.attr,
	NULL
};

static struct attribute_group cbd_segment_attr_group = {
	.attrs = cbd_segment_attrs,
};

static const struct attribute_group *cbd_segment_attr_groups[] = {
	&cbd_segment_attr_group,
	NULL
};

static void cbd_segment_release(struct device *dev)
{
}

const struct device_type cbd_segment_type = {
	.name		= "cbd_segment",
	.groups		= cbd_segment_attr_groups,
	.release	= cbd_segment_release,
};

const struct device_type cbd_segments_type = {
	.name		= "cbd_segments",
	.release	= cbd_segment_release,
};

void cbd_segment_init(struct cbd_transport *cbdt, struct cbd_segment *segment,
		      struct cbds_init_options *options)
{
	struct cbd_segment_info *segment_info = cbdt_get_segment_info(cbdt, options->seg_id);

	segment->cbdt = cbdt;
	segment->segment_info = segment_info;
	segment->seg_id = options->seg_id;
	segment_info->type = options->type;
	segment->seg_ops = options->seg_ops;
	segment->data_size = CBDT_SEG_SIZE - options->data_off;
	segment->data = (void *)(segment->segment_info) + options->data_off;
	segment->priv_data = options->priv_data;

	segment_info->ref++;
	segment_info->state = cbd_segment_state_running;

	INIT_DELAYED_WORK(&segment->hb_work, segment_hb_workfn);
	queue_delayed_work(cbd_wq, &segment->hb_work, 0);
}

void cbd_segment_exit(struct cbd_segment *segment)
{
	if (!segment->segment_info ||
			segment->segment_info->state != cbd_segment_state_running)
		return;

	cancel_delayed_work_sync(&segment->hb_work);

	if (--segment->segment_info->ref > 0)
		return;

	segment->segment_info->state = cbd_segment_state_none;
	segment->segment_info->alive_ts = 0;
}

int cbd_segment_clear(struct cbd_transport *cbdt, u32 seg_id)
{
	struct cbd_segment_info *segment_info;

	segment_info = cbdt_get_segment_info(cbdt, seg_id);
	if (cbd_segment_info_is_alive(segment_info)) {
		cbdt_err(cbdt, "segment %u is still alive\n", seg_id);
		return -EBUSY;
	}

	cbdt_zero_range(cbdt, segment_info, CBDT_SEG_SIZE);

	return 0;
}

void cbds_copy_data(struct cbd_seg_pos *dst_pos,
		struct cbd_seg_pos *src_pos, u32 len)
{
	u32 copied = 0;
	u32 to_copy;

	while (copied < len) {
		if (dst_pos->off >= dst_pos->segment->data_size)
			dst_pos->segment->seg_ops->sanitize_pos(dst_pos);

		if (src_pos->off >= src_pos->segment->data_size)
			src_pos->segment->seg_ops->sanitize_pos(src_pos);

		to_copy = len - copied;

		if (to_copy > dst_pos->segment->data_size - dst_pos->off)
			to_copy = dst_pos->segment->data_size - dst_pos->off;

		if (to_copy > src_pos->segment->data_size - src_pos->off)
			to_copy = src_pos->segment->data_size - src_pos->off;

		memcpy(dst_pos->segment->data + dst_pos->off, src_pos->segment->data + src_pos->off, to_copy);

		copied += to_copy;

		cbds_pos_advance(dst_pos, to_copy);
		cbds_pos_advance(src_pos, to_copy);
	}
}

void cbds_copy_to_bio(struct cbd_segment *segment,
		u32 data_off, u32 data_len, struct bio *bio, u32 bio_off)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	void *dst;
	u32 to_copy, page_off = 0;
	struct cbd_seg_pos pos = { .segment = segment,
				   .off = data_off };

next:
	bio_for_each_segment(bv, bio, iter) {
		if (bio_off > bv.bv_len) {
			bio_off -= bv.bv_len;
			continue;
		}
		page_off = bv.bv_offset;
		page_off += bio_off;
		bio_off = 0;

		dst = kmap_local_page(bv.bv_page);
again:
		if (pos.off >= pos.segment->data_size)
			segment->seg_ops->sanitize_pos(&pos);
		segment = pos.segment;

		to_copy = min(bv.bv_offset + bv.bv_len - page_off,
				segment->data_size - pos.off);
		if (to_copy > data_len)
			to_copy = data_len;
		flush_dcache_page(bv.bv_page);
		memcpy(dst + page_off, segment->data + pos.off, to_copy);

		/* advance */
		pos.off += to_copy;
		page_off += to_copy;
		data_len -= to_copy;
		if (!data_len) {
			kunmap_local(dst);
			return;
		}

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

void cbds_copy_from_bio(struct cbd_segment *segment,
		u32 data_off, u32 data_len, struct bio *bio, u32 bio_off)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	void *src;
	u32 to_copy, page_off = 0;
	struct cbd_seg_pos pos = { .segment = segment,
				   .off = data_off };

next:
	bio_for_each_segment(bv, bio, iter) {
		if (bio_off > bv.bv_len) {
			bio_off -= bv.bv_len;
			continue;
		}
		page_off = bv.bv_offset;
		page_off += bio_off;
		bio_off = 0;

		src = kmap_local_page(bv.bv_page);
again:
		if (pos.off >= pos.segment->data_size)
			segment->seg_ops->sanitize_pos(&pos);
		segment = pos.segment;

		to_copy = min(bv.bv_offset + bv.bv_len - page_off,
				segment->data_size - pos.off);
		if (to_copy > data_len)
			to_copy = data_len;

		memcpy(segment->data + pos.off, src + page_off, to_copy);
		flush_dcache_page(bv.bv_page);

		/* advance */
		pos.off += to_copy;
		page_off += to_copy;
		data_len -= to_copy;
		if (!data_len) {
			kunmap_local(src);
			return;
		}

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

u32 cbd_seg_crc(struct cbd_segment *segment, u32 data_off, u32 data_len)
{
	u32 crc = 0;
	u32 crc_size;
	struct cbd_seg_pos pos = { .segment = segment,
				   .off = data_off };

	while (data_len) {
		if (pos.off >= pos.segment->data_size)
			segment->seg_ops->sanitize_pos(&pos);
		segment = pos.segment;

		crc_size = min(segment->data_size - pos.off, data_len);

		crc = crc32(crc, segment->data + pos.off, crc_size);

		data_len -= crc_size;
		pos.off += crc_size;
	}

	return crc;
}

int cbds_map_pages(struct cbd_segment *segment, struct cbd_backend_io *io)
{
	struct cbd_transport *cbdt = segment->cbdt;
	struct cbd_se *se = io->se;
	u32 off = se->data_off;
	u32 size = se->data_len;
	u32 done = 0;
	struct page *page;
	u32 page_off;
	int ret = 0;
	int id;

	id = dax_read_lock();
	while (size) {
		unsigned int len = min_t(size_t, PAGE_SIZE, size);
		struct cbd_seg_pos pos = { .segment = segment,
					   .off = off + done };

		if (pos.off >= pos.segment->data_size)
			segment->seg_ops->sanitize_pos(&pos);
		segment = pos.segment;

		u64 transport_off = segment->data -
					(void *)cbdt->transport_info + pos.off;

		page = cbdt_page(cbdt, transport_off, &page_off);

		ret = bio_add_page(io->bio, page, len, 0);
		if (unlikely(ret != len)) {
			cbdt_err(cbdt, "failed to add page");
			goto out;
		}

		done += len;
		size -= len;
	}

	ret = 0;
out:
	dax_read_unlock(id);
	return ret;
}

int cbds_pos_advance(struct cbd_seg_pos *seg_pos, u32 len)
{
	u32 to_advance;

	while (len) {
		to_advance = len;

		if (seg_pos->off >= seg_pos->segment->data_size)
			seg_pos->segment->seg_ops->sanitize_pos(seg_pos);

		if (to_advance > seg_pos->segment->data_size - seg_pos->off)
			to_advance = seg_pos->segment->data_size - seg_pos->off;

		seg_pos->off += to_advance;

		len -= to_advance;
	}

	return 0;
}
