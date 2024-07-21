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

void cbd_segment_init(struct cbd_segment *segment, struct cbd_transport *cbdt,
		u32 seg_id, enum cbd_seg_type type)
{
	struct cbd_segment_info *segment_info = cbdt_get_segment_info(cbdt, seg_id);

	segment->cbdt = cbdt;
	segment->segment_info = segment_info;
	segment->seg_id = seg_id;

	segment_info->type = type;

	INIT_DELAYED_WORK(&segment->hb_work, segment_hb_workfn);
	queue_delayed_work(cbd_wq, &segment->hb_work, 0);

	segment_info->state = cbd_segment_state_running;
}

void cbd_segment_exit(struct cbd_segment *segment)
{
	if (!segment->segment_info ||
			segment->segment_info->state != cbd_segment_state_running)
		return;

	cancel_delayed_work_sync(&segment->hb_work);

	if (segment->seg_ops->seg_state_none(segment->segment_info))
		segment->segment_info->state = cbd_segment_state_none;
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

void cbds_copy_to_bio(struct cbd_segment *segment,
		u32 data_off, u32 data_len, struct bio *bio)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	void *dst;
	u32 data_head = data_off;
	u32 to_copy, page_off = 0;

next:
	bio_for_each_segment(bv, bio, iter) {
		dst = kmap_local_page(bv.bv_page);
		page_off = bv.bv_offset;
again:
		while (data_head >= segment->data_size) {
			data_head -= segment->data_size;
			segment = segment->next;
		}

		to_copy = min(bv.bv_offset + bv.bv_len - page_off,
				segment->data_size - data_head);
		flush_dcache_page(bv.bv_page);
		memcpy_flushcache(dst + page_off, segment->data + data_head, to_copy);

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

void cbds_copy_from_bio(struct cbd_segment *segment,
		u32 data_off, u32 data_len, struct bio *bio)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	void *src;
	u32 data_head = data_off;
	u32 to_copy, page_off = 0;

next:
	bio_for_each_segment(bv, bio, iter) {
		src = kmap_local_page(bv.bv_page);
		page_off = bv.bv_offset;
again:
		while (data_head >= segment->data_size) {
			data_head -= segment->data_size;
			segment = segment->next;
		}

		to_copy = min(bv.bv_offset + bv.bv_len - page_off,
				segment->data_size - data_head);
		memcpy_flushcache(segment->data + data_head, src + page_off, to_copy);
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

u32 cbd_seg_crc(struct cbd_segment *segment, u32 data_off, u32 data_len)
{
	u32 crc = 0;
	u32 crc_size;
	u32 data_head = data_off;

	while (data_len) {
		while (data_head >= segment->data_size) {
			data_head -= segment->data_size;
			segment = segment->next;
		}

		crc_size = min(segment->data_size - data_head, data_len);

		crc = crc32(crc, segment->data + data_head, crc_size);

		data_len -= crc_size;
		data_head += crc_size;
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
		u32 data_head = off + done;

		while (data_head >= segment->data_size) {
			data_head -= segment->data_size;
			segment = segment->next;
		}

		u64 transport_off = segment->data -
					(void *)cbdt->transport_info + data_head;

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
