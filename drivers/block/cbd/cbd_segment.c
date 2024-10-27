/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/dax.h>

#include "cbd_internal.h"
#include "cbd_transport.h"
#include "cbd_segment.h"

/* 
 * Show function for the "detail" attribute in a CBD segment device.
 * 
 * This function retrieves and displays detailed information about the segment
 * if the segment exists and is in a valid state.
 * 
 * @dev: Device structure pointer for the CBD segment device.
 * @attr: Device attribute structure pointer for the "detail" attribute.
 * @buf: Buffer to store the formatted segment details.
 * 
 * Return: The number of bytes written to the buffer, or 0 if no details are available.
 */
static ssize_t cbd_seg_detail_show(struct device *dev,
				   struct device_attribute *attr,
				   char *buf)
{
	struct cbd_segment_device *segment_dev;
	struct cbd_segment_info *segment_info;
	detail_show_fn show_fn;

	/* Retrieve the CBD segment device from the parent device */
	segment_dev = container_of(dev, struct cbd_segment_device, dev);

	/* Read segment info, returns NULL if info is not available */
	segment_info = cbdt_segment_info_read(segment_dev->cbdt, segment_dev->id, NULL);
	if (!segment_info)
		return 0;

	/* Exit if the segment state is none */
	if (segment_info->state == cbd_segment_state_none)
		return 0;

	/* Get the appropriate function for showing segment details based on type */
	show_fn = cbd_seg_get_detail_shower(segment_info->type);
	if (!show_fn)
		return 0;

	/* Call the detail show function and return its output size */
	return show_fn(segment_info, buf);
}

/* 
 * Show function for the "type" attribute in a CBD segment device.
 * 
 * This function retrieves and displays the type of the segment if the 
 * segment exists and is in a valid state.
 * 
 * @dev: Device structure pointer for the CBD segment device.
 * @attr: Device attribute structure pointer for the "type" attribute.
 * @buf: Buffer to store the segment type string.
 * 
 * Return: The number of bytes written to the buffer, or 0 if no type is available.
 */
static ssize_t cbd_seg_type_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct cbd_segment_device *segment_dev;
	struct cbd_segment_info *segment_info;

	/* Retrieve the CBD segment device from the parent device */
	segment_dev = container_of(dev, struct cbd_segment_device, dev);

	/* Read segment info, returns NULL if info is not available */
	segment_info = cbdt_segment_info_read(segment_dev->cbdt, segment_dev->id, NULL);
	if (!segment_info)
		return 0;

	/* Exit if the segment state is none */
	if (segment_info->state == cbd_segment_state_none)
		return 0;

	/* Format the segment type as a string and write it to the buffer */
	return sprintf(buf, "%s\n", cbds_type_str(segment_info->type));
}

static DEVICE_ATTR(detail, 0400, cbd_seg_detail_show, NULL);
static DEVICE_ATTR(type, 0400, cbd_seg_type_show, NULL);

static struct attribute *cbd_segment_attrs[] = {
	&dev_attr_detail.attr,
	&dev_attr_type.attr,
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
	.name       = "cbd_segment",
	.groups     = cbd_segment_attr_groups,
	.release    = cbd_segment_release,
};

const struct device_type cbd_segments_type = {
	.name       = "cbd_segments",
	.release    = cbd_segment_release,
};

/**
 * cbd_segment_init - Initialize a CBD segment.
 * @cbdt: The transport structure associated with the CBD segment.
 * @segment: The CBD segment structure to initialize.
 * @options: Initialization options containing segment ID, operations, and data offset.
 *
 * This function sets up a CBD segment by associating it with a transport,
 * setting the segment ID, segment operations, and calculating data size
 * based on segment offset.
 */
void cbd_segment_init(struct cbd_transport *cbdt, struct cbd_segment *segment,
		      struct cbds_init_options *options)
{
	struct cbd_segment_info *seg_info;

	segment->cbdt = cbdt;
	segment->seg_id = options->seg_id;
	segment->seg_ops = options->seg_ops;
	segment->data_size = CBDT_SEG_SIZE - options->data_off;

	seg_info = cbdt_get_segment_info(cbdt, segment->seg_id);
	segment->data = (void *)(seg_info) + options->data_off;
}

/**
 * cbd_segment_clear - Zero out a CBD segment.
 * @cbdt: The CBD transport structure.
 * @seg_id: The ID of the segment to clear.
 *
 * Zeroes the entire data range of a segment specified by seg_id within the
 * provided transport.
 */
void cbd_segment_clear(struct cbd_transport *cbdt, u32 seg_id)
{
	struct cbd_segment_info *segment_info;

	segment_info = cbdt_get_segment_info(cbdt, seg_id);
	cbdt_zero_range(cbdt, segment_info, CBDT_SEG_SIZE);
}

/**
 * cbd_segment_info_clear - Clear segment info by segment structure.
 * @segment: The CBD segment to clear.
 *
 * Clears the segment information for the segment within the associated transport.
 */
void cbd_segment_info_clear(struct cbd_segment *segment)
{
	cbdt_segment_info_clear(segment->cbdt, segment->seg_id);
}

/**
 * cbds_copy_data - Copy data between two segment positions.
 * @dst_pos: The destination segment position.
 * @src_pos: The source segment position.
 * @len: The number of bytes to copy.
 *
 * Copies data from src_pos to dst_pos within CBD segments, handling segment
 * boundaries by using the sanitize_pos function to wrap segment offsets.
 */
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

/**
 * cbds_copy_to_bio - Copy segment data to a bio.
 * @segment: The CBD segment to read from.
 * @data_off: Offset into the segment data to begin copying from.
 * @data_len: Length of data to copy.
 * @bio: The bio structure to copy data into.
 * @bio_off: Offset into the bio to begin copying data.
 *
 * Copies data from a segment into a bio, handling segment boundaries by using
 * the sanitize_pos function and bio page boundaries with bio_for_each_segment.
 */
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

/**
 * cbds_copy_from_bio - Copy data from a bio to a segment.
 * @segment: The CBD segment to write to.
 * @data_off: Offset into the segment data to write to.
 * @data_len: Length of data to write.
 * @bio: The bio structure to copy data from.
 * @bio_off: Offset into the bio to begin copying data.
 */
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

/**
 * cbd_seg_crc - Calculate CRC32 of a segment data range.
 * @segment: The CBD segment.
 * @data_off: Offset into the segment data.
 * @data_len: Length of data to calculate CRC.
 */
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

/**
 * cbds_map_pages - Map CBD segment pages to bio.
 * @segment: The CBD segment.
 * @bio: The bio to map pages into.
 * @off: Offset in segment to start mapping.
 * @size: Size of data to map.
 */
int cbds_map_pages(struct cbd_segment *segment,
		   struct bio *bio,
		   u32 off, u32 size)
{
	struct cbd_transport *cbdt = segment->cbdt;
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

		ret = bio_add_page(bio, page, len, 0);
		if (unlikely(ret != len)) {
			cbd_segment_err(segment, "failed to add page\n");
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

/**
 * cbds_pos_advance - Advance position within a segment.
 * @seg_pos: The segment position to advance.
 * @len: The length to advance by.
 */
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
