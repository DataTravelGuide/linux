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

void cbd_segment_init(struct cbd_segment *segment, struct cbd_transport *cbdt, u32 seg_id)
{
	struct cbd_segment_info *segment_info = cbdt_get_segment_info(cbdt, seg_id);

	segment->cbdt = cbdt;
	segment->segment_info = segment_info;
	segment->seg_id = seg_id;

	segment_info->state = cbd_segment_state_running;

	INIT_DELAYED_WORK(&segment->hb_work, segment_hb_workfn);
	queue_delayed_work(cbd_wq, &segment->hb_work, 0);
}

void cbd_segment_exit(struct cbd_segment *segment)
{
	cancel_delayed_work_sync(&segment->hb_work);

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
