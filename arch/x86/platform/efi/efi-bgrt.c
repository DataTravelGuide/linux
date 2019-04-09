/*
 * Copyright 2012 Intel Corporation
 * Author: Josh Triplett <josh@joshtriplett.org>
 *
 * Based on the bgrt driver:
 * Copyright 2012 Red Hat, Inc <mjg@redhat.com>
 * Author: Matthew Garrett
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/acpi.h>
#include <linux/efi.h>
#include <linux/efi-bgrt.h>

extern int page_is_ram(unsigned long pfn);

struct acpi_table_bgrt *bgrt_tab;
void *__initdata bgrt_image;
size_t __initdata bgrt_image_size;

struct bmp_header {
	u16 id;
	u32 size;
} __packed;

void __init efi_bgrt_init(void)
{
	acpi_status status;
	void *image;
	bool ioremapped = false;
	struct bmp_header bmp_header;
	int img_addr_in_ram;

	if (acpi_disabled)
		return;

	status = acpi_get_table("BGRT", 0,
	                        (struct acpi_table_header **)&bgrt_tab);
	if (ACPI_FAILURE(status))
		return;

	if (bgrt_tab->header.length < sizeof(*bgrt_tab))
		return;
	if (!bgrt_tab->status || bgrt_tab->version != 1)
		return;
	if (bgrt_tab->image_type != 0 || !bgrt_tab->image_address)
		return;

	/* Before ioremap check if image address falls in System RAM */
	img_addr_in_ram = page_is_ram(bgrt_tab->image_address >> PAGE_SHIFT);
	if (img_addr_in_ram) {
		pr_info("BGRT: Image Address falls in System RAM");
		image = phys_to_virt(bgrt_tab->image_address);
	} else {
		image = ioremap(bgrt_tab->image_address,
			sizeof(bmp_header));
		ioremapped = true;
	}

	 if (!image) {
		pr_err("Ignoring BGRT: failed to map image header memory\n");
		return;
	}

	if (img_addr_in_ram)
		memcpy(&bmp_header, image, sizeof(bmp_header));
	else
		memcpy_fromio(&bmp_header, image, sizeof(bmp_header));

	if (ioremapped)
		iounmap(image);

	bgrt_image_size = bmp_header.size;
	bgrt_image = kmalloc(bgrt_image_size, GFP_KERNEL);
	if (!bgrt_image)
		return;

	ioremapped = false;
	if (img_addr_in_ram) {
		image = phys_to_virt(bgrt_tab->image_address);
	} else {
		image = ioremap(bgrt_tab->image_address,
			bmp_header.size);
		ioremapped = true;
	}

	if (!image) {
		pr_err("Ignoring BGRT: failed to map image memory\n");
		kfree(bgrt_image);
		bgrt_image = NULL;
		return;
	}

	if (img_addr_in_ram)
		memcpy(bgrt_image, image, bgrt_image_size);
	else
		memcpy_fromio(bgrt_image, image, bgrt_image_size);

	if (ioremapped)
		iounmap(image);
}
