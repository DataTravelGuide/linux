/* module-verify.c: module verifier
 *
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "module-verify.h"

/*
 * verify a module's integrity
 * - check the ELF is viable
 */
int module_verify(const Elf_Ehdr *hdr, size_t size)
{
	struct module_verify_data mvdata;
	int ret;

	memset(&mvdata, 0, sizeof(mvdata));
	mvdata.buffer	= hdr;
	mvdata.hdr	= hdr;
	mvdata.size	= size;

	ret = module_verify_elf(&mvdata);
	if (ret < 0) {
		if (ret == -ELIBBAD)
			printk("Module failed ELF checks\n");
		goto error;
	}

error:
	kfree(mvdata.secsizes);
	kfree(mvdata.canonlist);
	return ret;
}
