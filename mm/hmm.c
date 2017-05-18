/*
 * Copyright 2013 Red Hat Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Authors: Jérôme Glisse <jglisse@redhat.com>
 */
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/init.h>
#include <linux/hmm.h>

static bool _hmm_enabled = false;

static int __init setup_hmm(char *str)
{
	int ret = 0;

	if (!str)
		goto out;
	if (!strcmp(str, "enable")) {
		_hmm_enabled = true;
		ret = 1;
	}

out:
	if (!ret)
		printk(KERN_WARNING "experimental_hmm= cannot parse, ignored\n");
	return ret;
}
__setup("experimental_hmm=", setup_hmm);
