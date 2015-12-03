/*
 * Copyright (C) 2015 Red Hat
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License v2. See the file COPYING in the main directory of this archive for
 * more details.
 */

#include <drm/drm_backport.h>
#include <drm/idr2.h>

int __init drm_backport_init(void)
{
	idr2_init_cache();
	return 0;
}

void __exit drm_backport_exit(void)
{
}
