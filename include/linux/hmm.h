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
/*
 * HMM provides helpers to help leverage heterogeneous memory ie memory with
 * differents characteristics (latency, bandwidth, ...). The core idea is to
 * migrate virtual address range of a process to different memory. HMM is not
 * involve in policy or decision making of what memory and where to migrate.
 * HMM only provides helpers for the grunt work of migrating memory.
 *
 * Second part of HMM is to provide helpers to mirror a process address space
 * on a device. Here it is about mirroring CPU page table inside device page
 * table and making sure that they keep pointing to same memory for any given
 * virtual address. Bonus feature is allowing migration to device memory that
 * can not be access by CPU.
 */
#ifndef _LINUX_HMM_H
#define _LINUX_HMM_H

#include <linux/kconfig.h>

#if IS_ENABLED(CONFIG_HMM)


#endif /* IS_ENABLED(CONFIG_HMM) */
#endif /* _LINUX_HMM_H */
