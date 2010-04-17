/******************************************************************************
 * platform-pci.h
 * 
 * Xen platform PCI device driver
 * Copyright (c) 2004, Intel Corporation. <xiaofeng.ling@intel.com>
 * Copyright (c) 2007, XenSource Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#ifndef _XEN_PLATFORM_PCI_H
#define _XEN_PLATFORM_PCI_H

#include <linux/version.h>

#define XEN_IOPORT_MAGIC_VAL 0x49d2
#define XEN_IOPORT_LINUX_PRODNUM 0xffff
#define XEN_IOPORT_LINUX_DRVVER  ((LINUX_VERSION_CODE << 8) + 0x0)

#ifdef CONFIG_XEN_PLATFORM_PCI
unsigned long alloc_xen_mmio(unsigned long len);
#else
static inline unsigned long alloc_xen_mmio(unsigned long len)
{
	return ~0UL;
}
#endif

#endif /* _XEN_PLATFORM_PCI_H */
