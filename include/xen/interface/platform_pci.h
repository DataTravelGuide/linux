/******************************************************************************
 * platform_pci.h
 *
 * Interface for granting foreign access to page frames, and receiving
 * page-ownership transfers.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef __XEN_PUBLIC_PLATFORM_PCI_H__
#define __XEN_PUBLIC_PLATFORM_PCI_H__

#define XEN_IOPORT_BASE 0x10

#define XEN_IOPORT_PLATFLAGS	(XEN_IOPORT_BASE + 0) /* 1 byte access (R/W) */
#define XEN_IOPORT_MAGIC	(XEN_IOPORT_BASE + 0) /* 2 byte access (R) */
#define XEN_IOPORT_UNPLUG	(XEN_IOPORT_BASE + 0) /* 2 byte access (W) */
#define XEN_IOPORT_DRVVER	(XEN_IOPORT_BASE + 0) /* 4 byte access (W) */

#define XEN_IOPORT_SYSLOG	(XEN_IOPORT_BASE + 2) /* 1 byte access (W) */
#define XEN_IOPORT_PROTOVER	(XEN_IOPORT_BASE + 2) /* 1 byte access (R) */
#define XEN_IOPORT_PRODNUM	(XEN_IOPORT_BASE + 2) /* 2 byte access (W) */

#define UNPLUG_ALL_IDE_DISKS 1
#define UNPLUG_ALL_NICS 2
#define UNPLUG_AUX_IDE_DISKS 4
#define UNPLUG_ALL 7

#endif /* __XEN_PUBLIC_PLATFORM_PCI_H__ */
