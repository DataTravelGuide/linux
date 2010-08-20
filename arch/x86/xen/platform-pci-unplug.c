/******************************************************************************
 * platform-pci-unplug.c
 *
 * Xen platform PCI device driver
 * Copyright (c) 2010, Citrix
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
 *
 */

#include <asm/io.h>

#include <linux/init.h>
#include <linux/module.h>

#include <xen/platform_pci.h>
#include <xen/xen.h>

extern int xen_pv_hvm_enable;

/* boolean to signal that the platform pci device can be used */
bool xen_platform_pci_enabled;
EXPORT_SYMBOL_GPL(xen_platform_pci_enabled);
static int xen_emul_unplug;

static int __init check_platform_magic(void)
{
	short magic;
	char protocol;

	magic = inw(XEN_IOPORT_MAGIC);
	if (magic != XEN_IOPORT_MAGIC_VAL) {
		printk(KERN_INFO "Xen Platform PCI: unrecognised magic value\n");
		return -1;
	}

	protocol = inb(XEN_IOPORT_PROTOVER);

	printk(KERN_DEBUG "Xen Platform PCI: I/O protocol version %d\n",
			protocol);

	switch (protocol) {
	case 1:
		outw(XEN_IOPORT_LINUX_PRODNUM, XEN_IOPORT_PRODNUM);
		outl(XEN_IOPORT_LINUX_DRVVER, XEN_IOPORT_DRVVER);
		if (inw(XEN_IOPORT_MAGIC) != XEN_IOPORT_MAGIC_VAL) {
			printk(KERN_INFO "Xen Platform: blacklisted by host\n");
			return -3;
		}
		break;
	default:
		printk(KERN_WARNING "Xen Platform PCI: unknown I/O protocol version");
		return -2;
	}

	return 0;
}

int xen_ide_unplug_unsupported = 1;
EXPORT_SYMBOL_GPL(xen_ide_unplug_unsupported);

void __init xen_unplug_emulated_devices(void)
{
	int r;

	/* not valid unless in HVM case */
	if (!xen_hvm_domain() || !xen_pv_hvm_enable)
		return;

	/* check the version of the xen platform PCI device */
	r = check_platform_magic();

	if (!r)
		xen_ide_unplug_unsupported = 0;

	/* If the version matches enable the Xen platform PCI driver.
	 * Also enable the Xen platform PCI driver if the version is really old
	 * and the user told us to ignore it. */
	if (!r || (r == -1 && (xen_emul_unplug & XEN_UNPLUG_IGNORE)))
		xen_platform_pci_enabled = 1;
	/* Set the default value of xen_emul_unplug depending on whether or
	 * not the Xen PV frontends and the Xen platform PCI driver have
	 * been compiled for this kernel (modules or built-in are both OK). */
	if (xen_platform_pci_enabled && !xen_emul_unplug) {
		if (xen_must_unplug_nics()) {
			printk(KERN_INFO "Netfront and the Xen platform PCI driver have "
					"been compiled for this kernel: unplug emulated NICs.\n");
			xen_emul_unplug |= XEN_UNPLUG_ALL_NICS;
		}
		if (xen_must_unplug_disks()) {
			printk(KERN_INFO "Blkfront and the Xen platform PCI driver have "
					"been compiled for this kernel: unplug emulated disks.\n"
					"You might have to change the root device\n"
					"from /dev/hd[a-d] to /dev/xvd[a-d]\n"
					"in your root= kernel command line option\n");
			xen_emul_unplug |= XEN_UNPLUG_ALL_IDE_DISKS;
		}
	}
	/* Now unplug the emulated devices */
	if (xen_platform_pci_enabled && !(xen_emul_unplug & XEN_UNPLUG_IGNORE))
		outw(xen_emul_unplug, XEN_IOPORT_UNPLUG);
}

static int __init parse_xen_emul_unplug(char *arg)
{
	char *p, *q;
	int l;

	for (p = arg; p; p = q) {
		q = strchr(p, ',');
		if (q) {
			l = q - p;
			q++;
		} else {
			l = strlen(p);
		}
		if (!strncmp(p, "all", l))
			xen_emul_unplug |= XEN_UNPLUG_ALL;
		else if (!strncmp(p, "ide-disks", l))
			xen_emul_unplug |= XEN_UNPLUG_ALL_IDE_DISKS;
		else if (!strncmp(p, "aux-ide-disks", l))
			xen_emul_unplug |= XEN_UNPLUG_AUX_IDE_DISKS;
		else if (!strncmp(p, "nics", l))
			xen_emul_unplug |= XEN_UNPLUG_ALL_NICS;
		else if (!strncmp(p, "ignore", l))
			xen_emul_unplug |= XEN_UNPLUG_IGNORE;
		else
			printk(KERN_WARNING "unrecognised option '%s' "
				 "in module parameter 'xen_emul_unplug'\n", p);
	}
	return 0;
}
early_param("xen_emul_unplug", parse_xen_emul_unplug);
