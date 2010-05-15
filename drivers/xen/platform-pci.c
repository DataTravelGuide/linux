/******************************************************************************
 * platform-pci.c
 * 
 * Xen platform PCI device driver
 * Copyright (c) 2005, Intel Corporation.
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
 *
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/interrupt.h>

#include <asm/io.h>

#include <xen/grant_table.h>
#include <xen/platform_pci.h>
#include <xen/interface/platform_pci.h>
#include <xen/xenbus.h>
#include <xen/events.h>
#include <xen/hvm.h>

#define DRV_NAME    "xen-platform-pci"

MODULE_AUTHOR("ssmith@xensource.com and stefano.stabellini@eu.citrix.com");
MODULE_DESCRIPTION("Xen platform PCI device");
MODULE_LICENSE("GPL");

static unsigned long platform_mmio;
static unsigned long platform_mmio_alloc;
static unsigned long platform_mmiolen;

unsigned long alloc_xen_mmio(unsigned long len)
{
	unsigned long addr;

	addr = platform_mmio + platform_mmio_alloc;
	platform_mmio_alloc += len;
	BUG_ON(platform_mmio_alloc > platform_mmiolen);

	return addr;
}

static uint64_t get_callback_via(struct pci_dev *pdev)
{
	u8 pin;
	int irq;

#ifdef __ia64__
	for (irq = 0; irq < 16; irq++) {
		if (isa_irq_to_vector(irq) == pdev->irq)
			return irq; /* ISA IRQ */
	}
#else /* !__ia64__ */
	irq = pdev->irq;
	if (irq < 16)
		return irq; /* ISA IRQ */
#endif
	pin = pdev->pin;

	/* We don't know the GSI. Specify the PCI INTx line instead. */
	return (((uint64_t)0x01 << 56) | /* PCI INTx identifier */
		((uint64_t)pci_domain_nr(pdev->bus) << 32) |
		((uint64_t)pdev->bus->number << 16) |
		((uint64_t)(pdev->devfn & 0xff) << 8) |
		((uint64_t)(pin - 1) & 3));
}

static irqreturn_t do_hvm_evtchn_intr(int irq, void *dev_id)
{
	xen_hvm_evtchn_do_upcall(get_irq_regs());
	return IRQ_HANDLED;
}

int xen_irq_init(struct pci_dev *pdev)
{
	__set_irq_handler(pdev->irq, handle_edge_irq, 0, NULL);
	return request_irq(pdev->irq, do_hvm_evtchn_intr,
			IRQF_SAMPLE_RANDOM | IRQF_DISABLED | IRQF_NOBALANCING |
			IRQF_TRIGGER_RISING, "xen-platform-pci", pdev);
}

static int __devinit platform_pci_init(struct pci_dev *pdev,
				       const struct pci_device_id *ent)
{
	int i, ret;
	long ioaddr, iolen;
	long mmio_addr, mmio_len;
	uint64_t callback_via;

	if (!xen_hvm_domain()) {
		printk("%s: Xen PV-on-HVM support not init'd ... exiting \n", 
			__FUNCTION__);
		return -ENODEV;
	}

	i = pci_enable_device(pdev);
	if (i)
		return i;

	ioaddr = pci_resource_start(pdev, 0);
	iolen = pci_resource_len(pdev, 0);

	mmio_addr = pci_resource_start(pdev, 1);
	mmio_len = pci_resource_len(pdev, 1);

	if (mmio_addr == 0 || ioaddr == 0) {
		printk(KERN_WARNING DRV_NAME ":no resources found\n");
		return -ENOENT;
	}

	if (request_mem_region(mmio_addr, mmio_len, DRV_NAME) == NULL) {
		printk(KERN_ERR DRV_NAME ":MEM I/O resource 0x%lx @ 0x%lx busy\n",
		       mmio_addr, mmio_len);
		return -EBUSY;
	}

	if (request_region(ioaddr, iolen, DRV_NAME) == NULL) {
		printk(KERN_ERR DRV_NAME ":I/O resource 0x%lx @ 0x%lx busy\n",
		       iolen, ioaddr);
		release_mem_region(mmio_addr, mmio_len);
		return -EBUSY;
	}

	platform_mmio = mmio_addr;
	platform_mmiolen = mmio_len;

	if (!xen_have_vector_callback) {
		xen_irq_init(pdev);
		callback_via = get_callback_via(pdev);
		if ((ret = xen_set_callback_via(callback_via)))
			goto out;
	}

	if ((ret = gnttab_init()))
		goto out;

	if ((ret = xenbus_probe_init()))
		goto out;

 out:
	if (ret) {
		release_mem_region(mmio_addr, mmio_len);
		release_region(ioaddr, iolen);
	}

	return ret;
}

#define XEN_PLATFORM_VENDOR_ID 0x5853
#define XEN_PLATFORM_DEVICE_ID 0x0001
static struct pci_device_id platform_pci_tbl[] __devinitdata = {
	{XEN_PLATFORM_VENDOR_ID, XEN_PLATFORM_DEVICE_ID,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	/* Continue to recognise the old ID for now */
	{0xfffd, 0x0101, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0,}
};

MODULE_DEVICE_TABLE(pci, platform_pci_tbl);

static struct pci_driver platform_driver = {
	name:     DRV_NAME,
	probe:    platform_pci_init,
	id_table: platform_pci_tbl,
};

int xen_ide_unplug_unsupported = 0;

static int check_platform_magic(void)
{
	short magic;
	char protocol, *err;

	magic = inw(XEN_IOPORT_MAGIC);

	if (magic != XEN_IOPORT_MAGIC_VAL) {
		err = "unrecognised magic value";
		goto no_dev;
	}

	protocol = inb(XEN_IOPORT_PROTOVER);

	printk(KERN_DEBUG DRV_NAME "I/O protocol version %d\n", protocol);

	switch (protocol) {
	case 1:
		outw(XEN_IOPORT_LINUX_PRODNUM, XEN_IOPORT_PRODNUM);
		outl(XEN_IOPORT_LINUX_DRVVER, XEN_IOPORT_DRVVER);
		if (inw(XEN_IOPORT_MAGIC) != XEN_IOPORT_MAGIC_VAL) {
			printk(KERN_ERR DRV_NAME "blacklisted by host\n");
			return -ENODEV;
		}
		/* Fall through */
	default:
		err = "unknown I/O protocol version";
		goto no_dev;
	}

	return 0;

 no_dev:
	xen_ide_unplug_unsupported = 1;
	printk(KERN_WARNING DRV_NAME ": failed Xen IOPORT backend handshake: %s\n", err);
	return 0;
}
EXPORT_SYMBOL_GPL(xen_ide_unplug_unsupported);

int xen_pv_hvm_enable = 0;
int xen_pv_hvm_smp = 0;

static int __init xen_pv_hvm_setup(char *p)
{
	size_t len;

	while (*p) {
		if (!strncmp(p, "enable", 6)) {
			len = 6;
			xen_pv_hvm_enable = 1;
		}
		if (!strncmp(p, "smpon", 5)) {
			xen_pv_hvm_smp = 1;
			len = 5;
		}
		p = strpbrk(p, ",");
		if (!p) break; /* no more to param */
		p++; /* skip ',' */
	}

	/* right now, pv-hvm hangs on boot if vcpus > 1 */
	/* enable workaround for test purposes */
	if (!(xen_pv_hvm_smp) && (num_present_cpus() > 1)) {
		 printk("Not enabling Xen PV-on-HVM; vcpus>1 \n");
		 xen_pv_hvm_enable = 0;
	}

	if (xen_pv_hvm_enable)
		 printk("Enabling Xen PV-on-HVM \n");

	return 1;
}
static int __init platform_pci_module_init(void)
{
	int rc;

	if (xen_hvm_domain()) {
		if (!xen_pv_hvm_enable) {
			printk("Xen pv-on-hvm disabled\n");
			goto out;
		} else {
			printk("Xen pv-on-hvm enabled\n");
		}
	}

	rc = check_platform_magic();
	if (rc < 0)
		return rc;

	rc = pci_register_driver(&platform_driver);
	if (rc) {
		printk(KERN_INFO DRV_NAME
	       		": No platform pci device model found\n");
		return rc;
	}

out:
	return 0;
}

module_init(platform_pci_module_init);

__setup("xen_pv_hvm=", xen_pv_hvm_setup);

