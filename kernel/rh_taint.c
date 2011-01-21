/*
 * This can be used throughout hardware code to indicate that the hardware
 * is unsupported in RHEL6.
 */
#include <linux/kernel.h>
#include <linux/module.h>

void mark_hardware_unsupported(const char *msg)
{
	printk(KERN_CRIT "UNSUPPORTED HARDWARE DEVICE: %s\n", msg);
	WARN_TAINT(1, TAINT_HARDWARE_UNSUPPORTED,
		   "Your hardware is unsupported.  Please do not report "
		   "bugs, panics, oopses, etc., on this hardware.\n");
}
EXPORT_SYMBOL(mark_hardware_unsupported);
