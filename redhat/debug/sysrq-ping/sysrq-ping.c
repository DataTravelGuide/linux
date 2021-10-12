/*
 * network_sysrq.c - allow sysrq to be executed over a network via ping
 *
 * written by:  Prarit Bhargava <prarit@redhat.com>
 *		Andy Gospodarek <agospoda@redhat.com>
 *		Neil Horman <nhorman@redhat.com>
 *
 * based on work by:	Larry Woodman <lwoodman@redhat.com>
 *
 * To use this do:
 *
 *	mount -t debugfs none /sys/kernel/debug/
 *	echo 1 > /proc/sys/kernel/sysrq
 *	echo <hex digit val> > /sys/kernel/debug/network_sysrq_magic
 *	echo 1 > /sys/kernel/debug/network_sysrq_enable
 *
 * Then on another system you can do:
 *
 *	ping -c 1 -p <hex digit val><hex val of sysrq> <target_system_name>
 *
 *	ex) sysrq-m, m is 0x6d
 *
 *	    ping -c 1 -p 1623a06f554d46d676d <target_system_name>
 *
 * Note that the network sysrq automatically disables after the receipt of
 * *ANY* ping.  If you want to use this again, you must complete the
 * above four steps again.  To override this, you can set auto_rearm = 1 as
 * a module parameter.
 *
 */

#include <linux/debugfs.h>
#include <linux/icmp.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/sysrq.h>

#include <net/xfrm.h>

static u8 network_sysrq_enable; /* set in debugfs network_sysrq_enable */
static u16 network_sysrq_magic[16]; /* 15 bytes leaves 1 feature byte */
static int network_sysrq_magic_len;
static int auto_rearm;

static int to_hex(int val)
{
	if ((val >= '0') && (val <= '9'))
		return val - 0x30;

	if ((val >= 'a') && (val <= 'f'))
		return val - 0x37;

	if ((val >= 'A') && (val <= 'F'))
		return val - 0x57;

	return -1;
}

static bool network_sysrq_armed(void)
{
	int i;

	if (!network_sysrq_enable)
		return false;
	if (!network_sysrq_magic_len)
		return false;
	for (i = 0; i < 16; i++)
		if (network_sysrq_magic[i] != 0)
			return true;
	return false;
}

static void network_sysrq_disable(void)
{
	network_sysrq_enable = 0;
	memset(network_sysrq_magic, 0, 32);
	network_sysrq_magic_len = 0;
}

static ssize_t network_sysrq_seq_write(struct file *file,
				       const char __user *ubuf,
				       size_t count, loff_t *ppos)
{
	int i, j, hi, lo;
	char buf[33];
	memset(buf, 0, sizeof(buf));

	if (count >= 33)
		return -EINVAL;

	if (copy_from_user(&buf, ubuf, min_t(size_t, sizeof(buf) - 1, count)))
		return -EFAULT;

	for (i = 0, j = 0; i < count - 2 ; i += 2, j++) {
		hi = to_hex(buf[i]);
		lo = to_hex(buf[i+1]) & 0x0f;
		if ((hi == -1) || (lo == -1)) {
			network_sysrq_disable();
			return -EINVAL;
		}
		network_sysrq_magic[j] = (u16)(hi << 4) + lo;
	}
	network_sysrq_magic_len = j;

	return count;
}

static int network_sysrq_seq_show(struct seq_file *m, void *p)
{
	int i;

	for (i = 0; i < network_sysrq_magic_len; i++)
		seq_printf(m, "%02x", network_sysrq_magic[i]);
	seq_printf(m, "\n");
	return 0;
}

static int network_sysrq_fops_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return single_open(file, network_sysrq_seq_show, inode->i_private);
}

static const struct file_operations xnetwork_sysrq_fops = {
	.open		= network_sysrq_fops_open,
	.write		= network_sysrq_seq_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
};

static int network_sysrq_func(struct sk_buff *skb, struct net_device *dev,
			      struct packet_type *pt,
			      struct net_device *orig_dev)
{
	struct icmphdr *icmph;
	char *found;

	if (ip_hdr(skb)->protocol != IPPROTO_ICMP)
		goto end;

	if (!skb_pull(skb, sizeof(struct iphdr)))
		goto end;

	skb_reset_transport_header(skb);
	icmph = icmp_hdr(skb);

	if (!skb_pull(skb, sizeof(*icmph)))
		goto end;

	/* is this a ping? */
	if (icmph->type != ICMP_ECHO)
		goto end;

	if (network_sysrq_armed()) {
		found = strnstr(skb->data, (char *)network_sysrq_magic,
				skb->len - skb->data_len);
		if (found) {
			printk(KERN_EMERG "Network issued sysrq-%c\n",
			       found[network_sysrq_magic_len]);
			handle_sysrq(found[network_sysrq_magic_len], NULL);
		}
		if (!auto_rearm)
			network_sysrq_disable();
	}
end:
	kfree_skb(skb);
	return 0;
}

static struct packet_type network_sysrq_type = {
	.type = cpu_to_be16(ETH_P_IP),
	.func = network_sysrq_func,
};

static struct dentry *network_sysrq_enable_dentry;
static struct dentry *network_sysrq_magic_dentry;

int __init init_network_sysrq(void)
{
	network_sysrq_enable_dentry = debugfs_create_u8("network_sysrq_enable",
							S_IWUGO | S_IRUGO,
							NULL,
							&network_sysrq_enable);
	if (!network_sysrq_enable_dentry)
		return -EIO;

	network_sysrq_magic_dentry = debugfs_create_file("network_sysrq_magic",
							S_IWUGO | S_IRUGO,
							NULL,
							&network_sysrq_magic,
							&xnetwork_sysrq_fops);
	if (!network_sysrq_magic_dentry) {
		debugfs_remove(network_sysrq_enable_dentry);
		return -EIO;
	}

	dev_add_pack(&network_sysrq_type);

	if (auto_rearm) {
		printk(KERN_EMERG "******************************************"
				  "************************************\n");
		printk(KERN_EMERG "WARNING: YOU ARE IN PING SYSRQ AUTO "
				  "REARM MODE.  USE AT YOUR OWN RISK.\n");
		printk(KERN_EMERG "******************************************"
				  "************************************\n");
	}
	return 0;
}

void __exit cleanup_network_sysrq(void)
{
	dev_remove_pack(&network_sysrq_type);
	debugfs_remove(network_sysrq_enable_dentry);
	debugfs_remove(network_sysrq_magic_dentry);
}

module_init(init_network_sysrq);
module_exit(cleanup_network_sysrq);
module_param(auto_rearm, int, 0444); /* always re-arm after ping received */

MODULE_LICENSE("GPL");
