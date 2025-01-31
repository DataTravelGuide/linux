// fs/capfs/capfs.h

#ifndef _CAPFS_H
#define _CAPFS_H

#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/parser.h>
#include <linux/cred.h>
#include <linux/err.h>

#define capfs_err(fmt, ...)							\
	pr_err("capfs: %s:%u " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define capfs_info(fmt, ...)							\
	pr_info("capfs: %s:%u " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define capfs_debug(fmt, ...)							\
	pr_debug("capfs: %s:%u " fmt, __func__, __LINE__, ##__VA_ARGS__)

struct capfs_file {
	struct file *data_file;
};

/* CAPFS inode information structure */
struct capfs_inode {
	struct inode		vfs_inode;
	struct dentry		*backing_dentry;
	struct dentry		*backing_data_file_dentry;
	struct capfs_file	tfile;
};

struct capfs_info {
	struct path backing_path;
	const struct cred *creator_cred;
};

/* Inode operation prototypes */
extern const struct inode_operations capfs_dir_inode_operations;
extern const struct file_operations capfs_dir_operations;
extern const struct inode_operations capfs_file_inode_operations;
extern const struct inode_operations capfs_symlink_inode_operations;
extern const struct inode_operations capfs_special_inode_operations;

/* File operation prototypes */
extern const struct file_operations capfs_file_operations;
extern const struct file_operations capfs_dir_operations;

/* Dentry operation prototypes */
extern const struct dentry_operations capfs_dentry_operations;

/* Helper functions */
static inline struct capfs_inode *capfs_i(struct inode *inode)
{
	return container_of(inode, struct capfs_inode, vfs_inode);
}

static inline struct dentry *capfs_get_backing_dentry_i(struct inode *inode)
{
	struct capfs_inode *ti;

	ti = capfs_i(inode);
	if (!ti->backing_dentry)
		return NULL;

	return ti->backing_dentry;
}

static inline struct capfs_info *capfs_info_i(struct inode *inode)
{
	return inode->i_sb->s_fs_info;
}

static inline struct mnt_idmap *capfs_info_mnt_idmap(struct capfs_info *tfs)
{
	struct vfsmount *mnt = tfs->backing_path.mnt;

	if (!mnt)
		return NULL;

	return mnt_idmap(mnt);
}

static inline int capfs_backing_path(struct inode *inode, struct path *path)
{
	struct capfs_info *tfs = capfs_info_i(inode);
	struct capfs_inode *ti = capfs_i(inode);

	if (!tfs->backing_path.mnt || !ti->backing_dentry)
		return -EINVAL;

	path->mnt = tfs->backing_path.mnt;
	path->dentry = ti->backing_dentry;

	path_get(path);

	return 0;
}

static inline int capfs_backing_data_path(struct inode *inode, struct path *path)
{
	struct capfs_info *tfs = capfs_info_i(inode);
	struct capfs_inode *ti = capfs_i(inode);

	if (!tfs->backing_path.mnt || !ti->backing_data_file_dentry)
		return -EINVAL;

	path->mnt = tfs->backing_path.mnt;
	path->dentry = ti->backing_data_file_dentry;

	path_get(path);

	return 0;
}

const struct cred *capfs_override_creds(const struct super_block *sb);
void capfs_revert_creds(const struct cred *old_cred);

static inline struct mnt_idmap *capfs_backing_mnt_idmap(struct inode *inode)
{
	struct capfs_info *tfs;
	struct vfsmount *mnt;

	tfs = capfs_info_i(inode);
	mnt = tfs->backing_path.mnt;
	if (!mnt) {
		capfs_err("backing_path for capfs not initialized.\n");
		return ERR_PTR(-EIO);
	}

	return mnt_idmap(mnt);
}

struct capfs_inode_param {
	struct dentry *backing_dentry;
	struct dentry *backing_data_file_dentry;
	umode_t mode;
};

struct inode *capfs_get_inode(struct super_block *sb, struct capfs_inode_param *param);

static inline void capfs_print_dentry(struct dentry *dentry)
{
	if (!dentry) {
		printk(KERN_WARNING "capfs_print_dentry: NULL dentry pointer provided.\n");
		return;
	}

	// 打印 dentry 的名称和长度
	printk(KERN_INFO "capfs_print_dentry: %p Name: %.*s (Length: %d)\n", dentry,
		   (int)dentry->d_name.len, dentry->d_name.name, dentry->d_name.len);

	// 打印关联的 inode 信息
	if (dentry->d_inode) {
		struct inode *inode = dentry->d_inode;
		printk(KERN_INFO "capfs_print_dentry: Inode Number: %lu\n", inode->i_ino);
		printk(KERN_INFO "capfs_print_dentry: Inode Mode: 0x%04o\n", inode->i_mode);
		printk(KERN_INFO "capfs_print_dentry: Inode UID: %u, GID: %u\n",
			   from_kuid(&init_user_ns, inode->i_uid),
			   from_kgid(&init_user_ns, inode->i_gid));
		printk(KERN_INFO "capfs_print_dentry: Inode Size: %llu bytes\n",
			   (unsigned long long)inode->i_size);
	} else {
		printk(KERN_INFO "capfs_print_dentry: No inode associated with this dentry.\n");
	}

	// 打印 dentry 的标志位
	printk(KERN_INFO "capfs_print_dentry: Dentry Flags: 0x%x\n", dentry->d_flags);

	// 检查是否为负 dentry
	if (d_really_is_negative(dentry)) {
		printk(KERN_INFO "capfs_print_dentry: This is a negative dentry (file does not exist).\n");
	} else {
		printk(KERN_INFO "capfs_print_dentry: This is a positive dentry (file exists).\n");
	}
}

#endif /* _CAPFS_H */
