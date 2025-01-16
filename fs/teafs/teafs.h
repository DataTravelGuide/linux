// fs/teafs/teafs.h

#ifndef _TEAFS_H
#define _TEAFS_H

#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/parser.h>
#include <linux/cred.h>
#include <linux/err.h>

#define teafs_err(fmt, ...)							\
	pr_err("teafs: %s:%u " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define teafs_info(fmt, ...)							\
	pr_info("teafs: %s:%u " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define teafs_debug(fmt, ...)							\
	pr_debug("teafs: %s:%u " fmt, __func__, __LINE__, ##__VA_ARGS__)

struct teafs_file {
	struct file *data_file;
};

/* TEAFS inode information structure */
struct teafs_inode {
	struct inode		vfs_inode;
	struct dentry		*backing_dentry;
	struct dentry		*backing_data_file_dentry;
	struct teafs_file	tfile;
};

struct teafs_info {
	struct path backing_path;
	const struct cred *creator_cred;
};

/* Inode operation prototypes */
extern const struct inode_operations teafs_dir_inode_operations;
extern const struct file_operations teafs_dir_operations;
extern const struct inode_operations teafs_file_inode_operations;
extern const struct inode_operations teafs_symlink_inode_operations;
extern const struct inode_operations teafs_special_inode_operations;

/* File operation prototypes */
extern const struct file_operations teafs_file_operations;
extern const struct file_operations teafs_dir_operations;

/* Dentry operation prototypes */
extern const struct dentry_operations teafs_dentry_operations;

/* Helper functions */
static inline struct teafs_inode *teafs_i(struct inode *inode)
{
	return container_of(inode, struct teafs_inode, vfs_inode);
}

static inline struct dentry *teafs_get_backing_dentry_i(struct inode *inode)
{
	struct teafs_inode *ti;

	ti = teafs_i(inode);
	if (!ti->backing_dentry)
		return NULL;

	return ti->backing_dentry;
}

static inline struct teafs_info *teafs_info_i(struct inode *inode)
{
	return inode->i_sb->s_fs_info;
}

static inline struct mnt_idmap *teafs_info_mnt_idmap(struct teafs_info *tfs)
{
	struct vfsmount *mnt = tfs->backing_path.mnt;

	if (!mnt)
		return NULL;

	return mnt_idmap(mnt);
}

static inline int teafs_backing_path(struct inode *inode, struct path *path)
{
	struct teafs_info *tfs = teafs_info_i(inode);
	struct teafs_inode *ti = teafs_i(inode);

	if (!tfs->backing_path.mnt || !ti->backing_dentry)
		return -EINVAL;

	path->mnt = tfs->backing_path.mnt;
	path->dentry = ti->backing_dentry;

	path_get(path);

	return 0;
}

static inline int teafs_backing_data_path(struct inode *inode, struct path *path)
{
	struct teafs_info *tfs = teafs_info_i(inode);
	struct teafs_inode *ti = teafs_i(inode);

	if (!tfs->backing_path.mnt || !ti->backing_data_file_dentry)
		return -EINVAL;

	path->mnt = tfs->backing_path.mnt;
	path->dentry = ti->backing_data_file_dentry;

	path_get(path);

	return 0;
}

const struct cred *teafs_override_creds(const struct super_block *sb);
void teafs_revert_creds(const struct cred *old_cred);

static inline struct mnt_idmap *teafs_backing_mnt_idmap(struct inode *inode)
{
	struct teafs_info *tfs;
	struct vfsmount *mnt;

	tfs = teafs_info_i(inode);
	mnt = tfs->backing_path.mnt;
	if (!mnt) {
		teafs_err("backing_path for teafs not initialized.\n");
		return ERR_PTR(-EIO);
	}

	return mnt_idmap(mnt);
}

struct teafs_inode_param {
	struct dentry *backing_dentry;
	struct dentry *backing_data_file_dentry;
	umode_t mode;
};

struct inode *teafs_get_inode(struct super_block *sb, struct teafs_inode_param *param);

static inline void teafs_print_dentry(struct dentry *dentry)
{
	if (!dentry) {
		printk(KERN_WARNING "teafs_print_dentry: NULL dentry pointer provided.\n");
		return;
	}

	// 打印 dentry 的名称和长度
	printk(KERN_INFO "teafs_print_dentry: %p Name: %.*s (Length: %d)\n", dentry,
		   (int)dentry->d_name.len, dentry->d_name.name, dentry->d_name.len);

	// 打印关联的 inode 信息
	if (dentry->d_inode) {
		struct inode *inode = dentry->d_inode;
		printk(KERN_INFO "teafs_print_dentry: Inode Number: %lu\n", inode->i_ino);
		printk(KERN_INFO "teafs_print_dentry: Inode Mode: 0x%04o\n", inode->i_mode);
		printk(KERN_INFO "teafs_print_dentry: Inode UID: %u, GID: %u\n",
			   from_kuid(&init_user_ns, inode->i_uid),
			   from_kgid(&init_user_ns, inode->i_gid));
		printk(KERN_INFO "teafs_print_dentry: Inode Size: %llu bytes\n",
			   (unsigned long long)inode->i_size);
	} else {
		printk(KERN_INFO "teafs_print_dentry: No inode associated with this dentry.\n");
	}

	// 打印 dentry 的标志位
	printk(KERN_INFO "teafs_print_dentry: Dentry Flags: 0x%x\n", dentry->d_flags);

	// 检查是否为负 dentry
	if (d_really_is_negative(dentry)) {
		printk(KERN_INFO "teafs_print_dentry: This is a negative dentry (file does not exist).\n");
	} else {
		printk(KERN_INFO "teafs_print_dentry: This is a positive dentry (file exists).\n");
	}
}

#endif /* _TEAFS_H */
