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

/* TEAFS inode information structure */
struct teafs_inode_info {
    struct inode        vfs_inode;
    struct dentry	*backing_dentry;
};

/* TEAFS superblock information structure */
struct teafs_fs_info {
    struct path backing_path;             /* Path to the backing directory */
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
static inline struct teafs_inode_info *teafs_i(struct inode *inode)
{
    return container_of(inode, struct teafs_inode_info, vfs_inode);
}

static struct dentry *teafs_get_backing_dentry_i(struct inode *inode)
{
    struct teafs_inode_info *ti;

    /* Get the teafs_inode_info from the inode */
    ti = teafs_i(inode);

    /* Check if the backing dentry exists */
    if (!ti->backing_dentry)
        return NULL;

    /* Return the backing dentry found in the inode_info */
    return ti->backing_dentry;
}

static void teafs_backing_path(struct inode *inode, struct path *path)
{
	struct super_block *sb = inode->i_sb;
    	struct teafs_fs_info *fs_info;

	sb = inode->i_sb;
	fs_info = sb->s_fs_info;

	path->mnt = fs_info->backing_path.mnt;
	path->dentry = teafs_i(inode)->backing_dentry;
}

const struct cred *teafs_override_creds(const struct super_block *sb);
void teafs_revert_creds(const struct cred *old_cred);

static struct mnt_idmap *teafs_backing_mnt_idmap(struct inode *inode)
{
    struct super_block *sb;
    struct teafs_fs_info *fs_info;
    struct path backing_path;
    struct vfsmount *mnt;
    const char *name;
    int len;
    struct dentry *base;
    struct dentry *result;
    struct dentry *backing_dentry;
    int ret;

    // 1. 获取超级块
    sb = inode->i_sb;
    if (!sb) {
        printk(KERN_ERR "teafs: Directory inode has no super_block\n");
        return ERR_PTR(-EINVAL);
    }

    // 2. 获取 teafs_fs_info
    fs_info = sb->s_fs_info;
    if (!fs_info) {
        printk(KERN_ERR "teafs: Super_block has no fs_info\n");
        return ERR_PTR(-EINVAL);
    }

    // 3. 获取 backing_path
    if (!fs_info->backing_path.dentry || !fs_info->backing_path.mnt) {
        printk(KERN_ERR "teafs: Invalid backing_path in fs_info\n");
        return ERR_PTR(-EINVAL);
    }

    // 4. 获取挂载点 mnt
    mnt = fs_info->backing_path.mnt;
    if (!mnt) {
        printk(KERN_ERR "teafs: backing_path has no mount\n");
        return ERR_PTR(-EINVAL);
    }

    return mnt_idmap(mnt);

}
/* inode.c */
struct inode *teafs_get_inode(struct super_block *sb, struct dentry *backing_dentry, umode_t mode);

/* Superblock functions */
extern struct dentry *teafs_mount(struct file_system_type *fs_type,
                                  int flags, const char *dev_name, void *data);

struct teafs_info {
	struct path backing_path;
	const struct cred *creator_cred;
};
#endif /* _TEAFS_H */
