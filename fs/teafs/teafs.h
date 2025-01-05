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
    struct inode       *backing_inode;    /* Actual inode in backingdir */
    struct dentry      *__upperdentry;    /* Actual dentry in backingdir */
    const char         *redirect;         /* Redirect path for symlinks (optional) */
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
    if (!ti->__upperdentry)
        return NULL;

    /* Return the backing dentry found in the inode_info */
    return ti->__upperdentry;
}

int teafs_get_backing_path(struct dentry *dentry, struct path *backing_path);
const struct cred *teafs_override_creds(const struct super_block *sb);
void teafs_revert_creds(const struct cred *old_cred);

/* inode.c */
struct inode *teafs_get_inode(struct super_block *sb, umode_t mode);

/* Superblock functions */
extern struct dentry *teafs_mount(struct file_system_type *fs_type,
                                  int flags, const char *dev_name, void *data);

struct teafs_info {
	struct path backing_path;
};
#endif /* _TEAFS_H */
