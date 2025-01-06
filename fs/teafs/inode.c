// fs/teafs/inode.c

#include "teafs.h"
#include <linux/slab.h>
#include <linux/pagemap.h>

/**
 * teafs_get_inode - Allocate and initialize a new inode
 * @sb: Superblock pointer
 * @mode: File mode
 *
 * Returns:
 *   A pointer to the new inode on success, or ERR_PTR on failure.
 */
struct inode *teafs_get_inode(struct super_block *sb, struct dentry *backing_dentry, umode_t mode)
{
    struct inode *inode;
    struct teafs_inode_info *ti;

    inode = new_inode(sb);
    if (!inode)
        return ERR_PTR(-ENOMEM);

    inode->i_mode = mode;
    inode->i_ino = get_next_ino();
    inode->i_uid = current_fsuid();
    inode->i_gid = current_fsgid();

    ti = teafs_i(inode);
    dget(backing_dentry);
    ti->backing_dentry = backing_dentry;

	switch (mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &teafs_file_inode_operations;
		inode->i_fop = &teafs_file_operations;
		break;

	case S_IFDIR:
		inode->i_op = &teafs_dir_inode_operations;
		inode->i_fop = &teafs_dir_operations;
		break;

	case S_IFLNK:
		inode->i_op = &teafs_symlink_inode_operations;
		break;

	default:
		inode->i_op = &teafs_special_inode_operations;
		init_special_inode(inode, mode, d_inode(backing_dentry)->i_rdev);
		break;
	}

    return inode;
}

/* Define inode operations for files */
const struct inode_operations teafs_file_inode_operations = {
    .setattr        = NULL,
    .getattr        = NULL,
    .permission     = NULL,
};
