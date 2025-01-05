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
struct inode *teafs_get_inode(struct super_block *sb, umode_t mode)
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
    ti->backing_inode = NULL;
    ti->__upperdentry = NULL;
    ti->redirect = NULL;

    return inode;
    /*
    if (S_ISDIR(mode)) {
        inode->i_op = &teafs_dir_inode_operations;
        inode->i_fop = &teafs_dir_operations;
    } else if (S_ISLNK(mode)) {
        inode->i_op = &teafs_symlink_inode_operations;
        inode->i_fop = &simple_symlink_operations;
    } else if (S_ISCHR(mode) || S_ISBLK(mode) || S_ISFIFO(mode) || S_ISSOCK(mode)) {
        inode->i_op = &teafs_special_inode_operations;
        init_special_inode(inode, mode, 0);
    } else {
        inode->i_op = &teafs_file_inode_operations;
        inode->i_fop = &teafs_file_operations;
    }

    if (ti->backing_inode) {
        ti->__upperdentry = d_find_alias(ti->backing_inode);
        if (!ti->__upperdentry) {
            iput(inode);
            return ERR_PTR(-ENOENT);
        }
        dget(ti->__upperdentry);
    }

    return inode;
    */
}

/* Define inode operations for files */
const struct inode_operations teafs_file_inode_operations = {
    .setattr        = NULL,
    .getattr        = NULL,
    .permission     = NULL,
};

