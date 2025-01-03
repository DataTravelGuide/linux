// fs/teafs/special.c

#include "teafs.h"
#include <linux/fs.h>

/**
 * teafs_permission - Check access permissions for special files
 * @mnt_userns: User namespace
 * @inode: Inode of the special file
 * @mask: Permission mask
 *
 * Returns:
 *   0 if access is allowed, or a negative error code on failure.
 */
static int teafs_permission(struct user_namespace *mnt_userns,
                            struct inode *inode, int mask)
{
    struct teafs_inode_info *ti = teafs_i(inode);
    struct path backing_path;
    int err;

    /* Retrieve the backing path */
    err = teafs_get_backing_path(inode->i_dentry, &backing_path);
    if (err)
        return err;

    /* Call VFS's permission check */
    err = vfs_permission(mnt_userns, &backing_path, mask);

    path_put(&backing_path);
    return err;
}

/* Define special inode operations */
const struct inode_operations teafs_special_inode_operations = {
    .permission = teafs_permission,
};

