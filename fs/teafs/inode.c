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
    inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);

    ti = teafs_i(inode);
    ti->backing_inode = NULL;
    ti->__upperdentry = NULL;
    ti->redirect = NULL;

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

    /* Initialize __upperdentry if backing_inode is set */
    if (ti->backing_inode) {
        ti->__upperdentry = d_find_alias(ti->backing_inode);
        if (!ti->__upperdentry) {
            iput(inode);
            return ERR_PTR(-ENOENT);
        }
        dget(ti->__upperdentry);  /* Increment dentry reference count */
    }

    return inode;
}

/**
 * teafs_alloc_inode - Allocate memory for TEAFS inode
 * @sb: Superblock pointer
 *
 * Returns:
 *   A pointer to the new inode on success, or NULL on failure.
 */
static struct inode *teafs_alloc_inode(struct super_block *sb)
{
    struct teafs_inode_info *ti;

    ti = kzalloc(sizeof(struct teafs_inode_info), GFP_KERNEL);
    if (!ti)
        return NULL;

    inode_init_once(&ti->vfs_inode);
    return &ti->vfs_inode;
}

/**
 * teafs_destroy_inode - Destroy a TEAFS inode
 * @inode: Inode pointer
 *
 * Frees the memory allocated for the inode.
 */
static void teafs_destroy_inode(struct inode *inode)
{
    struct teafs_inode_info *ti = teafs_i(inode);

    if (ti->__upperdentry)
        dput(ti->__upperdentry);

    kfree(ti);
}

/* Define superblock operations */
static const struct super_operations teafs_super_ops = {
    .alloc_inode    = teafs_alloc_inode,
    .destroy_inode  = teafs_destroy_inode,
};

/**
 * teafs_setattr - Set file or directory attributes
 * @mnt_userns: User namespace
 * @dentry: Dentry of the file or directory
 * @attr: Attributes to set
 *
 * Returns:
 *   0 on success, or a negative error code on failure.
 */
static int teafs_setattr(struct user_namespace *mnt_userns,
                         struct dentry *dentry, struct iattr *attr)
{
    struct path backing_path;
    int err;

    /* Retrieve the backing path */
    err = teafs_get_backing_path(dentry, &backing_path);
    if (err)
        return err;

    /* Call VFS's setattr */
    err = vfs_setattr(&backing_path, attr);

    path_put(&backing_path);
    return err;
}

/**
 * teafs_getattr - Retrieve file or directory attributes
 * @path: The file path
 * @stat: The kstat structure to fill with attributes
 * @request_mask: The mask specifying which attributes to retrieve
 * @flags: Flags controlling the operation
 *
 * This function retrieves the attributes of a file or directory by forwarding
 * the getattr call to the backing directory's corresponding path.
 *
 * Returns:
 *   0 on success, or a negative error code on failure.
 */
static int teafs_getattr(const struct path *path, struct kstat *stat,
                         u32 request_mask, unsigned int flags)
{
    struct dentry *dentry = path->dentry;
    struct teafs_inode_info *ti = teafs_i(d_inode(dentry));
    struct path backing_path;
    const struct cred *old_cred;
    int err;

    /* Clear the AT_GETATTR_NOSEC flag to avoid returning -EPERM */
    flags &= ~AT_GETATTR_NOSEC;

    /* Retrieve the backing_path corresponding to the TEAFS dentry */
    err = teafs_get_backing_path(dentry, &backing_path);
    if (err)
        return err;

    /* Override the current credentials to match the backing filesystem's context */
    old_cred = teafs_override_creds(dentry->d_sb);
    if (IS_ERR(old_cred)) {
        path_put(&backing_path);
        return PTR_ERR(old_cred);
    }

    /* Retrieve attributes from the backing_path */
    err = vfs_getattr(&backing_path, stat, request_mask, flags);
    path_put(&backing_path);  /* Release the backing_path reference */

    /* Revert to the original credentials */
    teafs_revert_creds(old_cred);

    return err;
}

/**
 * teafs_update_time - Update file or directory timestamps
 * @dentry: Dentry of the file or directory
 * @attr: Attributes to update
 *
 * Returns:
 *   0 on success, or a negative error code on failure.
 */
static int teafs_update_time(struct dentry *dentry, struct iattr *attr)
{
    struct path backing_path;
    int err;

    /* Retrieve the backing path */
    err = teafs_get_backing_path(dentry, &backing_path);
    if (err)
        return err;

    /* Call VFS's setattr to update timestamps */
    err = vfs_setattr(&backing_path, attr);

    path_put(&backing_path);
    return err;
}

/**
 * teafs_permission - Check access permissions for a file or directory
 * @mnt_userns: User namespace
 * @inode: Inode of the file or directory
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

/* Define inode operations for files */
const struct inode_operations teafs_file_inode_operations = {
    .setattr        = teafs_setattr,
    .getattr        = teafs_getattr,
    .permission     = teafs_permission,
};

/* Define inode operations for directories */
const struct inode_operations teafs_dir_inode_operations = {
    .lookup         = teafs_lookup,
    .mkdir          = teafs_mkdir,
    .unlink         = teafs_unlink,
    .rmdir          = teafs_rmdir,
    .rename         = teafs_rename,
    .setattr        = teafs_setattr,
    .permission     = teafs_permission,
    .getattr        = teafs_getattr,
    .update_time    = teafs_update_time,
};

