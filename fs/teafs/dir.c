// fs/teafs/dir.c

#include "teafs.h"
#include <linux/fs.h>
#include <linux/namei.h>

/**
 * teafs_lookup - Lookup a dentry in the backing directory
 * @dir: Pointer to the parent directory's inode
 * @dentry: Pointer to the dentry being looked up
 * @flags: Lookup flags
 *
 * Returns:
 *   A pointer to the dentry on success, or an ERR_PTR on failure.
 */
static struct dentry *teafs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
    struct path backing_path;
    struct dentry *real_dentry;
    struct dentry *new_dentry;
    int err;

    /* Retrieve the backing path corresponding to the TEAFS dentry */
    err = teafs_get_backing_path(dentry, &backing_path);
    if (err)
        return ERR_PTR(err);

    /* Perform a lookup in the backing directory for the given name */
    real_dentry = lookup_one_len(dentry->d_name.name, backing_path.dentry, dentry->d_name.len);
    if (IS_ERR(real_dentry)) {
        path_put(&backing_path);
        return ERR_CAST(real_dentry);
    }

    /* If the file does not exist in the backing directory, return NULL */
    if (d_really_is_negative(real_dentry)) {
        dput(real_dentry);
        path_put(&backing_path);
        return NULL;
    }

    /* Clone the real dentry to create a new TEAFS dentry */
    new_dentry = d_clone(real_dentry, dentry);
    dput(real_dentry);
    path_put(&backing_path);

    return new_dentry;
}

/**
 * teafs_mkdir - Create a directory in the backing directory
 * @mnt_userns: User namespace
 * @dir: Pointer to the parent directory's inode
 * @dentry: Pointer to the dentry representing the new directory
 * @mode: Mode of the new directory
 *
 * Returns:
 *   0 on success, or a negative error code on failure.
 */
static int teafs_mkdir(struct user_namespace *mnt_userns,
                       struct inode *dir, struct dentry *dentry,
                       umode_t mode)
{
    struct path backing_path;
    int err;

    /* Retrieve the backing path */
    err = teafs_get_backing_path(dentry, &backing_path);
    if (err)
        return err;

    /* Call VFS's mkdir */
    err = vfs_mkdir(backing_path.mnt->mnt_sb->s_root, dentry, mode);

    path_put(&backing_path);
    return err;
}

/**
 * teafs_unlink - Unlink (delete) a file in the backing directory
 * @dir: Pointer to the parent directory's inode
 * @dentry: Pointer to the dentry representing the file to delete
 *
 * Returns:
 *   0 on success, or a negative error code on failure.
 */
static int teafs_unlink(struct inode *dir, struct dentry *dentry)
{
    struct path backing_path;
    const struct cred *old_cred;
    int err;

    /* Retrieve the backing path */
    err = teafs_get_backing_path(dentry, &backing_path);
    if (err)
        return err;

    /* Override credentials to match the backing filesystem's context */
    old_cred = teafs_override_creds(dir->i_sb);
    if (IS_ERR(old_cred)) {
        path_put(&backing_path);
        return PTR_ERR(old_cred);
    }

    /* Call VFS's unlink */
    err = vfs_unlink(&backing_path, dentry, NULL);

    /* Revert credentials and release backing_path */
    teafs_revert_creds(old_cred);
    path_put(&backing_path);

    return err;
}

/**
 * teafs_rmdir - Remove a directory in the backing directory
 * @dir: Pointer to the parent directory's inode
 * @dentry: Pointer to the dentry representing the directory to remove
 *
 * Returns:
 *   0 on success, or a negative error code on failure.
 */
static int teafs_rmdir(struct inode *dir, struct dentry *dentry)
{
    struct path backing_path;
    const struct cred *old_cred;
    int err;

    /* Retrieve the backing path */
    err = teafs_get_backing_path(dentry, &backing_path);
    if (err)
        return err;

    /* Override credentials to match the backing filesystem's context */
    old_cred = teafs_override_creds(dir->i_sb);
    if (IS_ERR(old_cred)) {
        path_put(&backing_path);
        return PTR_ERR(old_cred);
    }

    /* Call VFS's rmdir */
    err = vfs_rmdir(&backing_path, dentry);

    /* Revert credentials and release backing_path */
    teafs_revert_creds(old_cred);
    path_put(&backing_path);

    return err;
}

/**
 * teafs_rename - Rename or move a file/directory in the backing directory
 * @mnt_userns: User namespace
 * @olddir: Pointer to the source directory's inode
 * @old: Pointer to the source dentry
 * @newdir: Pointer to the target directory's inode
 * @new: Pointer to the target dentry
 * @flags: Rename flags
 *
 * Returns:
 *   0 on success, or a negative error code on failure.
 */
static int teafs_rename(struct user_namespace *mnt_userns,
                        struct inode *olddir, struct dentry *old,
                        struct inode *newdir, struct dentry *new,
                        unsigned int flags)
{
    struct path old_backing_path, new_backing_path;
    const struct cred *old_cred;
    int err;

    /* Retrieve the backing paths for source and target */
    err = teafs_get_backing_path(old, &old_backing_path);
    if (err)
        return err;

    err = teafs_get_backing_path(new, &new_backing_path);
    if (err)
        goto out_put_old;

    /* Override credentials to match the backing filesystem's context */
    old_cred = teafs_override_creds(olddir->i_sb);
    if (IS_ERR(old_cred)) {
        err = PTR_ERR(old_cred);
        goto out_put_new;
    }

    /* Call VFS's rename */
    err = vfs_rename(&old_backing_path, old, &new_backing_path, new, NULL, flags);

    /* Revert credentials */
    teafs_revert_creds(old_cred);

out_put_new:
    path_put(&new_backing_path);
out_put_old:
    path_put(&old_backing_path);
    return err;
}

/**
 * teafs_lookup - Lookup a dentry in the backing directory
 * @dir: Pointer to the parent directory's inode
 * @dentry: Pointer to the dentry being looked up
 * @flags: Lookup flags
 *
 * Returns:
 *   A pointer to the dentry on success, or an ERR_PTR on failure.
 */
static struct dentry *teafs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
    struct path backing_path;
    struct dentry *real_dentry;
    struct dentry *new_dentry;
    int err;

    /* Retrieve the backing path */
    err = teafs_get_backing_path(dentry, &backing_path);
    if (err)
        return ERR_PTR(err);

    /* Perform a lookup in the backing directory for the given name */
    real_dentry = lookup_one_len(dentry->d_name.name, backing_path.dentry, dentry->d_name.len);
    if (IS_ERR(real_dentry)) {
        path_put(&backing_path);
        return ERR_CAST(real_dentry);
    }

    /* If the file does not exist in the backing directory, return NULL */
    if (d_really_is_negative(real_dentry)) {
        dput(real_dentry);
        path_put(&backing_path);
        return NULL;
    }

    /* Clone the real dentry to create a new TEAFS dentry */
    new_dentry = d_clone(real_dentry, dentry);
    dput(real_dentry);
    path_put(&backing_path);

    return new_dentry;
}

/* Define directory operations */
const struct file_operations teafs_dir_operations = {
    .owner      = THIS_MODULE,
    .read_iter  = generic_read_dir,
    .iterate_dir = generic_read_dir,      /* Use VFS's generic directory iterate */
    .open       = teafs_open,
    .release    = teafs_release,
};

