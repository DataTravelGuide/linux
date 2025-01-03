// fs/teafs/file.c

#include "teafs.h"
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/fs.h>

/**
 * teafs_open_realfile - Open the actual file in the backing directory
 * @file: Pointer to the struct file representing the TEAFS file
 * @backing_path: The path structure pointing to the backing directory's file
 *
 * Returns:
 *   A pointer to the actual struct file on success, or an ERR_PTR on failure.
 */
static struct file *teafs_open_realfile(struct file *file, struct path *backing_path)
{
    struct file *realfile;

    /* Open the file in the backing directory */
    realfile = dentry_open(backing_path->dentry, file->f_flags, backing_path->mnt);
    if (IS_ERR(realfile))
        return realfile;

    /* Adjust the f_flags by masking out flags not needed by the underlying filesystem */
    realfile->f_flags = file->f_flags & (O_ACCMODE | O_APPEND | O_NONBLOCK |
                                         O_SYNC | O_DIRECT | O_LARGEFILE |
                                         O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);

    return realfile;
}

/**
 * teafs_open - TEAFS's open function
 * @inode: Pointer to the struct inode
 * @file: Pointer to the struct file
 *
 * Returns:
 *   0 on success, or a negative error code on failure.
 */
static int teafs_open(struct inode *inode, struct file *file)
{
    struct dentry *dentry = file_dentry(file);
    struct file *realfile;
    struct path backing_path;
    const struct cred *old_cred;
    int err;

    /* Retrieve the backing path */
    err = teafs_get_backing_path(dentry, &backing_path);
    if (err)
        return err;

    /* Override credentials to match the backing filesystem's context */
    old_cred = teafs_override_creds(dentry->d_sb);
    if (IS_ERR(old_cred)) {
        path_put(&backing_path);
        return PTR_ERR(old_cred);
    }

    /* Open the actual file in the backing directory */
    realfile = teafs_open_realfile(file, &backing_path);
    path_put(&backing_path); /* Release the backing_path reference */
    if (IS_ERR(realfile)) {
        err = PTR_ERR(realfile);
        goto out_revert_creds;
    }

    /* Set file->private_data to the realfile */
    file->private_data = realfile;

    /* Revert to the original credentials */
    teafs_revert_creds(old_cred);

    return 0;

out_revert_creds:
    teafs_revert_creds(old_cred);
    return err;
}

/**
 * teafs_read - Read data from a file
 * @file: Pointer to the struct file
 * @buf: User-space buffer to read data into
 * @count: Number of bytes to read
 * @ppos: File position pointer
 *
 * Returns:
 *   Number of bytes read on success, or a negative error code on failure.
 */
static ssize_t teafs_read(struct file *file, char __user *buf,
                          size_t count, loff_t *ppos)
{
    struct file *realfile = file->private_data;

    if (!realfile)
        return -EINVAL;

    return vfs_read(realfile, buf, count, ppos);
}

/**
 * teafs_write - Write data to a file
 * @file: Pointer to the struct file
 * @buf: User-space buffer containing data to write
 * @count: Number of bytes to write
 * @ppos: File position pointer
 *
 * Returns:
 *   Number of bytes written on success, or a negative error code on failure.
 */
static ssize_t teafs_write(struct file *file, const char __user *buf,
                           size_t count, loff_t *ppos)
{
    struct file *realfile = file->private_data;

    if (!realfile)
        return -EINVAL;

    return vfs_write(realfile, buf, count, ppos);
}

/**
 * teafs_release - Release an open file
 * @inode: Pointer to the struct inode
 * @file: Pointer to the struct file
 *
 * Returns:
 *   0 on success, or a negative error code on failure.
 */
static int teafs_release(struct inode *inode, struct file *file)
{
    struct file *realfile = file->private_data;

    if (realfile)
        fput(realfile);

    return 0;
}

/* Define file operations */
const struct file_operations teafs_file_operations = {
    .owner      = THIS_MODULE,
    .open       = teafs_open,
    .read       = teafs_read,
    .write      = teafs_write,
    .llseek     = generic_file_llseek,
    .release    = teafs_release,
};

