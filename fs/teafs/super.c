// fs/teafs/super.c

#include "teafs.h"
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>

/**
 * teafs_override_creds - Override current credentials
 * @sb: The superblock pointer
 *
 * Returns:
 *   A pointer to the old credentials on success, or an ERR_PTR on failure.
 */
const struct cred *teafs_override_creds(const struct super_block *sb)
{
    struct cred *new_cred = prepare_creds();
    if (!new_cred)
        return ERR_PTR(-ENOMEM);

    /* Modify the new credentials as needed, e.g., set to root */
    new_cred->uid.val = GLOBAL_ROOT_UID;
    new_cred->gid.val = GLOBAL_ROOT_GID;
    new_cred->euid.val = GLOBAL_ROOT_UID;
    new_cred->egid.val = GLOBAL_ROOT_GID;

    override_creds(new_cred);
    return new_cred;
}

/**
 * teafs_revert_creds - Revert to the original credentials
 * @old_cred: The original credentials pointer
 */
void teafs_revert_creds(const struct cred *old_cred)
{
    revert_creds(old_cred);
}

/**
 * teafs_get_backing_path - Retrieve the actual path in the backing directory
 * @dentry: The TEAFS dentry
 * @backing_path: The path structure to be filled with the backing directory's path
 *
 * Returns:
 *   0 on success, or a negative error code on failure.
 */
int teafs_get_backing_path(struct dentry *dentry, struct path *backing_path)
{
    struct teafs_inode_info *ti = teafs_i(d_inode(dentry));

    if (!ti->__upperdentry)
        return -ENOENT;

    /* Set the backing_path to the backing directory's mount and dentry */
    backing_path->mnt = ti->__upperdentry->d_sb->s_root->mnt;
    backing_path->dentry = ti->__upperdentry;

    return 0;
}

/**
 * teafs_fill_super - Fill the superblock structure
 * @sb: Superblock pointer
 * @data: Mount options
 * @silent: Suppress error messages if non-zero
 *
 * Returns:
 *   0 on success, or a negative error code on failure.
 */
static int teafs_fill_super(struct super_block *sb, void *data, int silent)
{
    struct teafs_fs_info *fsi;
    struct inode *root_inode;
    struct dentry *root_dentry;
    char backing_dir[PATH_MAX];
    int err;

    fsi = kzalloc(sizeof(struct teafs_fs_info), GFP_KERNEL);
    if (!fsi)
        return -ENOMEM;

    sb->s_fs_info = fsi;
    sb->s_maxbytes = MAX_LFS_FILESIZE;
    sb->s_blocksize = PAGE_SIZE;
    sb->s_blocksize_bits = PAGE_SHIFT;
    sb->s_magic = 0x12345678; /* Placeholder magic number */
    sb->s_op = &simple_super_operations;

    /* Parse mount options to get backingdir */
    if (!data) {
        err = -EINVAL;
        goto fail;
    }

    strncpy(backing_dir, (char *)data, PATH_MAX);
    backing_dir[PATH_MAX - 1] = '\0';

    /* Resolve the backing directory path */
    err = kern_path(backing_dir, LOOKUP_FOLLOW, &fsi->backing_path);
    if (err) {
        printk(KERN_ERR "TEAFS: Failed to resolve backing directory path\n");
        goto fail;
    }

    /* Create root inode */
    root_inode = teafs_get_inode(sb, S_IFDIR | 0755);
    if (IS_ERR(root_inode)) {
        err = PTR_ERR(root_inode);
        goto fail_put_path;
    }

    root_dentry = d_make_root(root_inode);
    if (!root_dentry) {
        iput(root_inode);
        err = -ENOMEM;
        goto fail_put_path;
    }

    sb->s_root = root_dentry;
    return 0;

fail_put_path:
    path_put(&fsi->backing_path);
fail:
    kfree(fsi);
    return err;
}

/**
 * teafs_mount - Mount the TEAFS filesystem
 * @fs_type: Filesystem type
 * @flags: Mount flags
 * @dev_name: Device name (unused)
 * @data: Mount options (backingdir path)
 *
 * Returns:
 *   A pointer to the root dentry on success, or ERR_PTR on failure.
 */
struct dentry *teafs_mount(struct file_system_type *fs_type,
                           int flags, const char *dev_name, void *data)
{
    return mount_nodev(fs_type, flags, data, teafs_fill_super);
}

/**
 * teafs_kill_sb - Unmount the TEAFS filesystem
 * @sb: Superblock pointer
 *
 * Frees all resources associated with the superblock.
 */
static void teafs_kill_sb(struct super_block *sb)
{
    struct teafs_fs_info *fsi = sb->s_fs_info;

    if (fsi) {
        path_put(&fsi->backing_path);
        kfree(fsi);
        sb->s_fs_info = NULL;
    }
    kill_litter_super(sb);
}

/* Define the filesystem type structure */
static struct file_system_type teafs_fs_type = {
    .owner      = THIS_MODULE,
    .name       = "teafs",
    .mount      = teafs_mount,
    .kill_sb    = teafs_kill_sb,
    .fs_flags   = FS_REQUIRES_DEV,
};

/**
 * teafs_init - Initialize the TEAFS filesystem module
 *
 * Registers the filesystem type with the kernel.
 *
 * Returns:
 *   0 on success, or a negative error code on failure.
 */
static int __init teafs_init(void)
{
    return register_filesystem(&teafs_fs_type);
}

/**
 * teafs_exit - Exit the TEAFS filesystem module
 *
 * Unregisters the filesystem type from the kernel.
 */
static void __exit teafs_exit(void)
{
    unregister_filesystem(&teafs_fs_type);
}

module_init(teafs_init);
module_exit(teafs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("TEAFS - Transparent Extensible Aggregated Filesystem");


