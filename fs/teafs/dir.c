// fs/teafs/dir.c

#include "teafs.h"
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/file.h>

#include "teafs.h"
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>

/**
 * teafs_lookup - Lookup a dentry in the backing directory
 * @dir: Pointer to the parent directory's inode
 * @dentry: Pointer to the dentry being looked up
 * @flags: Lookup flags
 *
 * Returns:
 *   A pointer to the dentry on success, or an ERR_PTR on failure.
 */
struct dentry *teafs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
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

    printk(KERN_INFO "teafs: Lookup called for %s\n", dentry->d_name.name);

    // 1. 获取超级块
    sb = dir->i_sb;
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

    // 5. 获取目录名和长度
    name = dentry->d_name.name;
    len = dentry->d_name.len;

    // 6. 获取底层目录的 dentry
    base = teafs_get_backing_dentry_i(dir);
    if (!base) {
        printk(KERN_ERR "teafs: backing_path dentry is NULL\n");
        return ERR_PTR(-ENOENT);
    }

    // 7. 调用 lookup_one_unlocked 在底层文件系统中执行查找
    backing_dentry = lookup_one_unlocked(mnt_idmap(mnt), name, base, len);
    if (IS_ERR(backing_dentry)) {
        printk(KERN_ERR "teafs: lookup_one_unlocked failed for %s: %ld\n", name, PTR_ERR(backing_dentry));
        return ERR_CAST(backing_dentry);
    }

    // 8. 检查查找结果是否为负 dentry
    if (d_really_is_negative(backing_dentry)) {
        dput(backing_dentry);
        return NULL; // 文件不存在
    }

    // 9. 获取底层 inode
    struct inode *backing_inode = d_inode(backing_dentry);
    if (!backing_inode) {
        printk(KERN_ERR "teafs: backing dentry has no inode\n");
        dput(backing_dentry);
        return ERR_PTR(-ENOENT);
    }

    // 10. 创建 TEAFS 的 inode
    struct inode *teafs_inode = teafs_get_inode(sb, backing_dentry, backing_inode->i_mode);
    if (IS_ERR(teafs_inode)) {
        printk(KERN_ERR "teafs: teafs_get_inode failed for %s: %ld\n", name, PTR_ERR(teafs_inode));
        dput(backing_dentry);
        return ERR_CAST(teafs_inode);
    }

    // 11. 创建并关联 TEAFS 的 dentry
    result = d_splice_alias(teafs_inode, dentry);
    dput(backing_dentry); // 不再需要底层 dentry 的引用

    if (IS_ERR(result)) {
        printk(KERN_ERR "teafs: d_splice_alias failed: %ld\n", PTR_ERR(result));
        iput(teafs_inode); // 释放 teafs_inode
        return ERR_CAST(result);
    }

    return result;
}

/* Define inode operations for directories */
const struct inode_operations teafs_dir_inode_operations = {
    .lookup         = teafs_lookup,
    .mkdir          = NULL,
    .unlink         = NULL,
    .rmdir          = NULL,
    .rename         = NULL,
    .setattr        = NULL,
    .permission     = NULL,
    .getattr        = NULL,
    .update_time    = NULL,
};

static int teafs_dir_open(struct inode *inode, struct file *file)
{
	struct path backing_path;
	struct teafs_inode *ti;

	teafs_backing_path(d_inode(file->f_path.dentry), &backing_path);

	file->private_data = dentry_open(&backing_path, O_RDONLY, current_cred());
	path_put(&backing_path);

	return 0;
}

static int teafs_iterate(struct file *file, struct dir_context *ctx)
{
	struct file *realfile = file->private_data;

	return iterate_dir(realfile, ctx);
}

static int teafs_dir_release(struct inode *inode, struct file *file)
{
	struct file *realfile = file->private_data;

	fput(realfile);

	return 0;
}

WRAP_DIR_ITER(teafs_iterate) // FIXME!
const struct file_operations teafs_dir_operations = {
	.read		= generic_read_dir,
	.open		= teafs_dir_open,
	.iterate_shared	= shared_teafs_iterate,
	.llseek		= NULL,
	.fsync		= NULL,
	.release	= teafs_dir_release,
};
