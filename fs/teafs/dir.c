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
    struct teafs_info *fs_info;
    struct path backing_path;
    struct vfsmount *mnt;
    const char *name;
    int len;
    struct dentry *base;
    struct dentry *result;
    struct dentry *backing_dentry;
    const struct cred *old_cred;
    int ret;

    printk(KERN_INFO "teafs: Lookup called for %s\n", dentry->d_name.name);


    // 1. 获取超级块
    sb = dir->i_sb;
    if (!sb) {
        printk(KERN_ERR "teafs: Directory inode has no super_block\n");
        result = ERR_PTR(-EINVAL);
	goto out;
    }

    // 2. 获取 teafs_fs_info
    fs_info = sb->s_fs_info;
    if (!fs_info) {
        printk(KERN_ERR "teafs: Super_block has no fs_info\n");
        result =  ERR_PTR(-EINVAL);
	goto out;
    }

	old_cred = override_creds_light(fs_info->creator_cred);

    // 3. 获取 backing_path
    if (!fs_info->backing_path.dentry || !fs_info->backing_path.mnt) {
        printk(KERN_ERR "teafs: Invalid backing_path in fs_info\n");
        result = ERR_PTR(-EINVAL);
	goto revert_cred;
    }

    // 4. 获取挂载点 mnt
    mnt = fs_info->backing_path.mnt;
    if (!mnt) {
        printk(KERN_ERR "teafs: backing_path has no mount\n");
        result = ERR_PTR(-EINVAL);
	goto revert_cred;
    }

    // 5. 获取目录名和长度
    name = dentry->d_name.name;
    len = dentry->d_name.len;

    // 6. 获取底层目录的 dentry
    base = teafs_get_backing_dentry_i(dir);
    if (!base) {
        printk(KERN_ERR "teafs: backing_path dentry is NULL\n");
        result = ERR_PTR(-ENOENT);
	goto revert_cred;
    }

    teafs_print_dentry(base);
    // 7. 调用 lookup_one_unlocked 在底层文件系统中执行查找
    backing_dentry = lookup_one_unlocked(mnt_idmap(mnt), name, base, len);
    if (IS_ERR(backing_dentry)) {
        printk(KERN_ERR "teafs: lookup_one_unlocked failed for %s: %ld\n", name, PTR_ERR(backing_dentry));
        result =  ERR_CAST(backing_dentry);
	goto revert_cred;
    }

    // 8. 检查查找结果是否为负 dentry
    if (d_really_is_negative(backing_dentry)) {
        dput(backing_dentry);
        result = NULL; // 文件不存在
	goto revert_cred;
    }

    // 9. 获取底层 inode
    struct inode *backing_inode = d_inode(backing_dentry);
    if (!backing_inode) {
        printk(KERN_ERR "teafs: backing dentry has no inode\n");
        dput(backing_dentry);
        result = ERR_PTR(-ENOENT);
	goto revert_cred;
    }

    // 10. 创建 TEAFS 的 inode
    struct inode *teafs_inode = teafs_get_inode(sb, backing_dentry, backing_inode->i_mode);
    if (IS_ERR(teafs_inode)) {
        printk(KERN_ERR "teafs: teafs_get_inode failed for %s: %ld\n", name, PTR_ERR(teafs_inode));
        dput(backing_dentry);
        result = ERR_CAST(teafs_inode);
	goto revert_cred;
    }

    // 11. 创建并关联 TEAFS 的 dentry
    result = d_splice_alias(teafs_inode, dentry);
    dput(backing_dentry); // 不再需要底层 dentry 的引用

    if (IS_ERR(result)) {
        printk(KERN_ERR "teafs: d_splice_alias failed: %ld\n", PTR_ERR(result));
        iput(teafs_inode); // 释放 teafs_inode
        result = ERR_CAST(result);
	goto revert_cred;
    }

revert_cred:
    revert_creds_light(old_cred);
out:
    return result;
}
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/xattr.h>
#include <linux/mutex.h>

// 定义扩展属性的名称和值
#define TEAFS_XATTR_MARKER "user.teafs"
#define TEAFS_XATTR_VALUE "teafs_file_dir"

// 定义一个互斥锁，保护创建过程的原子性
static DEFINE_MUTEX(teafs_create_mutex);


// 生成 backing_subdir_name，使用前缀 "teafs_" 加上用户请求的文件名
static int generate_backing_subdir_name(struct dentry *dentry, char *name, size_t size)
{
    // 确保用户文件名长度不会导致缓冲区溢出
    size_t name_len = dentry->d_name.len;
    if (name_len + strlen("teafs_") + strlen(".dir.tmp") + 1 > size) { // +1 为 '\0'
        return -EINVAL;
    }

    // 添加前缀 "teafs_" 并复制用户文件名
    snprintf(name, size, "teafs_%.*s.dir.tmp", (int)dentry->d_name.len, dentry->d_name.name);
    return 0;
}

// 生成正式目录名称（去除 .tmp 后缀）
static int generate_final_backing_subdir_name(const char *tmp_name, char *final_name, size_t size)
{
    size_t len = strlen(tmp_name);
    if (len < 4) { // 至少要有 ".tmp"
        return -EINVAL;
    }

    // 去掉 ".tmp" 后缀
    if (len - 4 >= size) {
        return -EINVAL;
    }

    strncpy(final_name, tmp_name, size);
    final_name[size - 1] = '\0';
    final_name[len - 4] = '\0'; // 去 ".tmp"

    return 0;
}

// 设置扩展属性
static int teafs_set_xattr(struct teafs_info *tfs, struct dentry *dentry)
{
    return vfs_setxattr(teafs_info_mnt_idmap(tfs), dentry, TEAFS_XATTR_MARKER,
                        TEAFS_XATTR_VALUE,
                        strlen(TEAFS_XATTR_VALUE), 0);
}

// 检查扩展属性
static bool teafs_check_xattr(struct teafs_info *tfs, struct dentry *dentry)
{
    char buf[32];
    int ret;

    ret = vfs_getxattr(teafs_info_mnt_idmap(tfs), dentry, TEAFS_XATTR_MARKER, buf, sizeof(buf));
    if (ret < 0)
        return false;

    return strncmp(buf, TEAFS_XATTR_VALUE, ret) == 0;
}


static int teafs_create(struct mnt_idmap *idmap,
                        struct inode *dir,
                        struct dentry *dentry,
                        umode_t mode,
                        bool excl)
{
    struct inode *backing_dir;
    struct inode *inode;
    struct dentry *backing_dir_dentry;
    struct dentry *backing_subdir_dentry_tmp;
    struct dentry *backing_subdir_dentry_final;
    char backing_subdir_name_tmp[256];
    char backing_subdir_name_final[256];
    int err;
    unsigned int flags = 0; // 根据需要设置标志

    // 加锁，确保创建过程的原子性
    mutex_lock(&teafs_create_mutex);

    // 1. 获取后端目录 dentry
    backing_dir_dentry = teafs_get_backing_dentry_i(dir);
    if (!backing_dir_dentry) {
        printk(KERN_ERR "teafs: backing_dir dentry is NULL\n");
        err = -ENOENT;
        goto out_unlock;
    }

    backing_dir = d_inode(backing_dir_dentry);
    if (!backing_dir) {
        printk(KERN_ERR "teafs: backing_dir inode is NULL\n");
        err = -ENOENT;
        goto out_unlock;
    }

    // 2. 生成唯一的临时目录名称，使用前缀 "teafs_" 加上用户文件名
    err = generate_backing_subdir_name(dentry, backing_subdir_name_tmp, sizeof(backing_subdir_name_tmp));
    if (err) {
        printk(KERN_ERR "teafs: Failed to generate backing_subdir_name_tmp\n");
        goto out_unlock;
    }

    // 3. 创建临时目录
    backing_subdir_dentry_tmp = lookup_one(
        teafs_backing_mnt_idmap(dir),
        backing_subdir_name_tmp,
        backing_dir_dentry,
        strlen(backing_subdir_name_tmp)
    );

    if (IS_ERR(backing_subdir_dentry_tmp)) {
        err = PTR_ERR(backing_subdir_dentry_tmp);
        printk(KERN_ERR "teafs: lookup_one for '%s' failed with err=%d\n",
               backing_subdir_name_tmp, err);
        goto out_unlock;
    }

    if (d_really_is_positive(backing_subdir_dentry_tmp)) {
        dput(backing_subdir_dentry_tmp);
        printk(KERN_ERR "teafs: temp subdir '%s' already exists\n", backing_subdir_name_tmp);
        err = -EEXIST;
        goto out_unlock;
    }

    err = vfs_mkdir(idmap, backing_dir, backing_subdir_dentry_tmp, mode);
    if (err) {
        printk(KERN_ERR "teafs: vfs_mkdir for '%s' failed with err=%d\n",
               backing_subdir_name_tmp, err);
        dput(backing_subdir_dentry_tmp);
        goto out_unlock;
    }

    // 4. 设置扩展属性
    err = teafs_set_xattr(teafs_info_i(dir), backing_subdir_dentry_tmp);
    if (err) {
        printk(KERN_ERR "teafs: Failed to set xattr on '%s' with err=%d\n",
               backing_subdir_name_tmp, err);
        // 清理临时目录
        vfs_rmdir(idmap, backing_dir, backing_subdir_dentry_tmp);
        dput(backing_subdir_dentry_tmp);
        goto out_unlock;
    }

    // 5. 生成正式目录名称（去除 .tmp 后缀）
    err = generate_final_backing_subdir_name(backing_subdir_name_tmp, backing_subdir_name_final, sizeof(backing_subdir_name_final));
    if (err) {
        printk(KERN_ERR "teafs: Failed to generate final backing_subdir_name\n");
        // 清理临时目录
        vfs_rmdir(idmap, backing_dir, backing_subdir_dentry_tmp);
        dput(backing_subdir_dentry_tmp);
        goto out_unlock;
    }

    // 6. 准备正式目录 dentry
    backing_subdir_dentry_final = lookup_one(
        teafs_backing_mnt_idmap(dir),
        backing_subdir_name_final,
        backing_dir_dentry,
        strlen(backing_subdir_name_final)
    );

    if (IS_ERR(backing_subdir_dentry_final)) {
        err = PTR_ERR(backing_subdir_dentry_final);
        printk(KERN_ERR "teafs: lookup_one for '%s' failed with err=%d\n",
               backing_subdir_name_final, err);
        // 清理临时目录
        vfs_rmdir(idmap, backing_dir, backing_subdir_dentry_tmp);
        dput(backing_subdir_dentry_tmp);
        goto out_unlock;
    }

    if (d_really_is_positive(backing_subdir_dentry_final)) {
        // 正式目录已存在，可能引发冲突
        printk(KERN_ERR "teafs: final subdir '%s' already exists\n", backing_subdir_name_final);
        err = -EEXIST;
        dput(backing_subdir_dentry_final);
        // 清理临时目录
        vfs_rmdir(idmap, backing_dir, backing_subdir_dentry_tmp);
        dput(backing_subdir_dentry_tmp);
        goto out_unlock;
    }

    // 初始化 renamedata 结构体
    struct renamedata rd = {
    .old_mnt_idmap  = teafs_backing_mnt_idmap(dir),
    .old_dir        = backing_dir,
    .old_dentry     = backing_subdir_dentry_tmp,
    .new_mnt_idmap  = teafs_backing_mnt_idmap(dir),
    .new_dir        = backing_dir,
    .new_dentry     = backing_subdir_dentry_final,
    .flags          = flags,
    };

    pr_err("rename(%pd2, %pd2, 0x%x)\n", backing_subdir_dentry_tmp, backing_subdir_dentry_final, flags);

    // 7. 原子性重命名临时目录为正式目录
    err = vfs_rename(&rd);
    if (err) {
        printk(KERN_ERR "teafs: vfs_rename from '%s' to '%s' failed with err=%d\n",
               backing_subdir_name_tmp, backing_subdir_name_final, err);
        // 清理临时目录
        vfs_rmdir(idmap, backing_dir, backing_subdir_dentry_tmp);
        dput(backing_subdir_dentry_tmp);
        dput(backing_subdir_dentry_final);
        goto out_unlock;
    }

    // 8. 释放临时目录 dentry_final (已重命名)
    dput(backing_subdir_dentry_final);
    dput(backing_subdir_dentry_tmp);

    // 9. 查找正式目录 dentry
    backing_subdir_dentry_final = lookup_one(
        teafs_backing_mnt_idmap(dir),
        backing_subdir_name_final,
        backing_dir_dentry,
        strlen(backing_subdir_name_final)
    );

    if (IS_ERR(backing_subdir_dentry_final)) {
        err = PTR_ERR(backing_subdir_dentry_final);
        printk(KERN_ERR "teafs: lookup_one for '%s' failed with err=%d\n",
               backing_subdir_name_final, err);
        goto out_unlock;
    }

    // 10. 验证扩展属性，确保创建成功
    if (!teafs_check_xattr(teafs_info_i(dir), backing_subdir_dentry_final)) {
        printk(KERN_ERR "teafs: backing_subdir '%s' is not properly marked\n", backing_subdir_name_final);
        // 清理式目录
        vfs_rmdir(idmap, backing_dir, backing_subdir_dentry_final);
        dput(backing_subdir_dentry_final);
        err = -EINVAL;
        goto out_unlock;
    }

    // 11. 为这个目录创建 TEAFS 的 inode，并与前端 dentry 关联
    inode = teafs_get_inode(dir->i_sb, backing_subdir_dentry_final, mode);
    if (IS_ERR(inode)) {
        // 若获取 inode 失败，清理
        err = PTR_ERR(inode);
        printk(KERN_ERR "teafs: teafs_get_inode failed with err=%d, cleaning up subdir\n", err);

        // 移除已重命名的目录
        vfs_rmdir(idmap, backing_dir, backing_subdir_dentry_final);
        dput(backing_subdir_dentry_final);
        goto out_unlock;
    }

    // 12. 关联前端 dentry
    d_instantiate(dentry, inode);

    // 13. 释放对后端 dentry 的引用
    dput(backing_subdir_dentry_final);

    // 解锁
    mutex_unlock(&teafs_create_mutex);

    // 14. 返回成功
    return 0;

out_unlock:
    mutex_unlock(&teafs_create_mutex);
    return err;
}

/* Define inode operations for directories */
const struct inode_operations teafs_dir_inode_operations = {
    .lookup         = teafs_lookup,
    .create	    = teafs_create,
    .mkdir          = NULL,
    .rmdir          = NULL,
    .link	    = NULL,
    .symlink	    = NULL,
    .unlink         = NULL,
    .rename         = NULL,
    .setattr        = NULL,
    .getattr        = NULL,
    .permission     = NULL,
    .update_time    = NULL,
    .tmpfile	    = NULL,
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
