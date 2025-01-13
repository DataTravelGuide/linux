// fs/teafs/dir.c

#include "teafs.h"
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/file.h>

#include "teafs.h"
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>


#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/xattr.h>
#include <linux/uuid.h>
#include <linux/random.h>
#include <linux/slab.h> // For kmalloc and kfree

#define TEAFS_XATTR_MARKER "user.teafs"
#define TEAFS_XATTR_VALUE "teafs_file_dir"

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

// 生成 backing_subdir_name，使用前缀 "teafs_file_" 加上用户请求的文件名
static int generate_backing_subdir_name_with_prefix(struct dentry *dentry, char *name, size_t size)
{
    const char *prefix = "teafs_file_";
    size_t prefix_len = strlen(prefix);
    size_t name_len = dentry->d_name.len;

    // 确保用户文件名长度不会导致缓冲区溢出
    if (prefix_len + name_len + 1 > size) { // +1 为 '\0'
        return -EINVAL;
    }

    // 添加前缀 "teafs_file_" 并复制用户文件名
    snprintf(name, size, "%s%.*s", prefix, (int)name_len, dentry->d_name.name);
    return 0;
}


static struct dentry *lookup_backing_data_dentry(struct teafs_info *fs_info,
                                                  struct dentry *backing_subdir_dentry)
{
    struct dentry *data_dentry;
    const char *data_name = "data";
    int ret;

    /* 在 backing_subdir_dentry 目录下查找 data 文件 */
    data_dentry = lookup_one(teafs_info_mnt_idmap(fs_info), data_name,
                             backing_subdir_dentry, strlen(data_name));
    if (IS_ERR(data_dentry)) {
        printk(KERN_ERR "teafs: lookup_one for data file failed with err=%ld\n",
               PTR_ERR(data_dentry));
        return data_dentry;
    }

    /* 如果 data 文件已存在，则直接返回 */
    if (d_really_is_positive(data_dentry))
        return data_dentry;

    /* 如果 data 文件不存在，则创建一个 data 文件
     * 此处使用 vfs_create；需要传入 backing_subdir_dentry 的 inode 作父目录
     */
    ret = vfs_create(teafs_info_mnt_idmap(fs_info),
                     d_inode(backing_subdir_dentry),
                     data_dentry,
                     0644,  /* 可根据需要设定权限 */
                     true);
    if (ret) {
        printk(KERN_ERR "teafs: vfs_create for data file failed with err=%d\n", ret);
        dput(data_dentry);
        return ERR_PTR(ret);
    }
    return data_dentry;
}

static struct dentry *teafs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
    struct super_block *sb;
    struct teafs_info *fs_info;
    struct path backing_path;
    struct vfsmount *mnt;
    const char *orig_name;
    char conv_name[256];
    int orig_len, conv_len;
    struct dentry *base;
    struct dentry *result;
    struct dentry *backing_dentry;
    struct inode *teafs_inode;
    const struct cred *old_cred;
    int ret;

    printk(KERN_INFO "teafs: Lookup called for %s\n", dentry->d_name.name);

    // 1. 获取 super_block
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
        result = ERR_PTR(-EINVAL);
        goto out;
    }

    old_cred = override_creds_light(fs_info->creator_cred);

    // 3. 获取 backing_path
    if (!fs_info->backing_path.dentry || !fs_info->backing_path.mnt) {
        printk(KERN_ERR "teafs: Invalid backing_path in fs_info\n");
        result = ERR_PTR(-EINVAL);
        goto revert_cred;
    }

    // 4. 获取底层挂载点 mnt
    mnt = fs_info->backing_path.mnt;
    if (!mnt) {
        printk(KERN_ERR "teafs: backing_path has no mount\n");
        result = ERR_PTR(-EINVAL);
        goto revert_cred;
    }

    // 5. 获取原始名称和长度
    orig_name = dentry->d_name.name;
    orig_len = dentry->d_name.len;

    // 6. 转换名称，转换为 "teafs_file_<原始名>"
    ret = generate_backing_subdir_name_with_prefix(dentry, conv_name, sizeof(conv_name));
    if (ret < 0) {
        printk(KERN_ERR "teafs: Failed to generate backing subdir name with prefix\n");
        result = ERR_PTR(ret);
        goto revert_cred;
    }
    conv_len = strlen(conv_name);

    // 7. 获取底层目录的 dentry
    base = teafs_get_backing_dentry_i(dir);
    if (!base) {
        printk(KERN_ERR "teafs: backing_path dentry is NULL\n");
        result = ERR_PTR(-ENOENT);
        goto revert_cred;
    }

    teafs_print_dentry(base);

    // 8. 调用 lookup_one_unlocked 在底层文件系统中查找，使用转换后的名称
    backing_dentry = lookup_one_unlocked(mnt_idmap(mnt), conv_name, base, conv_len);
    if (IS_ERR(backing_dentry)) {
        printk(KERN_ERR "teafs: lookup_one_unlocked failed for %s: %ld\n", conv_name,
               PTR_ERR(backing_dentry));
        result = ERR_CAST(backing_dentry);
        goto revert_cred;
    }

    // 9. 检查查找结果是否为负 dentry
    if (d_really_is_negative(backing_dentry)) {
        dput(backing_dentry);
        result = NULL; /* 文件不存在 */
	pr_err("backing dentry is negativ ");
        goto revert_cred;
    }

    // 10. 获取底层 inode
    {
        struct inode *backing_inode = d_inode(backing_dentry);
        if (!backing_inode) {
            printk(KERN_ERR "teafs: backing dentry has no inode\n");
            dput(backing_dentry);
            result = ERR_PTR(-ENOENT);
            goto revert_cred;
        }

        // 11. 创建 TEAFS 的 inode（合并上层和底层信息）
        {
            teafs_inode = teafs_get_inode(sb, backing_dentry, S_IFREG);
            if (IS_ERR(teafs_inode)) {
                printk(KERN_ERR "teafs: teafs_get_inode failed for %s: %ld\n", conv_name, PTR_ERR(teafs_inode));
                dput(backing_dentry);
                result = ERR_CAST(teafs_inode);
                goto revert_cred;
            }
	    teafs_inode->i_mode = (teafs_inode->i_mode & ~S_IFMT) | S_IFREG;

            // 12. 通过 d_splice_alias 关联 TEAFS inode 和 dentry
            result = d_splice_alias(teafs_inode, dentry);
            dput(backing_dentry);
            if (IS_ERR(result)) {
                printk(KERN_ERR "teafs: d_splice_alias failed: %ld\n", PTR_ERR(result));
                iput(teafs_inode);
                result = ERR_CAST(result);
                goto revert_cred;
            }
        }
    }

    {
        struct teafs_inode_info *ti = teafs_i(teafs_inode);
        struct dentry *data_dentry;

        /* 在合并视图（result）对应的 backing 目录中查找名为 "data" 的文件
         * 注意：这里我们使用 lookup_one_unlocked() 查找 "data" 文件
         * 如果 "data" 文件不存在，则返回负 dentry（你也可以选择在此处调用 vfs_create() 来创建该文件）
         */
	pr_err("before lookup backing data:");
	teafs_print_dentry(result);
        data_dentry = lookup_one_unlocked(mnt_idmap(mnt), "data", backing_dentry, strlen("data"));
        if (IS_ERR(data_dentry)) {
            printk(KERN_ERR "teafs: lookup_one_unlocked for 'data' failed: %ld\n", PTR_ERR(data_dentry));
            result = ERR_CAST(data_dentry);
            goto revert_cred;
        }
        if (d_really_is_negative(data_dentry)) {
            /* 如果找不到 data 文件，可选：你可以选择创建一个空的 data 文件，
             * 这里先返回错误（或者将 backing_data_file_dentry 设置为 NULL），
             * 这样后续写 data 时再进行处理。
             */
            printk(KERN_ERR "teafs: backing data file not found in backing subdir\n");
            dput(data_dentry);
            result = NULL;
            goto revert_cred;
        }

	pr_err("print data_dentry");
	teafs_print_dentry(data_dentry);
        /* 保存 data 文件的 dentry 到 teafs_inode_info 中 */
        ti->backing_data_file_dentry = data_dentry;
        /* 注意：data_dentry 此处不需要马上 dput，因为我们需要保持引用，
         * 直到后续适当的时候释放 */
    }

revert_cred:
    revert_creds_light(old_cred);
out:
    return result;
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
    struct dentry *backing_subdir_dentry;
    char backing_subdir_name[256];
    int err;

    // 1. 获取后端目录 dentry
    backing_dir_dentry = teafs_get_backing_dentry_i(dir);
    if (!backing_dir_dentry) {
        printk(KERN_ERR "teafs: backing_dir dentry is NULL\n");
        return -ENOENT;
    }

    backing_dir = d_inode(backing_dir_dentry);
    if (!backing_dir) {
        printk(KERN_ERR "teafs: backing_dir inode is NULL\n");
        return -ENOENT;
    }

    // 2. 生成正式目录名称，使用前缀 "teafs_file_" 加上用户文件名
    err = generate_backing_subdir_name_with_prefix(dentry, backing_subdir_name, sizeof(backing_subdir_name));
    if (err) {
        printk(KERN_ERR "teafs: Failed to generate backing_subdir_name with prefix\n");
        return err;
    }

    // 3. 查找后端文件系统中的 backing_subdir_dentry
    backing_subdir_dentry = lookup_one(teafs_info_mnt_idmap(teafs_info_i(dir)),
                                       backing_subdir_name,
                                       backing_dir_dentry,
                                       strlen(backing_subdir_name));
    if (IS_ERR(backing_subdir_dentry)) {
        err = PTR_ERR(backing_subdir_dentry);
        printk(KERN_ERR "teafs: lookup_one for '%s' failed with err=%d\n",
               backing_subdir_name, err);
        return err;
    }

    teafs_print_dentry(backing_subdir_dentry);

    // 检查目录是否已存在
    if (d_really_is_positive(backing_subdir_dentry)) {
        printk(KERN_ERR "teafs: backing_subdir '%s' already exists\n", backing_subdir_name);
        dput(backing_subdir_dentry);
        return -EEXIST;
    }

    // 4. 创建目录
    err = vfs_mkdir(teafs_backing_mnt_idmap(dir), backing_dir, backing_subdir_dentry, mode);
    if (err) {
        printk(KERN_ERR "teafs: vfs_mkdir for '%s' failed with err=%d\n",
               backing_subdir_name, err);
        dput(backing_subdir_dentry);
        return err;
    }

    /* 6. 在刚创建的目录下，再创建一个名为 "data" 的文件 */
    {
        struct dentry *data_dentry;
        struct inode *data_inode;
        char data_name[] = "data";

        /* 在 backing_subdir_dentry 下查找 "data" 文件 */
        data_dentry = lookup_one(teafs_backing_mnt_idmap(dir),
                                 data_name,
                                 backing_subdir_dentry,
                                 strlen(data_name));
        if (IS_ERR(data_dentry)) {
            err = PTR_ERR(data_dentry);
            printk(KERN_ERR "teafs: lookup_one for 'data' failed with err=%d\n", err);
            /* 若失败，删除已创建的目录 */
            vfs_rmdir(teafs_backing_mnt_idmap(dir), backing_dir, backing_subdir_dentry);
            dput(backing_subdir_dentry);
            return err;
        }
        /* 如果 "data" 文件已经存在，返回错误 */
        if (d_really_is_positive(data_dentry)) {
            printk(KERN_ERR "teafs: data file already exists in backing subdir '%s'\n", backing_subdir_name);
            dput(data_dentry);
            vfs_rmdir(teafs_backing_mnt_idmap(dir), backing_dir, backing_subdir_dentry);
            dput(backing_subdir_dentry);
            return -EEXIST;
        }
        /* 创建 "data" 文件 */
        err = vfs_create(teafs_backing_mnt_idmap(dir), d_inode(backing_subdir_dentry), data_dentry, mode, true);
        if (err) {
            printk(KERN_ERR "teafs: vfs_create for 'data' in '%s' failed with err=%d\n", backing_subdir_name, err);
            dput(data_dentry);
            vfs_rmdir(teafs_backing_mnt_idmap(dir), backing_dir, backing_subdir_dentry);
            dput(backing_subdir_dentry);
            return err;
        }
        /* 释放对 data_dentry 的引用 */
        dput(data_dentry);
    }

    /* 
    // 5. 设置扩展属性
    err = teafs_set_xattr(teafs_info_i(dir), backing_subdir_dentry);
    if (err) {
        printk(KERN_ERR "teafs: Failed to set xattr on '%s' with err=%d\n",
               backing_subdir_name, err);
        // 清理已创建的目录
        vfs_rmdir(teafs_backing_mnt_idmap(dir), backing_dir, backing_subdir_dentry);
        dput(backing_subdir_dentry);
        return err;
    }

    // 6. 验证扩展属性，确保创建成功
    if (!teafs_check_xattr(teafs_info_i(dir), backing_subdir_dentry)) {
        printk(KERN_ERR "teafs: backing_subdir '%s' is not properly marked\n", backing_subdir_name);
        // 清理已创建的目录
        vfs_rmdir(teafs_backing_mnt_idmap(dir), backing_dir, backing_subdir_dentry);
        dput(backing_subdir_dentry);
        return -EINVAL;
    }
    */

    // 7. 为这个目录创建 TEAFS 的 inode，并与前端 dentry 关联
    inode = teafs_get_inode(dir->i_sb, backing_subdir_dentry, mode);
    if (IS_ERR(inode)) {
        // 若获取 inode 失败，清理
        err = PTR_ERR(inode);
        printk(KERN_ERR "teafs: teafs_get_inode failed with err=%d, cleaning up subdir\n", err);

        // 移除已创建的目录
        vfs_rmdir(teafs_backing_mnt_idmap(dir), backing_dir, backing_subdir_dentry);
        dput(backing_subdir_dentry);
        return err;
    }

    // 8. 关联前端 dentry
    d_instantiate(dentry, inode);

    // 9. 释放对后端 dentry 的引用
    dput(backing_subdir_dentry);

    // 10. 返回成功
    return 0;
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

struct teafs_getdents_callback {
    struct dir_context ctx;       // 自定义的 dir_context
    struct dir_context *caller;   // 原始的 dir_context
    struct teafs_info *tfs;        // TEAFS 信息
};

#define TEAFS_FILE_PREFIX "teafs_file_"
#define TEAFS_FILE_PREFIX_LEN (sizeof(TEAFS_FILE_PREFIX) - 1) // 不包括终止符

static bool teafs_filldir_func(struct dir_context *ctx_inner, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type)
{
    struct teafs_getdents_callback *data = container_of(ctx_inner, struct teafs_getdents_callback, ctx);
    const char *prefix = TEAFS_FILE_PREFIX;
    int prefix_len = TEAFS_FILE_PREFIX_LEN;

    // 检查名称是否以指定前缀开头
    if (namelen < prefix_len || strncmp(name, prefix, prefix_len) != 0) {
        return true; // 跳过不符合条件的目录项
    }

    // 去掉前缀
    const char *stripped_name = name + prefix_len;
    int stripped_namelen = namelen - prefix_len;

    // 可选：验证剩余名称是否符合预期（例如，非空）
    if (stripped_namelen <= 0) {
        printk(KERN_WARNING "teafs: Found directory with prefix but empty name\n");
        return true; // 跳过
    }

    // 通过 dir_emit 将目录项信息填充到用户空间
    bool res = dir_emit(data->caller, stripped_name, stripped_namelen, ino, DT_REG);

    return res;
}

static int teafs_iterate(struct file *file, struct dir_context *ctx)
{
    struct file *realfile = file->private_data;
    struct inode *backing_dir;
    struct dentry *backing_dir_dentry;
    struct teafs_info *tfs;
    struct teafs_getdents_callback data = { 0 };
    int ret;

    // 1. 获取后端目录 dentry
    backing_dir_dentry = teafs_get_backing_dentry_i(file->f_inode);
    if (!backing_dir_dentry) {
        printk(KERN_ERR "teafs: backing_dir dentry is NULL\n");
        return -ENOENT;
    }

    backing_dir = d_inode(backing_dir_dentry);
    if (!backing_dir) {
        printk(KERN_ERR "teafs: backing_dir inode is NULL\n");
        return -ENOENT;
    }

    // 2. 获取 teafs_info
    tfs = teafs_info_i(file->f_inode);
    if (!tfs) {
        printk(KERN_ERR "teafs: teafs_info is NULL\n");
        return -ENOENT;
    }

    // 3. 初始化辅助结构
    data.ctx.actor = teafs_filldir_func;
    data.caller = ctx;
    data.tfs = tfs;

    // 4. 调用 iterate_dir，使用自定义的 filldir 回调函数
    ret = iterate_dir(realfile, &data.ctx);
    pr_err("ret of iterate_dir: %d\n", ret);
    if (ret < 0)
        return ret;

    // 5. 更新 pos
    ctx->pos = data.ctx.pos;
    pr_err("pos: %d", ctx->pos);

    return ret;
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
