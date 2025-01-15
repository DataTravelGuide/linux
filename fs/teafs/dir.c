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

static int teafs_set_xattr(struct teafs_info *tfs, struct dentry *dentry)
{
	struct mnt_idmap *mnt_idmap;
	
	mnt_idmap = teafs_info_mnt_idmap(tfs);
	if (!mnt_idmap)
		return -EIO;

	return vfs_setxattr(mnt_idmap, dentry, TEAFS_XATTR_MARKER,
			TEAFS_XATTR_VALUE, strlen(TEAFS_XATTR_VALUE), 0);
}

static int teafs_check_xattr(struct teafs_info *tfs, struct dentry *dentry)
{
	struct mnt_idmap *mnt_idmap;
	char buf[32];
	int ret;

	mnt_idmap = teafs_info_mnt_idmap(tfs);
	if (!mnt_idmap)
		return -EIO;

	ret = vfs_getxattr(teafs_info_mnt_idmap(tfs), dentry, TEAFS_XATTR_MARKER, buf, sizeof(buf));
	if (ret < 0)
		return ret;

	if (strncmp(buf, TEAFS_XATTR_VALUE, ret) != 0)
		return -EINVAL;

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

    // 4. 获取挂载点 mnt
    mnt = fs_info->backing_path.mnt;
    if (!mnt) {
        printk(KERN_ERR "teafs: backing_path has no mount\n");
        result = ERR_PTR(-EINVAL);
        goto revert_cred;
    }

    // 5. 获取原始文件名
    orig_name = dentry->d_name.name;

    // 6. 直接使用 d_name 进行查找
    base = teafs_get_backing_dentry_i(dir);
    if (!base) {
        printk(KERN_ERR "teafs: backing_path dentry is NULL\n");
        result = ERR_PTR(-ENOENT);
        goto revert_cred;
    }

    teafs_print_dentry(base);
    pr_err("lookup %s in %s", orig_name, base->d_name.name);

    // 7. 调用 lookup_one_unlocked 进行查找
    backing_dentry = lookup_one_unlocked(mnt_idmap(mnt), orig_name, base, dentry->d_name.len);
    if (IS_ERR(backing_dentry)) {
        printk(KERN_ERR "teafs: lookup_one_unlocked failed for %s: %ld\n", orig_name, PTR_ERR(backing_dentry));
        result = ERR_CAST(backing_dentry);
        goto revert_cred;
    }

    // 8. 检查查找结果是否为负 dentry
    if (d_really_is_negative(backing_dentry)) {
        dput(backing_dentry);
        result = NULL; /* 文件不存在 */
        pr_err("backing dentry is negative ");
        goto revert_cred;
    }

    // 9. 获取 backing inode
    {
        struct inode *backing_inode = d_inode(backing_dentry);
        if (!backing_inode) {
            printk(KERN_ERR "teafs: backing dentry has no inode\n");
            dput(backing_dentry);
            result = ERR_PTR(-ENOENT);
            goto revert_cred;
        }

        // 10. 创建 TEAFS 的 inode（结合上层和下层信息）
        {
            teafs_inode = teafs_get_inode(sb, backing_dentry, S_IFREG);
            if (IS_ERR(teafs_inode)) {
                printk(KERN_ERR "teafs: teafs_get_inode failed for %s: %ld\n", orig_name, PTR_ERR(teafs_inode));
                dput(backing_dentry);
                result = ERR_CAST(teafs_inode);
                goto revert_cred;
            }
            teafs_inode->i_mode = (teafs_inode->i_mode & ~S_IFMT) | S_IFREG;

            // 11. 通过 d_splice_alias 关联 TEAFS inode 和 dentry
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
        struct teafs_inode *ti = teafs_i(teafs_inode);
        struct dentry *data_dentry;

        // 12. 使用 check_xattr 来验证是否为 TEAFS 文件
    	ret = teafs_check_xattr(fs_info, backing_dentry);
        if (ret) {
            printk(KERN_ERR "teafs: XAttr check failed for %s\n", orig_name);
            dput(backing_dentry);
            result = ERR_PTR(ret);
            goto revert_cred;
        }

        // 13. 查找 backing data 文
        pr_err("before lookup backing data:");
        teafs_print_dentry(result);
        data_dentry = lookup_one_unlocked(mnt_idmap(mnt), "data", backing_dentry, strlen("data"));
        if (IS_ERR(data_dentry)) {
            printk(KERN_ERR "teafs: lookup_one_unlocked for 'data' failed: %ld\n", PTR_ERR(data_dentry));
            result = ERR_CAST(data_dentry);
            goto revert_cred;
        }
        if (d_really_is_negative(data_dentry)) {
            printk(KERN_ERR "teafs: backing data file not found in backing subdir\n");
            dput(data_dentry);
            result = NULL;
            goto revert_cred;
        }

        pr_err("print data_dentry");
        teafs_print_dentry(data_dentry);
        /* 保存 data 文件的 dentry 到 teafs_inode 中 */
        ti->backing_data_file_dentry = data_dentry;
        /* 注意：data_dentry 此处不需要立即释放，因为它会被后续使用 */
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
	struct dentry *backing_dir_dentry;
	struct dentry *backing_subdir_dentry;
	struct dentry *data_dentry;
	struct mnt_idmap *backing_mnt_idmap;
	int ret;

	backing_mnt_idmap = teafs_backing_mnt_idmap(dir);
	if (IS_ERR(backing_mnt_idmap)) {
		ret = PTR_ERR(backing_mnt_idmap);
		pr_err("badking mnt_idmap is error: %d", ret);
		goto out;
	}

	backing_dir_dentry = teafs_get_backing_dentry_i(dir);
	if (!backing_dir_dentry) {
		pr_err("teafs: backing_dir dentry is NULL\n");
		return -ENOENT;
	}

	backing_dir = d_inode(backing_dir_dentry);
	if (!backing_dir) {
		pr_err("teafs: backing_dir inode is NULL\n");
		return -ENOENT;
	}

	backing_subdir_dentry = lookup_one_unlocked(backing_mnt_idmap,
					dentry->d_name.name,
					backing_dir_dentry,
					dentry->d_name.len);

	if (IS_ERR(backing_subdir_dentry)) {
		ret = PTR_ERR(backing_subdir_dentry);
		printk(KERN_ERR "teafs: lookup_one for '%s' failed with err=%d\n", dentry->d_name.name, ret);
		return ret;
	}

    if (d_really_is_positive(backing_subdir_dentry)) {
        printk(KERN_ERR "teafs: backing subdir '%s' already exists\n", dentry->d_name.name);
        dput(backing_subdir_dentry);
        return -EEXIST;
    }

    pr_err("create %s in %s", backing_subdir_dentry->d_name.name, backing_dir_dentry->d_name.name);
    ret = vfs_mkdir(teafs_backing_mnt_idmap(dir), backing_dir, backing_subdir_dentry, mode);
    if (ret) {
        printk(KERN_ERR "teafs: vfs_mkdir for '%s' failed with err=%d\n",
               dentry->d_name.name, ret);
        dput(backing_subdir_dentry);
        return ret;
    }

    // 6. 在新创建的目录下创建 "data" 文件
    data_dentry = lookup_one_unlocked(teafs_backing_mnt_idmap(dir),
                             "data",
                             backing_subdir_dentry,
                             strlen("data"));
    if (IS_ERR(data_dentry)) {
        ret = PTR_ERR(data_dentry);
        printk(KERN_ERR "teafs: lookup_one for 'data' failed with err=%d\n", ret);
        // 清理已创建的目录
        vfs_rmdir(teafs_backing_mnt_idmap(dir), backing_dir, backing_subdir_dentry);
        dput(backing_subdir_dentry);
        return ret;
    }

    // 7. 如果 "data" 文件已存在，返回错误
    if (d_really_is_positive(data_dentry)) {
        printk(KERN_ERR "teafs: data file already exists in '%s'\n", dentry->d_name.name);
        dput(data_dentry);
        vfs_rmdir(teafs_backing_mnt_idmap(dir), backing_dir, backing_subdir_dentry);
        dput(backing_subdir_dentry);
        return -EEXIST;
    }

    // 8. 创建 "data" 文件
    ret = vfs_create(teafs_backing_mnt_idmap(dir), d_inode(backing_subdir_dentry), data_dentry, mode, true);
    if (ret) {
        printk(KERN_ERR "teafs: vfs_create for 'data' in '%s' failed with err=%d\n", dentry->d_name.name, ret);
        dput(data_dentry);
        vfs_rmdir(teafs_backing_mnt_idmap(dir), backing_dir, backing_subdir_dentry);
        dput(backing_subdir_dentry);
        return ret;
    }

    // 10. 创建成功后设置 xattr 来标记目录为已完成
    ret = teafs_set_xattr(teafs_info_i(dir), backing_subdir_dentry);
    if (ret) {
        printk(KERN_ERR "teafs: Failed to set xattr on '%s' with err=%d\n", dentry->d_name.name, ret);
        // 如果设置 xattr 失败，清理已创建的目录和文件
        vfs_rmdir(teafs_backing_mnt_idmap(dir), backing_dir, backing_subdir_dentry);
        dput(backing_subdir_dentry);
        return ret;
    }

    // 11. 获取最终的 inode 并关联 dentry
    struct inode *inode = teafs_get_inode(dir->i_sb, backing_subdir_dentry, S_IFREG);
    if (IS_ERR(inode)) {
        ret = PTR_ERR(inode);
        printk(KERN_ERR "teafs: teafs_get_inode failed with err=%d\n", ret);
        vfs_rmdir(teafs_backing_mnt_idmap(dir), backing_dir, backing_subdir_dentry);
        dput(backing_subdir_dentry);
        return ret;
    }

    dget(data_dentry);
    teafs_i(inode)->backing_data_file_dentry = data_dentry;

    // 9. 释放 data_dentry 引用
    dput(data_dentry);

    // 12. 将 dentry 和 inode 关联
    d_instantiate(dentry, inode);

    // 13. 释放 backing_subdir_dentry 引用
    dput(backing_subdir_dentry);

    pr_err("teafs_create finished.");
out:
	return ret;
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
	int ret;

	ret = teafs_backing_path(d_inode(file->f_path.dentry), &backing_path);
	if (ret)
		return ret;

	file->private_data = dentry_open(&backing_path, O_RDONLY, current_cred());
	path_put(&backing_path);

	return 0;
}

#include <linux/dcache.h>
#include <linux/xattr.h>
#include <linux/namei.h>
#include <linux/string.h>

// 假设 teafs_getdents_callback 结构如下
struct teafs_getdents_callback {
    struct dir_context ctx;
    struct dir_context *caller;
    struct dentry *parent_dentry;
    struct teafs_info *tfs;
};

// 修改后的 teafs_filldir_func 函数
static bool teafs_filldir_func(struct dir_context *ctx_inner,
                               const char *name,
                               int namelen,
                               loff_t offset,
                               u64 ino,
                               unsigned int d_type)
{
    struct teafs_getdents_callback *data = container_of(ctx_inner, struct teafs_getdents_callback, ctx);
    struct dentry *parent_dentry = data->parent_dentry;
    struct teafs_info *tfs = data->tfs;
    struct dentry *entry_dentry;
    bool is_teafs_file;
    bool res;
    int ret;

    // 跳过 '.' 和 '..' 目录项
    if ((namelen == 1 && name[0] == '.') ||
        (namelen == 2 && name[0] == '.' && name[1] == '.')) {
        return true;
    }

    // 通过名称在父目录中查找对应的 dentry
    entry_dentry = lookup_one_len_unlocked(name, parent_dentry, namelen);
    if (IS_ERR(entry_dentry)) {
        // 查找失败，跳过此目录项并记录警告
        printk(KERN_WARNING "teafs: lookup_one_len_unlocked failed for '%.*s'\n", namelen, name);
        return true;
    }

    // 检查该 dentry 是否有 TEAFS 的 xattr 标记
    ret = teafs_check_xattr(tfs, entry_dentry);
    dput(entry_dentry); // 释放对 dentry 的引用

    if (ret) {
        // 如果不是 TEAFS 文件，跳过
        return true;
    }

    // 通过 dir_emit 将目录项信息填充到用户空间
    res = dir_emit(data->caller, name, namelen, ino, DT_REG);

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
    data.parent_dentry = backing_dir_dentry;

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
