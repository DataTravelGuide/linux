// fs/teafs/teafs.h

#ifndef _TEAFS_H
#define _TEAFS_H

#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/parser.h>
#include <linux/cred.h>
#include <linux/err.h>

struct teafs_file {
	struct file *data_file;
};

/* TEAFS inode information structure */
struct teafs_inode_info {
    struct inode        vfs_inode;
    struct dentry	*backing_dentry;
    struct dentry	*backing_data_file_dentry;
    struct teafs_file	tfile;
};

struct teafs_info {
	struct path backing_path;
	const struct cred *creator_cred;
};



/* Inode operation prototypes */
extern const struct inode_operations teafs_dir_inode_operations;
extern const struct file_operations teafs_dir_operations;
extern const struct inode_operations teafs_file_inode_operations;
extern const struct inode_operations teafs_symlink_inode_operations;
extern const struct inode_operations teafs_special_inode_operations;

/* File operation prototypes */
extern const struct file_operations teafs_file_operations;
extern const struct file_operations teafs_dir_operations;

/* Dentry operation prototypes */
extern const struct dentry_operations teafs_dentry_operations;

/* Helper functions */
static inline struct teafs_inode_info *teafs_i(struct inode *inode)
{
    return container_of(inode, struct teafs_inode_info, vfs_inode);
}

static struct dentry *teafs_get_backing_dentry_i(struct inode *inode)
{
    struct teafs_inode_info *ti;

    /* Get the teafs_inode_info from the inode */
    ti = teafs_i(inode);

    /* Check if the backing dentry exists */
    if (!ti->backing_dentry)
        return NULL;

    /* Return the backing dentry found in the inode_info */
    return ti->backing_dentry;
}

static struct teafs_info *teafs_info_i(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;

	    if (!sb) {
		printk(KERN_ERR "teafs: Directory inode has no super_block\n");
		return NULL;
	    }

	return sb->s_fs_info;
}

static struct mnt_idmap *teafs_info_mnt_idmap(struct teafs_info *tfs)
{
    	return mnt_idmap(tfs->backing_path.mnt);
}

static void teafs_backing_path(struct inode *inode, struct path *path)
{
    	struct teafs_info *fs_info;

	fs_info = teafs_info_i(inode);

	path->mnt = fs_info->backing_path.mnt;
	path->dentry = teafs_i(inode)->backing_dentry;
}

static void teafs_backing_data_path(struct inode *inode, struct path *path)
{
    	struct teafs_info *fs_info;

	fs_info = teafs_info_i(inode);

	path->mnt = fs_info->backing_path.mnt;
	path->dentry = teafs_i(inode)->backing_data_file_dentry;
}

const struct cred *teafs_override_creds(const struct super_block *sb);
void teafs_revert_creds(const struct cred *old_cred);

static struct vfsmount *teafs_backing_mnt(struct inode *inode)
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
    int ret;

    // 2. 获取 teafs_info
    fs_info = teafs_info_i(inode);
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

    return mnt;
}

static struct mnt_idmap *teafs_backing_mnt_idmap(struct inode *inode)
{
    return mnt_idmap(teafs_backing_mnt(inode));

}
/* inode.c */
struct inode *teafs_get_inode(struct super_block *sb, struct dentry *backing_dentry, umode_t mode);

/* Superblock functions */
extern struct dentry *teafs_mount(struct file_system_type *fs_type,
                                  int flags, const char *dev_name, void *data);

/**
 * teafs_print_dentry - 打印 dentry 的详细信息
 * @dentry: 指向要打印信息的 dentry 的指针
 *
 * 该函数使用 printk 将 dentry 的关键信息输出到内核日志。
 * 包括 dentry 的名称、完整路径、关联的 inode、标志位以及引用计数等。
 */
static void teafs_print_dentry(struct dentry *dentry)
{
    char path_buf[PATH_MAX];
    int ret;

    if (!dentry) {
        printk(KERN_WARNING "teafs_print_dentry: NULL dentry pointer provided.\n");
        return;
    }

    // 获取 dentry 的完整路径
    ret = dentry_path_raw(dentry, path_buf, sizeof(path_buf));
    if (ret) {
        printk(KERN_INFO "teafs_print_dentry: Failed to get path for dentry.\n");
    } else {
        printk(KERN_INFO "teafs_print_dentry: Path: %s\n", path_buf);
    }

    // 打印 dentry 的名称和长度
    printk(KERN_INFO "teafs_print_dentry: %p Name: %.*s (Length: %d)\n", dentry,
           (int)dentry->d_name.len, dentry->d_name.name, dentry->d_name.len);

    // 打印父 dentry 的名称
    if (dentry->d_parent) {
        ret = dentry_path_raw(dentry->d_parent, path_buf, sizeof(path_buf));
        if (ret) {
            printk(KERN_INFO "teafs_print_dentry: Parent Path: <unknown>\n");
        } else {
            printk(KERN_INFO "teafs_print_dentry: Parent Path: %s\n", path_buf);
        }
    } else {
        printk(KERN_INFO "teafs_print_dentry: No parent dentry.\n");
    }

    // 打印关联的 inode 信息
    if (dentry->d_inode) {
        struct inode *inode = dentry->d_inode;
        printk(KERN_INFO "teafs_print_dentry: Inode Number: %lu\n", inode->i_ino);
        printk(KERN_INFO "teafs_print_dentry: Inode Mode: 0x%04o\n", inode->i_mode);
        printk(KERN_INFO "teafs_print_dentry: Inode UID: %u, GID: %u\n",
               from_kuid(&init_user_ns, inode->i_uid),
               from_kgid(&init_user_ns, inode->i_gid));
        printk(KERN_INFO "teafs_print_dentry: Inode Size: %llu bytes\n",
               (unsigned long long)inode->i_size);
    } else {
        printk(KERN_INFO "teafs_print_dentry: No inode associated with this dentry.\n");
    }

    // 打印 dentry 的标志位
    printk(KERN_INFO "teafs_print_dentry: Dentry Flags: 0x%x\n", dentry->d_flags);

    // 打印 dentry 的 hash 值（用于 dcache）
    printk(KERN_INFO "teafs_print_dentry: Dentry Hash: 0x%x\n", dentry->d_hash);

    // 检查是否为负 dentry
    if (d_really_is_negative(dentry)) {
        printk(KERN_INFO "teafs_print_dentry: This is a negative dentry (file does not exist).\n");
    } else {
        printk(KERN_INFO "teafs_print_dentry: This is a positive dentry (file exists).\n");
    }
}

#endif /* _TEAFS_H */
