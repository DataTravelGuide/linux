#include "capfs.h"

static int capfs_inode_test(struct inode *inode, void *data)
{
	return inode->i_private == data;
}

static int capfs_inode_set(struct inode *inode, void *data)
{
	inode->i_private = data;

	return 0;
}

struct inode *capfs_get_inode(struct super_block *sb, struct capfs_inode_param *param)
{
	struct inode *inode;
	struct capfs_inode *ti;
	struct dentry *backing_dentry;
	struct dentry *backing_data_file_dentry;

	backing_dentry = param->backing_dentry;
	backing_data_file_dentry = param->backing_data_file_dentry;

	inode = iget5_locked(sb, (unsigned long) d_inode(backing_dentry),
			capfs_inode_test, capfs_inode_set, d_inode(backing_dentry));
	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (!(inode->i_state & I_NEW)) {
		capfs_err("found inode: %p\n", inode);
		capfs_print_dentry(backing_dentry);
		return inode;
	}

	inode->i_mode = param->mode;
	inode->i_ino = d_inode(backing_dentry)->i_ino;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();

	ti = capfs_i(inode);
	ti->backing_dentry = dget(backing_dentry);
	if (backing_data_file_dentry)
		ti->backing_data_file_dentry = dget(backing_data_file_dentry);

	switch (param->mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &capfs_file_inode_operations;
		inode->i_fop = &capfs_file_operations;
		break;
	case S_IFDIR:
		inode->i_op = &capfs_dir_inode_operations;
		inode->i_fop = &capfs_dir_operations;
		break;
	case S_IFLNK:
		inode->i_op = &capfs_symlink_inode_operations;
		break;
	default:
		inode->i_op = &capfs_special_inode_operations;
		init_special_inode(inode, param->mode, d_inode(backing_dentry)->i_rdev);
		break;
	}

	if (inode->i_state & I_NEW)
		unlock_new_inode(inode);

	pr_err("new allocated inode: %p", inode);
	capfs_print_dentry(backing_dentry);

	return inode;
}

/* Define inode operations for files */
const struct inode_operations capfs_file_inode_operations = {
	.setattr	= NULL,
	.getattr	= NULL,
	.permission	= NULL,
};
