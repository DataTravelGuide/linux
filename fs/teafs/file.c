// fs/teafs/file.c

#include "teafs.h"
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/backing-file.h>
#include <linux/security.h>

static int teafs_open(struct inode *inode, struct file *file)
{
	struct path backing_path;
	struct teafs_inode *ti;
	const struct cred *old_cred;
	struct teafs_info *tfs = inode->i_sb->s_fs_info;
	struct teafs_file *tfile = &teafs_i(inode)->tfile;

	old_cred = override_creds(tfs->creator_cred);

	teafs_backing_path(d_inode(file->f_path.dentry), &backing_path);

	tfile->data_file = backing_file_open(&file->f_path, file->f_flags, &backing_path,
					     current_cred());

	file->private_data = tfile;
	revert_creds(old_cred);
	path_put(&backing_path);

	return 0;
}

static int teafs_release(struct inode *inode, struct file *file)
{
	struct teafs_file *tfile = file->private_data;

	fput(tfile->data_file);

	tfile->data_file = NULL;

	return 0;
}

static ssize_t teafs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct teafs_info *tfs = file_inode(file)->i_sb->s_fs_info;
	struct fd real;
	ssize_t ret;
	struct backing_file_ctx ctx = {
		.cred = tfs->creator_cred,
	};
	struct teafs_file *tfile = file->private_data;

	if (!iov_iter_count(iter))
		return 0;

	ret = backing_file_read_iter(tfile->data_file, iter, iocb, iocb->ki_flags,
				     &ctx);
	return ret;
}

static ssize_t teafs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct teafs_info *tfs = file_inode(file)->i_sb->s_fs_info;
	struct inode *inode = file_inode(file);
	struct fd real;
	ssize_t ret;
	int ifl = iocb->ki_flags;
	struct backing_file_ctx ctx = {
		.cred = tfs->creator_cred,
	};
	struct teafs_file *tfile = file->private_data;

	if (!iov_iter_count(iter))
		return 0;

	inode_lock(inode);
	ret = backing_file_write_iter(tfile->data_file, iter, iocb, ifl, &ctx);
	inode_unlock(inode);

	return ret;
}

/* Define file operations */
const struct file_operations teafs_file_operations = {
    .owner      = THIS_MODULE,
    .open       = teafs_open,
	.read_iter	= teafs_read_iter,
	.write_iter	= teafs_write_iter,
    .llseek     = generic_file_llseek,
    .release    = teafs_release,
};
