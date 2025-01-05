// fs/teafs/dir.c

#include "teafs.h"
#include <linux/fs.h>
#include <linux/namei.h>


/* Define inode operations for directories */
const struct inode_operations teafs_dir_inode_operations = {
    .lookup         = NULL,
    .mkdir          = NULL,
    .unlink         = NULL,
    .rmdir          = NULL,
    .rename         = NULL,
    .setattr        = NULL,
    .permission     = NULL,
    .getattr        = NULL,
    .update_time    = NULL,
};


const struct file_operations teafs_dir_operations = {
	.read		= generic_read_dir,
	.open		= NULL,
	.iterate_shared	= NULL,
	.llseek		= NULL,
	.fsync		= NULL,
	.release	= NULL,
};
