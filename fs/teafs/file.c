// fs/teafs/file.c

#include "teafs.h"
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/fs.h>


/* Define file operations */
const struct file_operations teafs_file_operations = {
    .owner      = THIS_MODULE,
    .open       = NULL,
    .read       = NULL,
    .write      = NULL,
    .llseek     = generic_file_llseek,
    .release    = NULL,
};

