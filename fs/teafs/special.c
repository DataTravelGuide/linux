// fs/teafs/special.c

#include "teafs.h"
#include <linux/fs.h>


/* Define special inode operations */
const struct inode_operations teafs_special_inode_operations = {
    .permission = NULL,
};

