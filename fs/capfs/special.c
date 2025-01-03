// fs/capfs/special.c

#include "capfs.h"
#include <linux/fs.h>


/* Define special inode operations */
const struct inode_operations capfs_special_inode_operations = {
    .permission = NULL,
};

