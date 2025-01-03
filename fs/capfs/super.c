// fs/capfs/super.c

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/statfs.h>

#include "capfs.h"

static struct kmem_cache *capfs_inode_cachep;

static struct inode *capfs_alloc_inode(struct super_block *sb)
{
	struct capfs_inode *ti;

	ti = alloc_inode_sb(sb, capfs_inode_cachep, GFP_KERNEL);
	if (!ti)
		return NULL;

	return &ti->vfs_inode;
}

static void capfs_destroy_inode(struct inode *inode)
{
	struct capfs_inode *ti = capfs_i(inode);

	if (ti->backing_dentry)
		dput(ti->backing_dentry);

	kfree(ti);
}

static int capfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct path path;
	int ret;

	ret = capfs_backing_path(d_inode(dentry), &path);
	if (ret)
		return ret;

	ret = vfs_statfs(&path, buf);
	if (!ret)
		buf->f_type = CAPFS_SUPER_MAGIC;

	return ret;
}

/* Define superblock operations */
static const struct super_operations capfs_super_ops = {
	.alloc_inode	= capfs_alloc_inode,
	.destroy_inode	= capfs_destroy_inode,
	.statfs		= capfs_statfs,
};

static int capfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct capfs_info *tfs = sb->s_fs_info;
	struct inode *root_inode;
	struct dentry *root_dentry;
	int ret = -EIO;

	if (WARN_ON(fc->user_ns != current_user_ns()))
		goto out_err;

	sb->s_d_op = &capfs_dentry_operations;
	sb->s_op = &capfs_super_ops;

	sb->s_magic = CAPFS_SUPER_MAGIC;
	sb->s_fs_info = tfs;
	sb->s_iflags |= SB_I_SKIP_SYNC;
	/*
	 * Ensure that umask handling is done by the filesystems used
	 * for the upper layer instead of overlayfs as that would
	 * lead to unexpected results.
	 */
	sb->s_iflags |= SB_I_NOUMASK;
	sb->s_iflags |= SB_I_EVM_HMAC_UNSUPPORTED;

	tfs->creator_cred = prepare_creds();

	/* Create root inode */
	struct capfs_inode_param ti_param = { .backing_dentry = tfs->backing_path.dentry,
       						.mode = S_IFDIR	};

	root_inode = capfs_get_inode(sb, &ti_param);
	if (IS_ERR(root_inode)) {
		ret = PTR_ERR(root_inode);
		goto out_err;
	}

	root_dentry = d_make_root(root_inode);
	if (!root_dentry) {
		iput(root_inode);
		ret = -ENOMEM;
		goto out_err;
	}

	sb->s_root = root_dentry;

	return 0;
out_err:
	return ret;
}

enum capfs_opt {
	Opt_backingdir,
};

const struct fs_parameter_spec capfs_parameter_spec[] = {
	fsparam_string("backingdir",		  Opt_backingdir),
	{}
};

static int capfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	int err = 0;
	struct fs_parse_result result;
	struct capfs_info *tfs_info = fc->s_fs_info;
	int opt;

	if (fc->purpose == FS_CONTEXT_FOR_RECONFIGURE) {
		if (fc->oldapi)
			return 0;

		return invalfc(fc, "No changes allowed in reconfigure");
	}

	opt = fs_parse(fc, capfs_parameter_spec, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_backingdir:
		err = kern_path(param->string, LOOKUP_FOLLOW, &tfs_info->backing_path);
		if (err)
			pr_err("failed to resolve '%s': %i\n", param->string, err);
		break;
	default:
		pr_err("unrecognized mount option \"%s\" or missing value\n",
			   param->key);
		return -EINVAL;
	}

	return err;
}

static int capfs_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, capfs_fill_super);
}

static void capfs_free(struct fs_context *fc)
{
	struct capfs_info *tfs_info = fc->s_fs_info;

	if (tfs_info) {
		path_put(&tfs_info->backing_path);
		if (tfs_info->creator_cred)
			   put_cred(tfs_info->creator_cred);
		kfree(tfs_info);
	}
}

static const struct fs_context_operations tea_context_ops = {
	.parse_param	= capfs_parse_param,
	.get_tree	= capfs_get_tree,
	.free		= capfs_free,
};

static int capfs_init_fs_context(struct fs_context *fc)
{
	struct capfs_info *tfs_info;

	tfs_info = kzalloc(sizeof(struct capfs_info), GFP_KERNEL);
	if (!tfs_info)
		goto out;

	fc->s_fs_info		= tfs_info;
	fc->ops			= &tea_context_ops;

	return 0;
out:
	return -ENOMEM;

}

/* Define the filesystem type structure */
static struct file_system_type capfs_fs_type = {
	.owner			= THIS_MODULE,
	.name			= "capfs",
	.init_fs_context	= capfs_init_fs_context,
	.parameters		= capfs_parameter_spec,
	.fs_flags		= FS_USERNS_MOUNT,
	.kill_sb		= kill_anon_super,
};

static void capfs_inode_init_once(void *foo)
{
	struct capfs_inode *ti = foo;

	inode_init_once(&ti->vfs_inode);
}

static int __init capfs_init(void)
{
	int ret;

	capfs_inode_cachep = kmem_cache_create("capfs_inode",
					sizeof(struct capfs_inode), 0,
					(SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT),
					capfs_inode_init_once);
	if (capfs_inode_cachep == NULL)
		return -ENOMEM;

	ret = register_filesystem(&capfs_fs_type);
	if (ret)
		goto destroy_cache;

	return 0;

destroy_cache:
	kmem_cache_destroy(capfs_inode_cachep);

	return ret;
}

static void __exit capfs_exit(void)
{
	unregister_filesystem(&capfs_fs_type);
	kmem_cache_destroy(capfs_inode_cachep);
}

module_init(capfs_init);
module_exit(capfs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dongsheng Yang <dongsheng.yang@linux.dev>");
MODULE_DESCRIPTION("CAPFS - Transparent Extensible Aggregated Filesystem");
