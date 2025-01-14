// fs/teafs/super.c

#include "teafs.h"
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>

static struct kmem_cache *teafs_inode_cachep;

static struct inode *teafs_alloc_inode(struct super_block *sb)
{
    struct teafs_inode_info *ti;

    ti = alloc_inode_sb(sb, teafs_inode_cachep, GFP_KERNEL);
    if (!ti)
        return NULL;

    return &ti->vfs_inode;
}

static void teafs_destroy_inode(struct inode *inode)
{
    struct teafs_inode_info *ti = teafs_i(inode);

    if (ti->backing_dentry)
        dput(ti->backing_dentry);

    kfree(ti);
}

static int teafs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct path path;
	int err;

	teafs_backing_path(d_inode(dentry), &path);

	err = vfs_statfs(&path, buf);
	/*
	if (false && !err) {
		buf->f_namelen = ofs->namelen;
		buf->f_type = OVERLAYFS_SUPER_MAGIC;
		if (ovl_has_fsid(ofs))
			buf->f_fsid = uuid_to_fsid(sb->s_uuid.b);
	}
	*/

	return err;
}


/* Define superblock operations */
static const struct super_operations teafs_super_ops = {
    .alloc_inode    = teafs_alloc_inode,
    .destroy_inode  = teafs_destroy_inode,
    .statfs	     = teafs_statfs,
};

int teafs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct teafs_info *tfs = sb->s_fs_info;
	struct inode *root_inode;
	struct dentry *root_dentry;
	struct cred *cred;
	int err;

	err = -EIO;
	if (WARN_ON(fc->user_ns != current_user_ns()))
		goto out_err;

	sb->s_d_op = &teafs_dentry_operations;
	sb->s_op = &teafs_super_ops;

	sb->s_magic = TEAFS_SUPER_MAGIC;
	sb->s_fs_info = tfs;
	sb->s_iflags |= SB_I_SKIP_SYNC;
	/*
	 * Ensure that umask handling is done by the filesystems used
	 * for the the upper layer instead of overlayfs as that would
	 * lead to unexpected results.
	 */
	sb->s_iflags |= SB_I_NOUMASK;
	sb->s_iflags |= SB_I_EVM_HMAC_UNSUPPORTED;

	tfs->creator_cred = prepare_creds();
	err = -ENOMEM;
	    /* Create root inode */
	    root_inode = teafs_get_inode(sb, tfs->backing_path.dentry, S_IFDIR | 0755);
	    if (IS_ERR(root_inode)) {
		err = PTR_ERR(root_inode);
		goto out_err;
	    }

	    root_dentry = d_make_root(root_inode);
	    if (!root_dentry) {
		iput(root_inode);
		err = -ENOMEM;
		goto out_err;
	    }

	    sb->s_root = root_dentry;

	return 0;

out_err:
	return err;
}

enum teafs_opt {
	Opt_backingdir,
};

const struct fs_parameter_spec teafs_parameter_spec[] = {
	fsparam_string("backingdir",          Opt_backingdir),
	{}
};

static int teafs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	int err = 0;
	struct fs_parse_result result;
	struct teafs_info *tfs_info = fc->s_fs_info;
	int opt;

	if (fc->purpose == FS_CONTEXT_FOR_RECONFIGURE) {
		/*
		 * On remount overlayfs has always ignored all mount
		 * options no matter if malformed or not so for
		 * backwards compatibility we do the same here.
		 */
		if (fc->oldapi)
			return 0;

		/*
		 * Give us the freedom to allow changing mount options
		 * with the new mount api in the future. So instead of
		 * silently ignoring everything we report a proper
		 * error. This is only visible for users of the new
		 * mount api.
		 */
		return invalfc(fc, "No changes allowed in reconfigure");
	}

	opt = fs_parse(fc, teafs_parameter_spec, param, &result);
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

static int teafs_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, teafs_fill_super);
}

static void teafs_free(struct fs_context *fc)
{
	struct teafs_info *tfs_info = fc->s_fs_info;

	/*
	 * tfs_info is stored in the fs_context when it is initialized.
	 * tfs_info is transferred to the superblock on a successful mount,
	 * but if an error occurs before the transfer we have to free
	 * it here.
	 */
	if (tfs_info) {
		path_put(&tfs_info->backing_path);
		if (tfs_info->creator_cred)
		       put_cred(tfs_info->creator_cred);
		kfree(tfs_info);
	}
}

static const struct fs_context_operations tea_context_ops = {
	.parse_param = teafs_parse_param,
	.get_tree    = teafs_get_tree,
	.free        = teafs_free,
};

int teafs_init_fs_context(struct fs_context *fc)
{
	struct teafs_info *tfs_info;

	tfs_info = kzalloc(sizeof(struct teafs_info), GFP_KERNEL);
	if (!tfs_info)
		goto out;

	fc->s_fs_info		= tfs_info;
	fc->ops			= &tea_context_ops;

	return 0;
out:
	return -ENOMEM;

}

/* Define the filesystem type structure */
static struct file_system_type teafs_fs_type = {
	.owner			= THIS_MODULE,
	.name			= "teafs",
	.init_fs_context	= teafs_init_fs_context,
	.parameters		= teafs_parameter_spec,
	.fs_flags		= FS_USERNS_MOUNT,
	.kill_sb		= kill_anon_super,
};

static void teafs_inode_init_once(void *foo)
{
	struct teafs_inode_info *ti = foo;

	inode_init_once(&ti->vfs_inode);
}

static int __init teafs_init(void)
{
	int err;

	teafs_inode_cachep = kmem_cache_create("teafs_inode",
					     sizeof(struct teafs_inode_info), 0,
					     (SLAB_RECLAIM_ACCOUNT|
					      SLAB_ACCOUNT),
					     teafs_inode_init_once);
	if (teafs_inode_cachep == NULL)
		return -ENOMEM;

	err = register_filesystem(&teafs_fs_type);
	if (!err)
		return 0;

	kmem_cache_destroy(teafs_inode_cachep);

	return err;
}

static void __exit teafs_exit(void)
{
	unregister_filesystem(&teafs_fs_type);

	rcu_barrier();
	kmem_cache_destroy(teafs_inode_cachep);
}

module_init(teafs_init);
module_exit(teafs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("TEAFS - Transparent Extensible Aggregated Filesystem");
