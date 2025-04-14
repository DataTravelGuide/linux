#include <crypto/internal/acompress.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/io_uring.h>
#include <linux/io_uring/cmd.h>
#include <linux/slab.h>
#include <linux/string.h>

#define UCOMP_NAME "ucomp_nop"
#define UCOMP_OP_COMPRESS   0
#define UCOMP_OP_DECOMPRESS 1
#define UCOMP_CTRL_NAME "ucomp_ctrl"
#define UCOMP_MAX_NAME_LEN 32
#define UCOMP_OP_REGISTER   100
#define UCOMP_OP_UNREGISTER 101

#define UCOMP_MINORS		(1U << MINORBITS)

static LIST_HEAD(ucomp_alg_list);
static DEFINE_MUTEX(ucomp_alg_list_lock);

static dev_t ucomp_chr_devt;
static const struct class ucomp_chr_class = {
	.name = "ucomp-char",
};

struct ucomp_req {
	__u32 opcode;
	__u32 id;
	__u32 src_len;
	__u32 dst_len;
	__u64 src;
	__u64 dst;
};

struct ucomp_ctrl_req {
	__u32 opcode;
	char algname[UCOMP_MAX_NAME_LEN];
};

#define UCOMP_ALG_STATE_OPEN	0

struct ucomp_alg {
	unsigned long		state;
	struct list_head	node;
	struct cdev		cdev;
	struct device		cdev_dev;
	char algname[UCOMP_MAX_NAME_LEN];
	void *buf;
};

static struct ucomp_alg *ucomp_alg_nop;

struct ucomp_alg_ctx {
	struct ucomp_alg *alg;
};

static int ucomp_ch_open(struct inode *inode, struct file *filp)
{
	struct ucomp_alg *alg = container_of(inode->i_cdev,
			struct ucomp_alg, cdev);

	if (test_and_set_bit(UCOMP_ALG_STATE_OPEN, &alg->state))
		return -EBUSY;
	filp->private_data = alg;
	return 0;
}

static int ucomp_ch_release(struct inode *inode, struct file *filp)
{
	struct ucomp_alg *alg = filp->private_data;

	clear_bit(UCOMP_ALG_STATE_OPEN, &alg->state);
	return 0;
}

/* map pre-allocated per-queue cmd buffer to ucompsrv daemon */
static int ucomp_ch_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct ucomp_alg *alg = filp->private_data;
	size_t sz = vma->vm_end - vma->vm_start;
	unsigned long pfn, end, phys_off = vma->vm_pgoff << PAGE_SHIFT;

	pfn = virt_to_phys(alg->buf) >> PAGE_SHIFT;
	return remap_pfn_range(vma, vma->vm_start, pfn, sz, vma->vm_page_prot);
}

struct ucomp_ch_cmd {
};

#define UCOMP_CMD_FLAGS_COMP	(1 << 0)
#define UCOMP_CMD_FLAGS_DECOMP	(1 << 1)

struct ucomp_cmd {
	u32 flags;
	u32 src_off;
	u32 src_len;
	u32 dst_off;
	u32 dst_len;
	struct acomp_req *acomp_req;
	struct io_uring_cmd *uring_cmd;
};

#define UCOMP_CH_CMD_OP_FETCH		0
#define UCOMP_CH_CMD_OP_COMMIT_AND_FETCH	1

static int ucomp_ch_uring_cmd(struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	struct acomp_req *acomp_req;
	struct ucomp_alg *alg = cmd->file->private_data;
	const struct ucomp_ch_cmd *ucomp_ch_cmd = io_uring_sqe_cmd(cmd->sqe);
	u32 cmd_op = cmd->cmd_op;
	int ret = -EINVAL;

	//pr_err("into ucomp_ch_uring_cmd\n");
	struct ucomp_cmd *ucomp_cmd = alg->buf;
	char *src = alg->buf + 4096;
	char *dst = alg->buf + 4096 * 128;

	switch (cmd_op) {
	case UCOMP_CH_CMD_OP_FETCH:
		//pr_err("fetch");
		ucomp_cmd->uring_cmd = cmd;
		//pr_err("set uring_cmd: %p\n", cmd);
		ucomp_cmd->src_off = 4096;
		ucomp_cmd->dst_off = 4096 * 128;
		break;
	case UCOMP_CH_CMD_OP_COMMIT_AND_FETCH:
		//pr_err("commit and fetch\n");

		acomp_req = ucomp_cmd->acomp_req;
		if (!acomp_req) {
			pr_err("ucomp_cmd->acomp_req is NULL\n");
			return -EINVAL;
		}

		//pr_err("acomp_req: %px sg_virt in commit: %px", acomp_req, sg_virt(acomp_req->dst));

		acomp_req->dlen = ucomp_cmd->dst_len;

		//pr_err("copy back from kernel buf to sg dst, len=%u\n", ucomp_cmd->dst_len);

		sg_pcopy_from_buffer(acomp_req->dst, 1,
				     alg->buf + ucomp_cmd->dst_off,
				     ucomp_cmd->dst_len,
				     0);

		acomp_request_complete(acomp_req, 0);
		break;
	default:
		pr_err("unrecognized op: %d\n", cmd_op);
		return -EINVAL;
	}

	return -EIOCBQUEUED;
}

static const struct file_operations ucomp_ch_fops = {
	.owner = THIS_MODULE,
	.open = ucomp_ch_open,
	.release = ucomp_ch_release,
	.uring_cmd = ucomp_ch_uring_cmd,
	.mmap = ucomp_ch_mmap,
};

static void ucomp_cdev_release(struct device *dev)
{
	struct ucomp_alg *ub = container_of(dev, struct ucomp_alg, cdev_dev);

	kfree(ub);
}

static int ucomp_register_algorithm(const char *algname);

static int ucomp_ctrl_uring_cmd(struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	const struct io_uring_sqe *sqe = cmd->sqe;
	struct io_kiocb *req = cmd_to_io_kiocb(cmd);
	struct ucomp_ctrl_req ctrl;
	void __user *argp;
	//pr_err("ucomp_ctrl_uring_cmd\n");

	if (!sqe || !req)
		return -EINVAL;

	argp = (void __user *)(uintptr_t)sqe->addr;
	if (copy_from_user(&ctrl, argp, sizeof(ctrl))) {
		pr_err("ucomp_ctrl: failed to copy req from user\n");
		io_uring_cmd_done(cmd, -EFAULT, 0, issue_flags);
		return 0;
	}

	ctrl.algname[UCOMP_MAX_NAME_LEN - 1] = '\0';

	switch (ctrl.opcode) {
	case UCOMP_OP_REGISTER:
		ucomp_register_algorithm(ctrl.algname);
		break;
	case UCOMP_OP_UNREGISTER:
		pr_err("ucomp: unregister for %s is not implemented yet\n", ctrl.algname);
		break;
	default:
		pr_err("ucomp_ctrl: unknown opcode %u\n", ctrl.opcode);
		io_uring_cmd_done(cmd, -EINVAL, 0, issue_flags);
		return 0;
	}

	io_uring_cmd_done(cmd, 0, 0, issue_flags);
	return -EIOCBQUEUED;
}

static const struct file_operations ucomp_ctrl_fops = {
	.owner = THIS_MODULE,
	.uring_cmd = ucomp_ctrl_uring_cmd,
};

static int ucomp_uring_cmd(struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	const struct io_uring_sqe *sqe = cmd->sqe;
	struct io_kiocb *req = cmd_to_io_kiocb(cmd);
	struct ucomp_req req_data;
	void __user *argp;

	if (!sqe || !req) {
		pr_err("ucomp: invalid cmd or req\n");
		return -EINVAL;
	}

	argp = (void __user *)(uintptr_t)sqe->addr;
	if (copy_from_user(&req_data, argp, sizeof(req_data))) {
		pr_err("ucomp: failed to copy req from user\n");
		io_uring_cmd_done(cmd, -EFAULT, 0, issue_flags);
		return 0;
	}

	//pr_err("ucomp: uring_cmd received: opcode=%u, id=%u, src_len=%u, dst_len=%u, async_data: %p\n",
	//	req_data.opcode, req_data.id, req_data.src_len, req_data.dst_len, req->async_data);

	io_uring_cmd_done(cmd, req_data.src_len, 0, issue_flags);
	return -EIOCBQUEUED;
}

static const struct file_operations ucomp_fops = {
	.owner = THIS_MODULE,
	.uring_cmd = ucomp_uring_cmd,
};

static int ucomp_compress(struct acomp_req *req)
{
	struct ucomp_alg_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct ucomp_alg *alg = ctx->alg;
	struct ucomp_cmd *cmd = alg->buf;

	//pr_err("req: %px sg_virt in ucomp_compress: %px\n", req, sg_virt(req->dst));

	cmd->flags = UCOMP_CMD_FLAGS_COMP;
	cmd->acomp_req = req;
	cmd->src_len = req->slen;
	cmd->dst_len = req->dlen;
	memcpy(alg->buf + cmd->src_off, sg_virt(req->src) + req->soff, req->slen);

	//pr_err("done uring_cmd: %p\n", cmd->uring_cmd);
	io_uring_cmd_done(cmd->uring_cmd, 0, 0, 0);
	//pr_err("ucomp: compress called, slen=%u dlen=%u\n", req->slen, req->dlen);

	return -EINPROGRESS;
}

static int ucomp_decompress(struct acomp_req *req)
{
	struct ucomp_alg_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct ucomp_alg *alg = ctx->alg;
	struct ucomp_cmd *cmd = alg->buf;

	//pr_err("req: %px sg_virt in ucomp_decompress: %px\n", req, sg_virt(req->dst));

	cmd->flags = UCOMP_CMD_FLAGS_DECOMP;
	cmd->acomp_req = req;
	cmd->src_len = req->slen;
	cmd->dst_len = req->dlen;
	memcpy(alg->buf + cmd->src_off, sg_virt(req->src) + req->soff, req->slen);

	//pr_err("done uring_cmd: %p\n", cmd->uring_cmd);
	io_uring_cmd_done(cmd->uring_cmd, 0, 0, 0);
	//pr_err("ucomp: decompress called, slen=%u dlen=%u\n", req->slen, req->dlen);
	return -EINPROGRESS;
}

static struct miscdevice ucomp_ctrl_miscdev = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= UCOMP_CTRL_NAME,
	.fops		= &ucomp_ctrl_fops,
};

static int ucomp_alg_init(struct crypto_acomp *acomp_tfm)
{
	struct crypto_tfm *tfm = crypto_acomp_tfm(acomp_tfm);
	struct ucomp_alg_ctx *ctx = crypto_tfm_ctx(tfm);

	ctx->alg = ucomp_alg_nop;

	return 0;
}

static struct acomp_alg ucomp_acomp_nop = {
	.init			= ucomp_alg_init,
	.compress		= ucomp_compress,
	.decompress		= ucomp_decompress,
	.base			= {
		.cra_name		= "ucomp",
		.cra_driver_name	= "ucomp-generic",
		//.cra_flags		= CRYPTO_ALG_ASYNC,
		.cra_ctxsize		= sizeof(struct ucomp_alg_ctx),
		.cra_module		= THIS_MODULE,
	}
};

static int ucomp_register_algorithm(const char *algname)
{
	struct ucomp_alg *ucomp_alg;
	struct device *dev;
	int ret;
	//pr_err("into ucomp_alg_init\n");

	ucomp_alg = kzalloc(sizeof(*ucomp_alg), GFP_KERNEL);
	if (!ucomp_alg)
		goto err;

	ucomp_alg->buf = kzalloc(1024*1024, GFP_KERNEL);
	if (!ucomp_alg->buf) {
		ret = -ENOMEM;
		goto free_alg;
	}

	INIT_LIST_HEAD(&ucomp_alg->node);
	sprintf(ucomp_alg->algname, "ucomp_nop");

	dev = &ucomp_alg->cdev_dev;
	dev->parent = ucomp_ctrl_miscdev.this_device;
	dev->devt = MKDEV(MAJOR(ucomp_chr_devt), 0);
	dev->release = ucomp_cdev_release;
	device_initialize(dev);
	dev_set_name(dev, ucomp_alg->algname);

	cdev_init(&ucomp_alg->cdev, &ucomp_ch_fops);

	ret = cdev_device_add(&ucomp_alg->cdev, dev);
	if (ret) {
		goto put_dev;
	}
	mutex_lock(&ucomp_alg_list_lock);
	list_add(&ucomp_alg->node, &ucomp_alg_list);
	mutex_unlock(&ucomp_alg_list_lock);
	//pr_err("ucomp: registered algorithm device: %s\n", ucomp_alg->algname);

	ucomp_alg_nop = ucomp_alg;
	//pr_err("before register_acomps\n");
	ret = crypto_register_acomp(&ucomp_acomp_nop);
	//pr_err("ret of crypto_register_acomps: %d\n", ret);

	return 0;
put_dev:
	put_device(dev);
	kfree(ucomp_alg->buf);
free_alg:
	kfree(ucomp_alg);
err:
	return ret;
}

static int __init ucomp_init(void)
{
	int ret;

	ret = misc_register(&ucomp_ctrl_miscdev);
	if (ret) {
		pr_err("ucomp: failed to register control device\n");
		return ret;
	}

	ret = alloc_chrdev_region(&ucomp_chr_devt, 0, UCOMP_MINORS, "ucomp-char");
	if (ret)
		goto unregister_mis;

	ret = class_register(&ucomp_chr_class);
	if (ret)
		goto free_chrdev_region;

	pr_err("ucomp: control device registered as /dev/%s\n", UCOMP_CTRL_NAME);
	return 0;

free_chrdev_region:
	unregister_chrdev_region(ucomp_chr_devt, UCOMP_MINORS);
unregister_mis:
	misc_deregister(&ucomp_ctrl_miscdev);
	return ret;
}

static void __exit ucomp_exit(void)
{
	class_unregister(&ucomp_chr_class);
	unregister_chrdev_region(ucomp_chr_devt, UCOMP_MINORS);
	misc_deregister(&ucomp_ctrl_miscdev);
	pr_err("ucomp: module unloaded\n");
}

module_init(ucomp_init);
module_exit(ucomp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dongsheng Yang");
MODULE_DESCRIPTION("ucomp module with uring interface and algorithm registration");
