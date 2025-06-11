/*
 * baco-zstd: asynchronous acomp_alg backed by kernel workqueue
 * using zstd_compress as actual compression algorithm
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/workqueue.h>
#include <linux/crypto.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <crypto/internal/acompress.h>
#include <linux/zstd.h>

#define BACO_NAME "baco-zstd"
#define BACO_WORKERS 128

struct baco_zwork {
	struct work_struct work;
	struct acomp_req *req;
	bool in_use;
};

struct baco_ctx {
	struct baco_zwork *zworks;
	struct workqueue_struct *wq;
	spinlock_t lock;
};

static struct baco_ctx *baco;

static void *zstd_custom_alloc(void *opaque, size_t size)
{
	return kvzalloc(size, GFP_NOIO | __GFP_NOWARN);
}

static void zstd_custom_free(void *opaque, void *address)
{
	kvfree(address);
}

static void baco_zstd_workfn(struct work_struct *work)
{
	struct baco_zwork *z = container_of(work, struct baco_zwork, work);
	struct acomp_req *req = z->req;
	int ret = 0;
	size_t csize;

	zstd_compression_parameters cparams = zstd_get_cparams(ZSTD_CLEVEL_DEFAULT, PAGE_SIZE, 0);
	size_t sz = zstd_cctx_workspace_bound(&cparams);
	void *mem = vzalloc(sz);
	if (!mem) {
		acomp_request_complete(req, -ENOMEM);
		z->req = NULL;
		z->in_use = false;
		return;
	}

	ZSTD_CCtx *cctx = zstd_init_cctx(mem, sz);
	if (!cctx) {
		vfree(mem);
		acomp_request_complete(req, -EINVAL);
		z->req = NULL;
		z->in_use = false;
		return;
	}

	zstd_parameters params = zstd_get_params(ZSTD_CLEVEL_DEFAULT, PAGE_SIZE);

	csize = zstd_compress_cctx(cctx,
				  sg_virt(req->dst), req->dlen,
				  sg_virt(req->src) + req->soff, req->slen,
				  &params);

	if (zstd_is_error(csize)) {
		ret = -EINVAL;
	} else {
		req->dlen = csize;
	}

	zstd_free_cctx(cctx);
	vfree(mem);
	acomp_request_complete(req, ret);
	z->req = NULL;
	z->in_use = false;
}

static int baco_zstd_compress(struct acomp_req *req)
{
	int i;
	unsigned long flags;
	struct baco_zwork *z = NULL;

	spin_lock_irqsave(&baco->lock, flags);
	for (i = 0; i < BACO_WORKERS; i++) {
		if (!baco->zworks[i].in_use) {
			z = &baco->zworks[i];
			z->in_use = true;
			break;
		}
	}
	spin_unlock_irqrestore(&baco->lock, flags);

	if (!z)
		return -EBUSY;

	z->req = req;
	queue_work(baco->wq, &z->work);
	return -EINPROGRESS;
}

static int baco_zstd_decompress(struct acomp_req *req)
{
	return -ENOTSUPP;
}

static int baco_zstd_init(struct crypto_acomp *tfm)
{
	return 0;
}

static void baco_zstd_exit(struct crypto_acomp *tfm)
{
}

static struct acomp_alg baco_zstd_alg = {
	.init = baco_zstd_init,
	.exit = baco_zstd_exit,
	.compress = baco_zstd_compress,
	.decompress = baco_zstd_decompress,
	.base = {
		.cra_name = BACO_NAME,
		.cra_driver_name = BACO_NAME,
		//.cra_flags = CRYPTO_ALG_ASYNC,
		.cra_ctxsize = 0,
		.cra_module = THIS_MODULE,
	},
};

static int __init baco_zstd_init_module(void)
{
	int i, ret;

	baco = kzalloc(sizeof(*baco), GFP_KERNEL);
	if (!baco)
		return -ENOMEM;

	baco->wq = alloc_workqueue("baco_zstd_wq", WQ_UNBOUND | WQ_CPU_INTENSIVE, 0);
	if (!baco->wq) {
		ret = -ENOMEM;
		goto free_ctx;
	}

	baco->zworks = kcalloc(BACO_WORKERS, sizeof(struct baco_zwork), GFP_KERNEL);
	if (!baco->zworks) {
		ret = -ENOMEM;
		goto destroy_wq;
	}

	spin_lock_init(&baco->lock);
	for (i = 0; i < BACO_WORKERS; i++) {
		INIT_WORK(&baco->zworks[i].work, baco_zstd_workfn);
		baco->zworks[i].in_use = false;
	}

	ret = crypto_register_acomp(&baco_zstd_alg);
	if (ret)
		goto free_zworks;

	pr_info("baco-zstd: async acomp_alg registered\n");
	return 0;

free_zworks:
	kfree(baco->zworks);
destroy_wq:
	destroy_workqueue(baco->wq);
free_ctx:
	kfree(baco);
	return ret;
}

static void __exit baco_zstd_exit_module(void)
{
	crypto_unregister_acomp(&baco_zstd_alg);
	destroy_workqueue(baco->wq);
	kfree(baco->zworks);
	kfree(baco);
	pr_info("baco-zstd: module unloaded\n");
}

module_init(baco_zstd_init_module);
module_exit(baco_zstd_exit_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dongsheng Yang");
MODULE_DESCRIPTION("baco-zstd: async acomp_alg using workqueue + zstd");
