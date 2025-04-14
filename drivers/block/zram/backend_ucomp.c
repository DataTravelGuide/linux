#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <crypto/acompress.h>
#include <linux/scatterlist.h>

#include "backend_ucomp.h"

struct ucomp_ctx {
	struct crypto_acomp *acomp;
	struct acomp_req *req;
	struct crypto_wait wait;
	u8 *buffer;
};

static void ucomp_release_params(struct zcomp_params *params)
{
}

static int ucomp_setup_params(struct zcomp_params *params)
{
	return 0;
}

static void ucomp_destroy(struct zcomp_ctx *ctx)
{
	struct ucomp_ctx *zctx = ctx->context;
	if (!zctx)
		return;

	if (zctx->req)
		acomp_request_free(zctx->req);
	if (zctx->acomp)
		crypto_free_acomp(zctx->acomp);
	kfree(zctx->buffer);
	kfree(zctx);
}

static int ucomp_create(struct zcomp_params *params, struct zcomp_ctx *ctx)
{
	struct ucomp_ctx *zctx;
	int ret = 0;

	zctx = kzalloc(sizeof(*zctx), GFP_KERNEL);
	if (!zctx)
		return -ENOMEM;

	zctx->acomp = crypto_alloc_acomp("ucomp", 0, 0);
	if (IS_ERR(zctx->acomp)) {
		pr_err("failed to alloc ucomp-nop\n");
		ret = PTR_ERR(zctx->acomp);
		goto error;
	}

	zctx->req = acomp_request_alloc(zctx->acomp);
	if (!zctx->req) {
		ret = -ENOMEM;
		goto error;
	}

	zctx->buffer = kmalloc(PAGE_SIZE * 2, GFP_KERNEL);
	if (!zctx->buffer) {
		ret = -ENOMEM;
		goto error;
	}

	crypto_init_wait(&zctx->wait);
	acomp_request_set_callback(zctx->req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				crypto_req_done, &zctx->wait);

	ctx->context = zctx;
	return 0;

error:
	ucomp_destroy(ctx);
	pr_err("err: %d\n", ret);
	return ret;
}

static int ucomp_compress(struct zcomp_params *params, struct zcomp_ctx *ctx,
                          struct zcomp_req *req)
{
	struct ucomp_ctx *zctx = ctx->context;
	struct scatterlist src_sg, dst_sg;
	int ret;

	sg_init_one(&src_sg, req->src, req->src_len);
	sg_init_one(&dst_sg, zctx->buffer, PAGE_SIZE * 2);

	acomp_request_set_params(zctx->req, &src_sg, &dst_sg, req->src_len, PAGE_SIZE * 2);

	ret = crypto_wait_req(crypto_acomp_compress(zctx->req), &zctx->wait);
	if (ret)
		return ret;

	pr_err("after compress wait\n");
	req->dst_len = zctx->req->dlen;
	memcpy(req->dst, zctx->buffer, req->dst_len);
	return 0;
}

static int ucomp_decompress(struct zcomp_params *params, struct zcomp_ctx *ctx,
                            struct zcomp_req *req)
{
	struct ucomp_ctx *zctx = ctx->context;
	struct scatterlist src_sg, dst_sg;
	int ret;

	sg_init_one(&src_sg, req->src, req->src_len);
	sg_init_one(&dst_sg, req->dst, req->dst_len);

	acomp_request_set_params(zctx->req, &src_sg, &dst_sg, req->src_len, req->dst_len);

	ret = crypto_wait_req(crypto_acomp_decompress(zctx->req), &zctx->wait);
	return ret;
}

const struct zcomp_ops backend_ucomp = {
	.compress       = ucomp_compress,
	.decompress     = ucomp_decompress,
	.create_ctx     = ucomp_create,
	.destroy_ctx    = ucomp_destroy,
	.setup_params   = ucomp_setup_params,
	.release_params = ucomp_release_params,
	.name           = "ucomp",
};
