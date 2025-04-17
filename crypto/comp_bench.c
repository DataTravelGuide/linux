// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <crypto/acompress.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/timekeeping.h>

static char *path = "/tmp/input.dat";
module_param(path, charp, 0);
MODULE_PARM_DESC(path, "Path to input file to compress");

static char *alg = "zstd";
module_param(alg, charp, 0);
MODULE_PARM_DESC(alg, "Compression algorithm name");

static int async_depth = 1;
module_param(async_depth, int, 0);
MODULE_PARM_DESC(async_depth, "Number of concurrent async compression requests");

#define CHUNK_SIZE (PAGE_SIZE * 128)
#define MAX_OUT_SIZE (CHUNK_SIZE * 2)

struct bench_req {
	struct acomp_req *req;
	struct crypto_wait wait;
	char *inbuf;
	char *outbuf;
	struct scatterlist src;
	struct scatterlist dst;
};

static int comp_bench_init(void)
{
	struct crypto_acomp *tfm;
	struct file *file;
	loff_t pos = 0;
	struct bench_req *reqs;
	u64 start_ns, end_ns;
	u64 total_in = 0, total_out = 0;
	u64 duration_ns;
	size_t read_size;
	size_t current_slot = 0;
	int i, ret = 0, active = 0;

	pr_info("comp_bench: path=%s alg=%s depth=%d\n", path, alg, async_depth);

	tfm = crypto_alloc_acomp(alg, 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("comp_bench: failed to load algorithm %s\n", alg);
		return PTR_ERR(tfm);
	}

	reqs = kcalloc(async_depth, sizeof(*reqs), GFP_KERNEL);
	if (!reqs) {
		ret = -ENOMEM;
		goto out_free_tfm;
	}

	for (i = 0; i < async_depth; i++) {
		reqs[i].req = acomp_request_alloc(tfm);
		if (!reqs[i].req) {
			ret = -ENOMEM;
			goto out_cleanup_reqs;
		}
		reqs[i].inbuf = kmalloc(CHUNK_SIZE, GFP_KERNEL);
		reqs[i].outbuf = kmalloc(MAX_OUT_SIZE, GFP_KERNEL);
		if (!reqs[i].inbuf || !reqs[i].outbuf) {
			ret = -ENOMEM;
			goto out_cleanup_reqs;
		}
		crypto_init_wait(&reqs[i].wait);
	}

	file = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		pr_err("comp_bench: failed to open file %s (err=%d)\n", path, ret);
		goto out_cleanup_reqs;
	} else {
		pr_info("comp_bench: opened file %s successfully\n", path);
	}

	start_ns = ktime_get_ns();

	while (true) {
		struct bench_req *r = &reqs[current_slot];

		read_size = kernel_read(file, r->inbuf, CHUNK_SIZE, &pos);
		if (read_size <= 0)
			break;

		sg_init_one(&r->src, r->inbuf, read_size);
		sg_init_one(&r->dst, r->outbuf, MAX_OUT_SIZE);

		acomp_request_set_params(r->req, &r->src, &r->dst, read_size, MAX_OUT_SIZE);
		acomp_request_set_callback(r->req, CRYPTO_TFM_REQ_MAY_BACKLOG,
					   crypto_req_done, &r->wait);

		ret = crypto_acomp_compress(r->req);
		if (ret == -EINPROGRESS || ret == -EBUSY) {
			active++;
			current_slot = (current_slot + 1) % async_depth;

			if (active == async_depth) {
				for (i = 0; i < async_depth; i++) {
					ret = crypto_wait_req(-EINPROGRESS, &reqs[i].wait);
					if (ret) {
						pr_err("comp_bench: async wait failed ret=%d\n", ret);
						goto out_close;
					}
					total_in += reqs[i].req->slen;
					total_out += reqs[i].req->dlen;
					crypto_init_wait(&reqs[i].wait);
				}
				active = 0;
			}
		} else {
			ret = crypto_wait_req(ret, &r->wait);
			if (ret) {
				pr_err("comp_bench: compress failed ret=%d\n", ret);
				break;
			}
			total_in += read_size;
			total_out += r->req->dlen;
			crypto_init_wait(&r->wait);
		}
	}

	/* flush remaining */
	for (i = 0; i < active; i++) {
		ret = crypto_wait_req(-EINPROGRESS, &reqs[i].wait);
		total_in += reqs[i].req->slen;
		total_out += reqs[i].req->dlen;
	}

	end_ns = ktime_get_ns();
	duration_ns = end_ns - start_ns;

	if (total_in && duration_ns) {
		u64 speed_kb = div64_u64(total_in * 1000000000 / 1024, duration_ns);
#define PAD 24
		pr_info("comp_bench result:\n");
		pr_info("  %-*s: %s\n", PAD, "Algorithm", alg);
		pr_info("  %-*s: %llu bytes\n", PAD, "Original size", total_in);
		pr_info("  %-*s: %llu bytes\n", PAD, "Compressed size", total_out);
		pr_info("  %-*s: %llu.%02llu\n", PAD, "Compress ratio",
			total_in / total_out, (total_in % total_out) * 100 / total_out);
		pr_info("  %-*s: %llu.%03llu ms\n", PAD, "Time taken",
			duration_ns / 1000000, (duration_ns / 1000) % 1000);
		pr_info("  %-*s: %llu KB/s\n", PAD, "Compress speed", speed_kb);
	}

out_close:
	filp_close(file, NULL);
out_cleanup_reqs:
	for (i = 0; i < async_depth; i++) {
		if (reqs[i].req)
			acomp_request_free(reqs[i].req);
		kfree(reqs[i].inbuf);
		kfree(reqs[i].outbuf);
	}
	kfree(reqs);
out_free_tfm:
	crypto_free_acomp(tfm);
	return -EAGAIN;
}

static void comp_bench_exit(void)
{
	pr_info("comp_bench: exit\n");
}

module_init(comp_bench_init);
module_exit(comp_bench_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dongsheng Yang");
MODULE_DESCRIPTION("Compression benchmark using crypto_acomp");
