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

#define CHUNK_SIZE (PAGE_SIZE * 128)
#define MAX_OUT_SIZE (CHUNK_SIZE * 2)

static int comp_bench_init(void)
{
	struct crypto_acomp *tfm;
	struct acomp_req *req;
	struct file *file;
	loff_t pos = 0;
	char *inbuf = NULL, *outbuf = NULL;
	struct scatterlist src, dst;
	struct crypto_wait wait;
	int ret = 0;

	u64 start_ns, end_ns;
	u64 total_in = 0, total_out = 0;
	u64 duration_ns;
	u32 dlen;

	pr_info("comp_bench: path=%s alg=%s\n", path, alg);

	tfm = crypto_alloc_acomp(alg, 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("comp_bench: failed to load algorithm %s\n", alg);
		return PTR_ERR(tfm);
	}

	req = acomp_request_alloc(tfm);
	if (!req) {
		pr_err("comp_bench: failed to alloc acomp request\n");
		ret = -ENOMEM;
		goto out_free_tfm;
	}

	inbuf = kmalloc(CHUNK_SIZE, GFP_KERNEL);
	outbuf = kmalloc(MAX_OUT_SIZE, GFP_KERNEL);
	if (!inbuf || !outbuf) {
		ret = -ENOMEM;
		goto out_free_req;
	}
	
	file = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(file)) {
			ret = PTR_ERR(file);
				pr_err("comp_bench: failed to open file %s (err=%d)\n", path, ret);
					goto out_free_buf;
	} else {
			pr_info("comp_bench: opened file %s successfully\n", path);
	}

	crypto_init_wait(&wait);
	start_ns = ktime_get_ns();

	while (true) {
		ssize_t read_size = kernel_read(file, inbuf, CHUNK_SIZE, &pos);
		if (read_size <= 0)
			break;

		sg_init_one(&src, inbuf, read_size);
		sg_init_one(&dst, outbuf, MAX_OUT_SIZE);

		acomp_request_set_params(req, &src, &dst, read_size, MAX_OUT_SIZE);
		acomp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
					   crypto_req_done, &wait);

		ret = crypto_wait_req(crypto_acomp_compress(req), &wait);
		if (ret) {
			pr_err("comp_bench: compress failed ret=%d\n", ret);
			break;
		}

		dlen = req->dlen;
		total_in += read_size;
		total_out += dlen;

		//pr_debug("comp_bench: compressed %zu => %u bytes\n", read_size, dlen);
	}

	end_ns = ktime_get_ns();
	duration_ns = end_ns - start_ns;

	filp_close(file, NULL);

	if (total_in && duration_ns) {
		u64 speed_kb = div64_u64(total_in * 1000000000 / 1024, duration_ns);

#define PAD 24
		pr_info("comp_bench result:\n");
		pr_info("  %-*s: %s\n", PAD, "Algorithm", alg);
		pr_info("  %-*s: %llu bytes\n", PAD, "Original size", total_in);
		pr_info("  %-*s: %llu bytes\n", PAD, "Compressed size", total_out);
		pr_info("  %-*s: %llu.%02llu\n", PAD, "Compress ratio", total_in / total_out, (total_in % total_out) * 100 / total_out);
		pr_info("  %-*s: %llu.%03llu ms\n", PAD, "Time taken", duration_ns / 1000000, (duration_ns / 1000) % 1000);
		pr_info("  %-*s: %llu KB/s\n", PAD, "Compress speed", speed_kb);
	}

out_free_buf:
	kfree(inbuf);
	kfree(outbuf);
out_free_req:
	acomp_request_free(req);
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
