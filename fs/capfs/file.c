// fs/capfs/file.c

#include "capfs.h"
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/backing-file.h>
#include <linux/security.h>
#include <linux/zstd.h>
#include <linux/crc32.h>

static inline int capfs_file_maybe_extend_segs(struct capfs_file *cfile, size_t file_size)
{
	struct capfs_segment *new_segs;
	u64 old_seg_num = cfile->seg_num;

	if (DIV_ROUND_UP(file_size, (1024 * 1024)) >  old_seg_num) {
		cfile->seg_num = DIV_ROUND_UP(file_size, (1024*1024));
		new_segs = kzalloc(sizeof(struct capfs_segment) * cfile->seg_num, GFP_NOFS);
		if (old_seg_num) {
			memcpy(new_segs, cfile->segs, sizeof(struct capfs_segment) * old_seg_num);
			kfree(cfile->segs);
		}
		cfile->segs = new_segs;

		pr_err("======new_segs: %llu=====", cfile->seg_num);
	}

	return 0;
}

static int capfs_file_meta_load(struct capfs_file *cfile)
{
	struct capfs_file_meta *file_meta;;
	struct capfs_seg_meta *seg_meta;
	u64 meta_size;
	loff_t off = 0;
	ssize_t ret;
	u64 i;

	/* step 1 read file meta */
	meta_size = sizeof(struct capfs_file_meta);

	file_meta = kvzalloc(meta_size, GFP_KERNEL);
	ret = kernel_read(cfile->meta_file, file_meta, meta_size, &off);
	if (ret < 0) {
		pr_err("read meta error: %d", ret);
		kvfree(file_meta);
		return ret;
	}

	cfile->seg_num = le64_to_cpu(file_meta->seg_num);
	kvfree(file_meta);

	pr_err("load meta: seg_num: %lu", cfile->seg_num);

	/*step 2 read seg metas */
	off = 0;
	meta_size = sizeof(struct capfs_file_meta) + sizeof(struct capfs_seg_meta) * cfile->seg_num;

	file_meta = kvzalloc(meta_size, GFP_KERNEL);
	ret = kernel_read(cfile->meta_file, file_meta, meta_size, &off);
	if (ret < 0) {
		pr_err("read seg meta error: %d", ret);
		kvfree(file_meta);
		return ret;
	}

	cfile->segs = kzalloc(sizeof(struct capfs_segment) * cfile->seg_num, GFP_KERNEL);

	for (i = 0; i < cfile->seg_num; i++) {
		seg_meta = &file_meta->segs[i];
		cfile->segs[i].compressed_size = le32_to_cpu(seg_meta->compressed_size);
		pr_err("seg %lu, compressed_size: %lu", i, cfile->segs[i].compressed_size);
	}

	return 0;
}

static int capfs_file_meta_save(struct capfs_file *cfile)
{
	struct capfs_file_meta *file_meta;;
	struct capfs_seg_meta *seg_meta;
	u64 meta_size;
	loff_t off = 0;
	ssize_t ret;
	u64 i;

	meta_size = sizeof(struct capfs_file_meta) + sizeof(struct capfs_seg_meta) * cfile->seg_num;
	file_meta = kvzalloc(meta_size, GFP_KERNEL);
	file_meta->seg_num = cpu_to_le64(cfile->seg_num);

	for (i = 0; i < cfile->seg_num; i++) {
		seg_meta = &file_meta->segs[i];
		seg_meta->compressed_size = cpu_to_le32(cfile->segs[i].compressed_size);
		pr_err("save meta: %lu, compressed_size: %lu", i, cfile->segs[i].compressed_size);
	}

	ret = kernel_write(cfile->meta_file, file_meta, meta_size, &off);
	if (ret < 0) {
		printk(KERN_ERR "capfs: failed to write meta with err=%d\n", ret);
		kvfree(file_meta);
		return ret;
	}

	pr_err("write meta len: %llu", ret);

	return 0;
}

static int capfs_file_meta_update(struct capfs_file *cfile)
{
	return 0;
}

static int capfs_open(struct inode *inode, struct file *file)
{
	struct path backing_data_path;
	struct path backing_meta_path;
	const struct cred *old_cred;
	struct capfs_info *tfs = inode->i_sb->s_fs_info;
	struct capfs_file *cfile = &capfs_i(inode)->cfile;
	int ret;

	old_cred = override_creds(tfs->creator_cred);

	ret = capfs_backing_data_path(inode, &backing_data_path);
	if (ret)
		goto revert_creds;


	cfile->data_file = backing_file_open(&file->f_path, file->f_flags | MAY_READ, &backing_data_path,
						 current_cred());
	path_put(&backing_data_path);


	ret = capfs_backing_meta_path(inode, &backing_meta_path);
	if (ret)
		goto fput_data_file;


	cfile->meta_file = backing_file_open(&file->f_path, MAY_READ|MAY_WRITE, &backing_meta_path, current_cred());

	path_put(&backing_meta_path);

	cfile->seg_num = 0;
	cfile->segs = NULL;

	capfs_file_meta_load(cfile);

	file->private_data = cfile;

	revert_creds(old_cred);
	return 0;

fput_data_file:
	fput(cfile->data_file);
revert_creds:
	revert_creds(old_cred);

	return 0;
}

static int capfs_release(struct inode *inode, struct file *file)
{
	struct capfs_file *cfile = file->private_data;

	capfs_file_meta_save(cfile);

	fput(cfile->data_file);
	fput(cfile->meta_file);

	cfile->data_file = NULL;
	cfile->meta_file = NULL;

	if (cfile->segs) {
		pr_err("segs: %p", cfile->segs);
		kfree(cfile->segs);
	}

	return 0;
}

static ssize_t capfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	ssize_t ret;
	struct capfs_file *cfile = file->private_data;

	if (!iov_iter_count(iter))
		return 0;

	pr_err("len of read: %llu:%lu.", iocb->ki_pos, iov_iter_count(iter));

	/* Step 1: Get the read offset and length */
	loff_t off = iocb->ki_pos;
	size_t len = iov_iter_count(iter);

	/* Step 2: Calculate the start and end segment based on 1MB segments */
	unsigned int start_segment = off / (1024 * 1024);  /* 1MB per segment */
	unsigned int end_segment = (off + len - 1) / (1024 * 1024);

	pr_err("Reading from segment %u to segment %u.\n", start_segment, end_segment);

	/* Step 3: Process each segment */
	for (unsigned int seg = start_segment; seg <= end_segment; seg++) {
		loff_t segment_offset = seg * 1024 * 1024;  /* 1MB per segment */
		size_t segment_len;

		pr_err("Updating segment %u.\n", seg);

		if (seg == start_segment) {
			/* Special handling for the first segment: read only the part of the segment */
			if (off + len <= segment_offset + 1024 * 1024) {
				/* If off + len is still within the current segment */
				segment_len = len;  /* Just read the length since it fits in the segment */
			} else if (off % (1024 * 1024) != 0) {
				/* If off is not aligned to the segment boundary */
				segment_len = (segment_offset + 1024 * 1024) - off;  /* Read from 'off' to the end of the segment */
			} else {
				/* Regular segment read */
				segment_len = 1024 * 1024;
			}
		} else if (seg == end_segment) {
			/* Special handling for the last segment: read the remaining data */
			segment_len = (off + len) - segment_offset;
		} else {
			/* Regular 1MB segment */
			segment_len = 1024 * 1024;
		}

		pr_err("Segment %u, offset: %lld, length: %zu\n", seg, segment_offset, segment_len);
		if (seg >= cfile->seg_num)
			return 0;

		/* Step 4: Allocate memory for the segment */
		void *segment_buffer = kmalloc(1024*1024, GFP_KERNEL);
		if (!segment_buffer) {
			printk(KERN_ERR "capfs: Failed to allocate memory for segment %u\n", seg);
			return -ENOMEM;
		}

		u64 compressed_len = cfile->segs[seg].compressed_size;
		void *segment_compressed = kmalloc(compressed_len, GFP_NOFS);

		off = segment_offset;
		/* Step 5: Read the data for this segment into the buffer */
		ret = kernel_read(cfile->data_file, segment_compressed, compressed_len, &off);
		if (ret < 0) {
			printk(KERN_ERR "capfs: failed to read segment %u with err=%d\n", seg, ret);
			kfree(segment_buffer);
			return ret;
		}

		if (ret) {

		zstd_parameters prm = zstd_get_params(10, PAGE_SIZE);

		/* Step 5: Calculate workspace size for compression context */
		ssize_t sz = zstd_dctx_workspace_bound();  // Get required size for cctx memory
		void *workspace = vzalloc(sz);  // Allocate memory for compression context
		if (!workspace) {
		    printk(KERN_ERR "capfs: Failed to allocate memory for compression context\n");
		    kfree(segment_buffer);
		    return -ENOMEM;
		}

		/* Initialize the compression context */
		zstd_dctx *dctx = zstd_init_dctx(workspace, sz);  // Initialize compression context
		if (!dctx) {
		    printk(KERN_ERR "capfs: ZSTD compression context initialization failed\n");
		    kfree(segment_buffer);
		    return -ENOMEM;
		}

		pr_err("before decompress compressed_len: %llu, crc after compress: %u", compressed_len, crc32(0, segment_compressed, compressed_len));

		/* Step 7: Compress the segment using ZSTD */
		size_t decompressed_len = zstd_decompress_dctx(dctx, segment_buffer, 1024 * 1024, segment_compressed, compressed_len);
		if (zstd_is_error(decompressed_len)) {
		    printk(KERN_ERR "capfs: ZSTD decompression failed for segment %u\n", seg);
		    kfree(segment_buffer);
		    kfree(segment_compressed);
		    return -EIO;
		}
		pr_err("decompressed_len: %llu", decompressed_len);

			pr_err("seg_off: %llu, segment_len: %llu", (iocb->ki_pos % (1024*1024)), segment_len);
			/* Step 6: Copy the data to the iter (user space buffer) */
			size_t copied = copy_to_iter(segment_buffer + (iocb->ki_pos % (1024*1024)), segment_len, iter);
			if (copied < segment_len) {
				printk(KERN_ERR "capfs: failed to copy data to iter for segment %u\n", seg);
				kfree(segment_buffer);
				return -EIO;
			}

			iov_iter_advance(iter, segment_len);  /* Move the iov_iter offset for the next write */
			iocb->ki_pos += segment_len;
			pr_err("ki_pos: %llu", iocb->ki_pos);
			ret = segment_len;
		}

		/* Step 7: Free the allocated memory for the segment */
		kfree(segment_buffer);
	}

	pr_err("return len: %lu", ret);
	return ret;
}

static ssize_t capfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	ssize_t ret;
	int ifl = iocb->ki_flags;
	struct capfs_file *cfile = file->private_data;
	    void *segment_buffer;
	    size_t segment_len, compressed_len;
	    size_t sz;

	if (!iov_iter_count(iter))
		return 0;

	pr_err("len of write: %llu:%lu.", iocb->ki_pos, iov_iter_count(iter));

	/* Step 1: Get the write offset and length */
	loff_t off = iocb->ki_pos;
	size_t len = iov_iter_count(iter);

	capfs_file_maybe_extend_segs(cfile, off + len);

	/* Step 2: Calculate the start and end segment based on 1MB segments */
	unsigned int start_segment = off / (1024 * 1024);  /* 1MB per segment */
	unsigned int end_segment = (off + len - 1) / (1024 * 1024);

	pr_err("Writing from segment %u to segment %u.\n", start_segment, end_segment);

	/* Step 3: Process each segment */
	for (unsigned int seg = start_segment; seg <= end_segment; seg++) {
		loff_t segment_offset = seg * 1024 * 1024;  /* 1MB per segment */
		size_t segment_len;

		pr_err("Updating segment %u.\n", seg);

		/* Special handling for the first segment: write only the part of the segment */
		if (seg == start_segment) {
			if (off + len <= segment_offset + 1024 * 1024) {
				/* If off + len is still within the current segment */
				segment_len = len;  /* Just write the length since it fits in the segment */
			} else if (off % (1024 * 1024) != 0) {
				/* If off is not aligned to the segment boundary */
				segment_len = (segment_offset + 1024 * 1024) - off;  /* Write from 'off' to the end of the segment */
			} else {
				/* Regular segment write */
				segment_len = 1024 * 1024;
			}
		} else if (seg == end_segment) {
			/* Special handling for the last segment: write the remaining data */
			segment_len = (off + len) - segment_offset;
		} else {
			/* Regular 1MB segment */
			segment_len = 1024 * 1024;
		}

		pr_err("Segment %u, offset: %lld, length: %zu\n", seg, segment_offset, segment_len);

		/* Step 4: Allocate new memory for the segment */
		void *segment_buffer = kmalloc(1024*1024, GFP_KERNEL);
		if (!segment_buffer) {
			printk(KERN_ERR "capfs: Failed to allocate memory for segment %u\n", seg);
			return -ENOMEM;
		}

		off = segment_offset;
		/* Step 5: Read the data for this segment into the buffer */
		ret = kernel_read(cfile->data_file, segment_buffer, 1024*1024, &off);
		pr_err("ret of kernel_read: %d", ret);

		/* Step 5: Copy data from the original iov_iter to the new buffer */
		size_t copied = copy_from_iter(segment_buffer + (iocb->ki_pos % (1024*1024)), segment_len, iter);
		if (copied < segment_len) {
			printk(KERN_ERR "capfs: failed to copy segment %u, only copied %zu bytes\n", seg, copied);
			kfree(segment_buffer);
			return -EIO;
		}

		/* Step 6: Allocate memory for the compressed segment */
		void *segment_compressed = kmalloc(1024 * 1024, GFP_KERNEL);  /* Allocate memory for compressed segment */
		if (!segment_compressed) {
		    printk(KERN_ERR "capfs: Failed to allocate memory for compressed segment %u\n", seg);
		    kfree(segment_buffer);
		    return -ENOMEM;
		}

		/* Get compression parameters based on compression level */
		zstd_parameters prm = zstd_get_params(10, PAGE_SIZE);

		/* Step 5: Calculate workspace size for compression context */
		sz = zstd_cctx_workspace_bound(&prm.cParams);  // Get required size for cctx memory
		void *workspace = vzalloc(sz);  // Allocate memory for compression context
		if (!workspace) {
		    printk(KERN_ERR "capfs: Failed to allocate memory for compression context\n");
		    kfree(segment_buffer);
		    return -ENOMEM;
		}

		/* Initialize the compression context */
		zstd_cctx *cctx = zstd_init_cctx(workspace, sz);  // Initialize compression context
		if (!cctx) {
		    printk(KERN_ERR "capfs: ZSTD compression context initialization failed\n");
		    kfree(segment_buffer);
		    return -ENOMEM;
		}


		/* Step 7: Compress the segment using ZSTD */
		size_t compressed_len = zstd_compress_cctx(cctx, segment_compressed, 1024 * 1024, segment_buffer, 1024*1024, &prm);
		if (zstd_is_error(compressed_len)) {
		    printk(KERN_ERR "capfs: ZSTD compression failed for segment %u\n", seg);
		    kfree(segment_buffer);
		    kfree(segment_compressed);
		    return -EIO;
		}

		pr_err("compressed_len: %llu, crc after compress: %u", compressed_len, crc32(0, segment_compressed, compressed_len));

		cfile->segs[seg].compressed_size = compressed_len;

		off = segment_offset;
		/* Step 6: Write the data for this segment to the data file */
		ret = kernel_write(cfile->data_file, segment_compressed, compressed_len, &off);
		if (ret < 0) {
			printk(KERN_ERR "capfs: failed to write segment %u with err=%d\n", seg, ret);
			kfree(segment_buffer);
			return ret;
		}

		/* Step 7: Advance the iov_iter */
		iov_iter_advance(iter, segment_len);  /* Move the iov_iter offset for the next write */
		iocb->ki_pos += segment_len;

		/* Step 8: Free the allocated memory for the segment */
		kfree(segment_buffer);
		kfree(segment_compressed);
	}

	return len;
}

const struct file_operations capfs_file_operations = {
	.owner		= THIS_MODULE,
	.open		= capfs_open,
	.read_iter	= capfs_read_iter,
	.write_iter	= capfs_write_iter,
	.llseek		= generic_file_llseek,
	.release	= capfs_release,
};
