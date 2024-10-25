CBD_CACHE_DIR := cbd_cache/

cbd-y := cbd_main.o cbd_transport.o cbd_channel.o cbd_host.o \
         cbd_backend.o cbd_handler.o cbd_blkdev.o cbd_queue.o \
         cbd_segment.o \
         $(CBD_CACHE_DIR)cbd_cache.o \
         $(CBD_CACHE_DIR)cbd_cache_key.o \
         $(CBD_CACHE_DIR)cbd_cache_segment.o \
         $(CBD_CACHE_DIR)cbd_cache_req.o \
         $(CBD_CACHE_DIR)cbd_cache_gc.o \
         $(CBD_CACHE_DIR)cbd_cache_writeback.o \

obj-$(CONFIG_BLK_DEV_CBD) += cbd.o

