obj-$(CONFIG_NVME_CORE)			+= nvme-core.o
obj-$(CONFIG_BLK_DEV_NVME)		+= nvme.o

nvme-core-y				:= core.o
nvme-core-$(CONFIG_BLK_DEV_NVME_SCSI)	+= scsi.o

nvme-y					+= pci.o

