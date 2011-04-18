
BUILD_TAG=2.6.32-71.el6

PROG_RPMBUILD=rpmbuild
PROG_PATCH=patch
PROG_TAR=tar
PROG_M4=m4

DATE="$(shell date +"%a %b %d %Y")"
TMP_DIR=$(CURDIR)/redhat/dup/tmp
AUTHOR ?= "Jiri Olsa <jolsa@redhat.com>"
ARCH=$(shell uname -m)

# DUP final build directory
ifeq ($(DUP_BUILD_DIR),)
DUP_BUILD_DIR=$(CURDIR)/dup-build-$(ARCH)
endif

include redhat/dup/Makefile.sources

ifeq (multi,$(MAKECMDGOALS))
ifeq ($(DUP_MULTI),)
$(error You must specify the DUP_MULTI))
endif
DUP_MULTI_TMP=$(CURDIR)/dup-multi-$(ARCH)
endif

ifeq ($(filter all_dups all_check_version multi,$(MAKECMDGOALS)),)

$(warning Build will be placed to $(DUP_BUILD_DIR))

ifeq ($(DUP_DRIVER),)
$(error You must specify the DUP_DRIVER))
endif

# version check
ifeq ($(DUP_VERSION),)
$(warning Default version taken)
DUP_VERSION=$(DUP_VERSION_$(DUP_DRIVER))
endif

ifeq ($(DUP_VERSION),)
$(error You must specify the DUP_VERSION))
endif

#release check
ifeq ($(DUP_RELEASE),)
$(warning Default release 1)
DUP_RELEASE=1
endif

ifeq ($(DUP_COPY),)
DUP_COPY=$(TMP_DIR)/copy
endif

# multiple modules within the build
DUP_MODULES=$(DUP_MODULES_$(DUP_DRIVER))
ifeq ($(DUP_MODULES),)
DUP_MODULES=$(DUP_DRIVER)
endif

SOURCES=$(DUP_SOURCE_$(DUP_DRIVER))
SOURCES_DIR=$(DUP_DRIVER)-$(DUP_VERSION)
PATCH=$(DUP_PATCH_$(DUP_DRIVER))

# no dashes in the rpm Version tag
DUP_VERSION_REAL:=$(DUP_VERSION)
DUP_VERSION=`echo $(DUP_VERSION_REAL) | sed 's/-/_/g'`

ifeq ($(SOURCES),)
$(error No source specified for '$(DUP_DRIVER)' driver, edit Makefile.sources))
endif

endif # not all_dups or all_check_version

.PHONY: all create_tmp sources_tar_copy sources_tar_patch sources spec rh-dup-srpm rh-dup-rpm multi

check_version:
	@echo -n "---[ checking version for $(DUP_DRIVER) ... "; \
	grep $(DUP_VERSION_REAL) $(SOURCES) 2>&1 > /dev/null; \
	if [ $$? != 0 ]; then \
		echo "FAILED: version changed"; \
		exit 1; \
	fi; \
	echo "OK"

all: rh-dup-rpm copy_output
	DUP_SRPMS="$(DUP_COPY)/*src.rpm" ./redhat/dup/create_disk.sh $(DUP_COPY)/kmod*.rpm
	mkdir -p $(DUP_BUILD_DIR); \
	mv dd.iso $(DUP_BUILD_DIR)/dd-$(DUP_DRIVER)-$(DUP_VERSION)-$(ARCH).iso

all_dups:
	@rm -rf $(DUP_BUILD_DIR); mkdir -p $(DUP_BUILD_DIR); \
	for mod in `echo $(DUP_ALL) | sed 's/ /\n/'`; \
	do \
		echo -e "\n---[ $$mod \n"; \
		make -f redhat/dup/Makefile DUP_DRIVER=$$mod all 2>&1 \
		| tee $(DUP_BUILD_DIR)/log-$$mod-$(ARCH).txt; \
	done

all_check_version:
	for mod in `echo $(DUP_ALL) | sed 's/ /\n/'`; \
	do \
		make -s -f redhat/dup/Makefile check_version DUP_DRIVER=$$mod; \
	done

multi:
	rm -rf $(DUP_MULTI_TMP); mkdir -p $(DUP_MULTI_TMP); \
	for mod in `echo $(DUP_MULTI)`; \
	do \
		echo -e "\n---[ $$mod \n"; \
		make -f redhat/dup/Makefile DUP_DRIVER=$$mod rh-dup-rpm 2>&1; \
		cp $(TMP_DIR)/SRPMS/* $(DUP_MULTI_TMP); \
		find $(TMP_DIR)/RPMS/ -type f | grep -v debuginfo | xargs cp -t $(DUP_MULTI_TMP); \
	done; \
	DUP_SRPMS="$(DUP_MULTI_TMP)/*src.rpm" ./redhat/dup/create_disk.sh $(DUP_MULTI_TMP)/kmod*.rpm; \
	cp dd.iso dd-`echo $(DUP_MULTI) | sed 's/ \+/-/g'`-$(ARCH).iso

rpm: rh-dup-rpm copy_output

copy_output:
	rm -rf $(DUP_COPY); mkdir $(DUP_COPY); \
	cp -f $(TMP_DIR)/SRPMS/* $(DUP_COPY); \
	cp -f $(TMP_DIR)/RPMS/*/*  $(DUP_COPY); \

create_tmp:
	rm -rf $(TMP_DIR)
	mkdir -p $(TMP_DIR)/$(SOURCES_DIR)
	mkdir -p $(TMP_DIR)/SOURCES $(TMP_DIR)/SPECS $(TMP_DIR)/BUILD
	mkdir -p $(TMP_DIR)/SRPMS $(TMP_DIR)/RPMS

sources_tar_copy:
	cp $(SOURCES) $(TMP_DIR)/$(SOURCES_DIR)

sources_tar_patch:
	(cd $(TMP_DIR)/$(SOURCES_DIR); \
	if [ -n "$(PATCH)" -a -e "$(CURDIR)/$(PATCH)" ]; then \
		$(PROG_PATCH) -p1 < $(CURDIR)/$(PATCH); \
	fi )

sources: sources_tar_copy sources_tar_patch
	(cd $(TMP_DIR); \
	$(PROG_TAR) cjvf SOURCES/$(DUP_DRIVER)-$(DUP_VERSION).tar.bz2 $(SOURCES_DIR) )

dotfiles:
	$(PROG_M4) \
	-D DUP_KMOD_NAME=$(DUP_DRIVER) \
	redhat/dup/template.files > $(TMP_DIR)/SOURCES/$(DUP_DRIVER).files

dotconf:
	for mod in `echo $(DUP_MODULES)`; \
	do \
		$(PROG_M4) \
		-D DUP_KMOD_NAME1=$$mod -D DUP_KMOD_NAME2=$(DUP_DRIVER) \
		redhat/dup/template.conf >> $(TMP_DIR)/SOURCES/$(DUP_DRIVER).conf; \
	done;

spec:
	$(PROG_M4) \
	-D DUP_KMOD_NAME=$(DUP_DRIVER) \
	-D DUP_KMOD_DRIVER_VERSION=$(DUP_VERSION) \
	-D DUP_KMOD_RPM_RELEASE=$(DUP_RELEASE) \
	-D DUP_KMOD_KERNEL_KVERSION=$(BUILD_TAG) \
	-D DUP_DATE=$(DATE) \
	-D DUP_AUTHOR=$(AUTHOR) \
	redhat/dup/template.spec > $(TMP_DIR)/SPECS/$(DUP_DRIVER).spec

rh-dup-srpm: create_tmp sources spec dotfiles dotconf
	$(PROG_RPMBUILD) --target $(ARCH) --define "_topdir $(TMP_DIR)" -bs $(TMP_DIR)/SPECS/$(DUP_DRIVER).spec

rh-dup-rpm: create_tmp sources spec dotfiles dotconf
	$(PROG_RPMBUILD) --target $(ARCH) --define "_topdir $(TMP_DIR)" -ba $(TMP_DIR)/SPECS/$(DUP_DRIVER).spec
