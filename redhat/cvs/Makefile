# Makefile for source rpm: kernel
# $Id: Makefile,v 1.105 2011/06/28 18:37:22 kmcmarti Exp $
NAME     := kernel
DEFAULT_SPEC := kernel.spec
DETAILED_SPEC := kernel.spec.full
DETAILED_TEMP_SPEC := kernel-full.spec
KSB_SPEC := kernel.spec.ksb
KSB_TEMP_SPEC := kernel-ksb.spec

ifeq ($(SPECFILE),)
# if we're called without specifying the spec file, erase the temporary spec
# file: having two spec files can cause confusion
__TMP := $(shell rm -f $(DETAILED_TEMP_SPEC));
SPECFILE := $(DEFAULT_SPEC)
endif

# default collection for RHEL6 is RHEL-6-test
ifndef COLLECTION
ifndef TARGET
COLLECTION := RHEL-6-test
endif
endif

# use noarch for make prep instead of the current CPU
# noarch creates and checks all config files not just the current one,
# in addition "i386" isn't a valid kernel target
PREPARCH  = noarch

# we only check the .sign signatures
UPSTREAM_CHECKS = sign

TARGETS		= download-checks

define find-makefile-common
for d in common ../common ../../common ; do if [ -f $$d/Makefile.common ] ; then if [ -f $$d/CVS/Root -a -w $$/Makefile.common ] ; then cd $$d ; cvs -Q update ; fi ; echo "$$d/Makefile.common" ; break ; fi ; done
endef

MAKEFILE_COMMON := $(shell $(find-makefile-common))

ifeq ($(MAKEFILE_COMMON),)
# attept a checkout
define checkout-makefile-common
test -f CVS/Root && { cvs -Q -d $$(cat CVS/Root) checkout common && echo "common/Makefile.common" ; } || { echo "ERROR: I can't figure out how to checkout the 'common' module." ; exit -1 ; } >&2
endef

MAKEFILE_COMMON := $(shell $(checkout-makefile-common))
endif

include $(MAKEFILE_COMMON)
include Makefile.config

internal_release := $(shell rpm $(RPM_DEFINES) -q --qf "%{RELEASE}\n" --specfile $(DETAILED_SPEC) | head -1)

FULL_TARBALL := linux-$(VERSION)-$(internal_release).tar.bz2

extremedebug:
	@perl -pi -e 's/# CONFIG_DEBUG_PAGEALLOC is not set/CONFIG_DEBUG_PAGEALLOC=y/' config-nodebug

debug:
	@perl -pi -e 's/# CONFIG_SLUB_DEBUG_ON is not set/CONFIG_SLUB_DEBUG_ON=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_LOCK_STAT is not set/CONFIG_LOCK_STAT=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_DEBUG_STACK_USAGE is not set/CONFIG_DEBUG_STACK_USAGE=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_DEBUG_SLAB is not set/CONFIG_DEBUG_SLAB=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_DEBUG_MUTEXES is not set/CONFIG_DEBUG_MUTEXES=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_DEBUG_RT_MUTEXES is not set/CONFIG_DEBUG_RT_MUTEXES=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_DEBUG_RWSEMS is not set/CONFIG_DEBUG_RWSEMS=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_DEBUG_LOCK_ALLOC is not set/CONFIG_DEBUG_LOCK_ALLOC=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_PROVE_LOCKING is not set/CONFIG_PROVE_LOCKING=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_DEBUG_SPINLOCK is not set/CONFIG_DEBUG_SPINLOCK=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_DEBUG_VM is not set/CONFIG_DEBUG_VM=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_DEBUG_SLEEP_IN_IRQ is not set/CONFIG_DEBUG_SLEEP_IN_IRQ=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_FAULT_INJECTION is not set/CONFIG_FAULT_INJECTION=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_FAILSLAB is not set/CONFIG_FAILSLAB=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_FAIL_PAGE_ALLOC is not set/CONFIG_FAIL_PAGE_ALLOC=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_FAIL_MAKE_REQUEST is not set/CONFIG_FAIL_MAKE_REQUEST=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_FAULT_INJECTION_DEBUG_FS is not set/CONFIG_FAULT_INJECTION_DEBUG_FS=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_FAULT_INJECTION_STACKTRACE_FILTER is not set/CONFIG_FAULT_INJECTION_STACKTRACE_FILTER=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_DEBUG_SG is not set/CONFIG_DEBUG_SG=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_DEBUG_WRITECOUNT is not set/CONFIG_DEBUG_WRITECOUNT=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_DEBUG_OBJECTS is not set/CONFIG_DEBUG_OBJECTS=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_DEBUG_OBJECTS_FREE is not set/CONFIG_DEBUG_OBJECTS_FREE=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_DEBUG_OBJECTS_TIMERS is not set/CONFIG_DEBUG_OBJECTS_TIMERS=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_X86_PTDUMP is not set/CONFIG_X86_PTDUMP=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_CAN_DEBUG_DEVICES is not set/CONFIG_CAN_DEBUG_DEVICES=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_MODULE_FORCE_UNLOAD is not set/CONFIG_MODULE_FORCE_UNLOAD=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_SYSCTL_SYSCALL_CHECK is not set/CONFIG_SYSCTL_SYSCALL_CHECK=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_DEBUG_NOTIFIERS is not set/CONFIG_DEBUG_NOTIFIERS=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_DMA_API_DEBUG is not set/CONFIG_DMA_API_DEBUG=y/' config-nodebug
	@perl -pi -e 's/# CONFIG_PM_TEST_SUSPEND is not set/CONFIG_PM_TEST_SUSPEND=y/' config-generic
	@perl -pi -e 's/# CONFIG_BOOT_TRACER is not set/CONFIG_BOOT_TRACER=y/' config-generic
	@perl -pi -e 's/# CONFIG_PCI_MSI_DEFAULT_ON is not set/CONFIG_PCI_MSI_DEFAULT_ON=y/' config-generic
	@perl -pi -e 's/# CONFIG_B43_DEBUG is not set/CONFIG_B43_DEBUG=y/' config-generic
	@perl -pi -e 's/# CONFIG_B43LEGACY_DEBUG is not set/CONFIG_B43LEGACY_DEBUG=y/' config-generic
	@perl -pi -e 's/# CONFIG_MMIOTRACE is not set/CONFIG_MMIOTRACE=y/' config-nodebug
	@perl -pi -e 's/CONFIG_STRIP_ASM_SYMS=y/# CONFIG_STRIP_ASM_SYMS is not set/' config-nodebug

	@# just in case we're going from extremedebug -> debug
	@perl -pi -e 's/CONFIG_DEBUG_PAGEALLOC=y/# CONFIG_DEBUG_PAGEALLOC is not set/' config-nodebug

	@perl -pi -e 's/^%define debugbuildsenabled 1/%define debugbuildsenabled 0/' kernel.spec
	@perl -pi -e 's/CONFIG_NR_CPUS=64/CONFIG_NR_CPUS=512/' config-x86_64-generic

release:
	@perl -pi -e 's/CONFIG_SLUB_DEBUG_ON=y/# CONFIG_SLUB_DEBUG_ON is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_LOCK_STAT=y/# CONFIG_LOCK_STAT is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_DEBUG_STACK_USAGE=y/# CONFIG_DEBUG_STACK_USAGE is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_DEBUG_SLAB=y/# CONFIG_DEBUG_SLAB is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_DEBUG_MUTEXES=y/# CONFIG_DEBUG_MUTEXES is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_DEBUG_RT_MUTEXES=y/# CONFIG_DEBUG_RT_MUTEXES is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_DEBUG_RWSEMS=y/# CONFIG_DEBUG_RWSEMS is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_DEBUG_LOCK_ALLOC=y/# CONFIG_DEBUG_LOCK_ALLOC is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_PROVE_LOCKING=y/# CONFIG_PROVE_LOCKING is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_DEBUG_SPINLOCK=y/# CONFIG_DEBUG_SPINLOCK is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_DEBUG_PAGEALLOC=y/# CONFIG_DEBUG_PAGEALLOC is not set/' config-debug
	@perl -pi -e 's/CONFIG_DEBUG_PAGEALLOC=y/# CONFIG_DEBUG_PAGEALLOC is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_DEBUG_VM=y/# CONFIG_DEBUG_VM is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_DEBUG_SLEEP_IN_IRQ=y/# CONFIG_DEBUG_SLEEP_IN_IRQ is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_FAULT_INJECTION=y/# CONFIG_FAULT_INJECTION is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_FAILSLAB=y/# CONFIG_FAILSLAB is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_FAIL_PAGE_ALLOC=y/# CONFIG_FAIL_PAGE_ALLOC is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_FAIL_MAKE_REQUEST=y/# CONFIG_FAIL_MAKE_REQUEST is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_FAULT_INJECTION_DEBUG_FS=y/# CONFIG_FAULT_INJECTION_DEBUG_FS is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_FAULT_INJECTION_STACKTRACE_FILTER=y/# CONFIG_FAULT_INJECTION_STACKTRACE_FILTER is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_DEBUG_SG=y/# CONFIG_DEBUG_SG is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_DEBUG_WRITECOUNT=y/# CONFIG_DEBUG_WRITECOUNT is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_DEBUG_OBJECTS=y/# CONFIG_DEBUG_OBJECTS is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_DEBUG_OBJECTS_FREE=y/# CONFIG_DEBUG_OBJECTS_FREE is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_DEBUG_OBJECTS_TIMERS=y/# CONFIG_DEBUG_OBJECTS_TIMERS is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_X86_PTDUMP=y/# CONFIG_X86_PTDUMP is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_CAN_DEBUG_DEVICES=y/# CONFIG_CAN_DEBUG_DEVICES is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_MODULE_FORCE_UNLOAD=y/# CONFIG_MODULE_FORCE_UNLOAD is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_SYSCTL_SYSCALL_CHECK=y/# CONFIG_SYSCTL_SYSCALL_CHECK is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_DEBUG_NOTIFIERS=y/# CONFIG_DEBUG_NOTIFIERS is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_DMA_API_DEBUG=y/# CONFIG_DMA_API_DEBUG is not set/' config-nodebug
	@perl -pi -e 's/CONFIG_PM_TEST_SUSPEND=y/#\ CONFIG_PM_TEST_SUSPEND\ is\ not\ set/' config-generic
	@perl -pi -e 's/CONFIG_BOOT_TRACER=y/#\ CONFIG_BOOT_TRACER\ is\ not\ set/' config-generic
	@perl -pi -e 's/CONFIG_PCI_MSI_DEFAULT_ON=y/# CONFIG_PCI_MSI_DEFAULT_ON is not set/' config-generic
	@perl -pi -e 's/CONFIG_B43_DEBUG=y/# CONFIG_B43_DEBUG is not set/' config-generic
	@perl -pi -e 's/CONFIG_B43LEGACY_DEBUG=y/# CONFIG_B43LEGACY_DEBUG is not set/' config-generic
	@perl -pi -e 's/CONFIG_MMIOTRACE=y/# CONFIG_MMIOTRACE is not set/' config-nodebug
	@perl -pi -e 's/# CONFIG_STRIP_ASM_SYMS is not set/CONFIG_STRIP_ASM_SYMS=y/' config-nodebug

	@perl -pi -e 's/CONFIG_NR_CPUS=512/CONFIG_NR_CPUS=64/' config-x86_64-generic

	@perl -pi -e 's/^%define debugbuildsenabled 0/%define debugbuildsenabled 1/' kernel.spec
	@perl -pi -e 's/^%define rawhide_skip_docs 1/%define rawhide_skip_docs 0/' kernel.spec

rhel:
	@perl -pi -e 's/# CONFIG_PPC_64K_PAGES is not set/CONFIG_PPC_64K_PAGES=y/' config-powerpc64
	@perl -pi -e 's/CONFIG_NR_CPUS=64/CONFIG_NR_CPUS=512/' config-x86_64-generic

P_BRANCH := private-$(PRIVATE)-branch
P_TAG := $(shell echo $(PRIVATE) | sed s/-/_/g)
P_BASE := $(shell test -n "$(BASE)" && echo "-r $(BASE)")
CWD := $(shell basename `pwd`)

private:
	@if [ -z "$(PRIVATE)" ]; then \
		echo "Please specify a PRIVATE branch name"; \
		echo "see 'make help' for more info"; \
		exit 1; \
	fi;
	@if [ -z "$$(cvs log -h Makefile | grep $(P_BRANCH))" ]; then \
		scripts/ktags $(P_BASE) -b $(P_BRANCH); \
	fi;
	@cd ..; cvs co -r $(P_BRANCH) -d tmp kernel/$(CWD)
	@mv ../tmp/$(CWD) ../$(CWD).$(PRIVATE)
	@cd ../$(CWD).$(PRIVATE); \
	if [ ! "$$(grep $(P_TAG) $(SPECFILE))" ]; then \
		sed -i 's/^#% define buildid.*/%define buildid '".$(P_TAG)"'.1/g' \
			$(SPECFILE); \
	fi;

ifeq ($(MAKECMDGOALS),help)
help:
	@make -f ../common/Makefile.common -s NAME=$(NAME) SPECFILE=$(SPECFILE) help
	@echo
	@echo "Kernel targets are:"
	@echo "	private			Create a private branch in a separate directory"
	@echo "			example: make PRIVATE=bz1234 private"
	@echo "			Branches and creates a private ../$(CWD).bz1234"
	@echo "			example: make PRIVATE=bz1234 BASE=kernel-2_6_32-1_el6 private"
	@echo "			Branches off tag 'kernel-2_6_32-1_el6' and creates"
	@echo "					a private ../$(CWD).bz1234"
	@echo " update-spec		Updates the main spec and the single tarball file using $(DETAILED_SPEC)"
	@echo " full-srpm		Creates the detailed SRPM with individual patches"
	@echo " tarball-upload		Uploads $(FULL_TARBALL) and updates sources file"
	@echo
endif

# if a detailed spec file is used, warn about the 
# grabs the full spec file and updates the official (and reduced) spec file
update-spec:
	@# updating the tarball
	@make SPECFILE=$(DETAILED_SPEC) prep
	@(cd kernel-$(VERSION)/; \
	  mv linux-$(VERSION)-$(internal_release).noarch/ linux-$(VERSION)-$(internal_release)/; \
	  cd linux-$(VERSION)-$(internal_release)/; \
	  make mrproper; \
	  rm -Rf configs *.config config-* perf check-kabi *.pub *.pub~ *.sec merge.pl *.gpg temp-* .gitignore crypto/signature/key.h random_seed; \
	  cd ../; \
	  tar cfj ../$(FULL_TARBALL) linux-$(VERSION)-$(internal_release)/)
	@# updating the spec
	@cat $(DETAILED_SPEC) | \
		sed -e "/Patch:/,/^$$/d; /^ApplyPatch\ /,/^$$/d" | \
		sed -e "s,%define\ kversion\ 2.6.%{base_sublevel},%define\ kversion\ $(VERSION)-$(internal_release)," | \
		sed -e "s,linux-2.6.32.tar.bz2,$(FULL_TARBALL),">$(DEFAULT_SPEC);
	@make update-ksb-spec
	@md5sum linux-$(VERSION).tar.bz2 >sources;
	@echo -e "\nDon't forget to upload the new patch file with 'make tarball-upload'"

full-srpm:
	@# here we copy the detailed spec to a .spec file. We don't keep this
	@# one around to avoid confusion of having two .spec files
	@cp $(DETAILED_SPEC) $(DETAILED_TEMP_SPEC);
	@make SPECFILE=$(DETAILED_TEMP_SPEC) test-srpm
	@rm -f $(DETAILED_TEMP_SPEC);
	@echo "*** DO NOT distribute this SRPM ***"

update-ksb-spec:
	@# KSB needs a 6.0GA (-71) tarball and individual patches after that
	@echo "Updating KSB spec file"
	@cat $(DETAILED_SPEC) | \
		sed -e "/^Patch:\ /,/^Patch3807:\ /d" | \
		sed -e "/^ApplyPatch\ Fedora-redhat-introduce-nonint_oldconfig-target.patch/,/^ApplyPatch\ fs-nfsd-initialize-nfsd-versions-before-creating-svc.patch/d" | \
		sed -e "s,%define\ kversion\ 2.6.%{base_sublevel},%define\ kversion\ $(VERSION)-71.el6," | \
		sed -e "s,linux-2.6.32.tar.bz2,linux-2.6.32-71.el6.tar.bz2,">$(KSB_SPEC);

$(KSB_SPEC):
	@make update-ksb-spec;

ksb-srpm: $(KSB_SPEC)
	@if [ -z "`grep 2.6.32-71 sources`" ]; then\
		echo "c761eb05631f8ce888fd361883324d9c  linux-2.6.32-71.el6.tar.bz2" >>sources; \
	fi
	@cp $(KSB_SPEC) $(KSB_TEMP_SPEC);
	@make SPECFILE=$(KSB_TEMP_SPEC) test-srpm;
	@rm -f $(KSB_TEMP_SPEC);
	@echo "*** DO NOT distribute this SRPM ***";

tarball-upload:
	@make FILES=$(FULL_TARBALL) upload

reconfig:
	@rm -f kernel-*-config
	@VERSION="2.6.30" make -f Makefile.config configs
	@scripts/reconfig.sh

unused-kernel-patches:
	@for f in *.patch; do if [ -e $$f ]; then (egrep -q "^Patch[[:digit:]]+:[[:space:]]+$$f" $(SPECFILE) || echo "Unused:    $$f") && egrep -q "^ApplyPatch[[:space:]]+$$f|^ApplyOptionalPatch[[:space:]]+$$f" $(SPECFILE) || echo "Unapplied: $$f"; fi; done

# since i386 isn't a target...
compile compile-short: DIST_DEFINES += --target $(shell uname -m)

# 'make local' also needs to build the noarch firmware package
local: noarch

#
# Hacks for building vanilla (unpatched) kernel rpms.
# Use "make vanilla-TARGET" like "make TARGET" (make vanilla-scratch-build).
#
vanilla-%: $(SPECFILE:.spec=-vanilla.spec)
	@$(MAKE) $* SPECFILE=$<

$(SPECFILE:.spec=-vanilla.spec): $(SPECFILE)
	@rm -f $@
	(echo %define nopatches 1; cat $<) > $@

#scratch-build: NAME = $(shell rpm $(RPM_DEFINES) $(DIST_DEFINES) -q --qf "%{NAME}\n" --specfile $(SPECFILE)| head -1)
#scratch-build: test-srpm
#	$(BUILD_CLIENT) build $(BUILD_FLAGS) --scratch $(TARGET) \
#			$(SRCRPMDIR)/$(NAME)-$(VERSION)-$(RELEASE).src.rpm

# Dismal kludge for building via brew from cvs after "make vanilla-tag".
ifdef BEEHIVE_SRPM_BUILD
export CHECKOUT_TAG ?= $(shell sed s/^.// CVS/Tag)
tag-pattern = $(TAG_NAME)-$(TAG_VERSION)-0_%_$(TAG_RELEASE)
ifeq (,$(filter-out $(tag-pattern),$(CHECKOUT_TAG)))
variant := $(patsubst $(tag-pattern),%,$(CHECKOUT_TAG))
srpm: SPECFILE := $(wildcard $(SPECFILE:.spec=-$(variant).spec) \
			     $(SPECFILE:.spec=.t.$(variant).spec))
srpm beehive-sprm: RELEASE := 0.$(variant).$(RELEASE)
endif
endif

ifndef KVERSION
KVERSION := $(shell awk '$$1 == "%define" && $$2 == "base_sublevel" { \
				print "2.6." $$3 \
			 }' $(SPECFILE))
endif

#
# Hacks for building kernel rpms from upstream code plus local GIT branches.
# Use "make git/BRANCH/TARGET" like "make TARGET".
# Use "make git/BRANCH-fedora/TARGET" to include Fedora patches on top.
#
ifndef GIT_SPEC
git/%:
	@$(MAKE) GIT_SPEC=$(subst /,-,$(*D)) git-$(*F)
else
git-%: $(SPECFILE:.spec=.t.$(GIT_SPEC).spec)
	@$(MAKE) GIT_SPEC= $* SPECFILE=$<
endif

#
# Your git-branches.mk file can define GIT_DIR, e.g.:
#	GIT_DIR = ${HOME}/kernel/.git
# Make sure GIT_AUTHOR_NAME and GIT_AUTHOR_EMAIL are also set
# or your rpm changelogs will look like crap.
#
# For each branch it can define a variable branch-BRANCH or tag-BRANCH
# giving the parent of BRANCH to diff against in a separate patch.  If
# the parent is unknown, it will use $(branch-upstream) defaulting to
# "refs/remotes/upstream/master".
#
# Defining tag-BRANCH means the tag corresponds to an upstream patch in
# the sources file, so that is used instead of generating a patch with
# git.  If there is no tag-upstream defined, it will figure out a vNNN
# tag or vNNN-gitN pseudo-tag from the last patch in the sources file.
# For example:
#	tag-some-hacks = v2.6.21-rc5
#	branch-more-hacks = some-hacks
# Leads to patches:
#	git diff v2.6.21-rc5..more-hacks > linux-2.6.21-rc5-some-hacks.patch
#	git diff some-hacks..more-hacks > linux-2.6.21-rc5-more-hacks.patch
# Whereas having no git-branches.mk at all but doing
# "make GIT_DIR=... git/mybranch/test-srpm" does:
#	id=`cat patch-2.6.21-rc5-git4.id` # auto-fetched via upstream file
#	git diff $id..upstream > linux-2.6.21-rc5-git4-upstream.patch
#	git diff upstream..mybranch > linux-2.6.21-rc5-git4-mybranch.patch
# If the upstream patch (or any branch patch) is empty it's left out.
#
git-branches.mk:;
-include git-branches.mk

branch-upstream ?= refs/remotes/upstream/master

ifdef GIT_DIR
export GIT_DIR
export GIT_AUTHOR_NAME
export GIT_AUTHOR_EMAIL
gen-patches ?= gen-patches

ifndef havespec
$(SPECFILE:.spec=.t.%-fedora.spec): $(SPECFILE) $(gen-patches) FORCE
	./$(gen-patches) --fedora < $< > $@ $(gen-patches-args)
$(SPECFILE:.spec=.t.%.spec): $(SPECFILE) $(gen-patches) FORCE
	./$(gen-patches) < $< > $@ $(gen-patches-args)
.PRECIOUS: $(SPECFILE:.spec=.t.%.spec) $(SPECFILE:.spec=.t.%-fedora.spec)
endif

spec-%: $(SPECFILE:.spec=.t.%.spec) ;
$(SPECFILE):;
FORCE:;

branch-of-* = $(firstword $(head-$*) $*)
gen-patches-args = --name $* v$(KVERSION) $(call heads,$(branch-of-*))
define heads
$(if $(tag-$1),$(filter-out v$(KVERSION),$(tag-$1)),\
     $(call heads,$(firstword $(branch-$1) $(branch-upstream)))) $1
endef

files-%-fedora:
	@echo $(SPECFILE:.spec=.t.$*-fedora.spec)
	@$(call list-patches,$(branch-of-*))
files-%:
	@echo $(SPECFILE:.spec=.t.$*.spec)
	@$(call list-patches,$(branch-of-*))
define list-patches
$(if $(tag-$1),version=$(patsubst v%,%,$(tag-$1)),\
     $(call list-patches,$(firstword $(branch-$1) $(branch-upstream)))); \
echo linux-$${version}-$(patsubst refs/remotes/%/master,%,$1).patch
endef

ifndef tag-$(branch-upstream)
tag-$(branch-upstream) := $(shell \
	sed -n 's/^.*  *//;s/\.bz2$$//;s/patch-/v/;/^v/h;$${g;p}' sources)
endif
endif
