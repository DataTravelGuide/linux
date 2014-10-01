include Makefile.common
include Makefile.test

LOCVERFILE:=../localversion
LANG=C
BUILD_DEFAULT_TARGET = RHEL-6-test
BUILD_SCRATCH_TARGET = RHEL-6-test

TOPDIR:=$(shell dirname $(REDHAT))

#ifeq ($(shell git diff --quiet HEAD && git describe --exact-match 2>/dev/null && echo ok),)
BUILD_TARGET ?= --scratch $(BUILD_SCRATCH_TARGET)
#else
#BUILD_TARGET ?= $(BUILD_DEFAULT_TARGET)
#endif

RELEASE:=$(shell sed -ne 's/^[^\#]*define release \(.*\)%.*%.*/\1/p' $(REDHAT)/$(SPECFILE).template)
DIST:=.el6

# create an empty localversion file if you don't want a local buildid
ifneq ($(wildcard $(LOCVERFILE)),)
BUILDID:=$(shell cat $(LOCVERFILE))
else
BUILDID:=.test
endif
$(info BUILDID is "$(BUILDID)". Update '$(TOPDIR)/localversion' to change.)

#deal with build options.  Support for command line is due to koji support
BUILD_OPTIONS:=
BO_SINGLE_TARBALL :=
BO_QUICK_BUILD :=

#grab the command line build options
ifeq ("$(origin S)", "command line")
  BO_SINGLE_TARBALL := $(S)
endif
ifeq ("$(origin F)", "command line")
  BO_QUICK_BUILD := $(F)
endif

#filter out the builds with build options to re-use code
ifneq ($(filter rh-cross-% rh-brew-scratch,$(MAKECMDGOALS)),)
  BO_SINGLE_TARBALL := 1
  BO_QUICK_BUILD := 1
endif

#set the build options
TARFILE:=linux-$(KVERSION).tar.bz2
ifeq ($(BO_SINGLE_TARBALL),1)
  BUILD_OPTIONS += S
  CMARKER=$(LASTCOMMIT)
  LASTHASH:=$(shell git rev-parse --verify --short $(LASTCOMMIT))
  TARFILE:=linux-$(KVERSION).$(LASTHASH).tar.bz2
endif
ifeq ($(BO_QUICK_BUILD),1)
  BUILD_OPTIONS += Q
endif
TARBALL:=$(REDHAT)/$(TARFILE)

#we assume most users push to a seperate repo than they read
#and that repo is on the git.engineering website
RHGITPUSHURL:=$(shell git config remote.origin.pushurl | sed 's/+ssh//;s,//[a-zA-Z0-9]*@,//,;s,/srv/git,,')
RHGITURL:=$(shell git config rhg.url || git config remote.origin.url)
RHVALIDURL:=
ifneq ("$(RHGITPUSHURL)", "")
  ifneq ("$(shell echo "$(RHGITPUSHURL)" | grep -E '^git://git[2]?\.engineering\.redhat\.com')", "")
    RHVALIDURL = $(RHGITPUSHURL)
  endif
else
  ifneq ("$(shell echo "$(RHGITURL)" | grep -E '^git://git[2]?\.engineering\.redhat\.com')", "")
    RHVALIDURL = $(RHGITURL)
  endif
endif

RHGITCOMMIT=$(shell git log -1 --pretty=format:%H)
RHDISTGIT_USER:="$(shell whoami)"
RHDISTGIT:="ssh://$(RHDISTGIT_USER)@pkgs.devel.redhat.com/rpms/kernel"

# variables that can be overrided by ~/.rhel6git.mk or $(TOPDIR)/.rhel6git.mk
#
# Local dist-git _clean_ clone. To be used when updating dist-git
#RHDISTGIT_CACHE:=
# Temporary directory to clone the dist-git repo to. Change this if you 
# have a faster storage
RHDISTGIT_TMP:=/tmp
# Branch it should be switched into
# RHDISTGIT_BRANCH:=rhel-6.4

# load configuration, starting with home directory then local
ifeq ("$(RHDISTGIT_CACHE)", "")
 ifneq ("$(wildcard ${HOME}/.rhel6git.mk)", "")
  include ${HOME}/.rhel6git.mk
 endif
 ifneq ("$(wildcard $(TOPDIR)/.rhel6git.mk)", "")
  include $(TOPDIR)/.rhel6git.mk
 endif
endif

# this section is needed in order to make O= to work
_OUTPUT := ..
ifeq ("$(origin O)", "command line")
  _OUTPUT := $(O)
  _EXTRA_ARGS := O=$(_OUTPUT)
endif

ARCHCONFIG := $(shell uname -m | sed -e s/x86_64/X86_64/ -e  s/i.86/X86/ \
				     -e s/s390x/S390/ -e s/ppc.*/PPC/ )

PATH := /opt/crosstool/gcc-glibc/s390x-unknown-linux-gnu/bin:${PATH}
PATH := /opt/crosstool/gcc-glibc/i686-unknown-linux-gnu/bin:${PATH}
PATH := /opt/crosstool/gcc-glibc/powerpc64-unknown-linux-gnu/bin:${PATH}

include Makefile.cross

default: rh-help

rh-check-kabi:
	@if [ ! -e $(REDHAT)/../Module.symvers ]; then \
		echo "ERROR: You must compile the kernel and modules first";\
		exit 1;\
	fi
	@$(REDHAT)/kabi/check-kabi -k $(REDHAT)/kabi/Module.kabi_$(MACH) \
	 -s $(REDHAT)/../Module.symvers

rh-configs:
	cd $(REDHAT)/configs; $(MAKE) VERSION=$(KVERSION) configs

rh-configs-prep:
	cd $(REDHAT)/configs; $(MAKE) VERSION=$(KVERSION) $(_EXTRA_ARGS) configs-prep

rh-configs-arch-prep:
	cd $(REDHAT)/configs; $(MAKE) VERSION=$(KVERSION) $(_EXTRA_ARGS) ARCHCONFIG=$(ARCHCONFIG) configs-prep

rh-clean-configs:
	cd $(REDHAT)/configs; $(MAKE) VERSION=$(KVERSION) clean

rh-clean-sources:
	@find $(SOURCES) -mindepth 1 ! -name ".gitignore" -delete

rh-clean-rpmdirs:
	@for i in $(RPM)/{BUILD,SRPMS,RPMS,SPECS}/*; do \
		rm -rf $$i; \
	done;

rh-clean-tarballs:
	@rm -f $(REDHAT)/linux-2.6.32.*.tar.bz2

rh-clean: rh-clean-sources rh-clean-configs rh-clean-rpmdirs rh-clean-tarballs

rh-pull-configs:
	cd $(REDHAT)/configs; $(MAKE) VERSION=$(KVERSION) pull-configs

rh-key:
	@echo "Creating a new module signing key...";
	@cd $(_OUTPUT); \
	/sbin/rngd -r /dev/urandom; \
	gpg --homedir . --batch --gen-key $(REDHAT)/genkey; \
	if [ -s $(REDHAT)/extrakeys.pub ]; then \
		gpg --homedir . --no-default-keyring --keyring kernel.pub --import $(REDHAT)/extrakeys.pub; \
	fi; \
	gpg --homedir . --export --keyring kernel.pub Red > extract.pub; \
	mkdir -p crypto/signature/ scripts/; \
	gcc -o scripts/bin2c $(REDHAT)/../scripts/bin2c.c; \
	scripts/bin2c ksign_def_public_key __initdata < extract.pub >crypto/signature/key.h;

rh-stub-key:
	@echo "Copying pre-generated keys";
	@echo "*** THIS IS NOT RECOMMENDED ***";
	@echo "To be safe, keys should be created once for every build";
	@echo "Use this option only for development builds";
	@cp keys/*.{pub,sec,gpg} $(_OUTPUT)/;
	@mkdir -p $(_OUTPUT)/crypto/signature/;
	@cp keys/key.h $(_OUTPUT)/crypto/signature/;

rh-create-tarball:
	@#save last 3 tarballs
	@if [ -n "$(findstring S, $(BUILD_OPTIONS))" ]; then \
		let j=1; \
		for i in $(shell ls -t linux-$(KVERSION).*.tar.bz2 2> /dev/null); do \
			if [ $$j -gt 3 ]; then \
				echo "removing stale $$i"; \
				rm $$i; \
			fi; \
			let j=$$j+1; \
		done; \
	fi

	@#verify 2.6.32 cached tarball matches checksum
	@if [ -f linux-$(KVERSION).tar.bz2 -a \
	     "$(shell md5sum linux-$(KVERSION).tar.bz2)" != \
	     "$(shell cat sources|grep linux-$(KVERSION).tar.bz)" ]; then \
		echo "Bad cached linux-$(KVERSION).tar.bz2, removing"; \
		rm linux-$(KVERSION).tar.bz2; \
	fi

	@if [ ! -e $(TARBALL) ]; then \
		echo "Creating new archive $(TARBALL)"; \
		(cd ../; git archive --prefix=linux-$(KVERSION)/ --format=tar $(CMARKER) --worktree-attributes | bzip2 > $(TARBALL)); \
	fi

$(RC_PATCH):
	@if [ -n "$(RCREV)" ]; then \
		git diff v$(KVERSION)..v2.6.$(SUBLEVEL)-rc$(RCREV) | \
			bzip2 >$(REDHAT)/$(RC_PATCH); \
	fi

$(GIT_PATCH):
	@if [ -n "$(GITREV)" ]; then \
		git diff v2.6.$(SUBLEVEL)-rc$(RCREV)..$(MARKER) | \
			bzip2 >$(REDHAT)/$(GIT_PATCH); \
	fi

setup-source: rh-clean-sources
	@cp $(REDHAT)/$(SPECFILE).template $(SOURCES)/$(SPECFILE)

sources-rh: rh-create-tarball $(RC_PATCH) $(GIT_PATCH)
	@cp -l $(TARBALL) $(SOURCES)/ || cp $(TARBALL) $(SOURCES)/
	@(if [ -n "$(RCREV)" ]; then \
		cp $(RC_PATCH) $(SOURCES)/; \
	fi)
	@(if [ -n "$(GITREV)" ]; then \
		cp $(GIT_PATCH) $(SOURCES)/; \
	fi)
	@touch $(TESTPATCH)
	@git diff --no-renames HEAD > $(TESTPATCH).tmp
	@# 1) filterdiff will return crap from the patches it just filtered,
	@#    that's why egrep is needed so if there're changes under redhat/
	@#    but not everywhere else, it will be empty just like
	@#    linux-kernel-test.patch
	@# 2) egrep -v will return "1" if it sucessfully removed index and diff
	@#    lines, which will be considered an error
	@($(FILTERDIFF) $(TESTPATCH).tmp | egrep -v "^index|^diff" >$(TESTPATCH).tmp2; true)
	@mv $(TESTPATCH).tmp2 $(TESTPATCH).tmp
	@diff $(TESTPATCH).tmp $(TESTPATCH) > /dev/null || \
		echo "WARNING: There are uncommitted changes in your tree or the changes are not in sync with the kernel-test.patch.  Either commit the changes or run 'make rh-test-patch'"
	@rm $(TESTPATCH).tmp
	@$(REDHAT)/create-patches.sh $(MARKER) $(SOURCES) $(SOURCES)/$(SPECFILE) $(BUILD) "$(BUILDID)" "$(BUILD_OPTIONS)" "$(TARFILE)"
	@cp $(SOURCES)/$(SPECFILE) $(SOURCES)/../SPECS
	@cp $(TESTPATCH) $(SOURCES)/linux-kernel-test.patch
	@cp configs/Makefile $(SOURCES)/Makefile.config
	@# if the extrakeys.pub doesn't exist, create a empty one
	@(if [ ! -f extrakeys.pub ]; then \
		touch extrakeys.pub; \
	fi)
	@cp genkey perf perf-archive Makefile.common kabi/{find-provides,kabitool,check-kabi} \
	kabi/Module.kabi_{i686,ppc64,s390x,x86_64} kabi/Module.kabi_greylist_{i686,ppc64,s390x,x86_64}  \
	configs/{config-*,merge.pl} extrakeys.pub tests/submit-beaker-test.sh cvs/Makefile $(SOURCES)/
	@(cd kabi && \
	git archive --format=tar HEAD kabi-rhel6* | \
	bzip2 > $(SOURCES)/kernel-abi-whitelists-$(BUILD).tar.bz2)

rh-sources: setup-source sources-rh

rh-test-patch:
	@git diff --no-renames HEAD > $(TESTPATCH);
	@($(FILTERDIFF) $(TESTPATCH) | egrep -v "^index|^diff" >$(TESTPATCH).tmp; true)
	@mv $(TESTPATCH).tmp $(TESTPATCH);

rh-all-rpms: rh-sources
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --target $(MACH) -ba $(RPM)/SOURCES/kernel.spec

rh-srpm: rh-sources
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --nodeps -bs $(RPM)/SOURCES/kernel.spec

rh-rpms: rh-sources
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --target $(MACH) --target noarch -bb $(RPM)/SOURCES/kernel.spec

rh-kernel-%: rh-sources
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --target $(MACH) --with $* --without vdso_install --with firmware -bb $(RPM)/SOURCES/kernel.spec

rh-prep: rh-sources
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --nodeps --target noarch -bp $(RPM)/SOURCES/kernel.spec

rh-perf: rh-sources
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --without up --without smp --without kdump --without debug --without doc --without headers --without  --without doc --without firmware --without debuginfo --target $(MACH) -bb $(RPM)/SOURCES/kernel.spec

# unless you know what you're doing, you don't want to use the next two ones
rh-release: rh-clean-sources
	@$(REDHAT)/scripts/new_release.sh $(KVERSION) $(BUILD) $(REDHAT)
	@make rh-srpm
	@$(REDHAT)/scripts/update_changelog.sh $(KVERSION) $(shell echo $$[$(BUILD) + 1]) $(REDHAT) "$(STAMP_VERSION)-$(PREBUILD)$(shell echo $$[$(BUILD) + 1]).el6$(BUILDID)"
rh-release-commit:
	@echo "kernel-$(STAMP_VERSION)-$(PREBUILD)$(BUILD)$(BUILDID).el6" > $(REDHAT)/lastcommit
	@git commit -s ../Makefile Makefile.common kernel.spec.template $(REDHAT)/lastcommit -m "[redhat] tagging $(STAMP_VERSION)-$(PREBUILD)$(BUILD)$(BUILDID).el6"
	@git tag -a -m "kernel-$(STAMP_VERSION)-$(PREBUILD)$(BUILD)$(BUILDID).el6" kernel-$(STAMP_VERSION)-$(PREBUILD)$(BUILD)$(BUILDID).el6

.PHONY: rh-brew rh-koji
rh-brew : BUILD_FLAGS ?= $(BREW_FLAGS) $(TEST_FLAGS)
rh-koji : BUILD_FLAGS ?= $(KOJI_FLAGS) $(TEST_FLAGS)
rhg-brew: BUILD_FLAGS ?= $(BREW_FLAGS) $(TEST_FLAGS)
rhg-koji: BUILD_FLAGS ?= $(KOJI_FLAGS) $(TEST_FLAGS)

rh-brew rh-koji: rh-%: rh-srpm
	$* build $(BUILD_FLAGS) $(BUILD_TARGET) $(SRPMS)/kernel-$(KVERSION)-$(BUILD)$(DIST)$(BUILDID).src.rpm $(OUTPUT_FILE)

rh-brew-scratch rh-koji-scratch: rh-%-scratch: rh-%

rh-rpms-scratch rh-srpm-scratch: rh-%-scratch: rh-%
	@#clean up for a possible follow up non-scratch build
	@rm -rf $(TARBALL) $(RPM)/BUILD/kernel-2.6.32/vanilla-2.6.32

BKR_REPO=http://download.lab.bos.redhat.com/beakerrepos/beaker-client-RedHatEnterpriseLinux.repo
rh-bkr-download:
ifeq ($(shell whoami), root)
	@yum -y --config=$(BKR_REPO) install beaker-client
else
	@rpm -q beaker-client > /dev/null || echo "run \"make rh-bkr-download\" as root."
endif

rhg-valid-url-check:
ifeq ("$(RHVALIDURL)", "")
		@echo "The rhg-brew target requires a valid git remote config option in the form:"
		@echo "  git://git.engineering.redhat.com.*"
		@echo "Please update your git config to reflect this"
		@echo "Current pushurl -> $(RHGITPUSHURL)"
		@echo "Current url -> $(RHGITURL)"
		@echo
		@echo "You can specify the git remote.origin.pushurl option to do this (safest):"
		@echo "(this does _not_ disturb the normal rhel6 master repo mechanism)"
		@echo "  git config remote.origin.pushurl <git+ssh eng redhat url>"
		@echo
		@echo "Or to use orgin as read/write make sure it points to a valid"
		@echo "git.engineering.redhat.com url"
		@echo "  git config remote.origin.url <git eng redhat url>"
		@exit 1
endif

KOJIDIR=redhat/koji
rhg-brew rhg-koji: rhg-%: rhg-valid-url-check
	$* build $(BUILD_FLAGS) --scratch RHEL-6-kernel-test "$(RHVALIDURL)?$(KOJIDIR)#$(RHGITCOMMIT)"

rhg-%-scratch: KOJIDIR=redhat/koji/scratch
rhg-brew-scratch rhg-koji-scratch: rhg-%-scratch: rhg-%

$(REDHAT)/rpm/SOURCES/kernel.spec:
	@echo "rh-sources"

	@$(MAKE) rh-sources

rh-dist-git: $(REDHAT)/rpm/SOURCES/kernel.spec
ifeq ("$(RHDISTGIT_BRANCH)", "")
	$(error RHDISTGIT_BRANCH unset)
endif
	$(REDHAT)/scripts/rh-dist-git.sh "$(RHDISTGIT_BRANCH)" "$(RHDISTGIT_CACHE)" "$(RHDISTGIT_TMP)" "$(RHDISTGIT)"


rh-help:
	@echo  'Cleaning targets:'
	@echo  '  rh-clean            - Do rh-clean-sources, rh-clean-configs, & rh-clean-rpmdirs'
	@echo  '  rh-clean-sources    - Clean the redhat/rpm/SOURCES/ directory'
	@echo  '  rh-clean-configs    - Clean the redhat/configs/ directory'
	@echo  '  rh-clean-rpmdirs    - Clean the redhat/rpm/{BUILD,SRPMS,RPMS,SPECS}/ directories'
	@echo  ''
	@echo  'Building targets:'
	@echo  ' All RPM/SRPM files will be put under the redhat/rpm/ directory'
	@echo  ''
	@echo  '  rh-srpm	- Create a source RPM and put it into the redhat/rpm/SRPMS/ directory'
	@echo  '  rh-brew	- Create a kernel SRPM and then call brew to build the created SRPM'
	@echo  '  rh-koji	- Create a kernel SRPM and then call koji to build the created SRPM'
	@echo  '  rhg-brew	- Pass a commit hash to brew to build an RPM set'
	@echo  '  rhg-koji	- Pass a commit hash to koji to build an RPM set'
	@echo  '  rh-srpm-scratch - Same as rh-srpm but bypass debuginfo and docs (for speed purposes)'
	@echo  '  rh-brew-scratch - Same as rh-brew but bypass debuginfo and docs (for speed purposes)'
	@echo  '  rh-koji-scratch - Same as rh-koji but bypass debuginfo and docs (for speed purposes)'
	@echo  '  rhg-brew-scratch - Same as rhg-brew but bypass debuginfo and docs (for speed purposes)'
	@echo  '  rhg-koji-scratch - Same as rhg-koji but bypass debuginfo and docs (for speed purposes)'
	@echo  '  rh-test	- Pass in brew task number, TASK=1234 make rh-test, to use for an RHTS test'
	@echo  '		  setup ./tests to use a test from redhat/tests (minus the .xml)'
	@echo  '		  uses a known stable RHEL6 distro as the default'
	@echo  '		  use TASK=None to use a non-scratch build based on RELEASE string'
	@echo  '		  see output for possible override options (USER_ID,DISTRO,FAMILY,..)'
	@echo  '  rh-brew-test  - Calls rh-brew and passes the task number into an RHTS test. See rh-test for more'
	@echo  '  rh-rpms	- Create the binary RPMS for the kernel'
	@echo  '  rh-rpms-scratch - Same as rh-rpms but bypass debuginfo and docs (for speed purposes)'
	@echo  '  rh-kernel-<type> - Create  binary RPMS for a particular kernel type'
	@echo  '                   - <type> can be: baseonly, smponly, dbgonly'

	@echo  '  rh-all-rpms	- Create the binary RPMS and the SRPM for the kernel'
	@echo  '  rh-prep	- Setup the redhat/rpm/BUILD/ directory with the kernel source'
	@echo  '  rh-test-patch - Create a diff against HEAD and put it in linux-kernel-test.patch.'
	@echo  '                  Then linux-kernel-test.patch will be added to the kernel build'
	@echo  '  rh-check-kabi - Run check-kabi script on a pre-compiled tree.'
	@echo  '  rh-key	- Generate the required files for compiling with module signing enabled'
	@echo  '  rh-stub-key	- Use pre generated keys to speed local test builds'
	@echo  '  rh-cross-download - [x86_64 only] download cross compiler rpms'
	@echo  '  rh-cross-all-builds - [x86_64 only] execute "rpmbuild -bc" for i686, s390x,'
	@echo  '			ppc64, x86_64 using RHEL cross compiler'
	@echo  '  rh-cross-[ARCH]-build - [x86_64 only] execute "rpmbuild -bc" for specified'
	@echo  '			  ARCH using RHEL cross compiler'
	@echo  '  rh-cross-all-rpms - [x86_64 only] execute rpm builds for i686, s390x,'
	@echo  '		      ppc64, x86_64 using RHEL cross compiler'
	@echo  '  rh-cross-[ARCH]-rpm - [x86_64 only] execute rpm builds for specified'
	@echo  '			ARCH using RHEL cross compiler'
	@echo  '  rh-cross-build-beaker - uses beaker to git clone and run rh-cross-all-build'
	@echo  '			  must "git push" changes first'
	@echo  ''
	@echo  'Configuration targets:'
	@echo
	@echo  '  rh-configs-prep - Creates config files for RHEL 6 architectures, cleans them'
	@echo  '		    by running make nonint_oldconfig, and copies them to'
	@echo  '		    configs/ directory. This is the target to use for a config!'
	@echo  '		    Copy the config file you want from the configs/ directory'
	@echo  '		    to .config'
	@echo  '  rh-configs-arch-prep - Executes rh-configs-prep for local architecture only '
	@echo  ''
	@echo  ' Most developers will NOT use the following config targets.'
	@echo  ' See the redhat/README file for more info'
	@echo  '  rh-configs	    Creates config files in the redhat/configs/ directory,'
	@echo  '		    these will be used by other Makefile targets and are not'
	@echo  '		    intended for developer use'
	@echo  '  rh-dist-git       Clones a dist-git repository and updates with the state of the tree'
	@echo  '                    See redhat/docs/rh-dist-git.txt for more information'
