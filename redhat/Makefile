include Makefile.common
include Makefile.test

LOCVERFILE:=../localversion
LANG=C
BUILD_DEFAULT_TARGET = RHEL-6-test
BUILD_SCRATCH_TARGET = RHEL-6-test

#ifeq ($(shell git diff --quiet HEAD && git describe --exact-match 2>/dev/null && echo ok),)
BUILD_TARGET ?= --scratch $(BUILD_SCRATCH_TARGET)
#else
#BUILD_TARGET ?= $(BUILD_DEFAULT_TARGET)
#endif

RELEASE:=$(shell sed -ne 's/^[^\#]*define release \(.*\)%.*%.*/\1/p' $(REDHAT)/$(SPECFILE).template)
DIST:=.el6

# create an empty localversion file if you don't want a local buildid
ifneq ($(wildcard $(LOCVERFILE)),)
LOCALVERSION:=$(shell cat $(LOCVERFILE))
else
LOCALVERSION:=test
endif
ifneq ($(LOCALVERSION),)
BUILDID:=.$(LOCALVERSION)
$(info BUILDID is "$(BUILDID)". Update '$(shell dirname $(REDHAT))/localversion' to change.)
endif

# this section is needed in order to make O= to work
_OUTPUT := ..
ifeq ("$(origin O)", "command line")
  _OUTPUT := $(O)
  _EXTRA_ARGS := O=$(_OUTPUT)
endif

default: rh-help

rh-configs:
	cd $(REDHAT)/configs; $(MAKE) VERSION=$(KVERSION) configs

rh-configs-prep:
	cd $(REDHAT)/configs; $(MAKE) VERSION=$(KVERSION) $(_EXTRA_ARGS) configs-prep

rh-clean-configs:
	cd $(REDHAT)/configs; $(MAKE) VERSION=$(KVERSION) clean

rh-clean-sources:
	@for i in $(SOURCES)/*; do \
		rm -f $$i; \
	done;

rh-pull-configs:
	cd $(REDHAT)/configs; $(MAKE) VERSION=$(KVERSION) pull-configs

rh-key:
	echo "Creating a new module signing key...";
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

$(TARBALL):
	@echo "Creating archive $(TARBALL)"
	(cd ../; \
	git archive --prefix=linux-$(KVERSION)/ --format=tar v$(KVERSION) | \
	bzip2 > $(TARBALL))

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

sources-rh: $(TARBALL) $(RC_PATCH) $(GIT_PATCH)
	@cp $(TARBALL) $(SOURCES)/
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
	@$(REDHAT)/create-patches.sh $(MARKER) $(SOURCES) $(SOURCES)/$(SPECFILE) $(BUILD) $(BUILDID)
	@cp $(SOURCES)/$(SPECFILE) $(SOURCES)/../SPECS
	@cp $(TESTPATCH) $(SOURCES)/linux-kernel-test.patch
	@cp configs/Makefile $(SOURCES)/Makefile.config
	@cp genkey perf Makefile.common kabi/{find-provides,kabitool,check-kabi} kabi/Module.kabi_{i686,ppc64,s390x,x86_64} configs/{config-*,merge.pl} extrakeys.pub $(SOURCES)/

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
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --target $(MACH) -bb $(RPM)/SOURCES/kernel.spec

rh-kernel-%: rh-sources
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --target $(MACH) --with $* --without vdso_install --with firmware -bb $(RPM)/SOURCES/kernel.spec

rh-prep: rh-sources
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --nodeps --target noarch -bp $(RPM)/SOURCES/kernel.spec

# unless you know what you're doing, you don't want to use the next two ones
rh-release: rh-clean-sources
	@$(REDHAT)/scripts/new_release.sh $(KVERSION) $(BUILD) $(REDHAT)
	@make rh-srpm
	@$(REDHAT)/scripts/update_changelog.sh $(KVERSION) $(shell echo $$[$(BUILD) + 1]) $(REDHAT) "$(STAMP_VERSION)-$(PREBUILD)$(shell echo $$[$(BUILD) + 1]).el6$(BUILDID)"
rh-release-commit:
	@git commit -s Makefile.common kernel.spec.template -m "[redhat] tagging $(STAMP_VERSION)-$(PREBUILD)$(BUILD)$(LOCALVERSION).el6"
	@git tag kernel-$(STAMP_VERSION)-$(PREBUILD)$(BUILD)$(LOCALVERSION).el6
	@git log --max-count=1 --pretty=format:%H >$(REDHAT)/lastcommit;
	@git commit -s lastcommit -m "[redhat] updating lastcommit for $(STAMP_VERSION)-$(PREBUILD)$(BUILD)$(LOCALVERSION)"

.PHONY: rh-brew rh-koji
rh-brew : BUILD_FLAGS ?= $(BREW_FLAGS) $(TEST_FLAGS)
rh-koji : BUILD_FLAGS ?= $(KOJI_FLAGS) $(TEST_FLAGS)
rh-brew rh-koji: rh-%: rh-srpm
	$* build $(BUILD_FLAGS) $(BUILD_TARGET) $(SRPMS)/kernel-$(KVERSION)-$(BUILD)$(DIST)$(BUILDID).src.rpm $(OUTPUT_FILE)

rh-help:
	@echo  'Cleaning targets:'
	@echo  '  rh-clean-sources    - Clean the redhat/rpm/SOURCES/ directory'
	@echo  '  rh-clean-configs    - Clean the redhat/configs/ directory'
	@echo  ''
	@echo  'Building targets:'
	@echo  ' All RPM/SRPM files will be put under the redhat/rpm/ directory'
	@echo  ''
	@echo  '  rh-srpm	- Create a source RPM and put it into the redhat/rpm/SRPMS/ directory'
	@echo  '  rh-brew	- Create a kernel SRPM and then call brew to build the created SRPM'
	@echo  '  rh-koji	- Create a kernel SRPM and then call koji to build the created SRPM'
	@echo  '  rh-test	- Pass in brew task number, TASK=1234 make rh-test, to use for an RHTS test'
	@echo  '		  setup ./tests to use a test from redhat/tests (minus the .xml)'
	@echo  '		  uses a known stable RHEL6 distro as the default'
	@echo  '		  use TASK=None to use a non-scratch build based on RELEASE string'
	@echo  '		  see output for possible override options (USER_ID,DISTRO,FAMILY,..)'
	@echo  '  rh-brew-test  - Calls rh-brew and passes the task number into an RHTS test. See rh-test for more'
	@echo  '  rh-rpms	- Create the binary RPMS for the kernel'
	@echo  '  rh-kernel-<type> - Create  binary RPMS for a particular kernel type'
	@echo  '                   - <type> can be: baseonly, smponly, dbgonly'

	@echo  '  rh-all-rpms	- Create the binary RPMS and the SRPM for the kernel'
	@echo  '  rh-prep	- Setup the redhat/rpm/BUILD/ directory with the kernel source'
	@echo  '  rh-test-patch - Create a diff against HEAD and put it in linux-kernel-test.patch.'
	@echo  '                  Then linux-kernel-test.patch will be added to the kernel build'
	@echo  '  rh-key	- Generate the required files for compiling with module signing enabled'
	@echo  ''
	@echo  'Configuration targets:'
	@echo
	@echo  '  rh-configs-prep   Creates config files for RHEL 6 architectures, cleans them'
	@echo  '		    by running make nonint_oldconfig, and copies them to'
	@echo  '		    configs/ directory. This is the target to use for a config!'
	@echo  '		    Copy the config file you want from the configs/ directory'
	@echo  '		    to .config'
	@echo  ''
	@echo  ' Most developers will NOT use the following config targets.'
	@echo  ' See the redhat/README file for more info'
	@echo  '  rh-configs	    Creates config files in the redhat/configs/ directory,'
	@echo  '		    these will be used by other Makefile targets and are not'
	@echo  '		    intended for developer use'
