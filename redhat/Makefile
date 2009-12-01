include Makefile.common

LOCVERFILE:=../localversion
LANG=C
BUILD_DEFAULT_TARGET = RHEL-6-alpha
BUILD_SCRATCH_TARGET = RHEL-6-alpha

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

default: rh-help

rh-configs:
	cd $(REDHAT)/configs; $(MAKE) VERSION=$(KVERSION) configs

rh-configs-prep:
	cd $(REDHAT)/configs; $(MAKE) VERSION=$(KVERSION) configs-prep

rh-clean-configs:
	cd $(REDHAT)/configs; $(MAKE) VERSION=$(KVERSION) clean

rh-clean-sources:
	@for i in $(SOURCES)/*; do \
		rm -f $$i; \
	done;

rh-pull-configs:
	cd $(REDHAT)/configs; $(MAKE) VERSION=$(KVERSION) pull-configs

rh-key:
	cd $(REDHAT)/../; \
	gpg --homedir . --batch --gen-key $(REDHAT)/genkey; \
	if [ -s $(REDHAT)/extrakeys.pub ]; then \
		gpg --homedir . --no-default-keyring --keyring kernel.pub --import $(REDHAT)/extrakeys.pub; \
	fi; \
	gpg --homedir . --export --keyring kernel.pub Red > extract.pub; \
	gcc -o scripts/bin2c scripts/bin2c.c; \
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
	@diff $(TESTPATCH).tmp $(TESTPATCH) > /dev/null || \
		echo "WARNING: There are uncommitted changes in your tree or the changes are not in sync with the kernel-test.patch.  Either commit the changes or run 'make rh-test-patch'"
	@rm $(TESTPATCH).tmp
	@$(REDHAT)/create-patches.sh $(MARKER) $(SOURCES) $(SOURCES)/$(SPECFILE) $(BUILD) $(BUILDID)
	@cp $(SOURCES)/$(SPECFILE) $(SOURCES)/../SPECS
	@cp $(TESTPATCH) $(SOURCES)/linux-kernel-test.patch
	@cp configs/Makefile $(SOURCES)/Makefile.config
	@cp genkey perf Makefile.common kabi/{find-provides,kabitool,check-kabi} configs/{config-*,merge.pl} extrakeys.pub $(SOURCES)/

rh-sources: setup-source sources-rh

rh-test-patch:
	git diff --no-renames HEAD > $(TESTPATCH)

rh-all-rpms: rh-sources
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --target $(MACH) -ba $(RPM)/SOURCES/kernel.spec

rh-srpm: rh-sources
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --nodeps -bs $(RPM)/SOURCES/kernel.spec

rh-rpms: rh-sources
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --target $(MACH) -bb $(RPM)/SOURCES/kernel.spec

rh-prep: rh-sources
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --nodeps --target noarch -bp $(RPM)/SOURCES/kernel.spec

# unless you know what you're doing, you don't want to use the next two ones
rh-release: rh-clean-sources
	@$(REDHAT)/scripts/new_release.sh $(KVERSION) $(BUILD) $(REDHAT)
	@make rh-srpm
	@$(REDHAT)/scripts/update_changelog.sh $(KVERSION) $(shell echo $$[$(BUILD) + 1]) $(REDHAT) "$(STAMP_VERSION)-$(PREBUILD)$(shell echo $$[$(BUILD) + 1])$(BUILDID).el6"
rh-release-commit:
	@git commit -s Makefile.common kernel.spec.template -m "[redhat] tagging $(STAMP_VERSION)-$(PREBUILD)$(BUILD)$(LOCALVERSION).el6"
	@git tag kernel-$(STAMP_VERSION)-$(PREBUILD)$(BUILD)$(LOCALVERSION).el6
	@git log --max-count=1 --pretty=format:%H >$(REDHAT)/lastcommit;
	@git commit -s lastcommit -m "[redhat] updating lastcommit for $(STAMP_VERSION)-$(PREBUILD)$(BUILD)$(LOCALVERSION)"

.PHONY: rh-brew rh-koji
rh-brew : BUILD_FLAGS ?= $(BREW_FLAGS)
rh-koji : BUILD_FLAGS ?= $(KOJI_FLAGS)
rh-brew rh-koji: rh-%: rh-srpm
	$* build $(BUILD_FLAGS) $(BUILD_TARGET) $(SRPMS)/kernel-$(KVERSION)-$(BUILD)$(BUILDID)$(DIST).src.rpm

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
	@echo  '  rh-rpms	- Create the binary RPMS for the kernel'
	@echo  '  rh-all-rpms	- Create the binary RPMS and the SRPM for the kernel'
	@echo  '  rh-prep	- Setup the redhat/rpm/BUILD/ directory with the kernel source'
	@echo  '  rh-test-patch - Create a diff against HEAD and put it in linux-kernel-test.patch.'
	@echo  '                  Then linux-kernel-test.patch will be added to the kernel build'
	@echo  '  rh-key	- Generate the required files for compiling with module signing enabled'
	@echo  ''
	@echo  'Configuration targets:'
	@echo
	@echo  '  rh-configs-prep   Creates config files for RHEL 5 architectures, cleans them'
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
