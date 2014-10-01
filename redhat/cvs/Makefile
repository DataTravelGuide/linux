VERSION := 2.6.32
MAIN_SPEC := kernel.spec
DETAILED_SPEC := kernel.spec.full
KSB_SPEC := kernel.spec.ksb
BACKUP_SPEC := .kernel.spec
internal_release := $(shell rpm -q --qf "%{RELEASE}\n" --specfile $(DETAILED_SPEC) | head -1)
distro_build := $(shell echo $(internal_release) | sed -e 's|\(^[0-9]\{1,4\}.*\)\.el6.*|\1|')
FULL_TARBALL := linux-$(VERSION)-$(internal_release).tar.bz2
KABI_WHITELISTS_TARBALL := kernel-abi-whitelists-$(distro_build).tar.bz2

all:

# if a detailed spec file is used, warn about the 
# grabs the full spec file and updates the official (and reduced) spec file
update-spec:
	@# updating the tarball
	@cp $(MAIN_SPEC) $(BACKUP_SPEC)
	@cp $(DETAILED_SPEC) $(MAIN_SPEC)
	@rhpkg prep
	@(cd kernel-$(VERSION)/; \
	  if [ -e linux-$(VERSION)-$(internal_release) ]; then rm -rf linux-$(VERSION)-$(internal_release); fi; \
	  mv linux-$(VERSION)-$(internal_release).*/ linux-$(VERSION)-$(internal_release)/; \
	  cd linux-$(VERSION)-$(internal_release)/; \
	  make mrproper; \
	  rm -Rf configs *.config config-* perf check-kabi *.pub *.pub~ *.sec merge.pl *.gpg temp-* .gitignore crypto/signature/key.h random_seed; \
	  cd ../; \
	  tar cfj ../$(FULL_TARBALL) linux-$(VERSION)-$(internal_release)/)
	@# updating the spec
	@cat $(DETAILED_SPEC) | \
		sed -e "/Patch:/,/^$$/d; /^ApplyPatch\ /,/^$$/d" | \
		sed -e "s,%define\ kversion\ 2.6.%{base_sublevel},%define\ kversion\ $(VERSION)-$(internal_release)," | \
		sed -e "s,linux-2.6.32.tar.bz2,$(FULL_TARBALL),">$(MAIN_SPEC);
	@make update-ksb-spec
	@# keep the "old" source-packages checksum in the lookaside buffer
	@md5sum linux-$(VERSION).tar.bz2 >sources;
	@md5sum kernel-abi-whitelists.tar.bz2 >>sources;
	@git add kernel.spec*
	@echo -e "\nDon't forget to upload the new patch file with 'make tarball-upload'"

full-srpm:
	@# here we copy the detailed spec to a .spec file. We don't keep this
	@# one around to avoid confusion of having two .spec files
	@cp $(MAIN_SPEC) $(BACKUP_SPEC)
	@cp $(DETAILED_SPEC) $(MAIN_SPEC);
	@rhpkg srpm;
	@cp $(BACKUP_SPEC) $(MAIN_SPEC);
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
	@cp $(MAIN_SPEC) $(BACKUP_SPEC)
	@cp $(KSB_SPEC) $(MAIN_SPEC);
	@rhpkg srpm;
	@cp $(BACKUP_SPEC) $(MAIN_SPEC);
	@echo "*** DO NOT distribute this SRPM ***";

tarball-upload:
	@rhpkg upload $(KABI_WHITELISTS_TARBALL) $(FULL_TARBALL)

