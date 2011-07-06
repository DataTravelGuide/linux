# Make rules for configuration files.
#
# $Id$
# this section is needed in order to make O= to work

OUTPUT := $(abspath ../..)

ifeq ("$(origin O)", "command line")
  _EXTRA_ARGS := O=$(O)
  OUTPUT := $(O)
endif

CFG		= kernel-$(VERSION)
CFG_DIR		= $(OUTPUT)/configs

X86_64CONFIGFILES = $(CFG)-x86_64.config $(CFG)-x86_64-debug.config

X86CONFIGFILES	= $(CFG)-i686.config $(CFG)-i686-debug.config

S390CONFIGFILES = $(CFG)-s390x.config $(CFG)-s390x-debug.config \
		   $(CFG)-s390x-kdump.config

PPCCONFIGFILES = $(CFG)-ppc64.config $(CFG)-ppc64-kdump.config \
		  $(CFG)-ppc64-debug.config

CONFIGFILES = $(X86_64CONFIGFILES) $(X86CONFIGFILES) $(S390CONFIGFILES) \
	      $(PPCCONFIGFILES)

ARCHCONFIG =

PLATFORMS	= x86 x86_64 powerpc64 s390
TEMPFILES	= $(addprefix temp-, $(addsuffix -generic, $(PLATFORMS)))

configs: clean-configs $($(ARCHCONFIG)CONFIGFILES)
	@rm -f $(TEMPFILES)
	@rm -f temp-generic temp-*-generic temp-*-generic-tmp *-merged

# overrides updating/checking. not reason to use these unless you're updating
# config options requests before GA
OVERRIDE_PATH	= ~/redhat/rhel6/configs/;
pull-configs: update-configs configs-prep verify-configs

update-configs:
	./generate-rhel-overrides.sh $(OVERRIDE_PATH)

verify-configs:
	./verify_config_files.sh $(OVERRIDE_PATH)

# Augment the clean target to clean up our own cruft
clean ::
	@rm -fv $(CONFIGFILES) $(TEMPFILES) temp-generic kernel-*config config-*-merged *.include temp-i686-debug-final temp-i686-final

clean-configs:
	@rm -fv $(CONFIGFILES) $(TEMPFILES) temp-generic kernel-*config config-*-merged *.include temp-i686-debug-final temp-i686-final

configs-prep: clean configs
	@mkdir -p $(CFG_DIR)
	@rm -f $(CFG_DIR)/*
	@cp $(CFG)* $(CFG_DIR)
	@cd ../../ && \
	for i in $(CFG_DIR)/*.config; do \
		mv $$i $(OUTPUT)/.config ; \
		Arch=$$(head -1 $(OUTPUT)/.config | cut -b 3-) ; \
		echo "Configuring $$i" ; \
		make ARCH=$$Arch nonint_oldconfig $(_EXTRA_ARGS) > /dev/null || exit 1 ; \
		echo "# $$Arch" > $$i ; \
		cat $(OUTPUT)/.config >> $$i ; \
		rm $(OUTPUT)/.config; \
	done

config-%-merged:
	@if [ -f $$(basename $@ -merged)-rhel ]; then \
		perl merge.pl $$(basename $@ -merged)-rhel $$(basename $@ -merged) >$@; \
	else \
		cp $$(basename $@ -merged) $@; \
	fi

temp-generic: config-generic-merged config-nodebug-merged Makefile
	perl merge.pl config-nodebug-merged config-generic-merged > temp-generic

temp-debug-generic: config-generic-merged config-debug-merged Makefile
	perl merge.pl config-debug-merged config-generic-merged > temp-debug-generic

temp-x86-generic: config-x86-generic-merged temp-generic
	perl merge.pl $^  > $@

temp-x86-debug-generic: config-x86-generic-merged temp-debug-generic
	perl merge.pl $^  > $@

temp-x86_64-generic: config-x86_64-generic-merged temp-generic
	perl merge.pl $^  > $@

temp-x86_64-debug-generic: config-x86_64-generic-merged temp-debug-generic
	perl merge.pl $^  > $@

temp-powerpc-generic: config-powerpc-generic-merged temp-generic
	perl merge.pl $^  > $@

temp-powerpc-debug-generic: config-powerpc-generic-merged temp-debug-generic
	perl merge.pl $^  > $@

temp-s390x-generic: config-s390x-merged temp-generic
	perl merge.pl $^ > $@

temp-s390x-debug-generic: config-s390x-merged temp-debug-generic
	perl merge.pl $^  > $@

temp-i686-final: config-i686-merged temp-x86-generic
	perl merge.pl $^ > $@

temp-i686-debug-final: config-i686-merged temp-x86-debug-generic
	perl merge.pl $^ > $@

kernel-$(VERSION)-i686.config: config-i686-nodebug-merged temp-i686-final
	perl merge.pl $^ i386 > $@

kernel-$(VERSION)-i686-debug.config: config-i686-debug-merged temp-i686-debug-final
	perl merge.pl $^ i386 > $@

kernel-$(VERSION)-x86_64.config: config-x86_64-nodebug-merged temp-x86_64-generic
	perl merge.pl $^ x86_64 > $@

kernel-$(VERSION)-x86_64-debug.config: config-x86_64-debug-merged temp-x86_64-debug-generic
	perl merge.pl $^ x86_64 > $@

kernel-$(VERSION)-ppc64.config: config-powerpc64-merged temp-powerpc-generic
	perl merge.pl $^ powerpc > $@

kernel-$(VERSION)-ppc64-kdump.config: config-powerpc64-kdump-merged kernel-$(VERSION)-ppc64.config
	perl merge.pl $^ powerpc > $@

kernel-$(VERSION)-ppc64-debug.config: config-powerpc64-merged temp-powerpc-debug-generic
	perl merge.pl $^ powerpc > $@

kernel-$(VERSION)-s390x.config: config-s390x-merged temp-s390x-generic
	perl merge.pl $^ s390 > $@

kernel-$(VERSION)-s390x-debug.config: config-s390x-debug-merged temp-s390x-debug-generic
	perl merge.pl $^ s390 > $@

kernel-$(VERSION)-s390x-kdump.config: config-s390x-kdump-merged kernel-$(VERSION)-s390x.config
	perl merge.pl $^ s390 > $@

