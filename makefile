ifeq ($(filter rh-%,$(MAKECMDGOALS)),)
	include Makefile
endif

# this section is needed in order to make O= and KBUILD_OUTPUT to work
ifeq ($(KBUILD_OUTPUT),)
ifeq ("$(origin O)", "command line")
  KBUILD_OUTPUT := $(abspath $(O))
endif
ifeq ($(KBUILD_OUTPUT),)
  KBUILD_OUTPUT := $(abspath .)
endif
endif
rh-%::
	$(MAKE) -C redhat $(@) O=$(KBUILD_OUTPUT)

.PHONY: rhkey
Makefile: rhkey
rhkey:
	@if [ ! -e $(KBUILD_OUTPUT)/kernel.pub -o ! -e $(KBUILD_OUTPUT)/kernel.sec -o ! -e $(KBUILD_OUTPUT)/crypto/signature/key.h ]; then \
		$(MAKE) -C redhat rh-key O=${KBUILD_OUTPUT}; \
	fi;

