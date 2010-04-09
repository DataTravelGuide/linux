ifeq ($(filter rh-%,$(MAKECMDGOALS)),)
	include Makefile
endif

_OUTPUT := "."
# this section is needed in order to make O= to work
ifeq ("$(origin O)", "command line")
  _OUTPUT := "$(abspath $(O))"
  _EXTRA_ARGS := O=$(_OUTPUT)
endif
rh-%::
	$(MAKE) -C redhat $(@) $(_EXTRA_ARGS)

.PHONY: rhkey
Makefile: rhkey
rhkey:
	@if [ ! -s $(_OUTPUT)/kernel.pub -o ! -s $(_OUTPUT)/kernel.sec -o ! -s $(_OUTPUT)/crypto/signature/key.h ]; then \
		$(MAKE) -C redhat rh-key $(_EXTRA_ARGS); \
	fi;

