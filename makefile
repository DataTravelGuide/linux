.PHONY: crypto/signature/key.h

extract.pub:
	$(MAKE) -C redhat rh-key

ifeq ($(filter rh-%,$(MAKECMDGOALS)),)
%:: extract.pub
	$(MAKE) -f Makefile $(@)
else
%::
	$(MAKE) -C redhat $(@)
endif
