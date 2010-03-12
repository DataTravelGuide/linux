ifeq ($(filter rh-%,$(MAKECMDGOALS)),)
	include Makefile
endif

rh-%::
	$(MAKE) -C redhat $(@)

Makefile: kernel.pub kernel.sec crypto/signature/key.h

kernel.pub:
	$(MAKE) -C redhat rh-key

kernel.sec:
	$(MAKE) -C redhat rh-key

crypto/signature/key.h:
	$(MAKE) -C redhat rh-key

