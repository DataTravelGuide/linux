ifeq ($(filter rh-%,$(MAKECMDGOALS)),)
	include Makefile
endif

rh-%::
	$(MAKE) -C redhat $(@)

Makefile: extract.pub

extract.pub:
	$(MAKE) -C redhat rh-key

