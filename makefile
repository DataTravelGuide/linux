ifeq ($(filter rh-%,$(MAKECMDGOALS)),)
	include Makefile
else
%::
	$(MAKE) -C redhat $(@)
endif
