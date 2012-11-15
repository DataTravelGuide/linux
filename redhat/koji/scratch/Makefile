sources:
	$(MAKE) -C ../../ S=1 Q=1 rh-sources
	mv -f ../../rpm/SOURCES/* .
	rm -f ./kernel.spec
	mv ../../rpm/SPECS/kernel.spec .

PHONY = sources
