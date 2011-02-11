sources:
	$(MAKE) -C ../ rh-sources
	mv -f ../rpm/SOURCES/* .
	rm -f ./kernel.spec
	mv ../rpm/SPECS/kernel.spec .

PHONY = sources
