#!/bin/sh
#
# *****
# THIS SCRIPT SHOULD NOT BE CARRIED FORWARD TO A NEW VERSION OF RHEL.
# *****
#
# This used to be a stand alone script that was similar to upstream's
# get_maintainer.pl script from ~3.10.0-ish.  We can now just use
# upstream's get_maintainer.pl.
#

# ripped from process_configs.sh
switch_to_toplevel()
{
	path="$(pwd)"
	while test -n "$path"
	do
		test -d $path/firmware && \
			test -e $path/MAINTAINERS && \
			test -d $path/drivers && \
			break

		path="$(dirname $path)"
	done

	test -n "$path"  || die "Can't find toplevel"
	echo "$path"
}


pushd $(switch_to_toplevel) &>/dev/null
scripts/get_maintainer.pl "$@"
popd > /dev/null
