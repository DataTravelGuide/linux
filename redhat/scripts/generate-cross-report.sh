#!/bin/sh
#
# This script is called by the cross compile targets in redhat/Makefile.cross.
# The script outputs information for use by the maintainers to confirm that
# a build was completed.  The script output should be placed in the 0/1 header
# patch of a patch submission on RHKL.
#

echo "==============================================================================="
echo "                        CROSS COMPILE REPORT"
echo "==============================================================================="
echo "For patch submissions, this text must be cut-and-pasted into patch 0/1."
echo -n "Date: "
date

# Note, there is no guarantee that this environment is pristine.
echo -n "Build OS: "
cat /etc/redhat-release

# rhel6-cross-compiler version
echo -n "Cross compiler version: "
rpm -q rhel6-cross-compilers

# System name
echo -n "System name: "
HOSTNAME=`hostname`

if [ -e ~/.rpmmacros ]; then
	cat ~/.rpmmacros | grep smp_mflags >& /dev/null
	if [ $? -eq 0 ]; then
		smpflags=`cat ~/.rpmmacros | awk -F " " ' { print $2 } '`
		# PRARIT: fix me
		echo "$HOSTNAME with $smpflags"
	fi
else
	echo $HOSTNAME
fi

# Last known tag
lasttag=`git describe --abbrev=0 --tags`
echo "Built on: $lasttag"

# Arches built?
# would have to be passed in on command line as string?
echo -n "Arch built: "
echo $1

echo "==============================================================================="
echo "For patch submissions this can optionally be included to show the changes"
echo "that were compiled into the tree."
echo "diffstat output (relative to $lasttag)"
git diff $lasttag | diffstat

echo "==============================================================================="
echo "==============================================================================="
