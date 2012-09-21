#!/bin/bash

# Copy required files to dist-git. Uses redhat/cvs/files to know which files
# to copy
#
# $1: git source tree directory
# $2: cloned tree

tree="$1";
cloned="$2";
redhat="$1/redhat";
sources="$redhat/rpm/SOURCES";
spec="$sources/kernel.spec";
# RHEL6 has a different local spec with individual patches that will be used
# to update the public spec file using "make update-spec"
local_spec="kernel.spec.full";

function die
{
	echo "Error: $1" >&2;
	exit 1;
}

if [ -z "$tree" -o ! -d "$sources" ]; then
	die "\"$tree\" doesn't seem to be a valid kernel source tree";
fi

if [ ! -d "$cloned" ]; then
	die "\"$cloned\" doesn't seem to be a valid directory";
fi

cd $cloned/kernel || die "\"$cloned\" doesn't seem to have a dist-git clone";

# We only copy new patches
patches=$(diff -up $local_spec $spec | grep ^+ApplyPatch | sed -e "s,.*\ ,$sources/,");
if [ -n "$patches" ]; then
	cp $patches . || die "Unable to copy new patches";
	git add *.patch;
fi

# spec file, special case since it's a different name
cp $spec $local_spec || die "Unable to copy spec file";

# copy the other files
cp $(cat $redhat/cvs/files | sed -e "s,^,$sources/,") . || die "Unable to copy files";
git add $(cat $redhat/cvs/files);

exit 0;
