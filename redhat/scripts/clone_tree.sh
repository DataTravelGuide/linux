#!/bin/bash

# Clones a RHEL dist-git tree using a local reference if existent
# $1: repository
# $2: local clone
# $3: use a different tmp directory (for people with SSDs)

repo="$1";
local="$2";
tmp_dir="$3";

function die
{
	echo "Error: $1" >&2;
	exit 1;
}

tmp="$(mktemp -d --tmpdir="$tmp_dir")";
cd $tmp || die "Unable to create temporary directory";

if [ -n "$repo" -a -n "$local" ]; then
	git clone --reference $local $repo kernel >/dev/null || die "Unable to clone using local cache";
	# if there're tarballs present that are listed in the "sources" file,
	# copy them or it'll be downloaded again
	if [ -e "$local/sources" ]; then
		for i in $(cat "$local/sources"); do
			if [ -f "$local/$i" ]; then
				cp "$local/$i" "$tmp/kernel/";
			fi
		done
	fi
else
	echo "No local repo, cloning using rhpkg" >&2;
	rhpkg clone kernel >/dev/null || die "Unable to clone using rhpkg";
fi

echo $tmp;

