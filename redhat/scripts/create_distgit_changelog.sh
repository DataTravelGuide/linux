#!/bin/bash

# Outputs a ready to use commit message for dist-git
# $1: spec file

spec=$1;
tmp=$(mktemp);

function die
{
	echo "Error: $1" >&2;
	rm -f $tmp;
	exit 1;
}

if [ ! -f "$spec" ]; then
	die "$0 <spec file>";
fi

# this expression looks for the beginning of the changelog and extracts the
# first entry
cat $spec |
	sed -n -e '0,/%changelog/d; :abc; s/^$//; t end; p; d; N; b abc; :end; q;' >$tmp;
if [ ! -s "$tmp" ]; then
	die "Unabled to extract the changelog";
fi

# getting the version from the first line
version=$(cat $tmp | head -n 1 | sed -e 's/.*\[\(.*\)\]/\1/');
if [ -z "$version" ]; then
	die "Unable to get version/release";
fi

# extracting the BZs to create the "Resolves" line
cat $tmp |
	grep ^- |
        sed -n -e "s/.*\[\([0-9\ ]\+\)\].*/\1/p" |
        tr ' ' '\n' |
        sort -u |
        tr '\n' ',' |
        sed -e "s/^/Resolves: rhbz#/; s/,\$//; s/,/, rhbz#/g;" >>$tmp;

echo -e "kernel-$version\n"
cat $tmp;
echo;
rm -f $tmp;
