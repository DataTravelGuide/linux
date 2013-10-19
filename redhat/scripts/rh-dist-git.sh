#!/bin/bash

# clones and updates a dist-git repo
# $1: branch to be used
# $2: local pristine clone of dist-git
# $3: alternate tmp directory (if you have faster storage)
# $4: alternate dist-git server

rhdistgit_branch=$1;
rhdistgit_cache=$2;
rhdistgit_tmp=$3;
rhdistgit_server=$4;

redhat=$(dirname $0)/..;
topdir=$redhat/..;

function die
{
	echo "Error: $1" >&2;
	exit 1;
}

if [ -z "$rhdistgit_branch" ]; then
	echo "$0 <branch> [local clone] [alternate tmp] [alternate dist-git server]" >&2;
	exit 1;
fi

echo "Cloning the repository"
# clone the dist-git, considering cache
tmpdir=$($redhat/scripts/clone_tree.sh "$rhdistgit_server" "$rhdistgit_cache" "$rhdistgit_tmp");

echo "Switching the branch"
# change in the correct branch
cd $tmpdir/kernel;
rhpkg switch-branch $rhdistgit_branch || die "switching to branch $rhdistgit_branch";

echo "Copying updated files"
# copy the required files (redhat/cvs/files)
$redhat/scripts/copy_files.sh "$topdir" "$tmpdir"

echo "Updating spec file and single tarball (please be patient)"
# run update-spec
make update-spec >/dev/null || die "updating spec";

# copy the new kernel-abi-whitelists tarball
echo "Updating kernel-abi-whitelists source package"
# This copyfile step has to be done here, otherwise the 'rhpkg prep' step
# taken at 'make update-spec' would overwrite the new kabi-whitelists tarball
# with the old source file from the lookaside buffer.
kabi_whitelists="$redhat/rpm/SOURCES/kernel-abi-whitelists.tar.bz2"
cp $kabi_whitelists . || die "Unable to update $kabi_whitelists"

echo "Uploading new tarball"
# upload tarball
make tarball-upload >/dev/null || die "uploading tarball";

echo "Creating diff for review ($tmpdir/diff) and changelog"
# diff the result (redhat/cvs/dontdiff). note: diff reuturns 1 if
# differences were found
diff -X $redhat/cvs/dontdiff -upr $tmpdir/kernel $redhat/rpm/SOURCES/ > $tmpdir/diff;
# creating the changelog file
$redhat/scripts/create_distgit_changelog.sh $redhat/rpm/SOURCES/kernel.spec >$tmpdir/changelog

# all done
echo "$tmpdir"
