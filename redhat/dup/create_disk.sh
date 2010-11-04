#!/bin/sh

ARCH=`uname -p`
DIR_TMP=$(mktemp -d)
DIR_DISK=$DIR_TMP/disk
DIR_RPMS=$DIR_DISK/rpms/$ARCH
DIR_SRCS=$DIR_DISK/src

FILE_RHDD=$DIR_DISK/rhdd3

function check_retval
{
	ret=$?
	msg=$1

	if [ $ret -ne 0 ]; then
		echo -e "---[ error: $msg\n"
		exit -1
	fi
}

function file_rhdd
{
	echo "Driver Update Disk version 3" > $FILE_RHDD
}

function dir_src
{
	if [ -z "$DUP_SRPMS" ]; then
		echo "---[ no source RPMs available"
		return
	fi

	echo "---[ adding source RPMs: $DUP_SRPMS"

	mkdir -p $DIR_SRCS
	cp $DUP_SRPMS $DIR_SRCS
	check_retval "failed to copy source RPMs"
}

echo "---[ creating temp dir: $DIR_TMP"
(rm -rf $DIR_TMP && mkdir -p $DIR_TMP $DIR_DISK)
check_retval "failed to create temp dir"

mkdir -p $DIR_RPMS $DIR_SRCS
check_retval "failed to create disk rpm directory"

for rpm in "$@"; do
	cp $rpm $DIR_RPMS
done

file_rhdd
dir_src

echo "---[ creating rpm repository"
createrepo --pretty $DIR_RPMS
check_retval "failed to create rpm repository"

echo "---[ creating disk image - $PWD/dd.iso"
mkisofs -V OEMDRV -R -o dd.iso $DIR_DISK >/dev/null 2>&1
check_retval "failed to create disk image $PWD/dd.iso"

if [ -z "$DEBUG" -a -n "$DIR_TMP" ]; then
	echo "---[ removing temp directory"
	rm -rf $DIR_TMP
else
	echo "---[ preserving temp direcotory: $DIR_TMP"
fi
