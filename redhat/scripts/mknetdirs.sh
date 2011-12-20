#!/bin/sh

# only 1 argument needed to this script, the remote location of your
# upstream tree.  Usage is like this:
#
# mkdirs.sh /home/user/path/to/upstream/tree
#

function link_file
{
	newpath=$(dirname ${1})
	newfile=$(basename ${1})
	oldfile=${2}

	levels=""
	for subdir in `echo $newpath | tr \/ ' '`
	do
		if [ ! -d $subdir ]
		then
			mkdir $subdir
		fi
		cd $subdir;
		levels=${levels}../;
	done
	if [ ! -L $oldfile -a ! -e $newfile ]
	then
		ln -s $levels$oldfile $newfile
	fi
	cd $levels
}

if [ "${1}" == "" ]
then
	echo "usage:"
	echo "  $ cd rhel/kernel/git/tree"
	echo "  $ mkdirs.sh path/to/upstream/tree"
	exit 1
fi

upstream=${1}
rhel=${PWD}
cd ${upstream}

# first look for dirs that need to be mapped
for subdir in `find drivers/net/ethernet/ -type d`;
do
	cd $rhel
	# look for directories that match this one found upstream
	old=$(find drivers/net/ -name $(basename $subdir) | \
		grep -v ethernet | cut -d\/ -f3-);

	# hacks -- exception for chelsio -> cxgb move
	if [ "$(basename $subdir)" == "cxgb" ]
	then
		old="chelsio"
	fi

	# one more chelsio hack
	if [ "$old" != "" -a "$(basename $subdir)" != "chelsio" ]
	then
		new=$(echo $subdir | cut -d\/ -f3-)
		cd drivers/net
		#echo $old " -> " $new
		echo creating directory link $new
		link_file $new $old
		cd ../../
	fi
done

# check all files in drivers/net and see if they should be remapped to
# a vendor specific area
for old in `find drivers/net/ -maxdepth 1 -name *.[ch]`
do
	cd ${upstream}
	for new in `find drivers/net/ethernet -name $(basename $old) \
		| cut -d\/ -f3-`;
	do
		cd $rhel/drivers/net
		#echo "$(basename $old) -> $new";
		echo creating file link $new
		link_file $new $(basename $old)
	done
	cd $rhel
done
