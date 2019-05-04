#!/bin/bash
#
# Download and install cross-compile tools if necessary.  If there is
# a cross-compiler already in the path, assume all is ready and there
# is nothing to do.
#
# In some cases, it may be necessary to download & install the latest
# EPEL8 repo information to get to the right packages.
#
# Argument(s) to this script is a list of rpm names to install.  If there
# is a value for the environment variable ARCH, we will use that, too.

# if there's already a cross-compiler specified, assume we're done
if [ "$ARCH" ]; then
	if [ "$CROSS_COMPILE" ]; then
		crossbin=$(whereis -b ${CROSS_COMPILE}gcc | cut -d: -f2 | cut -d' ' -f2)
		if [ "$crossbin" ]; then
			echo "Using $crossbin as the cross-compiler."
			exit 0
		else
			echo "Cross-compiler ${CROSS_COMPILE}gcc does not exist.  Standard cross-compiler"
			echo "packages will be used instead."
		fi
	fi
fi

# if we're not root, all we can do now is see what's installed
if [ "$(whoami)" != "root" ]; then
	echo "Checking for RHEL8 cross compile packages.  If this fails, run \"make rh-cross-download\" as root."
	rpm -q $@
	if [ $? == 0 ]; then
		echo "Compilers found."
		exit 0
	else
		echo "FAIL: Some packages are missing."
		exit 1
	fi
fi

# if everything is installed then exit successfully
rpm -q $@ && exit 0

# install epel-release if necessary
REPO_OPTS=""
rpm -q epel-release >& /dev/null
if [ $? -ne 0 ]; then
	wget -nd -r -l1 --no-parent -A "epel-release*.rpm" http://dl.fedoraproject.org/pub/epel/8/x86_64/Packages/e/
	if [ $? -eq 0 ]; then
		rpm -ivh epel-release*.rpm
		# clean up
		rm -f epel-release*.rpm
	else
		# This is a fall-back for the time prior to EPEL-8 existing, and while functional now,
		# will continue to be less similar to our stock compilers over time, and should not be
		# relied upon long-term as a viable option
		REPOURL=http://download.devel.redhat.com/released/fedora/F-29/GOLD/Everything/x86_64/os
		REPO_OPTS="--repofrompath=rhel8fedora,$REPOURL --enablerepo=rhel8fedora"
		# Get the fedora-gpg-keys.  This can be removed once the EPEL8 repo is active.
		yum --nogpgcheck ${REPO_OPTS} -y install fedora-gpg-keys
		rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-29-primary
	fi
fi



# install list of rpms for cross compile
yum ${REPO_OPTS} -y install $@

exit 0
