#!/bin/sh
#
# Submit a beaker kernel tier 1 test
#

NAME=kernel
BRANCH=$(git branch | grep ^\* | cut -d" " -f2)
WORKDIR=$(pwd)
SPECFILE="kernel.spec"

DISTVAR="rhel"
DISTVAL=$(echo $BRANCH | sed -e "s/${DISTVAR}-//g" | cut -d. -f1)
DIST=".el${DISTVAL}"
#FAMILY=$(echo ${DISTVAR}-${DISTVAL} | tr '[:lower:]' '[:upper:]')
FAMILY="RedHatEnterpriseLinux6"

DIST_DEFINES="--define \"dist ${DIST}\" --define \"${DISTVAR} ${DISTVAL}\""

SYS_NAME_VER=$(rpm -q --qf "%{NAME} %{VERSION}\n" `rpm -q --whatprovides redhat-release` | head -1)
SYS_NAME=$(echo ${SYS_NAME_VER} | cut -d" " -f1)
SYS_VERSION=$(echo ${SYS_NAME_VER} | cut -d" " -f2)

# Defaults, often overridden on the job submission cli
DEFAULT_DISTRO_TAG="--tag=STABLE"
DEFAULT_REPO_SYSTEM_URL_BASE=http://file.bos.redhat.com
DEFAULT_REPO_OPTIONS=$(createrepo -h | grep -q '\-\-checksum' && echo "--checksum sha" || echo "")
DEFAULT_TEST_ARGS=""
DEFAULT_TASK_ID=""

VER_REL=$(rpm -q --qf "%{VERSION} %{RELEASE}\n" --specfile ${SPECFILE} | head -1)
VERSION=$(echo ${VER_REL} | cut -d" " -f1)
DEFAULT_RELEASE=$(echo ${VER_REL} | cut -d" " -f2)

# RELEASE can be passed in on the command line, particularly relevant for test builds
RELEASE=${RELEASE:-${DEFAULT_RELEASE}}

# use the test target to queue a run in RHTS for this package
DISTRO_TAG=${DISTRO_TAG:-${DEFAULT_DISTRO_TAG}}
REPO_SYSTEM_URL_BASE=${REPO_SYSTEM_URL_BASE:-${DEFAULT_REPO_SYSTEM_URL_BASE}}
TEST_TIER="--type=KernelTier1"

BUILDSYS_FRAGMENT=brewroot/packages/${NAME}/${VERSION}/${RELEASE}
BUILDSYS_URL_BASE=http://download.lab.bos.redhat.com

BUILDSYS_URL=${BUILDSYS_URL_BASE}/${BUILDSYS_FRAGMENT}/
BUILDSYS_PATH=/mnt/redhat/${BUILDSYS_FRAGMENT}

REPO_BASEDIR=${HOME}/public_html/dist-cvs-repos
REPO_DIR=${REPO_BASEDIR}/${NAME}-${VERSION}-${RELEASE}
REPO_URL=${REPO_SYSTEM_URL_BASE}/~${USER}/dist-cvs-repos/${NAME}-${VERSION}-${RELEASE}

REPO_OPTIONS=${REPO_OPTIONS:-${DEFAULT_REPO_OPTIONS}}
TEST_ARGS=${TEST_ARGS:-${DEFAULT_TEST_ARGS}}
TASK_ID=${TASK_ID:-${DEFAULT_TASK_ID}}

if [ ! -d ${BUILDSYS_PATH} ]; then
	BUILDSYS_FRAGMENT=brewroot/scratch/${USER}/task_${TASK_ID}/
	BUILDSYS_URL=${BUILDSYS_URL_BASE}/${BUILDSYS_FRAGMENT}/
	BUILDSYS_PATH=/mnt/redhat/${BUILDSYS_FRAGMENT}
	if [ ! -d ${BUILDSYS_PATH} ]; then
		echo "Unable to locate build, aborting"
		exit 1
	fi
fi

if [ -d ${REPO_DIR}/repodata ]; then
	echo "Repodata directory already exists ${REPO_DIR}/repodata"
else
	mkdir -p ${REPO_DIR}
	/usr/bin/createrepo ${REPO_OPTIONS} -o ${REPO_DIR} --baseurl ${BUILDSYS_URL} ${BUILDSYS_PATH}
fi

if [ $(echo $BRANCH | grep -c rhel-4) -ge 1 ]; then
	BKR_DUMP_OPT="--ndump"
else
	BKR_DUMP_OPT="--kdump"
fi

bkr workflow-kernel ${TEST_TIER} ${DISTRO_TAG} --family=${FAMILY} ${BKR_DUMP_OPT} \
	--nvr="${NAME}-${VERSION}-${RELEASE}" --repo="${REPO_URL}" ${TEST_ARGS}

