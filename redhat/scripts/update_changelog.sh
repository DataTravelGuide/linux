#!/bin/bash
if [ -z "$1" -o -z "$2" -o -z "$3" ]; then
	echo "$(basename $0) <kversion> <version> <redhat path> <last changelog entry> <full version>" >&2;
	exit 1;
fi

KVERSION="$1";
RELEASE="$2";
RHPATH="$3";
FULL_VERSION="$4";

tmp=$(mktemp);
NAME="$(git config user.name)";
EMAIL="$(git config user.email)";

echo "* $(date "+%a %b %d %Y") $NAME <$EMAIL> [$FULL_VERSION]" >$tmp;
#echo "- redhat: tagging $FULL_VERSION" >>$tmp;
sed -n -e "1,/%changelog/d; /^\-/,/^$/p; /^$/q;" rpm/SPECS/kernel.spec >> $tmp;
sed -i -e "/%%CHANGELOG%%/r $tmp" $RHPATH/kernel.spec.template;
rm -f "$tmp";

