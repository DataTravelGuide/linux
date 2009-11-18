#!/bin/bash
OVERRIDE_PATH="$1";

if [ ! -d $OVERRIDE_PATH ]; then
	echo "$0 <override files path>" >&2;
	exit 1;
fi

rm -f config-*-rhel
if [ -f $OVERRIDE_PATH/want_enabled ]; then
	for i in $(cat $OVERRIDE_PATH/want_enabled | grep -v "^#" | cut -f 4 -d ':' | sort -u); do
		grep ":$i\$" $OVERRIDE_PATH/want_enabled | grep -v "^#" | cut -f 1,2 -d ':' |
			sed -e "s/:/=/" >$i-rhel;
	done
fi
if [ -f $OVERRIDE_PATH/want_disabled ]; then
	for i in $(cat $OVERRIDE_PATH/want_disabled | grep -v "^#" | cut -f 3 -d ':' | sort -u); do
		grep ":$i\$" $OVERRIDE_PATH/want_disabled | grep -v "^#" | cut -f 1 -d ':' |
			sed -e "s/\(.*\)/# \1 is not set/" >>$i-rhel;
	done
fi

