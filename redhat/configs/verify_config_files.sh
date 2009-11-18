#!/bin/bash
# this script checks if the requested config options are satisfied by the
# final config files. this is needed because some options may be enabled
# automatically by others

if [ -z "$1" ]; then
	echo "$0 <want_* files path>" >&2;
	exit 1;
fi

for config in ../../configs/*.config; do
	name="$(basename $config .config | sed -e "s/kernel-[^-]\+-//")";
	priority="$(egrep -e "^$name:" priority | cut -f 2- -d ':')";
	if [ -z "$priority" ]; then
		echo "Empty priority rules for $name" >&2;
		continue;
	fi
	echo "$config" >&2;

	for prio_file in $(echo $priority | sed -e "s/:/\t/g"); do
		for request in $(grep "$prio_file$" $1/want_enabled | grep -v ^# | cut -f 1,2 -d ':'); do
			config_name=$(echo $request | cut -f 1 -d ':');
			config_value=$(echo $request | cut -f 2 -d ':');
			actual="$(grep "^$config_name[=\ ]" $config)";
			if [ -z "$actual" ]; then
				echo "[MISSING] $config_name (requested by $prio_file)" >&2;
				continue;
			fi
			if [ ! $actual = "$config_name=$config_value" ]; then
				echo "[DIFF] $config_name ($config_value requested, $(echo $actual | cut -f 2 -d '=') set) (requested by $prio_file)";
			fi
		done
		for request in $(grep "$prio_file$" $1/want_disabled | grep -v ^# | cut -f 1 -d ':'); do
			actual="$(grep "^$request[=\ ]" $config)";
			if [ -z "$actual" ]; then
				continue;
			fi
			echo "[NOT DISABLED] $request (requested on $prio_file)";
		done
	done
done

