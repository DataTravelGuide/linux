#!/bin/sh
#
# This script parses the deadtome.txt file of known build
# breakage patch submission offenders, and looks for any
# patches in the provided git log output from these people,
# which are going to be our prime suspects to look a for
# any new build breakages introduced.

scriptdir=$(dirname $0)
offender_list="${scriptdir}/../deadtome.txt"
git_log=$(mktemp)
cat < /dev/stdin > $git_log

while read offender
do
  if [ ! -z "$(echo $offender | grep -v "^#")" ]; then
    count=$(grep -c "^Author: $offender" $git_log)
    if [ "$count" -gt "0" ]; then
      echo "Offender $offender has $count patch(es) to consider"
    fi
  fi
done < $offender_list

rm -f $git_log
