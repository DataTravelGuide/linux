#!/bin/sh

for i in "$@"; do
	objcopy -I binary -O ihex $i $i.ihex
	dos2unix -q $i.ihex
	md5sum $i $i.ihex
done
