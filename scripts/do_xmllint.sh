#!/bin/sh
for A in */doc/manual.xml
do
	cp $A /tmp/input.xml
	xmllint --format /tmp/input.xml > $A
done
