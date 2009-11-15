#!/bin/bash

dir=`dirname $0`
OUTFILE="/tmp/logparse.test.output"

for testcase in `ls -dF1 $dir/* | grep '/$'`
do
	echo Testcase: $testcase
	$1 -l $testcase/test.log -c $testcase/logparse.conf -d0 > $OUTFILE
	diff -u $OUTFILE $testcase/expected.output
	if test $? -eq 0 ; then
		echo $testcase passed
	else
		echo $testcase failed
	fi
	rm $OUTFILE
done
