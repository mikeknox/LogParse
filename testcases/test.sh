#!/bin/bash

dir=`dirname $0`

for testcase in `ls -dF1 $dir/* | grep '/$'`
do
	echo Testcase: $testcase
	$1 -l $testcase/test.log -c $testcase/logparse.conf -d0 > tmp.output
	diff -u tmp.output $testcase/expected.output
	if test $? -eq 0 ; then
		echo $testcase passed
	else
		echo $testcase failed
	fi
done
