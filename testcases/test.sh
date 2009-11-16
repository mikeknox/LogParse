#!/bin/bash

dir="`pwd`/`dirname $0`"
OUTFILE="/tmp/logparse.test.output"
DEFAULTARGS=" -l ./test.log -c ./logparse.conf -d 0"

cd $dir

for testcasedir in `ls -dF1 * | grep '/$'`
do
	cd $dir/$testcasedir
	if [ -f ./args ] ; then
		$1 `cat ./args` > $OUTFILE
	else
		$1 $DEFAULTARGS > $OUTFILE
	fi
	diff -u $OUTFILE ./expected.output
	if test $? -eq 0 ; then
		echo Testcase `echo $testcasedir | sed 's/\///g'` passed
	else
		echo Testcase `echo $testcasedir| sed 's/\///g'` failed
	fi
	rm $OUTFILE
done
