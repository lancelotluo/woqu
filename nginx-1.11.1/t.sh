#!/bin/bash

h="hell.cc"

echo "$h"

if [[ $h =~ .*\.cc$ ]];then
	echo "cc"
else
	echo "nocc"
fi

echo "hi"
