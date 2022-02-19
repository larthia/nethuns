#!/bin/bash

if [ "$#" -lt 3 ]; then
    echo "usage: make_revision GIT_PATH version.in version.out"
    exit 1
fi

echo "generating $3..." 

REV=`git -C $1 describe --abbrev=8 --dirty --always --long`
VER=`git -C $1 describe --always --tags`

cat $2 | sed -e "s#\\\$REVISION\\\$#${REV}#" -e "s#\\\$VERSION\\\$#${VER}#" > $3 


