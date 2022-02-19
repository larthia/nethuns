#!/bin/bash

if [ "$#" -lt 3 ]; then
    echo "usage: make_revision GIT_PATH version.in version.out"
    exit 1
fi

echo "generating $3..." 

REV=`git -C $1 describe --abbrev=8 --dirty --always --long`
VER=`git -C $1 describe --always --tags`

cat $2 | sed -e "s#\\\$REVISION\\\$#${REV}#"  \
             -e "s#\\\$VERSION\\\$#${VER}#"   \
             -e "s#\\\$PCAP_TOGGLE\\\$#${4}#" \
             -e "s#\\\$XDP_TOGGLE\\\$#${5}#" \
             -e "s#\\\$NETMAP_TOGGLE\\\$#${6}#" \
             -e "s#\\\$TPACKET3_TOGGLE\\\$#${7}#" \
             > $3 


