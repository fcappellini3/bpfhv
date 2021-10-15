#!/bin/bash
PKT_COUNT_LIMIT=20000000
PKT_SIZE=512
IFNAME=ens3

echo Receive from ${IFNAME}, PKT_SIZE=${PKT_SIZE}

./pkt-gen -f rx -i ${IFNAME} -n ${PKT_COUNT_LIMIT} -a 0 -l ${PKT_SIZE}
