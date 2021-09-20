#!/bin/bash
PKT_SIZE=512
IFNAME=vale0:ixh

echo Receive from ${IFNAME}, PKT_SIZE=${PKT_SIZE}

pkt-gen -f tx -i ${IFNAME} -l ${PKT_SIZE}
