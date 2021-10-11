#!/bin/bash

# Enable NAT routing from the guest "help interface" (tap0) to the outside via this physical server
# network interface (eno1)

SERVER_IFNAME=eno1
TAP_IFNAME=tap0

ifconfig ${TAP_IFNAME} up
ifconfig ${TAP_IFNAME} 10.0.1.1/24

echo "1" > /proc/sys/net/ipv4/ip_forward

#iptables --flush
iptables -t nat -F
iptables -X
iptables -Z
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -A FORWARD -i ${TAP_IFNAME} -o ${SERVER_IFNAME} -j ACCEPT
iptables -A FORWARD -i ${SERVER_IFNAME} -o ${TAP_IFNAME} -j ACCEPT

# POSTROUTING (MASQUERADE) -> from the guest to the outside "masking" (changing) che source with
# the IP of the pysical server
iptables -t nat -A POSTROUTING -o ${SERVER_IFNAME} -s 10.0.1.0/24 -j MASQUERADE
