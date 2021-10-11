#!/bin/bash

# Enable NAT routing from the guest TAP interface (tapx0) to the outside via this physical server
# network interface (eno1)
# The TAP interface that communicates with the guest must be already started (up):
# start-backend-multi.py already does what is necessary ->
#     sudo ip tuntap add mode tap name tapx0
#     sudo ip link set tapx0 address be:c7:54:8a:13:00
#     sudo ip link set tapx0 up
#     sudo ip addr add 10.0.0.10/24 dev tapx0

SERVER_IFNAME=eno1
TAP_IFNAME=tapx0
GUEST_IP=10.0.0.101

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
# the IP of the pysical server. Note: after -s 10.0.0.0/24 it is possible to add -i ${TAP_IFNAME}.
# Instead of MASQUERADE it is possible to use -j SNAT --to PHYSICAL_SERVER_IP:PORT.
iptables -t nat -A POSTROUTING -o ${SERVER_IFNAME} -s 10.0.0.0/24 -j MASQUERADE

# PREROUTING -> everything that comes from ${SERVER_IFNAME} at the specified ports has to be
# redirected to the guest.
# The destination IP has to be changed from the one of the physical server to that of the guest.
iptables -t nat -A PREROUTING -p tcp -i ${SERVER_IFNAME} --dport 5000 -j DNAT --to-destination ${GUEST_IP}:5000
