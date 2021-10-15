#!/bin/bash

# Code executed on guest at startup
#IFNAME=ens4
#ETHFILE=/sys/class/net/${IFNAME}
IP=10.0.0.101
SYNC_FOLDER=/root/sync

# Option parsing
while [[ $# > 0 ]]
do
    key="$1"
    case $key in

        "-ip")
        if [ -n "$2" ]; then
            IP=$2
            shift
        else
            echo "-ip requires an argument"
            exit 255
        fi
        ;;

        *)
        echo "Unknown option '$key'"
        exit 255
        ;;
    esac
    shift
done

echo "7" > /proc/sys/kernel/printk

# Enable jit for best performance (over bfp interpreter)
echo 1 > /proc/sys/net/core/bpf_jit_enable

# Load kstats
# insmod ${SYNC_FOLDER}/kstats.ko

# Load driver
insmod ${SYNC_FOLDER}/bpfhv.ko

# Load netmap
insmod ${SYNC_FOLDER}/netmap.ko

# Wait for IFNAME to come up
#while [ ! -d "$ETHFILE" ]; do
#        sleep 0.2
#done
sleep 2

#IFNAME=$(lshw -class network | grep -A 10 "driver=bpfhv" | grep "logical name:" | awk '{ print $3 }' | head -n 1)
IFNAME=$(dmesg|grep bpfhv|grep renamed|awk -F'[: \t]*' '{print $7}')

echo The network interface is called ${IFNAME}

# Set IFNAME up and set IP
ifconfig ${IFNAME} up
ifconfig ${IFNAME} ${IP}/24

# Show info
ifconfig -a

echo Done

