#!/bin/bash

SOCK=/var/run/sockfile-0.socket
MAC=00:AA:BB:CC:DD:00
MEM=512M
VM_ID=0
OTHER_IF=""
VM_DISK=vm-disk.img
CORE_COUNT=1
COREMAP=(2 4 6 8 10 12 14 16 18 1 3 5 7 9 11 13 15 17 19)


# Option parsing
while [[ $# > 0 ]]
do
    key="$1"
    case $key in

        "-mac")
        if [ -n "$2" ]; then
            MAC=$2
            shift
        else
            echo "-mac requires an argument"
            exit 255
        fi
        ;;

	"-sock")
        if [ -n "$2" ]; then
            SOCK=$2
            shift
        else
            echo "-sock requires an argument"
            exit 255
        fi
        ;;

        "-core_count")
        if [ -n "$2" ]; then
            CORE_COUNT=$2
            shift
        else
            echo "-core_count requires an argument"
            exit 255
        fi
        ;;

	"-mem")
        if [ -n "$2" ]; then
            MEM=$2
            shift
        else
            echo "-mem requires an argument (in MB)"
            exit 255
        fi
        ;;

	"-multi_index")
        if [ -n "$2" ]; then
            VM_ID=${2}
            SOCK=/var/run/sockfile-${2}.socket
            MAC=00:AA:BB:CC:DD:$(printf '%02x\n' ${2})
            # VM_DISK=vm-disk-${2}.img
            if (( ${VM_ID} > 0 )); then dont_update_disk=1; fi
            echo SOCK: ${SOCK}
            echo MAC: ${MAC}
            shift
        else
            echo "-multi_index requires an argument"
            exit 255
        fi
        ;;

        "-other_if")
        OTHER_IF="-netdev tap,ifname=tap0,script=no,downscript=no,id=mynet0 -device e1000,netdev=mynet0,mac=52:55:00:d1:55:01"
        ;;

        *)
        echo "Unknown option '$key'"
        exit 255
        ;;
    esac
    shift
done


if [ -z ${dont_update_disk+x} ]; then ./update-img.sh -vm_disk ${VM_DISK}; else echo "Skipping disk updating"; fi

numactl --hardware

PIDFILE=/tmp/vm-${VM_ID}.pid
#PHYSICAL_CORE=${COREMAP[$VM_ID]}
NUMA_ID=$((${VM_ID} % 2))

# SNAPSHOT_FLAG management. It can be void (off) or "-snapshot" (on). If its initial state is "-snapshot", it means
# that the snapshot features is always enabled. If it is void it means that the feature is enabled only for VM_ID
# greater than 0.
SNAPSHOT_FLAG="-snapshot"
if (( ${VM_ID} > 0 )); then SNAPSHOT_FLAG="-snapshot"; fi

rm ${PIDFILE}

echo Virtual machine VM_ID=${VM_ID} has ${CORE_COUNT} cores and it is running on numa node NUMA_ID=${NUMA_ID}
echo SOCK is ${SOCK}
if (( ${VM_ID} > 0 )); then echo "Snapshot mode enabled!"; fi

stty intr ^]
echo "intr remapped to CTRL+]"

numactl --membind=${NUMA_ID} --cpunodebind=${NUMA_ID} \
qemu-system-x86_64 -enable-kvm ${SNAPSHOT_FLAG} -smp cores=${CORE_COUNT},threads=1,sockets=1 -m ${MEM} -serial stdio \
-name ${VM_ID},debug-threads=on \
-pidfile ${PIDFILE} \
-drive format=raw,file=${VM_DISK} \
${OTHER_IF} \
 \
-numa node,memdev=mem0 \
-object memory-backend-file,id=mem0,size=${MEM},mem-path=/dev/hugepages/${VM_ID},share=on \
-device bpfhv-pci,netdev=data20,mac=${MAC} \
-netdev type=bpfhv-proxy,id=data20,chardev=char20 \
-chardev socket,id=char20,path=${SOCK},server #&

#sleep 0.5

#QEMUPID=$(cat ${PIDFILE})
#qemu-affinity $QEMUPID -k $PHYSICAL_CORE -p $PHYSICAL_CORE -w $PHYSICAL_CORE

#echo Affinity set!

#fg

stty intr ^c
echo "intr remapped to CTRL+c"
