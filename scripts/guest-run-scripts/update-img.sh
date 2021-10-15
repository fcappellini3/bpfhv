#!/bin/bash
MOUNT_DIR=/tmp/guest-temp-mount-point
SYNC_DIR_DEST=${MOUNT_DIR}/root/sync
SYNC_DIR_SRC=./sync-src
VM_DISK="vm-disk.img"

# Option parsing
while [[ $# > 0 ]]
do
    key="$1"
    case $key in

        "-vm_disk")
        if [ -n "$2" ]; then
            VM_DISK=$2
            shift
        else
            echo "--vm_disk requires an argument"
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

echo Updating ${VM_DISK}

# Driver
cp ../bpfhv/driver/bpfhv.ko ${SYNC_DIR_SRC}/

mkdir ${MOUNT_DIR}
losetup -P /dev/loop7 ${VM_DISK}
mount /dev/loop7p1 ${MOUNT_DIR}
mkdir ${SYNC_DIR_DEST}
# rm -r ${SYNC_DIR_DEST}/*
cp -v -R ${SYNC_DIR_SRC}/* ${SYNC_DIR_DEST}/
umount /dev/loop7p1
losetup -d /dev/loop7

echo Done
