#!/usr/bin/python3
import os
from os.path import isfile


PATH = "/tmp/"
COREMAP=(2, 4, 6, 8, 10, 12, 14, 16, 18, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19)


def __vm_id_to_numa_node(vm_id: int):
    if vm_id % 2 == 0:
        return 0
    else:
        return 1


def __vm_id_to_core(vm_id: int):
    return COREMAP[vm_id // 2 + 9 * __vm_id_to_numa_node(vm_id)]


def __pidfile_to_vm_id(pidfile: str):
    return int(pidfile.split("vm-")[1].split(".")[0])


def __get_pid(pidfile):
    with open(PATH + pidfile) as f:
        r = int(next(f))
    return r


def main():
    pidfiles = [f for f in os.listdir(PATH) if isfile(PATH + f) and f.startswith("vm-") and ".pid" in f]
    for pidfile in pidfiles:
        pid = __get_pid(pidfile)
        vm_id = __pidfile_to_vm_id(pidfile)
        numa_node = __vm_id_to_numa_node(vm_id)
        core = __vm_id_to_core(vm_id)
        print(f"vm_id: {vm_id} (pid: {pid}) -> goes on core: {core} of numa node {numa_node}")
        #os.system(f"taskset -pc {core} {pid}")
        os.system(f"qemu-affinity {pid} -k {core} -p {core}")
        print("")


if __name__ == "__main__":
    main()
