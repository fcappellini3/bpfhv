#!/usr/bin/python3
import os
from os.path import isfile
import sys


PATH = "/tmp/"
CORE_PER_VM = 1
COREMAP = (
    (2, 4, 6, 8, 10, 12, 14, 16, 18),
    (1, 3, 5, 7,  9, 11, 13, 15, 17, 19)
)


def __vm_id_to_numa_node(vm_id: int):
    if vm_id % 2 == 0:
        return 0
    else:
        return 1


def __vm_id_to_core(vm_id: int):
    cm = COREMAP[__vm_id_to_numa_node(vm_id)]
    vm_id_in_numa_node = vm_id // 2
    corelist = []
    for i in range(CORE_PER_VM):
        corelist.append(cm[vm_id_in_numa_node * CORE_PER_VM + i])
    return corelist


def __pidfile_to_vm_id(pidfile: str):
    return int(pidfile.split("vm-")[1].split(".")[0])


def __get_pid(pidfile):
    with open(PATH + pidfile) as f:
        r = int(next(f))
    return r


def main():
    global CORE_PER_VM

    try:
        core_per_vm_arg_index = sys.argv.index("-core_per_vm")
        CORE_PER_VM = int(sys.argv[core_per_vm_arg_index + 1])
    except ValueError:
        print("arg -core_per_vm not specified, assuming 1")

    pidfiles = [f for f in os.listdir(PATH) if isfile(PATH + f) and f.startswith("vm-") and ".pid" in f]
    for pidfile in pidfiles:
        pid = __get_pid(pidfile)
        vm_id = __pidfile_to_vm_id(pidfile)
        numa_node = __vm_id_to_numa_node(vm_id)
        corelist = [str(c) for c in __vm_id_to_core(vm_id)]
        corelist_comma = ",".join(corelist)
        corelist_space = " ".join(corelist)
        print(f"vm_id: {vm_id} (pid: {pid}) -> goes on core: {corelist_comma} of numa node {numa_node}")
        #os.system(f"taskset -pc {core} {pid}")
        print(f"qemu-affinity {pid} -k {corelist_space} -p {corelist_comma}")
        os.system(f"qemu-affinity {pid} -k {corelist_space} -p {corelist_comma}")
        print("")


if __name__ == "__main__":
    main()
