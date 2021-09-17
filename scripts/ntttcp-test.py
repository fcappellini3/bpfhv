#!/usr/bin/python3
import os
import sys


def main():
    index = sys.argv.index("-n_guest")
    if index < 0:
        print("Use -n_guest")
        return
    n_guest = int(sys.argv[index + 1])
    cmd = []
    for i in range(n_guest):
        cmd.append(f"~/tesi/img/sync-src/ntttcp -s -m 2,*,10.0.{i}.101 -t 30 -b 1048576")
    cmd = " & ".join(cmd)
    print(f"Running: {cmd}")
    os.system(cmd)


if __name__ == "__main__":
    main()
