#!/usr/bin/python3
import subprocess
import signal
import sys


N_GUEST = 2

WAIT_BELOCK_SCRIPT = """
SOCK={ph_sock}
set -x
if [ -f ${SOCK}.belock ]; then
    # Lock file exists
    sudo kill -SIGTERM $(cat ${SOCK}.pid)
    while [ -f ${SOCK}.belock ]; do
        sleep 0.001
    done
fi
sudo touch ${SOCK}.belock
"""


def __interface_name(i: int):
    return f"tapx{i}"


def __ip_address(i: int):
    return f"10.0.{i}.10/24"


def __mac_address(i: int):
    return "be:c7:54:8a:13:{:02x}".format(i)


def __execute_script(script_txt: str):
    print("Executing:")
    print(script_txt)
    process = subprocess.Popen(["bash"], stdin=subprocess.PIPE, text=True)
    process.stdin.write(script_txt)
    process.stdin.close()
    process.wait()
    #print(process.stdout.read())
    #print(process.stderr.read())


def __init_interfaces():
    for i in range(N_GUEST):
        script = """
            sudo ip tuntap add mode tap name {ph_interface_name}
            sudo ip link set {ph_interface_name} address {ph_mac}
            sudo ip link set {ph_interface_name} up
            sudo ip addr add {ph_ip} dev {ph_interface_name}
        """
        script = script.format(
            ph_interface_name=__interface_name(i), ph_ip=__ip_address(i), ph_mac=__mac_address(i)
        )
        __execute_script(script)


def __fini_interfaces():
    for i in range(N_GUEST):
        script = """
            sudo ip link set {ph_interface_name} down
            sudo ip link del {ph_interface_name}
        """
        script = script.format(ph_interface_name=__interface_name(i))
        __execute_script(script)


def __run_backend_process():
    script = """
            sudo proxy/backend-multi -p {ph_socks} -i {ph_interface_names} -v
    """
    socks = []
    interface_names = []
    for i in range(N_GUEST):
        socks.append(f"/var/run/sockfile-{i}.socket")
        interface_names.append(__interface_name(i))
    script = script.format(
        ph_socks=",".join(socks), ph_interface_names=",".join(interface_names)
    )
    __execute_script(script)


def __signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    __fini_interfaces()
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, __signal_handler)
    __init_interfaces()
    __run_backend_process()
    __fini_interfaces()


if __name__ == "__main__":
    main()
