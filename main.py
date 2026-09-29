from ipaddress import IPv4Address, ip_address

import scapy.all as scapy
from scapy.arch.windows import get_windows_if_list

from GUI import GUI
from controller import Controller
from router import Router


def discover_interfaces():
    devices = []
    os_ipv4 = set()

    for adapter in get_windows_if_list():
        for value in adapter.get("ips", []):
            try:
                address = ip_address(value)
            except ValueError:
                continue
            if isinstance(address, IPv4Address):
                os_ipv4.add(address)

        if adapter.get("type") != 6:
            continue
        try:
            device = scapy.dev_from_index(adapter["index"])
        except (KeyError, ValueError, OSError):
            continue
        if "WIRELESS" in device.flags or not device.mac:
            continue
        devices.append(device)

    return devices, os_ipv4


def main():
    devices, os_ipv4 = discover_interfaces()
    router = Router(devices)
    controller = Controller(router, os_ipv4)
    GUI(controller).show()


if __name__ == "__main__":
    main()
