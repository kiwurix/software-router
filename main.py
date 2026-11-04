from ipaddress import IPv4Address

from scapy.config import conf
from scapy.interfaces import NetworkInterface

from controller import Controller
from gui import GUI
from router import Router


def _discover_devices() -> tuple[list[NetworkInterface], set[IPv4Address]]:
    interfaces = list(conf.ifaces.values())
    devices = [device for device in interfaces
               if device.type == 6 and device.mac
               and "virtual" not in device.description.lower() and not "bluetooth" in device.description.lower()]
    os_ipv4_addresses = {IPv4Address(address) for device in interfaces for address in device.ips[4]}
    return devices, os_ipv4_addresses


def main() -> None:
    devices, os_ipv4_addresses = _discover_devices()
    router = Router(devices)
    controller = Controller(router, os_ipv4_addresses)
    try:
        router.start()
        GUI(controller).show()
    finally:
        router.stop()


if __name__ == "__main__":
    main()
