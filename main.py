from ipaddress import IPv4Address
from subprocess import run

from scapy.arch.windows import get_windows_if_list
from scapy.interfaces import NetworkInterface, dev_from_index

from controller import Controller
from gui import GUI
from router import Router


def _discover_devices() -> tuple[list[NetworkInterface], set[IPv4Address]]:
    devices: list[NetworkInterface] = []
    os_ipv4_addresses: set[IPv4Address] = set()
    result = run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-NetAdapter -Physical | Select-Object -ExpandProperty ifIndex",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    physical_adapter_indices = {int(value) for value in result.stdout.split()}

    for adapter in get_windows_if_list():
        for value in adapter.get("ips", []):
            try:
                address = IPv4Address(value)
            except ValueError:
                continue
            os_ipv4_addresses.add(address)

        if adapter.get("type") != 6 or adapter.get("index") not in physical_adapter_indices:
            continue
        try:
            adapter_index = adapter["index"]
            device = dev_from_index(adapter_index)
        except (KeyError, ValueError, OSError):
            continue
        if "WIRELESS" in device.flags or not device.mac:
            continue
        devices.append(device)

    return devices, os_ipv4_addresses


def main() -> None:
    devices, os_ipv4_addresses = _discover_devices()
    router = Router(devices)
    controller = Controller(router, os_ipv4_addresses)
    router.start()
    try:
        GUI(controller).show()
    finally:
        router.stop()


if __name__ == "__main__":
    main()
