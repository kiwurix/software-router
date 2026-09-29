from dataclasses import dataclass
from ipaddress import IPv4Interface, ip_address
from threading import RLock


@dataclass
class RouterPort:
    device: object
    mac: str
    interface: IPv4Interface | None = None


class Router:
    def __init__(self, devices):
        self._ports = [RouterPort(device, device.mac.lower()) for device in devices]
        self.macs = frozenset(port.mac for port in self._ports)
        self._lock = RLock()

    @property
    def ports(self):
        with self._lock:
            return tuple(self._ports)

    def set_address(self, port: int, interface: IPv4Interface):
        with self._lock:
            self._ports[port].interface = interface

    def clear_address(self, port: int):
        with self._lock:
            self._ports[port].interface = None

    def owns_address(self, address):
        address = ip_address(address)
        with self._lock:
            return any(port.interface is not None and port.interface.ip == address for port in self._ports)
