from dataclasses import dataclass
from ipaddress import IPv4Interface

from scapy.interfaces import NetworkInterface


@dataclass
class RouterPort:
    index: int
    device: NetworkInterface
    mac: str
    interface: IPv4Interface | None = None
