from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface

from scapy.interfaces import NetworkInterface


@dataclass
class RouterPort:
    index: int
    device: NetworkInterface
    mac: str
    ipv4: IPv4Interface | None = None
    rip_enabled: bool = False


@dataclass(frozen=True)
class FIBEntry:
    output_port: RouterPort
    next_hop: IPv4Address | None
