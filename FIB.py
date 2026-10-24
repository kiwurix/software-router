from collections.abc import Collection
from ipaddress import IPv4Address, IPv4Network

from models import FIBEntry, RouterPort


def lookup_network(ip: IPv4Address, networks: Collection[IPv4Network]) -> IPv4Network | None:
    for prefix_length in range(32, -1, -1):
        network = IPv4Network((ip, prefix_length), strict=False)
        if network in networks:
            return network
    return None


class FIB:
    def __init__(self) -> None:
        self._entries: dict[IPv4Network, FIBEntry] = {}

    def replace(self, entries: dict[IPv4Network, FIBEntry]) -> None:
        self._entries = entries

    def lookup(self, ip: IPv4Address) -> tuple[RouterPort, IPv4Address] | None:
        entries = self._entries
        network = lookup_network(ip, entries)
        if network is None:
            return None
        entry = entries[network]
        return entry.output_port, entry.next_hop if entry.next_hop is not None else ip
