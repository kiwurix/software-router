from ipaddress import IPv4Address, IPv4Interface, ip_network
from collections.abc import Iterable

from router import Router, RouterPort


class Controller:
    def __init__(self, router: Router, os_ipv4_addresses: Iterable[IPv4Address]) -> None:
        self.router = router
        self.os_ipv4_addresses = frozenset(os_ipv4_addresses)

    @property
    def ports(self) -> tuple[RouterPort, ...]:
        return self.router.ports

    def set_address(self, port_index: int, address: str, netmask: str) -> IPv4Interface:
        self._check_port(port_index)
        try:
            ip = IPv4Address(address.strip())
            raw_netmask = netmask.strip().removeprefix("/")
            prefix_length = ip_network(f"0.0.0.0/{raw_netmask}").prefixlen
            ipv4 = IPv4Interface(f"{ip}/{prefix_length}")
        except ValueError as exc:
            raise ValueError("Enter a valid IPv4 address and subnet mask.") from exc

        if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_reserved:
            raise ValueError("This address cannot be used on a router interface.")
        if prefix_length < 31 and ip in (ipv4.network.network_address, ipv4.network.broadcast_address):
            raise ValueError("Choose a host address, not a network or broadcast address.")
        if ip in self.os_ipv4_addresses:
            raise ValueError("Windows already uses this IP address.")
        if any(
            other.ipv4 is not None and other.ipv4.ip == ip
            for index, other in enumerate(self.router.ports) if index != port_index
        ):
            raise ValueError("Another router interface already uses this IP address.")
        self.router.set_address(port_index, ipv4)
        return ipv4

    def clear_address(self, port_index: int) -> None:
        self._check_port(port_index)
        self.router.clear_address(port_index)

    def get_arp_table(self) -> list[tuple[int, IPv4Address, str, int]]:
        return self.router.get_arp_table()

    def get_arp_timers(self) -> tuple[int, int]:
        return self.router.get_arp_timers()

    def set_arp_timers(self, entry_lifetime: str, request_timeout: str) -> None:
        try:
            lifetime = int(entry_lifetime.strip())
            timeout = int(request_timeout.strip())
        except ValueError as exc:
            raise ValueError("Enter positive whole seconds for both ARP timers.") from exc
        if lifetime <= 0 or timeout <= 0:
            raise ValueError("Enter positive whole seconds for both ARP timers.")
        self.router.set_arp_timers(lifetime, timeout)

    def send_arp_request(self, port_index: int, address: str) -> bool:
        self._check_port(port_index)
        try:
            dst_ip = IPv4Address(address.strip())
        except ValueError as exc:
            raise ValueError("Enter a valid target IPv4 address.") from exc
        return self.router.send_arp_request(port_index, dst_ip)

    def clear_arp(self) -> None:
        self.router.clear_arp()

    def _check_port(self, port_index: int) -> None:
        if type(port_index) is not int or not 0 <= port_index < len(self.router.ports):
            raise ValueError("Choose an existing interface.")
