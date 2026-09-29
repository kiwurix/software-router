from ipaddress import IPv4Address, IPv4Interface, ip_network
from collections.abc import Iterable

from router import Router
from router_port import RouterPort


class Controller:
    def __init__(self, router: Router, os_ipv4: Iterable[IPv4Address]) -> None:
        self.router = router
        self.os_ipv4 = frozenset(os_ipv4)

    @property
    def ports(self) -> tuple[RouterPort, ...]:
        return self.router.ports

    def set_address(self, port_idx: int, address: str, mask: str) -> IPv4Interface:
        self._check_port(port_idx)
        try:
            host = IPv4Address(address.strip())
            raw_mask = mask.strip().removeprefix("/")
            prefix = ip_network(f"0.0.0.0/{raw_mask}").prefixlen
            configured = IPv4Interface(f"{host}/{prefix}")
        except ValueError as exc:
            raise ValueError("Enter a valid IPv4 address and subnet mask.") from exc

        if host.is_unspecified or host.is_loopback or host.is_multicast or host.is_reserved:
            raise ValueError("This address cannot be used on a router interface.")
        if prefix < 31 and host in (configured.network.network_address, configured.network.broadcast_address):
            raise ValueError("Choose a host address, not a network or broadcast address.")
        if host in self.os_ipv4:
            raise ValueError("Windows already uses this IP address.")
        if any(
            other.interface is not None and other.interface.ip == host
            for index, other in enumerate(self.router.ports) if index != port_idx
        ):
            raise ValueError("Another router interface already uses this IP address.")
        self.router.set_address(port_idx, configured)
        return configured

    def clear_address(self, port_idx: int) -> None:
        self._check_port(port_idx)
        self.router.clear_address(port_idx)

    def update_timers(self) -> None:
        self.router.update_timers()

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

    def send_arp_request(self, port_idx: int, address: str) -> bool:
        self._check_port(port_idx)
        try:
            dst_ip = IPv4Address(address.strip())
        except ValueError as exc:
            raise ValueError("Enter a valid target IPv4 address.") from exc
        return self.router.send_arp_request(port_idx, dst_ip)

    def clear_arp(self) -> None:
        self.router.clear_arp()

    def _check_port(self, port_idx: int) -> None:
        if type(port_idx) is not int or not 0 <= port_idx < len(self.router.ports):
            raise ValueError("Choose an existing interface.")
