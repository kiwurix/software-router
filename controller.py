from ipaddress import IPv4Address, IPv4Interface, IPv4Network, ip_network
from collections.abc import Iterable

from router import Router
from RIB import Route, RouteSource
from RIP import RIPRecord
from models import RIPTimers, RouterPort


class Controller:
    def __init__(self, router: Router, os_ipv4_addresses: Iterable[IPv4Address]) -> None:
        self.router = router
        self.os_ipv4_addresses = frozenset(os_ipv4_addresses)

    @property
    def ports(self) -> tuple[RouterPort, ...]:
        return self.router.ports

    def set_address(self, port_index: int, address: str, netmask: str) -> None:
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

    def clear_address(self, port_index: int) -> None:
        self._check_port(port_index)
        self.router.set_address(port_index, None)

    def set_rip_enabled(self, port_index: int, enabled: bool) -> None:
        self._check_port(port_index)
        self.router.set_rip_enabled(port_index, enabled)

    def add_static_route(self, network: str, port_index: int | None,
                         next_hop: str, AD: str) -> Route:
        try:
            destination = IPv4Network(network.strip())
            neighbour = IPv4Address(next_hop.strip()) if next_hop.strip() else None
            distance = int(AD.strip())
        except ValueError as exc:
            raise ValueError("Enter a valid network/prefix, next-hop IPv4 address and administrative distance.") from exc
        if not 1 <= distance <= 254:
            raise ValueError("Administrative distance must be between 1 and 254.")
        output_port = None
        if port_index is not None:
            self._check_port(port_index)
            output_port = self.router.ports[port_index]
        if neighbour is not None:
            if neighbour.is_unspecified or neighbour.is_loopback or neighbour.is_multicast or neighbour.is_reserved:
                raise ValueError("Choose a unicast next-hop IPv4 address.")
            if any(port.ipv4 is not None and port.ipv4.ip == neighbour for port in self.router.ports):
                raise ValueError("The next hop cannot be one of the router's own addresses.")
        route = Route(RouteSource.STATIC, distance, destination, output_port, neighbour)
        if route in self.router.get_static_routes():
            raise ValueError("This static route is already configured.")
        self.router.add_static_route(route)
        return route

    def remove_static_route(self, route: Route) -> None:
        if route not in self.router.get_static_routes():
            raise ValueError("Select a configured static route.")
        self.router.remove_static_route(route)

    def get_selected_routes(self) -> tuple[Route, ...]:
        return self.router.get_selected_routes()

    def get_static_routes(self) -> tuple[Route, ...]:
        return self.router.get_static_routes()

    def get_arp_table(self) -> list[tuple[int, IPv4Address, str, int]]:
        return self.router.get_arp_table()

    def remove_arp_entry(self, port_index: int, address: str) -> None:
        self._check_port(port_index)
        self.router.remove_arp_entry(port_index, IPv4Address(address.strip()))

    def get_arp_timers(self) -> tuple[int, int]:
        return self.router.get_arp_timers()

    def get_rip_timers(self) -> RIPTimers:
        return self.router.get_rip_timers()

    def get_rip_database(self) -> dict[IPv4Network, RIPRecord]:
        return self.router.get_rip_database()

    def set_rip_timers(self, update_interval: str, invalid_timeout: str, hold_down_timeout: str, flush_timeout: str) -> None:
        try:
            update = int(update_interval.strip())
            invalid = int(invalid_timeout.strip())
            hold_down = int(hold_down_timeout.strip())
            flush = int(flush_timeout.strip())
        except ValueError as exc:
            raise ValueError("Enter whole seconds for RIP timers.") from exc
        if update <= 0 or invalid <= 0 or flush <= 0 or hold_down < 0:
            raise ValueError("Update, Invalid and Flush must be positive. Hold-down may be zero.")
        if flush < invalid:
            raise ValueError("Flush must be greater than or equal to Invalid.")
        self.router.set_rip_timers(RIPTimers(update, invalid, hold_down, flush))

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
