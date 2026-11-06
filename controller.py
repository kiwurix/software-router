from ipaddress import IPv4Address, IPv4Interface, IPv4Network

from dhcp_manager import DHCPAllocationType, DHCPRecord
from models import RouterPort
from rib import Route, RouteSource
from rip_manager import RIPRecord, RIPTimers
from router import Router


class Controller:
    def __init__(self, router: Router, os_ipv4_addresses: set[IPv4Address]) -> None:
        self._router = router
        self._os_ipv4_addresses = frozenset(os_ipv4_addresses)

    @property
    def ports(self) -> tuple[RouterPort, ...]:
        return self._router.ports

    def set_address(self, port_index: int, address: str, netmask: str) -> None:
        self._check_port(port_index)
        ipv4 = self._parse_address(address, netmask)
        ip = ipv4.ip
        prefix_length = ipv4.network.prefixlen

        if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_reserved:
            raise ValueError("This address cannot be used on a router interface.")
        if prefix_length < 31 and ip in (ipv4.network.network_address, ipv4.network.broadcast_address):
            raise ValueError("Choose a host address, not a network or broadcast address.")
        if ip in self._os_ipv4_addresses:
            raise ValueError("Windows already uses this IP address.")
        if any(
                other.ipv4 is not None and other.ipv4.ip == ip
                for index, other in enumerate(self._router.ports) if index != port_index
        ):
            raise ValueError("Another router interface already uses this IP address.")
        self._router.set_address(port_index, ipv4)

    def clear_address(self, port_index: int) -> None:
        self._check_port(port_index)
        self._router.set_address(port_index, None)

    def set_rip_enabled(self, port_index: int, enabled: bool) -> None:
        self._check_port(port_index)
        self._router.set_rip_enabled(port_index, enabled)

    def add_static_route(self, address: str, netmask: str, port_index: int | None,
                         next_hop: str, AD: str) -> Route:
        try:
            network = self._parse_address(address, netmask).network
            next_hop_ip = IPv4Address(next_hop.strip()) if next_hop.strip() else None
            administrative_distance = int(AD.strip())
        except ValueError as exc:
            raise ValueError("Enter a valid IPv4 address, subnet mask, next hop and administrative distance.") from exc
        if not 1 <= administrative_distance <= 254:
            raise ValueError("Administrative distance must be between 1 and 254.")
        output_port = None
        if port_index is not None:
            self._check_port(port_index)
            output_port = self._router.ports[port_index]
        if next_hop_ip is not None:
            if next_hop_ip.is_unspecified or next_hop_ip.is_loopback or next_hop_ip.is_multicast or next_hop_ip.is_reserved:
                raise ValueError("Choose a unicast next-hop IPv4 address.")
            if any(port.ipv4 is not None and port.ipv4.ip == next_hop_ip for port in self._router.ports):
                raise ValueError("The next hop cannot be one of the router's own addresses.")
        route = Route(RouteSource.STATIC, administrative_distance, network, output_port, next_hop_ip)
        if route in self._router.get_static_routes():
            raise ValueError("This static route is already configured.")
        self._router.add_static_route(route)
        return route

    def remove_static_route(self, route: Route) -> None:
        if route not in self._router.get_static_routes():
            raise ValueError("Select a configured static route.")
        self._router.remove_static_route(route)

    def get_selected_routes(self) -> tuple[Route, ...]:
        return self._router.get_selected_routes()

    def get_static_routes(self) -> tuple[Route, ...]:
        return self._router.get_static_routes()

    def get_arp_table(self) -> list[tuple[int, IPv4Address, str, float]]:
        return self._router.get_arp_table()

    def get_arp_timers(self) -> tuple[int, int]:
        return self._router.get_arp_timers()

    def get_rip_timers(self) -> RIPTimers:
        return self._router.get_rip_timers()

    def get_rip_database(self) -> dict[IPv4Network, RIPRecord]:
        return self._router.get_rip_database()

    def set_rip_timers(self, update_interval: str, invalid_timeout: str, hold_down_timeout: str,
                       flush_timeout: str) -> None:
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
        self._router.set_rip_timers(RIPTimers(update, invalid, hold_down, flush))

    def set_arp_timers(self, entry_lifetime: str, request_timeout: str) -> None:
        try:
            lifetime = int(entry_lifetime.strip())
            timeout = int(request_timeout.strip())
        except ValueError as exc:
            raise ValueError("Enter positive whole seconds for both ARP timers.") from exc
        if lifetime <= 0 or timeout <= 0:
            raise ValueError("Enter positive whole seconds for both ARP timers.")
        self._router.set_arp_timers(lifetime, timeout)

    def send_arp_request(self, port_index: int, address: str) -> bool:
        self._check_port(port_index)
        try:
            dst_ip = IPv4Address(address.strip())
        except ValueError as exc:
            raise ValueError("Enter a valid target IPv4 address.") from exc
        return self._router.send_arp_request(port_index, dst_ip)

    def clear_arp(self) -> None:
        self._router.clear_arp()

    def _check_port(self, port_index: int) -> None:
        if type(port_index) is not int or not 0 <= port_index < len(self._router.ports):
            raise ValueError("Choose an existing interface.")

    def get_dhcp_settings(self) -> tuple[DHCPAllocationType, int, int]:
        return self._router.get_dhcp_settings()

    def set_dhcp_settings(self, allocation_mode: str, offer_timeout: str, lease_time: str) -> None:
        try:
            mode = DHCPAllocationType[allocation_mode.strip().upper()]
            offer = int(offer_timeout.strip())
            lease = int(lease_time.strip())
        except (KeyError, ValueError) as exc:
            raise ValueError("Choose an allocation mode and enter whole seconds for DHCP timers.") from exc
        if offer <= 0 or not 1 <= lease < 0xffffffff:
            raise ValueError("Offer timeout must be positive. Lease time must be between 1 and 4294967294 seconds.")
        self._router.set_dhcp_settings(mode, offer, lease)

    def get_dhcp_assignments(self) -> dict[tuple[int, bytes], DHCPRecord]:
        return self._router.get_dhcp_assignments()

    def get_dhcp_manual_bindings(self) -> dict[bytes, IPv4Address]:
        return self._router.get_dhcp_manual_bindings()

    def set_dhcp_manual_binding(self, client_mac: str, address: str) -> bytes:
        try:
            mac = bytes.fromhex(client_mac.strip().replace(":", "").replace("-", ""))
            ip = IPv4Address(address.strip())
        except ValueError as exc:
            raise ValueError("Enter a valid MAC address and IPv4 address.") from exc
        if len(mac) != 6 or mac == bytes(6) or mac[0] & 1:
            raise ValueError("Enter a unicast MAC address with six bytes.")
        if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_reserved:
            raise ValueError("Choose a unicast IPv4 address.")
        self._router.set_dhcp_manual_binding(mac, ip)
        return mac

    def remove_dhcp_manual_binding(self, client_mac: str) -> None:
        self._router.remove_dhcp_manual_binding(bytes.fromhex(client_mac.replace(":", "")))

    @staticmethod
    def _parse_address(address: str, netmask: str) -> IPv4Interface:
        try:
            return IPv4Interface(f"{address.strip()}/{netmask.strip().removeprefix('/')}")
        except ValueError as exc:
            raise ValueError("Enter a valid IPv4 address and subnet mask.") from exc
