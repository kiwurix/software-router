from ipaddress import IPv4Address, IPv4Interface, ip_address, ip_network


class Controller:
    def __init__(self, router, os_ipv4):
        self.router = router
        self.os_ipv4 = frozenset(os_ipv4)

    @property
    def ports(self):
        return self.router.ports

    def set_address(self, port, address, mask):
        self._check_port(port)
        try:
            host = ip_address(address.strip())
            if not isinstance(host, IPv4Address):
                raise ValueError("IPv6 is not supported.")
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
            for index, other in enumerate(self.router.ports) if index != port
        ):
            raise ValueError("Another router interface already uses this IP address.")
        self.router.set_address(port, configured)
        return configured

    def clear_address(self, port):
        self._check_port(port)
        self.router.clear_address(port)

    def _check_port(self, port):
        if type(port) is not int or not 0 <= port < len(self.router.ports):
            raise ValueError("Choose an existing interface.")
