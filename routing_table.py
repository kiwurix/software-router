from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network

from router_port import RouterPort


@dataclass(frozen=True)
class Route:
    network: IPv4Network
    port: RouterPort
    next_hop: IPv4Address | None = None


class RoutingTable:
    def __init__(self, ports: list[RouterPort]) -> None:
        self._ports = ports

    def get_routes(self) -> tuple[Route, ...]:
        return tuple(
            Route(port.interface.network, port)
            for port in self._ports
            if port.interface is not None
        )

    def lookup(self, dst_ip: IPv4Address) -> Route | None:
        best: Route | None = None
        for route in self.get_routes():
            if dst_ip in route.network and (
                best is None or route.network.prefixlen > best.network.prefixlen
            ):
                best = route
        return best
