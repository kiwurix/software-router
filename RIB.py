from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network
from threading import Lock

from router_port import RouterPort


class RouteSource(StrEnum):
    CONNECTED = "C"
    STATIC = "S"
    RIP = "R"


@dataclass(frozen=True)
class Route:
    source: RouteSource
    AD: int
    network: IPv4Network
    output_port: RouterPort | None = None
    next_hop: IPv4Address | None = None
    metric: int = 0
    possibly_down: bool = False

    def __post_init__(self) -> None:
        if self.output_port is None and self.next_hop is None:
            raise ValueError("A route must specify an output port or next hop.")


class RIB:
    def __init__(self) -> None:
        self._candidates: dict[IPv4Network, list[Route]] = {}
        self._selected: dict[IPv4Network, Route] = {}
        self._lock = Lock()

    @staticmethod
    def _rib_update(func):
        def wrapper(self, *args, update=True, **kwargs):
            if update:
                with self._lock:
                    func(self, *args, **kwargs)
                    self._rebuild_selected()
            else:
                func(self, *args, **kwargs)

        return wrapper

    @_rib_update
    def update_port_routes(self, port: RouterPort) -> None:
        for network, candidates in tuple(self._candidates.items()):
            remaining = [
                route for route in candidates
                if route.source == RouteSource.STATIC or route.output_port is not port
            ]
            if remaining:
                self._candidates[network] = remaining
            else:
                del self._candidates[network]

        if port.ipv4 is not None:
            route = Route(
                source=RouteSource.CONNECTED, AD=0, network=port.ipv4.network, output_port=port
            )
            self._candidates.setdefault(route.network, []).append(route)

    @_rib_update
    def add_route(self, route: Route) -> None:
        self._candidates.setdefault(route.network, []).append(route)

    @_rib_update
    def remove_route(self, route: Route) -> None:
        candidates = self._candidates[route.network]
        candidates.remove(route)
        if not candidates:
            del self._candidates[route.network]

    @_rib_update
    def replace_route(self, old: Route, new: Route) -> None:
        self.remove_route(old, update=False)
        self.add_route(new, update=False)

    def lookup(self, ip: IPv4Address) -> Route | None:
        with self._lock:
            routes_by_network = self._selected
        return self._lookup(ip, routes_by_network)

    def resolve(self, ip: IPv4Address) -> tuple[RouterPort, IPv4Address] | None:
        with self._lock:
            routes_by_network = self._selected
        return self._resolve(ip, routes_by_network)

    def get_selected_routes(self) -> tuple[Route, ...]:
        with self._lock:
            return tuple(self._selected.values())

    def _rebuild_selected(self) -> None:
        ordered_candidates = {}
        for network, candidates in self._candidates.items():
            available = []
            for route in candidates:
                if route.possibly_down or (route.output_port is not None and route.output_port.ipv4 is None):
                    continue

                available.append(route)
            ordered_candidates[network] = sorted(available, key=lambda candidate: (candidate.AD, candidate.metric))

        selected: dict[IPv4Network, Route] = {}
        for network, candidates in ordered_candidates.items():
            for route in candidates:
                if route.source == RouteSource.CONNECTED:
                    selected[network] = route
                    break

        changed = True
        while changed:
            changed = False
            for network, candidates in ordered_candidates.items():
                previous = selected.get(network)
                for route in candidates:
                    if route is previous:
                        break
                    updated = selected | {network: route}
                    if route.output_port is None and self._resolve(route.next_hop, updated) is None:
                        continue
                    selected = updated
                    changed = True
                    break
        self._selected = selected

    @staticmethod
    def _lookup(ip: IPv4Address, routes_by_network: dict[IPv4Network, Route]) -> Route | None:
        for prefix_length in range(32, -1, -1):
            route = routes_by_network.get(IPv4Network((ip, prefix_length), strict=False))
            if route is not None:
                return route
        return None

    def _resolve(self, ip: IPv4Address, routes_by_network: dict[IPv4Network, Route]) -> tuple[RouterPort, IPv4Address] | None:
        visited: set[IPv4Network] = set()
        while True:
            route = self._lookup(ip, routes_by_network)
            if route is None or route.network in visited:
                return None
            visited.add(route.network)
            if route.output_port is not None:
                if route.output_port.ipv4 is None:
                    return None
                return route.output_port, route.next_hop if route.next_hop is not None else ip
            ip = route.next_hop

