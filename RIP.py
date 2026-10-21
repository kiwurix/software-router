from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from random import randint
from time import monotonic
from typing import TYPE_CHECKING

from scapy.interfaces import NetworkInterface
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.rip import RIP as RIPBase, RIPEntry
from scapy.packet import Packet

from RIB import RIB, Route, RouteSource

if TYPE_CHECKING:
    from router import RouterPort


@dataclass
class RIPRecord:
    metric: int
    next_hop: IPv4Address
    learned_port: RouterPort
    advertiser_ip: IPv4Address
    updated_at: float
    tag: int
    hold_down: bool = False


@dataclass(frozen=True)
class RIPAdvertisement:
    metric: int
    tag: int = 0
    learned_port: RouterPort | None = None


class RIP:
    def __init__(self, ports: list[RouterPort], rib: RIB,
                 send_frame: Callable[[Packet, NetworkInterface], bool], lock) -> None:
        self._ports = ports
        self._rib = rib
        self._send_frame = send_frame
        self._database: dict[IPv4Network, RIPRecord] = {}
        self._changed_advertisements: dict[IPv4Network, RIPAdvertisement] = {}
        self._update_started_at = monotonic()
        self._trigger_started_at: float | None = None
        self._trigger_delay = 0
        self._lock = lock

    @staticmethod
    def _locked(func):
        def wrapper(self, *args, **kwargs):
            with self._lock:
                func(self, *args, **kwargs)

        return wrapper

    @contextmanager
    def advertise_changes(self):
        with self._lock:
            before = self._get_advertisement_data()
            yield
            self._detect_and_advertise_changes(before)

    @_locked
    def handle(self, port: RouterPort, frame: Packet) -> None:
        if not port.rip_enabled:
            return

        message = frame[UDP].payload
        if not isinstance(message, RIPBase) or message.version != 2:
            return

        entries = []
        entry = message.payload
        while isinstance(entry, RIPEntry):
            entries.append(entry)
            entry = entry.payload

        if len(entries) > 25 or len(message.original) != 4 + 20 * len(entries):
            return

        if message.cmd == 1:
            self._handle_request(port, frame, entries)
        elif message.cmd == 2:
            self._handle_response(port, frame, entries)

    def _handle_request(self, port: RouterPort, frame: Packet, entries: list[RIPEntry]) -> None:
        if len(entries) == 1 and entries[0].AF == 0 and entries[0].metric == 16:
            advertisements = self._changed_advertisements | self._get_advertisement_data()
            self.send_response([port], advertisements, reply_to=frame)

    def _handle_response(self, port: RouterPort, frame: Packet, entries: list[RIPEntry]) -> None:
        advertiser_ip = IPv4Address(frame[IP].src)
        
        if frame[UDP].sport != 520 or advertiser_ip not in port.ipv4.network:
            return
        if any(other.ipv4 is not None and other.ipv4.ip == advertiser_ip for other in self._ports):
            return

        before = self._get_advertisement_data()
        now = monotonic()
        rib_changed = False
        for entry in entries:
            if entry.AF != 2 or not 1 <= entry.metric <= 16:
                continue
            network = self._parse_network(entry)
            if network is None:
                continue

            old_record = self._database.get(network)
            old_route = None

            if old_record is not None:
                if old_record.hold_down or \
                        old_record.advertiser_ip != advertiser_ip and entry.metric >= old_record.metric:

                    continue

                if old_record.metric < 16:
                    old_route = self._build_rib_route(network, old_record)



            if entry.metric == 16:
                if old_route:
                    old_record.metric = 16
                    self._rib.remove_route(old_route, update=False)
                    rib_changed = True
                continue

            next_hop = IPv4Address(entry.nextHop)
            if next_hop.is_unspecified or next_hop not in port.ipv4.network:
                next_hop = advertiser_ip

            record = RIPRecord(entry.metric, next_hop, port, advertiser_ip, now, entry.RouteTag)
            self._database[network] = record

            new_route = self._build_rib_route(network, record)

            if old_route:
                if new_route != old_route:
                    self._rib.replace_route(old_route, new_route, update=False)
                    rib_changed = True
            else:
                self._rib.add_route(new_route, update=False)
                rib_changed = True

        if rib_changed:
            self._rib.rebuild_selected()
        self._detect_and_advertise_changes(before)

    @_locked
    def update_timers(self) -> None:
        before = self._get_advertisement_data()
        now = monotonic()
        rib_changed = False
        for network, record in tuple(self._database.items()):
            elapsed = now - record.updated_at
            if elapsed >= 240:
                if record.metric < 16 or record.hold_down:
                    self._rib.remove_route(self._build_rib_route(network, record), update=False)
                    rib_changed = True
                del self._database[network]
            elif elapsed >= 180 and record.metric < 16:
                old_route = self._build_rib_route(network, record)
                record.metric = 16
                record.hold_down = True
                self._rib.replace_route(old_route, self._build_rib_route(network, record), update=False)
                rib_changed = True

        if rib_changed:
            self._rib.rebuild_selected()
        self._detect_and_advertise_changes(before)

    def invalidate_port_routes(self, port: RouterPort, *, update=True) -> None:
        rib_changed = False
        for network, record in self._database.items():
            if record.learned_port is not port:
                continue
            if record.metric < 16 or record.hold_down:
                self._rib.remove_route(self._build_rib_route(network, record), update=False)
                rib_changed = True
            record.metric = 16
            record.hold_down = False
        if update and rib_changed:
            self._rib.rebuild_selected()

    def _detect_and_advertise_changes(self, before: dict[IPv4Network, RIPAdvertisement]) -> None:
        after = self._get_advertisement_data()
        for network in before.keys() | after.keys():
            if before.get(network) != after.get(network):
                self._changed_advertisements[network] = after.get(network, RIPAdvertisement(metric=16))
        self._send_update()

    @staticmethod
    def _parse_network(entry: RIPEntry) -> IPv4Network | None:
        try:
            network = IPv4Network((entry.addr, entry.mask))
        except ValueError:
            return None
        return network

    @staticmethod
    def _build_rib_route(network: IPv4Network, record: RIPRecord) -> Route:
        return Route(
            source=RouteSource.RIP,
            AD=120,
            network=network,
            output_port=record.learned_port,
            next_hop=record.next_hop,
            metric=record.metric,
            possibly_down=record.hold_down,
        )

    def _get_advertisement_data(self) -> dict[IPv4Network, RIPAdvertisement]:
        advertisement_data = {}
        for route in self._rib.get_selected_routes():
            if route.source == RouteSource.CONNECTED and route.output_port.rip_enabled:
                advertisement_data[route.network] = RIPAdvertisement(metric=route.metric)
            elif route.source == RouteSource.RIP:
                record = self._database[route.network]
                advertisement_data[route.network] = RIPAdvertisement(
                    metric=record.metric, tag=record.tag, learned_port=record.learned_port
                )
        for network, record in self._database.items():
            if record.metric == 16:
                advertisement_data.setdefault(network, RIPAdvertisement(
                    metric=16, tag=record.tag, learned_port=record.learned_port
                ))
        return advertisement_data

    def send_request(self, ports: list[RouterPort]) -> None:
        entries = [RIPEntry(AF=0, metric=16)]
        for port in ports:
            if port.rip_enabled and port.ipv4 is not None:
                self._send_frame(self._build_frame(port, entries, command=1), port.device)

    def send_response(self, ports: list[RouterPort], advertisements: dict[IPv4Network, RIPAdvertisement],
                      reply_to: Packet | None = None) -> bool:
        frames = []
        for port in ports:
            if not port.rip_enabled or port.ipv4 is None:
                continue

            entries = []
            for network, advertisement in advertisements.items():
                if advertisement.learned_port is port:
                    continue

                entries.append(RIPEntry(
                    AF=2, RouteTag=advertisement.tag, addr=str(network.network_address), mask=str(network.netmask),
                    nextHop="0.0.0.0", metric=min(advertisement.metric + 1, 16),
                ))
                if len(entries) == 25:
                    frames.append((self._build_frame(port, entries, command=2, reply_to=reply_to), port.device))
                    entries.clear()

            if entries:
                frames.append((self._build_frame(port, entries, command=2, reply_to=reply_to), port.device))

        return all([self._send_frame(frame, device) for frame, device in frames])

    @staticmethod
    def _build_frame(port: RouterPort, entries: list[RIPEntry], command: int,
                     reply_to: Packet | None = None) -> Packet:
        if reply_to is None:
            dst_mac, dst_ip, dst_port = "01:00:5e:00:00:09", "224.0.0.9", 520
        else:
            dst_mac, dst_ip, dst_port = reply_to[Ether].src, reply_to[IP].src, reply_to[UDP].sport

        message = RIPBase(cmd=command, version=2)
        for entry in entries:
            message /= entry
        return (
                Ether(src=port.mac, dst=dst_mac)
                / IP(src=str(port.ipv4.ip), dst=dst_ip, ttl=1)
                / UDP(sport=520, dport=dst_port)
                / message
        )

    def _send_update(self) -> None:
        now = monotonic()
        if now - self._update_started_at >= 30:
            advertisements = self._changed_advertisements | self._get_advertisement_data()
            if self.send_response(self._ports, advertisements):
                self._changed_advertisements.clear()
                self._update_started_at = now
            return
        if not self._changed_advertisements:
            return
        if self._trigger_started_at is not None and now - self._trigger_started_at < self._trigger_delay:
            return
        if self.send_response(self._ports, self._changed_advertisements):
            self._changed_advertisements.clear()
            self._trigger_started_at = now
            self._trigger_delay = randint(1, 5)
