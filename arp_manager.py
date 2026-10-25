from ipaddress import IPv4Address
from time import monotonic

from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from models import RouterPort


class ARPManager:
    def __init__(self) -> None:
        self._entry_lifetime = 300
        self._request_timeout = 2
        self._cache: dict[tuple[int, IPv4Address], tuple[str, float]] = {}
        self._pending_requests: dict[tuple[int, IPv4Address], float] = {}

    def build_request(self, port: RouterPort, dst_ip: IPv4Address) -> Packet:
        src_mac = port.mac.lower()
        frame = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1,
            hwsrc=src_mac,
            psrc=port.ipv4.ip.compressed,
            hwdst="00:00:00:00:00:00",
            pdst=dst_ip.compressed
        )
        self._pending_requests[(port.index, dst_ip)] = monotonic()
        return frame

    @staticmethod
    def build_reply(port: RouterPort, src_ip: IPv4Address, dst_mac: str, dst_ip: IPv4Address) -> Packet:
        return Ether(src=port.mac, dst=dst_mac) / ARP(
            op=2,
            hwsrc=port.mac,
            psrc=src_ip.compressed,
            hwdst=dst_mac,
            pdst=dst_ip.compressed
        )

    def complete_request(self, port: RouterPort, dst_mac: str, dst_ip: IPv4Address) -> bool:
        key = (port.index, dst_ip)
        if key not in self._pending_requests:
            return False
        del self._pending_requests[key]
        self._cache[key] = (dst_mac, monotonic())
        return True

    def get_mac(self, port: RouterPort, dst_ip: IPv4Address) -> str | None:
        key = (port.index, dst_ip)
        entry = self._cache.get(key)
        if entry is None:
            return None
        return entry[0]

    def get_table(self) -> list[tuple[int, IPv4Address, str, float]]:
        return [(port_index, dst_ip, mac, learned_at)
                for (port_index, dst_ip), (mac, learned_at) in self._cache.items()]

    def is_pending(self, port: RouterPort, dst_ip: IPv4Address) -> bool:
        return (port.index, dst_ip) in self._pending_requests

    def remove_entry(self, port: RouterPort, ip: IPv4Address) -> None:
        self._cache.pop((port.index, ip), None)

    def clear_port(self, port: RouterPort) -> None:
        self._cache = {key: entry for key, entry in self._cache.items() if key[0] != port.index}
        self._pending_requests = {key: requested_at for key, requested_at in self._pending_requests.items() if key[0] != port.index}

    def clear(self) -> None:
        self._cache.clear()
        self._pending_requests.clear()

    def get_timers(self) -> tuple[int, int]:
        return self._entry_lifetime, self._request_timeout

    def set_timers(self, entry_lifetime: int, request_timeout: int) -> None:
        self._entry_lifetime = entry_lifetime
        self._request_timeout = request_timeout

    def update_timers(self) -> set[tuple[int, IPv4Address]]:
        now = monotonic()
        self._cache = {
            key: entry
            for key, entry in self._cache.items()
            if now - entry[1] < self._entry_lifetime
        }
        expired = {
            key for key, requested_at in self._pending_requests.items()
            if now - requested_at >= self._request_timeout
        }
        for key in expired:
            del self._pending_requests[key]
        return expired
