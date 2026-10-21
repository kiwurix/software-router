from ipaddress import IPv4Address
from time import monotonic

from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet


class ArpManager:
    def __init__(self, lock, entry_lifetime: int = 300, request_timeout: int = 5) -> None:
        self.entry_lifetime = entry_lifetime
        self.request_timeout = request_timeout
        self._cache: dict[tuple[int, IPv4Address], tuple[str, float]] = {}
        self._pending_requests: dict[tuple[int, IPv4Address], float] = {}
        self._lock = lock

    def build_request(self, port_index: int, src_mac: str, src_ip: IPv4Address, dst_ip: IPv4Address) -> Packet:
        src_mac = src_mac.lower()
        frame = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1,
            hwsrc=src_mac,
            psrc=src_ip.compressed,
            hwdst="00:00:00:00:00:00",
            pdst=dst_ip.compressed,
        )
        with self._lock:
            self._pending_requests[(port_index, dst_ip)] = monotonic()
        return frame

    @staticmethod
    def build_reply(src_mac: str, src_ip: IPv4Address, dst_mac: str, dst_ip: IPv4Address) -> Packet:
        return Ether(src=src_mac, dst=dst_mac) / ARP(
            op=2,
            hwsrc=src_mac,
            psrc=src_ip.compressed,
            hwdst=dst_mac,
            pdst=dst_ip.compressed,
        )

    def complete_request(self, port_index: int, dst_mac: str, dst_ip: IPv4Address) -> bool:
        key = (port_index, dst_ip)
        with self._lock:
            if key not in self._pending_requests:
                return False
            del self._pending_requests[key]
            self._cache[key] = (dst_mac, monotonic())
            return True

    def get_mac(self, port_index: int, dst_ip: IPv4Address) -> str | None:
        key = (port_index, dst_ip)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            return entry[0]

    def get_table(self) -> list[tuple[int, IPv4Address, str, int]]:
        now = monotonic()
        with self._lock:
            entries = tuple(self._cache.items())
        return [
            (port_index, dst_ip, mac, int(now - learned_at))
            for (port_index, dst_ip), (mac, learned_at) in sorted(
                entries, key=lambda item: (item[0][0], item[0][1])
            )
        ]

    def is_pending(self, port_index: int, dst_ip: IPv4Address) -> bool:
        with self._lock:
            return (port_index, dst_ip) in self._pending_requests

    def remove_entry(self, port_index: int, ip: IPv4Address) -> None:
        with self._lock:
            self._cache.pop((port_index, ip), None)

    def clear_port(self, port_index: int) -> None:
        with self._lock:
            self._cache = {key: entry for key, entry in self._cache.items() if key[0] != port_index}
            self._pending_requests = {key: requested_at for key, requested_at in self._pending_requests.items() if key[0] != port_index}

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._pending_requests.clear()

    def get_timers(self) -> tuple[int, int]:
        with self._lock:
            return self.entry_lifetime, self.request_timeout

    def set_timers(self, entry_lifetime: int, request_timeout: int) -> None:
        with self._lock:
            self.entry_lifetime = entry_lifetime
            self.request_timeout = request_timeout

    def update_timers(self) -> set[tuple[int, IPv4Address]]:
        now = monotonic()
        with self._lock:
            self._cache = {
                key: entry
                for key, entry in self._cache.items()
                if now - entry[1] < self.entry_lifetime
            }
            expired = {
                key for key, requested_at in self._pending_requests.items()
                if now - requested_at >= self.request_timeout
            }
            for key in expired:
                del self._pending_requests[key]
            return expired
