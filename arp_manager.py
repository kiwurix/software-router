from ipaddress import IPv4Address
from threading import Lock
from time import monotonic

from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet


class ArpManager:
    def __init__(self, entry_lifetime: int = 300, request_timeout: int = 5) -> None:
        self.entry_lifetime = entry_lifetime
        self.request_timeout = request_timeout
        self._table: dict[tuple[int, IPv4Address], tuple[str, float]] = {}
        self._pending: dict[tuple[int, IPv4Address], float] = {}
        self._lock = Lock()

    def generate_request(
        self, port_idx: int, src_mac: str, src_ip: IPv4Address, dst_ip: IPv4Address
    ) -> Packet:
        src_mac = src_mac.lower()
        frame = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1,
            hwsrc=src_mac,
            psrc=src_ip.compressed,
            hwdst="00:00:00:00:00:00",
            pdst=dst_ip.compressed,
        )
        with self._lock:
            self._pending[(port_idx, dst_ip)] = monotonic()
        return frame

    @staticmethod
    def generate_reply(
        src_mac: str, src_ip: IPv4Address, dst_mac: str, dst_ip: IPv4Address
    ) -> Packet:
        return Ether(src=src_mac, dst=dst_mac) / ARP(
            op=2,
            hwsrc=src_mac,
            psrc=src_ip.compressed,
            hwdst=dst_mac,
            pdst=dst_ip.compressed,
        )

    def complete_request(self, port_idx: int, dst_mac: str, dst_ip: IPv4Address) -> bool:
        key = (port_idx, dst_ip)
        with self._lock:
            if key not in self._pending:
                return False
            del self._pending[key]
            self._table[key] = (dst_mac, monotonic())
            return True

    def get_mac(self, port_idx: int, dst_ip: IPv4Address) -> str | None:
        key = (port_idx, dst_ip)
        with self._lock:
            entry = self._table.get(key)
            if entry is None:
                return None
            return entry[0]

    def get_table(self) -> list[tuple[int, IPv4Address, str, int]]:
        now = monotonic()
        with self._lock:
            return [
                (port_idx, dst_ip, mac, int(now - learned_at))
                for (port_idx, dst_ip), (mac, learned_at) in sorted(
                    self._table.items(), key=lambda item: (item[0][0], item[0][1])
                )
            ]

    def is_pending(self, port_idx: int, dst_ip: IPv4Address) -> bool:
        with self._lock:
            return (port_idx, dst_ip) in self._pending

    def clear_port(self, port_idx: int) -> None:
        with self._lock:
            self._table = {key: entry for key, entry in self._table.items() if key[0] != port_idx}
            self._pending = {key: sent_at for key, sent_at in self._pending.items() if key[0] != port_idx}

    def clear(self) -> None:
        with self._lock:
            self._table.clear()
            self._pending.clear()

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
            self._table = {
                key: entry
                for key, entry in self._table.items()
                if now - entry[1] < self.entry_lifetime
            }
            expired = {
                key for key, requested_at in self._pending.items()
                if now - requested_at >= self.request_timeout
            }
            for key in expired:
                del self._pending[key]
            return expired
