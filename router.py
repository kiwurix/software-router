import logging
from ipaddress import IPv4Address, IPv4Interface
from threading import RLock

from scapy.interfaces import NetworkInterface
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer, sendp

from arp_manager import ArpManager
from router_port import RouterPort
from routing_table import RoutingTable


class Router:
    def __init__(self, devices: list[NetworkInterface]) -> None:
        self._ports: list[RouterPort] = [
            RouterPort(index, device, device.mac.lower()) for index, device in enumerate(devices)
        ]
        self.macs = frozenset(port.mac for port in self._ports)
        self.routing_table = RoutingTable(self._ports)
        self.arp = ArpManager()
        self._waiting: dict[tuple[int, IPv4Address], list[IP]] = {}
        self._sniffer: AsyncSniffer | None = None
        self._lock = RLock()

    def start(self) -> None:
        if not self._ports or self._sniffer is not None:
            return
        device_name_to_port = {port.device.network_name: port for port in self._ports}
        self._sniffer = AsyncSniffer(
            iface=device_name_to_port,
            prn=self._handle_frame,
            store=False,
        )
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is not None and self._sniffer.running:
            self._sniffer.stop()
        self._sniffer = None

    def _handle_frame(self, frame: Packet) -> None:
        if Ether not in frame or frame[Ether].src.lower() in self.macs:
            return

        port = frame.sniffed_on

        if ARP in frame:
            self._handle_arp(port, frame)
        elif port.interface is not None and IP in frame and frame[Ether].dst.lower() == port.mac:

            self._process_ipv4(frame[IP])

    def _handle_arp(self, port: RouterPort, frame: Packet) -> None:
        with self._lock:
            interface = port.interface
        if interface is None:
            return

        packet = frame[ARP]
        src_mac = packet.hwsrc.lower()

        try:
            src_ip = IPv4Address(packet.psrc)
            dst_ip = IPv4Address(packet.pdst)
        except ValueError:
            return

        if packet.op == 1:
            if dst_ip != interface.ip:
                with self._lock:
                    route = self.routing_table.lookup(dst_ip)
                if route is None or route.port is port:
                    return

            reply = self.arp.generate_reply(port.mac, dst_ip, src_mac, src_ip)
            self._send_frame(reply, port.device)
            return

        if packet.op == 2:
            if self.arp.complete_request(port.index, src_mac, src_ip):
                key = (port.index, src_ip)
                with self._lock:
                    waiting = self._waiting.pop(key, [])
                for ip_packet in waiting:
                    self._process_ipv4(ip_packet)

    def _process_ipv4(self, packet: IP) -> None:
        if packet.ttl <= 1:
            return

        dst_ip = IPv4Address(packet.dst)
        request = None

        with self._lock:
            if any(port.interface is not None and port.interface.ip == dst_ip for port in self._ports):
                return

            route = self.routing_table.lookup(dst_ip)
            if route is None:
                return

            port = route.port

            next_hop = route.next_hop or dst_ip

            dst_mac = self.arp.get_mac(port.index, next_hop)

            if dst_mac is None:
                key = (port.index, next_hop)
                self._waiting.setdefault(key, []).append(packet)

                if not self.arp.is_pending(port.index, next_hop):
                    request = self.arp.generate_request(
                        port.index, port.mac, port.interface.ip, next_hop
                    )

        if dst_mac is not None:
            self._send_ipv4(packet, port.device, port.mac, dst_mac)
        elif request is not None:
            self._send_frame(request, port.device)


    def _send_ipv4(self, packet: IP, device: NetworkInterface, src_mac: str, dst_mac: str) -> None:
        packet.ttl -= 1
        del packet.chksum
        self._send_frame(Ether(src=src_mac, dst=dst_mac) / packet, device)

    @staticmethod
    def _send_frame(frame: Packet, device: NetworkInterface) -> bool:
        try:
            sendp(frame, iface=device, verbose=False)
            return True
        except Exception:
            logging.exception("Failed to send frame")
            return False

    @property
    def ports(self) -> tuple[RouterPort, ...]:
        with self._lock:
            return tuple(self._ports)

    def set_address(self, port_idx: int, interface: IPv4Interface) -> None:
        with self._lock:
            self._ports[port_idx].interface = interface
            self.arp.clear_port(port_idx)
            self._waiting = {key: packets for key, packets in self._waiting.items() if key[0] != port_idx}

    def clear_address(self, port_idx: int) -> None:
        with self._lock:
            self._ports[port_idx].interface = None
            self.arp.clear_port(port_idx)
            self._waiting = {key: packets for key, packets in self._waiting.items() if key[0] != port_idx}

    def update_timers(self) -> None:
        with self._lock:
            expired = self.arp.update_timers()
            for key in expired:
                self._waiting.pop(key, None)

    def get_arp_table(self) -> list[tuple[int, IPv4Address, str, int]]:
        return self.arp.get_table()

    def get_arp_timers(self) -> tuple[int, int]:
        return self.arp.get_timers()

    def set_arp_timers(self, entry_lifetime: int, request_timeout: int) -> None:
        self.arp.set_timers(entry_lifetime, request_timeout)

    def send_arp_request(self, port_idx: int, dst_ip: IPv4Address) -> bool:
        with self._lock:
            port = self._ports[port_idx]
            interface = port.interface
            if interface is None:
                raise ValueError("Selected interface has no IPv4 address.")
            request = self.arp.generate_request(port_idx, port.mac, interface.ip, dst_ip)

        return self._send_frame(request, port.device)

    def clear_arp(self) -> None:
        with self._lock:
            self.arp.clear()
            self._waiting.clear()
