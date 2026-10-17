import logging
from ipaddress import IPv4Address, IPv4Interface
from threading import RLock, Thread
from time import sleep

from scapy.interfaces import NetworkInterface
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer, sendp
from scapy.utils import checksum

from arp_manager import ArpManager
from RIB import RIB
from router_port import RouterPort


class Router:
    def __init__(self, devices: list[NetworkInterface]) -> None:
        self._ports: list[RouterPort] = [
            RouterPort(index, device, device.mac.lower()) for index, device in enumerate(devices)
        ]
        self._own_macs = frozenset(port.mac for port in self._ports)
        self.rib = RIB()
        self.arp = ArpManager()
        self._pending_packets: dict[tuple[int, IPv4Address], list[IP]] = {}
        self._sniffer: AsyncSniffer | None = None
        self._timers_running = False
        self._timer_thread: Thread | None = None
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
        self._timers_running = True
        self._timer_thread = Thread(target=self._run_timers, daemon=True)
        self._timer_thread.start()

    def stop(self) -> None:
        self._timers_running = False
        try:
            if self._sniffer is not None and self._sniffer.running:
                self._sniffer.stop()
        finally:
            self._sniffer = None
            if self._timer_thread is not None:
                self._timer_thread.join()
                self._timer_thread = None

    def _run_timers(self) -> None:
        while self._timers_running:
            self.update_timers()
            sleep(1)

    def _handle_frame(self, frame: Packet) -> None:
        if Ether not in frame or frame[Ether].src.lower() in self._own_macs:
            return

        port = frame.sniffed_on
        dst_mac = frame[Ether].dst.lower()

        if ARP in frame:
            if dst_mac in (port.mac, "ff:ff:ff:ff:ff:ff"):
                self._handle_arp(port, frame)
        elif port.ipv4 is not None and IP in frame and dst_mac == port.mac:
            packet = frame[IP]
            header_length = packet.ihl * 4
            if packet.version != 4 or header_length < 20 or len(packet.original) < header_length:
                return
            if checksum(packet.original[:header_length]) != 0:
                return

            self._process_ipv4(packet)

    def _handle_arp(self, port: RouterPort, frame: Packet) -> None:
        with self._lock:
            ipv4 = port.ipv4
        if ipv4 is None:
            return

        arp_packet = frame[ARP]
        src_mac = arp_packet.hwsrc.lower()

        try:
            src_ip = IPv4Address(arp_packet.psrc)
            dst_ip = IPv4Address(arp_packet.pdst)
        except ValueError:
            return

        if arp_packet.op == 1:
            if dst_ip != ipv4.ip:
                with self._lock:
                    resolved = self.rib.resolve(dst_ip)
                if resolved is None or resolved[0] is port:
                    return

            reply = self.arp.build_reply(port.mac, dst_ip, src_mac, src_ip)
            self._send_frame(reply, port.device)
            return

        if arp_packet.op == 2:
            if self.arp.complete_request(port.index, src_mac, src_ip):
                key = (port.index, src_ip)
                with self._lock:
                    pending_packets = self._pending_packets.pop(key, [])
                for ip_packet in pending_packets:
                    self._process_ipv4(ip_packet)

    def _process_ipv4(self, packet: IP) -> None:
        if packet.ttl <= 1:
            return

        dst_ip = IPv4Address(packet.dst)
        request = None

        with self._lock:
            if any(port.ipv4 is not None and port.ipv4.ip == dst_ip for port in self._ports):
                return

            resolved = self.rib.resolve(dst_ip)
            if resolved is None:
                return

            port, next_hop = resolved

            dst_mac = self.arp.get_mac(port.index, next_hop)

            if dst_mac is None:
                key = (port.index, next_hop)
                self._pending_packets.setdefault(key, []).append(packet)

                if not self.arp.is_pending(port.index, next_hop):
                    request = self.arp.build_request(
                        port.index, port.mac, port.ipv4.ip, next_hop
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

    def set_address(self, port_index: int, ipv4: IPv4Interface) -> None:
        with self._lock:
            self._ports[port_index].ipv4 = ipv4
            self.rib.update_port_routes(self._ports[port_index])
            self.arp.clear_port(port_index)
            self._pending_packets = {key: packets for key, packets in self._pending_packets.items() if key[0] != port_index}

    def clear_address(self, port_index: int) -> None:
        with self._lock:
            self._ports[port_index].ipv4 = None
            self.rib.update_port_routes(self._ports[port_index])
            self.arp.clear_port(port_index)
            self._pending_packets = {key: packets for key, packets in self._pending_packets.items() if key[0] != port_index}

    def update_timers(self) -> None:
        with self._lock:
            expired = self.arp.update_timers()
            for key in expired:
                self._pending_packets.pop(key, None)

    def get_arp_table(self) -> list[tuple[int, IPv4Address, str, int]]:
        return self.arp.get_table()

    def get_arp_timers(self) -> tuple[int, int]:
        return self.arp.get_timers()

    def set_arp_timers(self, entry_lifetime: int, request_timeout: int) -> None:
        self.arp.set_timers(entry_lifetime, request_timeout)

    def send_arp_request(self, port_index: int, dst_ip: IPv4Address) -> bool:
        with self._lock:
            port = self._ports[port_index]
            ipv4 = port.ipv4
            if ipv4 is None:
                raise ValueError("Selected interface has no IPv4 address.")
            request = self.arp.build_request(port_index, port.mac, ipv4.ip, dst_ip)

        return self._send_frame(request, port.device)

    def clear_arp(self) -> None:
        with self._lock:
            self.arp.clear()
            self._pending_packets.clear()
