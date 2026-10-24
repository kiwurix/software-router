import logging
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from threading import RLock, Thread
from time import sleep

from scapy.interfaces import NetworkInterface
from scapy.layers.inet import ICMP, IP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer, sendp
from scapy.utils import checksum

from arp_manager import ArpManager
from FIB import FIB
from RIB import RIB, Route
from RIP import RIP, RIPRecord
from locking import locked
from models import RIPTimers, RouterPort


class Router:
    def __init__(self, devices: list[NetworkInterface]) -> None:
        self._ports: list[RouterPort] = [
            RouterPort(index, device, device.mac.lower()) for index, device in enumerate(devices)
        ]
        self._own_macs = frozenset(port.mac for port in self._ports)
        self._lock = RLock()
        self.fib = FIB()
        self.rib = RIB(self.fib)
        self.rip = RIP(self._ports, self.rib, self._send_frame)
        self.arp = ArpManager()
        self._pending_packets: dict[tuple[int, IPv4Address], list[IP]] = {}
        self._sniffer: AsyncSniffer | None = None
        self._timers_running = False
        self._timer_thread: Thread | None = None

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
            self._update_timers()
            sleep(1)

    @locked
    def _handle_frame(self, frame: Packet) -> None:
        port = frame.sniffed_on
        frame = frame.getlayer(Ether)

        if not frame or frame.src in self._own_macs:
            return

        if port.ipv4 is None:
            return

        dst_mac = frame.dst.lower()
        local_mac = dst_mac == port.mac
        if ARP in frame:
            if local_mac or dst_mac == "ff:ff:ff:ff:ff:ff":
                self._handle_arp(port, frame)
            return

        packet = frame.payload
        if not isinstance(packet, IP):
            return

        header_length = packet.ihl * 4
        if packet.version != 4 or header_length < 20 or len(packet.original) < header_length:
            return
        if checksum(packet.original[:header_length]) != 0:
            return

        local_ip = self._is_local_ip(IPv4Address(packet.dst))
        if isinstance(packet.payload, UDP):
            udp = packet.payload
            if udp.dport == 520 and (local_mac and local_ip or
                    dst_mac == "01:00:5e:00:00:09" and packet.dst == "224.0.0.9"):
                self.rip.handle(port, frame)
                return

        if not local_mac:
            return

        if not local_ip:
            self._process_ipv4(packet)
        elif isinstance(packet.payload, ICMP):
            self._handle_icmp(port, frame)

    def _handle_icmp(self, port: RouterPort, frame: Packet) -> None:
        packet = frame[IP]
        request = packet[ICMP]
        if request.type != 8 or request.code != 0:
            return
        reply = (Ether(src=port.mac, dst=frame[Ether].src) /
                 IP(src=packet.dst, dst=packet.src) /
                 ICMP(type=0, id=request.id, seq=request.seq) /
                 request.payload)

        self._send_frame(reply, port.device)

    def _is_local_ip(self, ip: IPv4Address) -> bool:
        return any(port.ipv4 is not None and port.ipv4.ip == ip for port in self._ports)

    def _handle_arp(self, port: RouterPort, frame: Packet) -> None:
        arp_packet = frame[ARP]
        src_mac = arp_packet.hwsrc.lower()

        try:
            src_ip = IPv4Address(arp_packet.psrc)
            dst_ip = IPv4Address(arp_packet.pdst)
        except ValueError:
            return

        if arp_packet.op == 1:
            if dst_ip != port.ipv4.ip:
                resolved = self.fib.lookup(dst_ip)
                if resolved is None or resolved[0] is port:
                    return

            reply = self.arp.build_reply(port.mac, dst_ip, src_mac, src_ip)
            self._send_frame(reply, port.device)
            return

        if arp_packet.op == 2:
            if self.arp.complete_request(port.index, src_mac, src_ip):
                key = (port.index, src_ip)
                pending_packets = self._pending_packets.pop(key, [])
                for ip_packet in pending_packets:
                    self._process_ipv4(ip_packet)

    @locked
    def _process_ipv4(self, packet: IP) -> None:
        if packet.ttl <= 1:
            return

        dst_ip = IPv4Address(packet.dst)
        request = None

        if self._is_local_ip(dst_ip):
            return

        resolved = self.fib.lookup(dst_ip)
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
            self._send_ipv4(packet, port, dst_mac)
        elif request is not None:
            self._send_frame(request, port.device)


    def _send_ipv4(self, packet: IP, port: RouterPort, dst_mac: str) -> None:
        packet.ttl -= 1
        del packet.chksum
        self._send_frame(Ether(src=port.mac, dst=dst_mac) / packet, port.device)

    @staticmethod
    def _send_frame(frame: Packet, device: NetworkInterface) -> bool:
        try:
            sendp(frame, iface=device, verbose=False)
            return True
        except Exception:
            logging.exception("Failed to send frame")
            return False

    @property
    @locked
    def ports(self) -> tuple[RouterPort, ...]:
        return tuple(self._ports)

    @locked
    def set_address(self, port_index: int, ipv4: IPv4Interface | None) -> None:
        port = self._ports[port_index]
        if port.ipv4 == ipv4:
            return
        with self.rip.advertise_changes():
            self.rip.invalidate_port_routes(port, update=False)
            port.ipv4 = ipv4
            self.rib.update_port_routes(port)
        self.rip.send_request(port)
        self.arp.clear_port(port_index)
        self._pending_packets = {key: packets for key, packets in self._pending_packets.items() if key[0] != port_index}

    @locked
    def set_rip_enabled(self, port_index: int, enabled: bool) -> None:
        port = self._ports[port_index]
        if port.rip_enabled == enabled:
            return
        with self.rip.advertise_changes():
            if not enabled:
                self.rip.invalidate_port_routes(port)
            port.rip_enabled = enabled
        self.rip.send_request(port)

    @locked
    def _update_timers(self) -> None:
        expired = self.arp.update_timers()
        for key in expired:
            self._pending_packets.pop(key, None)
        self.rip.update_timers()

    @locked
    def add_static_route(self, route: Route) -> None:
        with self.rip.advertise_changes():
            self.rib.add_route(route)

    @locked
    def remove_static_route(self, route: Route) -> None:
        with self.rip.advertise_changes():
            self.rib.remove_route(route)

    @locked
    def get_selected_routes(self) -> tuple[Route, ...]:
        return self.rib.get_selected_routes()

    @locked
    def get_static_routes(self) -> tuple[Route, ...]:
        return self.rib.get_static_routes()

    @locked
    def get_arp_table(self) -> list[tuple[int, IPv4Address, str, int]]:
        return self.arp.get_table()

    @locked
    def remove_arp_entry(self, port_index: int, ip: IPv4Address) -> None:
        self.arp.remove_entry(port_index, ip)

    @locked
    def get_arp_timers(self) -> tuple[int, int]:
        return self.arp.get_timers()

    @locked
    def get_rip_timers(self) -> RIPTimers:
        return self.rip.get_timers()

    @locked
    def get_rip_database(self) -> dict[IPv4Network, RIPRecord]:
        return self.rip.get_database()

    @locked
    def set_rip_timers(self, timers: RIPTimers) -> None:
        self.rip.set_timers(timers)

    @locked
    def set_arp_timers(self, entry_lifetime: int, request_timeout: int) -> None:
        self.arp.set_timers(entry_lifetime, request_timeout)

    @locked
    def send_arp_request(self, port_index: int, dst_ip: IPv4Address) -> bool:
        port = self._ports[port_index]
        ipv4 = port.ipv4
        if ipv4 is None:
            raise ValueError("Selected interface has no IPv4 address.")
        request = self.arp.build_request(port_index, port.mac, ipv4.ip, dst_ip)

        return self._send_frame(request, port.device)

    @locked
    def clear_arp(self) -> None:
        self.arp.clear()
        self._pending_packets.clear()
