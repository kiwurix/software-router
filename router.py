import logging
from collections.abc import Callable
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from threading import RLock, Thread
from time import sleep

from scapy.interfaces import NetworkInterface
from scapy.layers.inet import ICMP, IP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer
from scapy.supersocket import SuperSocket
from scapy.utils import checksum

from arp_manager import ARPManager
from dhcp_manager import DHCPAllocationType, DHCPManager, DHCPRecord
from fib import FIB
from models import RouterPort
from rib import RIB, Route
from rip_manager import RIPManager, RIPRecord, RIPTimers


def _locked(func: Callable):
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return func(self, *args, **kwargs)

    return wrapper


class Router:
    def __init__(self, devices: list[NetworkInterface]) -> None:
        self._ports: list[RouterPort] = [
            RouterPort(index, device, device.mac.lower()) for index, device in enumerate(devices)
        ]
        self._own_macs = frozenset(port.mac for port in self._ports)
        self._lock = RLock()
        self._send_sockets: dict[int, SuperSocket] = {}
        self._fib = FIB()
        self._rib = RIB(self._fib)
        self._rip = RIPManager(self._ports, self._rib, self._send_frame)
        self._arp = ARPManager()
        self._dhcp = DHCPManager(self._ports, self._arp, self._send_frame)
        self._pending_packets: dict[tuple[int, IPv4Address], list[IP]] = {}
        self._sniffer: AsyncSniffer | None = None
        self._timers_running = False
        self._timer_thread: Thread | None = None

    def start(self) -> None:
        if not self._ports or self._sniffer is not None:
            return
        for port in self._ports:
            socket_class = port.device.l2socket()
            self._send_sockets[port.index] = socket_class(iface=port.device)
        device_name_to_port = {port.device.network_name: port for port in self._ports}
        self._sniffer = AsyncSniffer(
            iface=device_name_to_port,
            prn=self._handle_frame,
            store=False
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
            for socket in self._send_sockets.values():
                socket.close()
            self._send_sockets.clear()

    def _run_timers(self) -> None:
        while self._timers_running:
            self._update_timers()
            sleep(1)

    @_locked
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
            if (udp.sport == 68 and udp.dport == 67
                    and (local_mac or dst_mac == "ff:ff:ff:ff:ff:ff")
                    and packet.dst in (str(port.ipv4.ip), "255.255.255.255")):
                self._dhcp.handle(port, udp)
                return

            if udp.dport == 520 and (local_mac and local_ip or
                                     dst_mac == "01:00:5e:00:00:09" and packet.dst == "224.0.0.9"):
                self._rip.handle(port, frame)
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

        self._send_frame(port, reply)

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
                resolved = self._fib.lookup(dst_ip)
                if resolved is None or resolved[0] is port:
                    return

            reply = self._arp.build_reply(port, dst_ip, src_mac, src_ip)
            self._send_frame(port, reply)
            return

        if arp_packet.op == 2:
            if self._arp.complete_request(port, src_mac, src_ip):
                key = (port.index, src_ip)
                self._dhcp.complete_probe(port, src_ip, True)
                pending_packets = self._pending_packets.pop(key, [])
                for ip_packet in pending_packets:
                    self._process_ipv4(ip_packet)

    @_locked
    def _process_ipv4(self, packet: IP) -> None:
        if packet.ttl <= 1:
            return

        dst_ip = IPv4Address(packet.dst)
        request = None

        if self._is_local_ip(dst_ip):
            return

        resolved = self._fib.lookup(dst_ip)
        if resolved is None:
            return

        port, next_hop = resolved

        dst_mac = self._arp.get_mac(port, next_hop)

        if dst_mac is None:
            key = (port.index, next_hop)
            self._pending_packets.setdefault(key, []).append(packet)

            if not self._arp.is_pending(port, next_hop):
                request = self._arp.build_request(port, next_hop)

        if dst_mac is not None:
            self._send_ipv4(port, packet, dst_mac)
        elif request is not None:
            self._send_frame(port, request)

    def _send_ipv4(self, port: RouterPort, packet: IP, dst_mac: str) -> None:
        packet.ttl -= 1
        del packet.chksum
        self._send_frame(port, Ether(src=port.mac, dst=dst_mac) / packet)

    def _send_frame(self, port: RouterPort, frame: Packet) -> bool:
        try:
            self._send_sockets[port.index].send(frame)
            return True
        except Exception:
            logging.exception("Failed to send frame")
            return False

    @_locked
    def _update_timers(self) -> None:
        expired = self._arp.update_timers()
        for port_index, ip in expired:
            self._pending_packets.pop((port_index, ip), None)
            self._dhcp.complete_probe(self._ports[port_index], ip, False)
        self._rip.update_timers()
        self._dhcp.update_timers()

    @property
    @_locked
    def ports(self) -> tuple[RouterPort, ...]:
        return tuple(self._ports)

    @_locked
    def set_address(self, port_index: int, ipv4: IPv4Interface | None) -> None:
        port = self._ports[port_index]
        if port.ipv4 == ipv4:
            return
        with self._rip.advertise_changes():
            self._rip.invalidate_port_routes(port, update=False)
            port.ipv4 = ipv4
            self._rib.update_port_routes(port)
        self._rip.send_request(port)
        self._arp.clear_port(port)
        self._pending_packets = {key: packets for key, packets in self._pending_packets.items() if key[0] != port_index}
        self._dhcp.update_port(port)

    @_locked
    def set_rip_enabled(self, port_index: int, enabled: bool) -> None:
        port = self._ports[port_index]
        if port.rip_enabled == enabled:
            return
        with self._rip.advertise_changes():
            if not enabled:
                self._rip.invalidate_port_routes(port)
            port.rip_enabled = enabled
        self._rip.send_request(port)

    @_locked
    def add_static_route(self, route: Route) -> None:
        with self._rip.advertise_changes():
            self._rib.add_route(route)

    @_locked
    def remove_static_route(self, route: Route) -> None:
        with self._rip.advertise_changes():
            self._rib.remove_route(route)

    @_locked
    def get_selected_routes(self) -> tuple[Route, ...]:
        return self._rib.get_selected_routes()

    @_locked
    def get_static_routes(self) -> tuple[Route, ...]:
        return self._rib.get_static_routes()

    @_locked
    def get_arp_table(self) -> list[tuple[int, IPv4Address, str, float]]:
        return self._arp.get_table()

    @_locked
    def get_arp_timers(self) -> tuple[int, int]:
        return self._arp.get_timers()

    @_locked
    def get_rip_timers(self) -> RIPTimers:
        return self._rip.get_timers()

    @_locked
    def get_rip_database(self) -> dict[IPv4Network, RIPRecord]:
        return self._rip.get_database()

    @_locked
    def set_rip_timers(self, timers: RIPTimers) -> None:
        self._rip.set_timers(timers)

    @_locked
    def set_arp_timers(self, entry_lifetime: int, request_timeout: int) -> None:
        self._arp.set_timers(entry_lifetime, request_timeout)

    @_locked
    def send_arp_request(self, port_index: int, dst_ip: IPv4Address) -> bool:
        port = self._ports[port_index]
        ipv4 = port.ipv4
        if ipv4 is None:
            raise ValueError("Selected interface has no IPv4 address.")
        request = self._arp.build_request(port, dst_ip)

        return self._send_frame(port, request)

    @_locked
    def clear_arp(self) -> None:
        self._arp.clear()
        self._pending_packets.clear()
        self._dhcp.clear_pending_probes()

    @_locked
    def get_dhcp_settings(self) -> tuple[DHCPAllocationType, int, int]:
        return self._dhcp.get_settings()

    @_locked
    def set_dhcp_settings(self, allocation_mode: DHCPAllocationType, offer_timeout: int, lease_time: int) -> None:
        self._dhcp.set_settings(allocation_mode, offer_timeout, lease_time)

    @_locked
    def get_dhcp_assignments(self) -> dict[tuple[int, bytes], DHCPRecord]:
        return self._dhcp.get_assignments()

    @_locked
    def get_dhcp_manual_bindings(self) -> dict[bytes, IPv4Address]:
        return self._dhcp.get_manual_bindings()

    @_locked
    def set_dhcp_manual_binding(self, client_mac: bytes, ip: IPv4Address) -> None:
        self._dhcp.set_manual_binding(client_mac, ip)

    @_locked
    def remove_dhcp_manual_binding(self, client_mac: bytes) -> None:
        self._dhcp.remove_manual_binding(client_mac)
