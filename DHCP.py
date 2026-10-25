from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import IPv4Address
from time import monotonic

from scapy.layers.dhcp import BOOTP, DHCP, DHCPOptions, DHCPRevOptions
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from enum import Enum, auto

from arp_manager import ArpManager
from models import RouterPort

class AllocationType(Enum):
    MANUAL = auto()
    AUTOMATIC = auto()
    DYNAMIC = auto()


@dataclass
class DHCPRecord:
    ip: IPv4Address
    allocation_type: AllocationType
    expires_at: float | None

@dataclass
class DHCPProbe:
    allocation_type: AllocationType
    bootp: BOOTP

class DHCPManger:
    def __init__(self, ports: list[RouterPort], arp: ArpManager, send_frame: Callable[[RouterPort, Packet], bool]) -> None:
        self.ports = ports
        self._arp = arp
        self._send_frame = send_frame
        self.allocation_type = AllocationType.DYNAMIC
        self.offer_timeout = 30
        self.lease_time = 3600
        self.pending_offers: dict[tuple[int, bytes], DHCPRecord] = {}
        self.assignments: dict[tuple[int, bytes], DHCPRecord] = {}
        self.manual_bindings: dict[bytes, IPv4Address] = {}
        self.occupied_addresses: set[tuple[int, IPv4Address]] = set()
        self.pending_probes: dict[tuple[int, IPv4Address], DHCPProbe] = {}


    def handle(self, port: RouterPort, datagram: UDP) -> None:
        bootp = datagram.payload
        if not isinstance(bootp, BOOTP):
            return

        dhcp = bootp.payload

        if  not isinstance(dhcp, DHCP):
            return

        options = {}
        for option in dhcp.options:
            if isinstance(option, tuple):
                code = DHCPRevOptions[option[0]][0]
                options[code] = option[1]


        match options.get(53):
            case 1: self._handle_discover(port, bootp, self.allocation_type)
            case 3: self._handle_request(port, bootp, options)
            case 4: self._handle_decline(port, bootp, options)
            case 7: self._handle_release(port, bootp, options)
            case 8: self._handle_inform(port, bootp)
            case _: return


    def _handle_discover(self, port: RouterPort, bootp: BOOTP, allocation_type: AllocationType) -> None:
        key = self.get_key(port, bootp)
        client_mac = key[1]
        record = self.assignments.get(key) or self.pending_offers.get(key)
        if record is not None:
            self.send_offer(port, bootp, record.ip, record.allocation_type)
            return

        for (port_index, _), probe in self.pending_probes.items():
            if port_index == port.index and probe.bootp.chaddr[:6] == client_mac:
                probe.bootp = bootp
                return

        manual_allocation = allocation_type == AllocationType.MANUAL

        while True:
            ip = self.manual_bindings.get(client_mac) if manual_allocation else\
                self.get_next_available_address(port)

            if ip is None:
                return

            if self._arp.get_mac(port, ip):
                self.occupied_addresses.add((port.index, ip))
                if manual_allocation:
                    return

            else:
                self.pending_probes[(port.index, ip)] = DHCPProbe(allocation_type, bootp)
                request = self._arp.build_request(port, ip)

                self._send_frame(port, request)
                return


    def complete_probe(self, port: RouterPort, ip: IPv4Address, is_replied: bool):
        probe = self.pending_probes.pop((port.index, ip), None)
        if probe is None:
            return

        if not is_replied:
            self.send_offer(port, probe.bootp, ip, probe.allocation_type)

        else:
            self.occupied_addresses.add((port.index, ip))
            if probe.allocation_type == AllocationType.MANUAL:
                return
            self._handle_discover(port, probe.bootp, probe.allocation_type)


    def send_offer(self, port: RouterPort, bootp: BOOTP, ip: IPv4Address, allocation_type: AllocationType):
        key = self.get_key(port, bootp)

        self.pending_offers[key] = DHCPRecord(ip, allocation_type, monotonic() + self.offer_timeout)
        self._send_reply(port, bootp, 2, ip, allocation_type)



    def get_next_available_address(self, port: RouterPort) -> IPv4Address | None:
        not_available_addresses = ([address for mac, address in self.manual_bindings.items()] +
                    [record.ip for (port_idx, _), record in self.pending_offers.items() if port_idx == port.index] +
                    [record.ip for (port_idx, _), record in self.assignments.items() if port_idx == port.index] +
                    [addr for port_idx, addr in self.occupied_addresses if port_idx == port.index] +
                    [p.ipv4.ip for p in self.ports if p.ipv4 is not None] +
                    [addr for port_idx, addr in self.pending_probes if port_idx == port.index])


        for address in port.ipv4.network.hosts():
            if address not in not_available_addresses:
                return address

        return None

    def _send_reply(self, port: RouterPort, bootp: BOOTP, message_type: int,
                    assigned_ip: IPv4Address, allocation_type: AllocationType | None) -> None:

        client_mac = bootp.chaddr[:6]
        port_ip = str(port.ipv4.ip)

        if message_type == 6 or bootp.flags.B:
            dst_ip, dst_mac = "255.255.255.255", "ff:ff:ff:ff:ff:ff"
        elif bootp.ciaddr != "0.0.0.0":
            dst_ip, dst_mac = bootp.ciaddr, client_mac
        else:
            dst_ip, dst_mac = str(assigned_ip), client_mac

        reply = BOOTP(op=2, htype=1, hlen=6, xid=bootp.xid, chaddr=bootp.chaddr, flags=bootp.flags,
                      giaddr="0.0.0.0", ciaddr=bootp.ciaddr if message_type == 5 else "0.0.0.0", yiaddr=str(assigned_ip))

        options = {53: message_type, 54: str(port_ip)}
        if message_type in (2, 5):
            options[1] = str(port.ipv4.netmask)
            options[3] = str(port_ip)
        if not assigned_ip.is_unspecified and message_type != 6:
            options[51] = self.lease_time if allocation_type == AllocationType.DYNAMIC else 0xffffffff

        reply /= DHCP(options=[(DHCPOptions[code].name, value) for code, value in options.items()] + ["end"])

        frame = (Ether(src=port.mac, dst=dst_mac) /
                 IP(src=str(port_ip), dst=dst_ip) /
                 UDP(sport=67, dport=68) /
                 reply)


        self._send_frame(port, frame)

    def _handle_request(self, port: RouterPort, bootp: BOOTP, options: dict) -> None:
        key = self.get_key(port, bootp)

        offer = self.pending_offers.get(key)
        assignment = self.assignments.get(key)

        server_ip = IPv4Address(options[54]) if 54 in options else None
        requested_ip = IPv4Address(options[50]) if 50 in options else None

        if server_ip is not None:
            if server_ip != port.ipv4.ip:
                return
            valid_request = (offer is not None and requested_ip == offer.ip or
                             assignment is not None and requested_ip == assignment.ip)
        else:
            if assignment is None:
                return
            if bootp.ciaddr != "0.0.0.0":
                requested_ip = IPv4Address(bootp.ciaddr)
            valid_request = requested_ip == assignment.ip

        if not valid_request:
            self._send_reply(port, bootp, 6, IPv4Address("0.0.0.0"), None)
            return

        assignment = offer or assignment
        assignment.expires_at = monotonic() + self.lease_time\
            if assignment.allocation_type == AllocationType.DYNAMIC else None

        self.assignments[key] = assignment
        self.pending_offers.pop(key, None)
        self._send_reply(port, bootp, 5, assignment.ip, assignment.allocation_type)

    def _handle_decline(self, port: RouterPort, bootp: BOOTP, options: dict) -> None:
        if 54 not in options or 50 not in options:
            return
        if IPv4Address(options[54]) != port.ipv4.ip:
            return
        requested_ip = IPv4Address(options[50])

        key = self.get_key(port, bootp)
        offer = self.pending_offers.get(key)
        assignment = self.assignments.get(key)

        if not (offer is not None and requested_ip == offer.ip or
                assignment is not None and requested_ip == assignment.ip):
            return

        self.occupied_addresses.add((port.index, requested_ip))
        self.pending_offers.pop(key, None)
        self.assignments.pop(key, None)

    def _handle_release(self, port: RouterPort, bootp: BOOTP, options: dict) -> None:
        if 54 not in options or IPv4Address(options[54]) != port.ipv4.ip:
            return

        key = self.get_key(port, bootp)
        assignment = self.assignments.get(key)
        if assignment is None or IPv4Address(bootp.ciaddr) != assignment.ip:
            return

        if assignment.allocation_type == AllocationType.DYNAMIC:
            del self.assignments[key]

    def _handle_inform(self, port: RouterPort, bootp: BOOTP) -> None:
        client_ip = IPv4Address(bootp.ciaddr)
        if client_ip.is_unspecified or client_ip not in port.ipv4.network:
            return

        self._send_reply(port, bootp, 5, IPv4Address("0.0.0.0"), None)

    def update_timers(self) -> None:
        now = monotonic()
        for records in (self.pending_offers, self.assignments):
            for key, record in tuple(records.items()):
                if record.expires_at is not None and now >= record.expires_at:
                    del records[key]

    def update_port(self, port: RouterPort) -> None:
        network = port.ipv4.network if port.ipv4 is not None else None
        for records in (self.pending_offers, self.assignments):
            for key, record in tuple(records.items()):
                if key[0] == port.index and (network is None or record.ip not in network or record.ip == port.ipv4.ip):
                    del records[key]
        self.pending_probes = {key: probe for key, probe in self.pending_probes.items() if key[0] != port.index}

    @staticmethod
    def get_key(port: RouterPort, bootp: BOOTP) -> tuple[int, bytes]:
        return port.index, bootp.chaddr[:6]
