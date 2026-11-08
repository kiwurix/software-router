# Software Router

An IPv4 software router written in Python with Scapy and a Tkinter interface. I built it to understand routing and packet forwarding, and tested it with physical Cisco networking equipment.

## Features

- Separate RIB and FIB, with longest-prefix matching for forwarding.
- Connected and static routes, including next-hop resolution.
- RIPv2 with route updates and configurable timers.
- ARP table, ARP requests and proxy ARP.
- DHCP server with address assignments and lease tracking.
- ICMP echo replies and TTL/checksum updates when forwarding IPv4 packets.
- GUI for interfaces, routing, ARP, RIP and DHCP.

## Run

Requires Python 3.11+, Tkinter and Scapy. On Windows, install [Npcap](https://npcap.com/). Packet capture and transmission require suitable privileges.

From the project folder, create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

Connect wired Ethernet interfaces to a lab topology. Configure their IPv4 addresses in the **Interfaces** tab, then add static routes or enable RIP as needed. The other tabs show ARP entries, routing information and DHCP assignments.

## Main files

- `router.py` - packet handling and forwarding.
- `rib.py` and `fib.py` - route selection and forwarding lookup.
- `rip_manager.py`, `arp_manager.py`, `dhcp_manager.py` - protocol logic.
- `controller.py` and `gui.py` - configuration and interface.

