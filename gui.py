import tkinter as tk
from math import ceil
from time import monotonic
from tkinter import messagebox, ttk

from controller import Controller
from dhcp_manager import DHCPAllocationType
from rib import RouteSource


class GUI:
    def __init__(self, controller: Controller) -> None:
        self._controller = controller
        self._root = tk.Tk()
        self._root.title("Software Router")
        self._root.geometry("940x640")
        self._root.minsize(940, 640)
        self._root.protocol("WM_DELETE_WINDOW", self._close)
        self._address = tk.StringVar(self._root)
        self._mask = tk.StringVar(self._root)
        self._rip_enabled = tk.BooleanVar(self._root)
        self._static_address = tk.StringVar(self._root)
        self._static_mask = tk.StringVar(self._root)
        self._static_port = tk.StringVar(self._root, value="-")
        self._static_next_hop = tk.StringVar(self._root)
        self._static_AD = tk.StringVar(self._root, value="1")
        self._arp_target = tk.StringVar(self._root)
        self._port_choices = {f"Fa{port.index}": port.index for port in controller.ports}
        self._arp_port = tk.StringVar(self._root, value=next(iter(self._port_choices), ""))
        entry_lifetime, request_timeout = controller.get_arp_timers()
        self._arp_entry_lifetime = tk.StringVar(self._root, value=str(entry_lifetime))
        self._arp_request_timeout = tk.StringVar(self._root, value=str(request_timeout))
        timers = controller.get_rip_timers()
        self._rip_update_interval = tk.StringVar(self._root, value=str(timers.update))
        self._rip_invalid_timeout = tk.StringVar(self._root, value=str(timers.invalid))
        self._rip_hold_down_timeout = tk.StringVar(self._root, value=str(timers.hold_down))
        self._rip_flush_timeout = tk.StringVar(self._root, value=str(timers.flush))
        allocation_mode, offer_timeout, lease_time = controller.get_dhcp_settings()
        self._dhcp_allocation_mode = tk.StringVar(self._root, value=allocation_mode.name.title())
        self._dhcp_offer_timeout = tk.StringVar(self._root, value=str(offer_timeout))
        self._dhcp_lease_time = tk.StringVar(self._root, value=str(lease_time))
        self._dhcp_binding_mac = tk.StringVar(self._root)
        self._dhcp_binding_ip = tk.StringVar(self._root)
        self._static_routes = {}

        self._notebook = ttk.Notebook(self._root)
        self._notebook.pack(fill="both", expand=True, padx=12, pady=12)
        for title, build in (("Interfaces", self._build_interfaces), ("ARP", self._build_arp),
                             ("Routing", self._build_routing), ("RIP", self._build_rip), ("DHCP", self._build_dhcp)):
            tab = ttk.Frame(self._notebook, padding=12)
            self._notebook.add(tab, text=title)
            build(tab)
        self._refresh()
        self._after_id = self._root.after(1000, self._tick)

    @staticmethod
    def _build_table(parent, columns, selectmode="browse", height=8):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True, pady=(6, 12))
        table = ttk.Treeview(frame, columns=[key for key, _, _ in columns], show="headings",
                             selectmode=selectmode, height=height)
        for key, title, width in columns:
            table.heading(key, text=title)
            table.column(key, width=width, minwidth=45, stretch=True)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=table.yview)
        table.configure(yscrollcommand=scrollbar.set)
        table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        return table

    def _build_interfaces(self, parent) -> None:
        ttk.Label(parent, text="Interface IP addresses", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        self._table = self._build_table(parent, (
            ("interface", "Interface", 130), ("mac", "MAC address", 180),
            ("ip", "IP address", 140), ("mask", "Subnet mask", 140), ("rip", "RIP", 70)
        ))
        self._table.bind("<<TreeviewSelect>>", self._on_select)
        form = ttk.Frame(parent)
        form.pack(anchor="w", pady=(0, 10))
        ttk.Label(form, text="IPv4 address").grid(row=0, column=0, sticky="w")
        ttk.Label(form, text="Mask or /prefix").grid(row=0, column=1, sticky="w")
        ttk.Entry(form, textvariable=self._address, width=19).grid(row=1, column=0, padx=(0, 12))
        ttk.Entry(form, textvariable=self._mask, width=19).grid(row=1, column=1, padx=(0, 12))
        ttk.Button(form, text="Apply address", command=self._apply_address).grid(row=1, column=2, padx=(0, 8))
        ttk.Button(form, text="Clear address", command=self._clear_address).grid(row=1, column=3, padx=(0, 16))
        self._rip_toggle = ttk.Checkbutton(form, text="Enable RIP", variable=self._rip_enabled,
                                           command=self._set_rip_enabled)
        self._rip_toggle.grid(row=1, column=4)

    def _build_routing(self, parent) -> None:
        ttk.Label(parent, text="Routing table", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        self._routing_table = self._build_table(parent, (
            ("code", "Code", 60), ("network", "Network", 220), ("preference", "[AD/Metric]", 130),
            ("next_hop", "Next hop", 240), ("interface", "Interface", 120)
        ), selectmode="none", height=6)
        ttk.Label(parent, text="Static routes configuration", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        self._static_table = self._build_table(parent, (
            ("state", "State", 120), ("network", "Network", 220), ("AD", "AD", 70),
            ("next_hop", "Next hop", 240), ("interface", "Interface", 120)
        ), height=6)
        form = ttk.Frame(parent)
        form.pack(anchor="w", pady=(10, 0))
        for column, label in enumerate(("IPv4 address", "Mask or /prefix", "Interface", "Next hop", "AD")):
            ttk.Label(form, text=label).grid(row=0, column=column, sticky="w")
        ttk.Entry(form, textvariable=self._static_address, width=19).grid(row=1, column=0, padx=(0, 12))
        ttk.Entry(form, textvariable=self._static_mask, width=19).grid(row=1, column=1, padx=(0, 12))
        ttk.Combobox(form, textvariable=self._static_port, values=("-", *self._port_choices),
                     state="readonly", width=12).grid(row=1, column=2, padx=(0, 12))
        ttk.Entry(form, textvariable=self._static_next_hop, width=18).grid(row=1, column=3, padx=(0, 12))
        ttk.Entry(form, textvariable=self._static_AD, width=7).grid(row=1, column=4, padx=(0, 12))
        ttk.Button(form, text="Add route", command=self._add_static_route).grid(row=1, column=5)
        ttk.Button(parent, text="Delete selected static route", command=self._remove_static_route).pack(anchor="w",
                                                                                                        pady=(10, 0))

    def _build_rip(self, parent) -> None:
        ttk.Label(parent, text="RIP timers", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        form = ttk.Frame(parent)
        form.pack(anchor="w", pady=(12, 0))
        fields = (("Update (s)", self._rip_update_interval), ("Invalid (s)", self._rip_invalid_timeout),
                  ("Hold-down (s)", self._rip_hold_down_timeout), ("Flush (s)", self._rip_flush_timeout))
        for column, (label, variable) in enumerate(fields):
            ttk.Label(form, text=label).grid(row=0, column=column, sticky="w")
            ttk.Entry(form, textvariable=variable, width=15).grid(row=1, column=column, padx=(0, 12))
        ttk.Button(form, text="Apply RIP timers", command=self._apply_rip_timers).grid(row=1, column=4)
        ttk.Label(parent, text="RIP database", font=("Segoe UI", 14, "bold")).pack(anchor="w", pady=(18, 0))
        self._rip_table = self._build_table(parent, (
            ("network", "Network", 165), ("metric", "Metric", 60), ("next_hop", "Next hop", 130),
            ("advertiser", "Advertiser", 130), ("interface", "Interface", 80), ("age", "Age (s)", 85),
            ("hold_down", "Hold-down (s)", 110), ("tag", "Tag", 55)
        ), selectmode="none")

    def _build_arp(self, parent) -> None:
        ttk.Label(parent, text="ARP table", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        self._arp_table = self._build_table(parent, (
            ("interface", "Interface", 100), ("mac", "MAC address", 230), ("ip", "IP address", 230),
            ("age", "Age (s)", 120)
        ), selectmode="none")
        controls = ttk.Frame(parent)
        controls.pack(anchor="w", pady=(0, 10))
        ttk.Label(controls, text="Interface").grid(row=0, column=0, sticky="w")
        ttk.Label(controls, text="Target IPv4").grid(row=0, column=1, sticky="w")
        ttk.Combobox(controls, textvariable=self._arp_port, values=tuple(self._port_choices),
                     state="readonly", width=28).grid(row=1, column=0, padx=(0, 12))
        ttk.Entry(controls, textvariable=self._arp_target, width=19).grid(row=1, column=1, padx=(0, 12))
        ttk.Button(controls, text="Send ARP request", command=self._send_arp_request).grid(row=1, column=2)
        buttons = ttk.Frame(parent)
        buttons.pack(anchor="w", pady=(0, 16))
        ttk.Button(buttons, text="Clear ARP table", command=self._clear_arp).pack(side="left")
        timers = ttk.Frame(parent)
        timers.pack(anchor="w")
        ttk.Label(timers, text="ARP entry lifetime (s)").grid(row=0, column=0, sticky="w")
        ttk.Label(timers, text="ARP request timeout (s)").grid(row=0, column=1, sticky="w")
        ttk.Entry(timers, textvariable=self._arp_entry_lifetime, width=20).grid(row=1, column=0, padx=(0, 12))
        ttk.Entry(timers, textvariable=self._arp_request_timeout, width=20).grid(row=1, column=1, padx=(0, 12))
        ttk.Button(timers, text="Apply timers", command=self._apply_arp_timers).grid(row=1, column=2)

    @staticmethod
    def _sync_table(table, rows) -> None:
        for iid in table.get_children():
            if iid not in rows:
                table.delete(iid)
        for position, (iid, values) in enumerate(rows.items()):
            values = tuple(str(value) for value in values)
            if table.exists(iid):
                if table.item(iid, "values") != values:
                    table.item(iid, values=values)
            else:
                table.insert("", "end", iid=iid, values=values)
            if table.index(iid) != position:
                table.move(iid, "", position)

    def show(self) -> None:
        self._root.mainloop()

    def _close(self) -> None:
        self._root.after_cancel(self._after_id)
        self._root.destroy()

    def _selected_port_index(self) -> int | None:
        selected = self._table.selection()
        return int(selected[0]) if selected else None

    def _on_select(self, _event: tk.Event | None = None) -> None:
        port_index = self._selected_port_index()
        if port_index is None:
            return
        port = self._controller.ports[port_index]
        ipv4 = port.ipv4
        self._address.set(str(ipv4.ip) if ipv4 else "")
        self._mask.set(str(ipv4.network.netmask) if ipv4 else "")
        self._rip_enabled.set(port.rip_enabled)

    def _refresh(self) -> None:
        rows = {}
        ports = self._controller.ports
        for port in ports:
            ipv4 = port.ipv4
            rows[str(port.index)] = (f"Fa{port.index}", port.mac, str(ipv4.ip) if ipv4 else "",
                                     str(ipv4.network.netmask) if ipv4 else "", "On" if port.rip_enabled else "Off")
        self._sync_table(self._table, rows)
        if not self._table.selection() and rows:
            self._table.selection_set(next(iter(rows)))
            self._on_select()
        selected = self._selected_port_index()
        if selected is not None:
            self._rip_enabled.set(ports[selected].rip_enabled)
        self._refresh_routes()
        self._refresh_arp()
        self._refresh_rip_database()
        self._refresh_dhcp()

    def _refresh_routes(self) -> None:
        selected = sorted(self._controller.get_selected_routes(),
                          key=lambda route: (int(route.network.network_address), route.network.prefixlen))
        rows = {}
        for route in selected:
            preference = "" if route.source == RouteSource.CONNECTED else f"[{route.AD}/{route.metric}]"
            next_hop = f"via {route.next_hop}" if route.next_hop is not None else "directly connected"
            interface = f"Fa{route.output_port.index}" if route.output_port else "Recursive"
            rows[str(route.network)] = (route.source, route.network, preference, next_hop, interface)
        self._sync_table(self._routing_table, rows)
        selected_by_network = {route.network: route for route in selected}
        statics = sorted(self._controller.get_static_routes(),
                         key=lambda route: (int(route.network.network_address), route.network.prefixlen, route.AD))
        self._static_routes = {str(id(route)): route for route in statics}
        rows = {iid: ("Selected" if selected_by_network.get(route.network) == route else "Inactive",
                      route.network, route.AD, route.next_hop if route.next_hop is not None else "directly connected",
                      f"Fa{route.output_port.index}" if route.output_port else "Recursive")
                for iid, route in self._static_routes.items()}
        self._sync_table(self._static_table, rows)

    def _refresh_arp(self) -> None:
        entries = sorted(self._controller.get_arp_table(), key=lambda entry: (entry[0], entry[1]))
        now = monotonic()
        rows = {f"{port_index}:{ip}": (f"Fa{port_index}", mac, ip, int(now - learned_at))
                for port_index, ip, mac, learned_at in entries}
        self._sync_table(self._arp_table, rows)

    def _refresh_rip_database(self) -> None:
        database = self._controller.get_rip_database()
        timers = self._controller.get_rip_timers()
        now = monotonic()
        rows = {}
        for network, record in sorted(database.items(),
                                      key=lambda item: (int(item[0].network_address), item[0].prefixlen)):
            age = int(now - record.updated_at)
            remaining = 0
            if record.hold_down_started_at is not None:
                remaining = max(0, ceil(timers.hold_down - (now - record.hold_down_started_at)))
            rows[str(network)] = (network, record.metric, record.next_hop, record.advertiser_ip,
                                  f"Fa{record.learned_port.index}", age, remaining if remaining else "-", record.tag)
        self._sync_table(self._rip_table, rows)

    def _apply_address(self) -> None:
        port_index = self._selected_port_index()
        if port_index is None:
            messagebox.showinfo("No interface", "Select an interface first.")
            return
        try:
            self._controller.set_address(port_index, self._address.get(), self._mask.get())
        except ValueError as exc:
            messagebox.showerror("Invalid IP configuration", str(exc))
            return
        self._refresh()
        self._on_select()

    def _clear_address(self) -> None:
        port_index = self._selected_port_index()
        if port_index is None:
            return
        self._controller.clear_address(port_index)
        self._refresh()
        self._on_select()

    def _set_rip_enabled(self) -> None:
        port_index = self._selected_port_index()
        if port_index is None:
            self._rip_enabled.set(False)
            messagebox.showinfo("No interface", "Select an interface first.")
            return
        try:
            self._controller.set_rip_enabled(port_index, self._rip_enabled.get())
        except ValueError as exc:
            messagebox.showerror("RIP configuration", str(exc))
        self._refresh()
        self._on_select()

    def _add_static_route(self) -> None:
        try:
            route = self._controller.add_static_route(self._static_address.get(), self._static_mask.get(),
                                                      self._port_choices.get(self._static_port.get()),
                                                      self._static_next_hop.get(), self._static_AD.get())
        except ValueError as exc:
            messagebox.showerror("Invalid static route", str(exc))
            return
        self._refresh_routes()
        self._static_table.selection_set(str(id(route)))

    def _remove_static_route(self) -> None:
        selected = self._static_table.selection()
        if not selected:
            messagebox.showinfo("No static route", "Select a static route first.")
            return
        try:
            self._controller.remove_static_route(self._static_routes[selected[0]])
        except ValueError as exc:
            messagebox.showerror("Static route", str(exc))
        self._refresh_routes()

    def _tick(self) -> None:
        self._refresh()
        self._after_id = self._root.after(1000, self._tick)

    def _send_arp_request(self) -> None:
        port_index = self._port_choices.get(self._arp_port.get())
        if port_index is None:
            messagebox.showinfo("No interface", "Choose an interface first.")
            return
        try:
            sent = self._controller.send_arp_request(port_index, self._arp_target.get())
        except ValueError as exc:
            messagebox.showerror("ARP request", str(exc))
            return
        if not sent:
            messagebox.showerror("ARP request", "Failed to send the request.")
        self._refresh_arp()

    def _clear_arp(self) -> None:
        self._controller.clear_arp()
        self._refresh_arp()

    def _apply_rip_timers(self) -> None:
        try:
            self._controller.set_rip_timers(self._rip_update_interval.get(), self._rip_invalid_timeout.get(),
                                            self._rip_hold_down_timeout.get(), self._rip_flush_timeout.get())
        except ValueError as exc:
            messagebox.showerror("RIP timers", str(exc))
            return
        timers = self._controller.get_rip_timers()
        self._rip_update_interval.set(str(timers.update))
        self._rip_invalid_timeout.set(str(timers.invalid))
        self._rip_hold_down_timeout.set(str(timers.hold_down))
        self._rip_flush_timeout.set(str(timers.flush))

    def _apply_arp_timers(self) -> None:
        try:
            self._controller.set_arp_timers(self._arp_entry_lifetime.get(), self._arp_request_timeout.get())
        except ValueError as exc:
            messagebox.showerror("ARP timers", str(exc))
            return
        entry_lifetime, request_timeout = self._controller.get_arp_timers()
        self._arp_entry_lifetime.set(str(entry_lifetime))
        self._arp_request_timeout.set(str(request_timeout))

    def _build_dhcp(self, parent) -> None:
        ttk.Label(parent, text="DHCP configuration", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        settings = ttk.Frame(parent)
        settings.pack(anchor="w", pady=(8, 14))
        ttk.Label(settings, text="Allocation mode").grid(row=0, column=0, sticky="w")
        ttk.Combobox(settings, textvariable=self._dhcp_allocation_mode,
                     values=tuple(
                         mode.name.title() for mode in (DHCPAllocationType.DYNAMIC, DHCPAllocationType.AUTOMATIC)),
                     state="readonly", width=16
                     ).grid(row=1, column=0, padx=(0, 12))
        for column, (label, variable) in enumerate((("Offer timeout (s)", self._dhcp_offer_timeout),
                                                    ("Lease time (s)", self._dhcp_lease_time)), start=1):
            ttk.Label(settings, text=label).grid(row=0, column=column, sticky="w")
            ttk.Entry(settings, textvariable=variable, width=18).grid(row=1, column=column, padx=(0, 12))
        ttk.Button(settings, text="Apply settings", command=self._apply_dhcp_settings).grid(row=1, column=3)

        ttk.Label(parent, text="DHCP assignments", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        self._dhcp_table = self._build_table(parent, (
            ("interface", "Interface", 100), ("mac", "MAC address", 200), ("ip", "IP address", 170),
            ("allocation", "Allocation", 130), ("lease", "Lease remaining (s)", 170)
        ), selectmode="none", height=5)

        ttk.Label(parent, text="Manual bindings", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        self._dhcp_bindings_table = self._build_table(parent, (
            ("mac", "MAC address", 280), ("ip", "IP address", 280)
        ), height=4)
        self._dhcp_bindings_table.bind("<<TreeviewSelect>>", self._on_dhcp_binding_select)
        bindings = ttk.Frame(parent)
        bindings.pack(anchor="w", pady=(0, 12))
        ttk.Label(bindings, text="MAC address").grid(row=0, column=0, sticky="w")
        ttk.Label(bindings, text="IP address").grid(row=0, column=1, sticky="w")
        ttk.Entry(bindings, textvariable=self._dhcp_binding_mac, width=23).grid(row=1, column=0, padx=(0, 12))
        ttk.Entry(bindings, textvariable=self._dhcp_binding_ip, width=19).grid(row=1, column=1, padx=(0, 12))
        ttk.Button(bindings, text="Add / update binding", command=self._set_dhcp_manual_binding
                   ).grid(row=1, column=2, padx=(0, 8))
        buttons = ttk.Frame(parent)
        buttons.pack(anchor="w")
        ttk.Button(buttons, text="Delete selected manual binding", command=self._remove_dhcp_manual_binding
                   ).pack(side="left", padx=(0, 8))

    def _refresh_dhcp(self) -> None:
        now = monotonic()
        assignments = self._controller.get_dhcp_assignments()
        rows = {}
        for (port_index, mac), record in sorted(assignments.items(), key=lambda item: (item[0][0], int(item[1].ip))):
            remaining = "Permanent" if record.expires_at is None else max(0, ceil(record.expires_at - now))
            rows[f"{port_index}:{mac.hex()}"] = (f"Fa{port_index}", mac.hex(":"), record.ip,
                                                 record.allocation_type.name.title(), remaining)
        self._sync_table(self._dhcp_table, rows)
        bindings = self._controller.get_dhcp_manual_bindings()
        rows = {mac.hex(":"): (mac.hex(":"), ip) for mac, ip in sorted(bindings.items())}
        self._sync_table(self._dhcp_bindings_table, rows)

    def _apply_dhcp_settings(self) -> None:
        try:
            self._controller.set_dhcp_settings(self._dhcp_allocation_mode.get(), self._dhcp_offer_timeout.get(),
                                               self._dhcp_lease_time.get())
        except ValueError as exc:
            messagebox.showerror("DHCP configuration", str(exc))
            return
        allocation_mode, offer_timeout, lease_time = self._controller.get_dhcp_settings()
        self._dhcp_allocation_mode.set(allocation_mode.name.title())
        self._dhcp_offer_timeout.set(str(offer_timeout))
        self._dhcp_lease_time.set(str(lease_time))

    def _on_dhcp_binding_select(self, _event: tk.Event | None = None) -> None:
        selected = self._dhcp_bindings_table.selection()
        if not selected:
            return
        mac, ip = self._dhcp_bindings_table.item(selected[0], "values")
        self._dhcp_binding_mac.set(mac)
        self._dhcp_binding_ip.set(ip)

    def _set_dhcp_manual_binding(self) -> None:
        try:
            mac = self._controller.set_dhcp_manual_binding(self._dhcp_binding_mac.get(), self._dhcp_binding_ip.get())
        except ValueError as exc:
            messagebox.showerror("Manual binding", str(exc))
            return
        self._refresh_dhcp()
        self._dhcp_bindings_table.selection_set(mac.hex(":"))

    def _remove_dhcp_manual_binding(self) -> None:
        selected = self._dhcp_bindings_table.selection()
        if not selected:
            messagebox.showinfo("No manual binding", "Select a manual binding first.")
            return
        self._controller.remove_dhcp_manual_binding(selected[0])
        self._refresh_dhcp()
