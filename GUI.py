import tkinter as tk
from math import ceil
from time import monotonic
from tkinter import messagebox, ttk

from controller import Controller
from RIB import RouteSource


class GUI:
    def __init__(self, controller: Controller) -> None:
        self.controller = controller
        self.root = tk.Tk()
        self.root.title("Software Router")
        self.root.geometry("940x640")
        self.root.minsize(940, 640)
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.address = tk.StringVar(self.root)
        self.mask = tk.StringVar(self.root)
        self.rip_enabled = tk.BooleanVar(self.root)
        self.static_network = tk.StringVar(self.root)
        self.static_port = tk.StringVar(self.root, value="-")
        self.static_next_hop = tk.StringVar(self.root)
        self.static_AD = tk.StringVar(self.root, value="1")
        self.arp_target = tk.StringVar(self.root)
        self._port_choices = {f"Fa{port.index}": port.index for port in controller.ports}
        self.arp_port = tk.StringVar(self.root, value=next(iter(self._port_choices), ""))
        entry_lifetime, request_timeout = controller.get_arp_timers()
        self.arp_entry_lifetime = tk.StringVar(self.root, value=str(entry_lifetime))
        self.arp_request_timeout = tk.StringVar(self.root, value=str(request_timeout))
        update, invalid, hold_down, flush = controller.get_rip_timers()
        self.rip_update_interval = tk.StringVar(self.root, value=str(update))
        self.rip_invalid_timeout = tk.StringVar(self.root, value=str(invalid))
        self.rip_hold_down_timeout = tk.StringVar(self.root, value=str(hold_down))
        self.rip_flush_timeout = tk.StringVar(self.root, value=str(flush))
        self._static_routes = {}

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=12)
        for title, build in (("Interfaces", self._build_interfaces), ("Routing", self._build_routing),
                             ("ARP", self._build_arp), ("RIP", self._build_rip)):
            tab = ttk.Frame(self.notebook, padding=12)
            self.notebook.add(tab, text=title)
            build(tab)
        self._refresh()
        self._after_id = self.root.after(1000, self._tick)

    @staticmethod
    def _make_table(parent, columns, selectmode="browse", height=8):
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
        self.table = self._make_table(parent, (
            ("interface", "Interface", 130), ("mac", "MAC", 180),
            ("ip", "IP address", 140), ("mask", "Subnet mask", 140), ("rip", "RIP", 70),
        ))
        self.table.bind("<<TreeviewSelect>>", self._on_select)
        form = ttk.Frame(parent)
        form.pack(anchor="w", pady=(0, 10))
        ttk.Label(form, text="IPv4 address").grid(row=0, column=0, sticky="w")
        ttk.Label(form, text="Mask or /prefix").grid(row=0, column=1, sticky="w")
        ttk.Entry(form, textvariable=self.address, width=19).grid(row=1, column=0, padx=(0, 12))
        ttk.Entry(form, textvariable=self.mask, width=19).grid(row=1, column=1, padx=(0, 12))
        ttk.Button(form, text="Apply address", command=self._apply).grid(row=1, column=2, padx=(0, 8))
        ttk.Button(form, text="Clear address", command=self._clear).grid(row=1, column=3, padx=(0, 16))
        self.rip_toggle = ttk.Checkbutton(form, text="Enable RIP", variable=self.rip_enabled, command=self._set_rip_enabled)
        self.rip_toggle.grid(row=1, column=4)

    def _build_routing(self, parent) -> None:
        ttk.Label(parent, text="Routing table", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        self.routing_table = self._make_table(parent, (
            ("code", "Code", 60), ("network", "Network", 220), ("preference", "[AD/Metric]", 130),
            ("next_hop", "Next hop", 240), ("interface", "Interface", 120),
        ), selectmode="none", height=6)
        ttk.Label(parent, text="Static routes configuration", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        self.static_table = self._make_table(parent, (
            ("state", "State", 120), ("network", "Network", 220), ("AD", "AD", 70),
            ("next_hop", "Next hop", 240), ("interface", "Interface", 120),
        ), height=6)
        form = ttk.Frame(parent)
        form.pack(anchor="w", pady=(10, 0))
        for column, label in enumerate(("Network / prefix", "Interface", "Next hop", "AD")):
            ttk.Label(form, text=label).grid(row=0, column=column, sticky="w")
        ttk.Entry(form, textvariable=self.static_network, width=22).grid(row=1, column=0, padx=(0, 12))
        ttk.Combobox(form, textvariable=self.static_port, values=("-", *self._port_choices),
                     state="readonly", width=24).grid(row=1, column=1, padx=(0, 12))
        ttk.Entry(form, textvariable=self.static_next_hop, width=18).grid(row=1, column=2, padx=(0, 12))
        ttk.Entry(form, textvariable=self.static_AD, width=7).grid(row=1, column=3, padx=(0, 12))
        ttk.Button(form, text="Add route", command=self._add_static_route).grid(row=1, column=4)
        ttk.Button(parent, text="Delete selected static route", command=self._remove_static_route).pack(anchor="w", pady=(10, 0))

    def _build_rip(self, parent) -> None:
        ttk.Label(parent, text="RIP timers", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        form = ttk.Frame(parent)
        form.pack(anchor="w", pady=(12, 0))
        fields = (("Update (s)", self.rip_update_interval), ("Invalid (s)", self.rip_invalid_timeout),
                  ("Hold-down (s)", self.rip_hold_down_timeout), ("Flush (s)", self.rip_flush_timeout))
        for column, (label, variable) in enumerate(fields):
            ttk.Label(form, text=label).grid(row=0, column=column, sticky="w")
            ttk.Entry(form, textvariable=variable, width=15).grid(row=1, column=column, padx=(0, 12))
        ttk.Button(form, text="Apply RIP timers", command=self._apply_rip_timers).grid(row=1, column=4)
        ttk.Label(parent, text="RIP database", font=("Segoe UI", 14, "bold")).pack(anchor="w", pady=(18, 0))
        self.rip_table = self._make_table(parent, (
            ("network", "Network", 165), ("metric", "Metric", 60), ("next_hop", "Next hop", 130),
            ("advertiser", "Advertiser", 130), ("interface", "Interface", 80), ("age", "Age (s)", 85),
            ("hold_down", "Hold-down (s)", 110), ("tag", "Tag", 55),
        ))

    def _build_arp(self, parent) -> None:
        ttk.Label(parent, text="ARP table", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        self.arp_table = self._make_table(parent, (
            ("interface", "Interface", 100), ("ip", "IP address", 230), ("mac", "MAC address", 230), ("age", "Age (s)", 120),
        ))
        controls = ttk.Frame(parent)
        controls.pack(anchor="w", pady=(0, 10))
        ttk.Label(controls, text="Interface").grid(row=0, column=0, sticky="w")
        ttk.Label(controls, text="Target IPv4").grid(row=0, column=1, sticky="w")
        ttk.Combobox(controls, textvariable=self.arp_port, values=tuple(self._port_choices),
                     state="readonly", width=28).grid(row=1, column=0, padx=(0, 12))
        ttk.Entry(controls, textvariable=self.arp_target, width=19).grid(row=1, column=1, padx=(0, 12))
        ttk.Button(controls, text="Send ARP request", command=self._send_arp_request).grid(row=1, column=2)
        buttons = ttk.Frame(parent)
        buttons.pack(anchor="w", pady=(0, 16))
        ttk.Button(buttons, text="Delete selected entry", command=self._remove_arp_entry).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Clear ARP table", command=self._clear_arp).pack(side="left")
        timers = ttk.Frame(parent)
        timers.pack(anchor="w")
        ttk.Label(timers, text="ARP entry lifetime (s)").grid(row=0, column=0, sticky="w")
        ttk.Label(timers, text="ARP request timeout (s)").grid(row=0, column=1, sticky="w")
        ttk.Entry(timers, textvariable=self.arp_entry_lifetime, width=20).grid(row=1, column=0, padx=(0, 12))
        ttk.Entry(timers, textvariable=self.arp_request_timeout, width=20).grid(row=1, column=1, padx=(0, 12))
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
        self.root.mainloop()

    def _close(self) -> None:
        self.root.after_cancel(self._after_id)
        self.root.destroy()

    def _selected_port_idx(self) -> int | None:
        selected = self.table.selection()
        return int(selected[0]) if selected else None

    def _on_select(self, _event: tk.Event | None = None) -> None:
        port_idx = self._selected_port_idx()
        if port_idx is None:
            return
        port = self.controller.ports[port_idx]
        ipv4 = port.ipv4
        self.address.set(str(ipv4.ip) if ipv4 else "")
        self.mask.set(str(ipv4.network.netmask) if ipv4 else "")
        self.rip_enabled.set(port.rip_enabled)

    def _refresh(self) -> None:
        rows = {}
        ports = self.controller.ports
        for port in ports:
            ipv4 = port.ipv4
            rows[str(port.index)] = (f"Fa{port.index}", port.mac, str(ipv4.ip) if ipv4 else "",
                                     str(ipv4.network.netmask) if ipv4 else "", "On" if port.rip_enabled else "Off")
        self._sync_table(self.table, rows)
        if not self.table.selection() and rows:
            self.table.selection_set(next(iter(rows)))
            self._on_select()
        selected = self._selected_port_idx()
        if selected is not None:
            self.rip_enabled.set(ports[selected].rip_enabled)
        self._refresh_routes()
        self._refresh_arp()
        self._refresh_rip_database()

    def _refresh_routes(self) -> None:
        selected = sorted(self.controller.get_selected_routes(),
                          key=lambda route: (int(route.network.network_address), route.network.prefixlen))
        rows = {}
        for route in selected:
            preference = "" if route.source == RouteSource.CONNECTED else f"[{route.AD}/{route.metric}]"
            next_hop = f"via {route.next_hop}" if route.next_hop is not None else "directly connected"
            interface = f"Fa{route.output_port.index}" if route.output_port else "Recursive"
            rows[str(route.network)] = (route.source, route.network, preference, next_hop, interface)
        self._sync_table(self.routing_table, rows)
        selected_by_network = {route.network: route for route in selected}
        statics = sorted(self.controller.get_static_routes(),
                         key=lambda route: (int(route.network.network_address), route.network.prefixlen, route.AD))
        self._static_routes = {str(id(route)): route for route in statics}
        rows = {iid: ("Selected" if selected_by_network.get(route.network) == route else "Inactive",
                      route.network, route.AD, route.next_hop if route.next_hop is not None else "directly connected",
                      f"Fa{route.output_port.index}" if route.output_port else "Recursive")
                for iid, route in self._static_routes.items()}
        self._sync_table(self.static_table, rows)

    def _refresh_arp(self) -> None:
        rows = {f"{port_index}:{ip}": (f"Fa{port_index}", ip, mac, age)
                for port_index, ip, mac, age in self.controller.get_arp_table()}
        self._sync_table(self.arp_table, rows)

    def _refresh_rip_database(self) -> None:
        database = self.controller.get_rip_database()
        _, _, hold_down_timeout, _ = self.controller.get_rip_timers()
        now = monotonic()
        rows = {}
        for network, record in sorted(database.items(), key=lambda item: (int(item[0].network_address), item[0].prefixlen)):
            age = int(now - record.updated_at)
            remaining = 0
            if record.hold_down_started_at is not None:
                remaining = max(0, ceil(hold_down_timeout - (now - record.hold_down_started_at)))
            rows[str(network)] = (network, record.metric, record.next_hop, record.advertiser_ip,
                                  f"Fa{record.learned_port.index}", age, remaining if remaining else "-", record.tag)
        self._sync_table(self.rip_table, rows)

    def _apply(self) -> None:
        port_idx = self._selected_port_idx()
        if port_idx is None:
            messagebox.showinfo("No interface", "Select an interface first.")
            return
        try:
            self.controller.set_address(port_idx, self.address.get(), self.mask.get())
        except ValueError as exc:
            messagebox.showerror("Invalid IP configuration", str(exc))
            return
        self._refresh()
        self._on_select()

    def _clear(self) -> None:
        port_idx = self._selected_port_idx()
        if port_idx is None:
            return
        self.controller.clear_address(port_idx)
        self._refresh()
        self._on_select()

    def _set_rip_enabled(self) -> None:
        port_idx = self._selected_port_idx()
        if port_idx is None:
            self.rip_enabled.set(False)
            messagebox.showinfo("No interface", "Select an interface first.")
            return
        try:
            self.controller.set_rip_enabled(port_idx, self.rip_enabled.get())
        except ValueError as exc:
            messagebox.showerror("RIP configuration", str(exc))
        self._refresh()
        self._on_select()

    def _add_static_route(self) -> None:
        try:
            route = self.controller.add_static_route(self.static_network.get(), self._port_choices.get(self.static_port.get()),
                                                      self.static_next_hop.get(), self.static_AD.get())
        except ValueError as exc:
            messagebox.showerror("Invalid static route", str(exc))
            return
        self._refresh_routes()
        self.static_table.selection_set(str(id(route)))

    def _remove_static_route(self) -> None:
        selected = self.static_table.selection()
        if not selected:
            messagebox.showinfo("No static route", "Select a static route first.")
            return
        try:
            self.controller.remove_static_route(self._static_routes[selected[0]])
        except ValueError as exc:
            messagebox.showerror("Static route", str(exc))
        self._refresh_routes()

    def _tick(self) -> None:
        self._refresh()
        self._after_id = self.root.after(1000, self._tick)

    def _send_arp_request(self) -> None:
        port_idx = self._port_choices.get(self.arp_port.get())
        if port_idx is None:
            messagebox.showinfo("No interface", "Choose an interface first.")
            return
        try:
            sent = self.controller.send_arp_request(port_idx, self.arp_target.get())
        except ValueError as exc:
            messagebox.showerror("ARP request", str(exc))
            return
        if not sent:
            messagebox.showerror("ARP request", "Failed to send the request.")
        self._refresh_arp()

    def _remove_arp_entry(self) -> None:
        selected = self.arp_table.selection()
        if not selected:
            messagebox.showinfo("No ARP entry", "Select an ARP entry first.")
            return
        port_index, ip = selected[0].split(":", 1)
        self.controller.remove_arp_entry(int(port_index), ip)
        self._refresh_arp()

    def _clear_arp(self) -> None:
        self.controller.clear_arp()
        self._refresh_arp()

    def _apply_rip_timers(self) -> None:
        try:
            self.controller.set_rip_timers(self.rip_update_interval.get(), self.rip_invalid_timeout.get(),
                                           self.rip_hold_down_timeout.get(), self.rip_flush_timeout.get())
        except ValueError as exc:
            messagebox.showerror("RIP timers", str(exc))
            return
        update, invalid, hold_down, flush = self.controller.get_rip_timers()
        self.rip_update_interval.set(str(update))
        self.rip_invalid_timeout.set(str(invalid))
        self.rip_hold_down_timeout.set(str(hold_down))
        self.rip_flush_timeout.set(str(flush))

    def _apply_arp_timers(self) -> None:
        try:
            self.controller.set_arp_timers(self.arp_entry_lifetime.get(), self.arp_request_timeout.get())
        except ValueError as exc:
            messagebox.showerror("ARP timers", str(exc))
            return
        entry_lifetime, request_timeout = self.controller.get_arp_timers()
        self.arp_entry_lifetime.set(str(entry_lifetime))
        self.arp_request_timeout.set(str(request_timeout))
