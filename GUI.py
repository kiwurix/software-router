import tkinter as tk
from tkinter import messagebox, ttk

from controller import Controller


class GUI:
    def __init__(self, controller: Controller) -> None:
        self.controller = controller
        self.root = tk.Tk()
        self.root.title("Software Router")
        self.root.geometry("980x650")

        self.address = tk.StringVar()
        self.mask = tk.StringVar()
        self.arp_target = tk.StringVar()
        entry_lifetime, request_timeout = self.controller.get_arp_timers()
        self.arp_entry_lifetime = tk.StringVar(value=str(entry_lifetime))
        self.arp_request_timeout = tk.StringVar(value=str(request_timeout))

        frame = ttk.Frame(self.root, padding=12)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        frame.rowconfigure(4, weight=1)

        ttk.Label(frame, text="Interface IP addresses", font=("Segoe UI", 14, "bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 10)
        )

        self.table = ttk.Treeview(
            frame,
            columns=("port", "name", "mac", "ip", "mask"),
            show="headings",
            selectmode="browse",
        )
        for key, title, width in (
            ("port", "Port", 60),
            ("name", "Interface", 350),
            ("mac", "MAC", 160),
            ("ip", "Router IP", 140),
            ("mask", "Subnet mask", 140),
        ):
            self.table.heading(key, text=title)
            self.table.column(key, width=width, stretch=key == "name")
        self.table.grid(row=1, column=0, sticky="nsew")
        self.table.bind("<<TreeviewSelect>>", self._on_select)

        form = ttk.Frame(frame)
        form.grid(row=2, column=0, sticky="w", pady=(12, 0))
        ttk.Label(form, text="IPv4 address").grid(row=0, column=0, sticky="w")
        ttk.Label(form, text="Mask or /prefix").grid(row=0, column=1, sticky="w")
        ttk.Entry(form, textvariable=self.address, width=19).grid(row=1, column=0, padx=(0, 12))
        ttk.Entry(form, textvariable=self.mask, width=19).grid(row=1, column=1, padx=(0, 12))
        ttk.Button(form, text="Apply", command=self._apply).grid(row=1, column=2, padx=(0, 8))
        ttk.Button(form, text="Clear", command=self._clear).grid(row=1, column=3)

        ttk.Label(frame, text="ARP table", font=("Segoe UI", 14, "bold")).grid(
            row=3, column=0, sticky="w", pady=(16, 10)
        )
        self.arp_table = ttk.Treeview(
            frame,
            columns=("port", "ip", "mac", "age"),
            show="headings",
            selectmode="none",
        )
        for key, title, width in (
            ("port", "Port", 90),
            ("ip", "IP address", 230),
            ("mac", "MAC address", 230),
            ("age", "Age (s)", 120),
        ):
            self.arp_table.heading(key, text=title)
            self.arp_table.column(key, width=width, stretch=key in ("ip", "mac"))
        self.arp_table.grid(row=4, column=0, sticky="nsew")

        arp_controls = ttk.Frame(frame)
        arp_controls.grid(row=5, column=0, sticky="w", pady=(10, 0))
        ttk.Label(arp_controls, text="Target IPv4").pack(side="left", padx=(0, 8))
        ttk.Entry(arp_controls, textvariable=self.arp_target, width=19).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(arp_controls, text="Send ARP request", command=self._send_arp_request).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(arp_controls, text="Clear ARP table", command=self._clear_arp).pack(side="left")

        arp_timers = ttk.Frame(frame)
        arp_timers.grid(row=6, column=0, sticky="w", pady=(10, 0))
        ttk.Label(arp_timers, text="ARP entry lifetime (s)").grid(row=0, column=0, sticky="w")
        ttk.Label(arp_timers, text="ARP request timeout (s)").grid(row=0, column=1, sticky="w")
        ttk.Entry(arp_timers, textvariable=self.arp_entry_lifetime, width=18).grid(
            row=1, column=0, padx=(0, 12)
        )
        ttk.Entry(arp_timers, textvariable=self.arp_request_timeout, width=18).grid(
            row=1, column=1, padx=(0, 12)
        )
        ttk.Button(arp_timers, text="Apply timers", command=self._apply_arp_timers).grid(
            row=1, column=2
        )

        self._refresh()
        self._refresh_arp()
        self.root.after(1000, self._tick)

    def show(self) -> None:
        self.root.mainloop()

    def _selected_port_idx(self) -> int | None:
        selected = self.table.selection()
        return int(selected[0]) if selected else None

    def _on_select(self, _event: tk.Event | None = None) -> None:
        port_idx = self._selected_port_idx()
        if port_idx is None:
            return
        configured = self.controller.ports[port_idx].interface
        self.address.set(str(configured.ip) if configured else "")
        self.mask.set(str(configured.network.netmask) if configured else "")

    def _refresh(self) -> None:
        selected = self._selected_port_idx()
        self.table.delete(*self.table.get_children())
        ports = self.controller.ports
        for port_idx, port in enumerate(ports):
            self.table.insert("", "end", iid=str(port_idx), values=(
                port_idx,
                port.device.name,
                port.mac,
                str(port.interface.ip) if port.interface else "",
                str(port.interface.network.netmask) if port.interface else "",
            ))
        if selected is not None:
            self.table.selection_set(str(selected))
        elif ports:
            self.table.selection_set("0")
            self._on_select()

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

    def _clear(self) -> None:
        port_idx = self._selected_port_idx()
        if port_idx is None:
            return
        self.controller.clear_address(port_idx)
        self.address.set("")
        self.mask.set("")
        self._refresh()

    def _tick(self) -> None:
        self.controller.update_timers()
        self._refresh_arp()
        self.root.after(1000, self._tick)

    def _refresh_arp(self) -> None:
        self.arp_table.delete(*self.arp_table.get_children())
        for port_idx, dst_ip, mac, age in self.controller.get_arp_table():
            self.arp_table.insert("", "end", values=(port_idx, dst_ip, mac, age))

    def _send_arp_request(self) -> None:
        port_idx = self._selected_port_idx()
        if port_idx is None:
            messagebox.showinfo("No interface", "Select an interface first.")
            return
        try:
            sent = self.controller.send_arp_request(port_idx, self.arp_target.get())
        except ValueError as exc:
            messagebox.showerror("ARP request", str(exc))
            return
        if not sent:
            messagebox.showerror("ARP request", "Failed to send the request.")

    def _clear_arp(self) -> None:
        self.controller.clear_arp()
        self._refresh_arp()

    def _apply_arp_timers(self) -> None:
        try:
            self.controller.set_arp_timers(
                self.arp_entry_lifetime.get(), self.arp_request_timeout.get()
            )
        except ValueError as exc:
            messagebox.showerror("ARP timers", str(exc))
            return
        entry_lifetime, request_timeout = self.controller.get_arp_timers()
        self.arp_entry_lifetime.set(str(entry_lifetime))
        self.arp_request_timeout.set(str(request_timeout))
