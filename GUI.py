import tkinter as tk
from tkinter import messagebox, ttk


class GUI:
    def __init__(self, controller):
        self.controller = controller
        self.root = tk.Tk()
        self.root.title("Software Router")
        self.root.geometry("980x420")

        self.address = tk.StringVar()
        self.mask = tk.StringVar()

        frame = ttk.Frame(self.root, padding=12)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

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

        ttk.Label(
            frame,
            text="These addresses exist only in the router program. Windows adapter settings are unchanged.",
        ).grid(row=3, column=0, sticky="w", pady=(16, 0))
        self._refresh()

    def show(self):
        self.root.mainloop()

    def _selected_port(self):
        selected = self.table.selection()
        return int(selected[0]) if selected else None

    def _on_select(self, _event=None):
        port = self._selected_port()
        if port is None:
            return
        configured = self.controller.ports[port].interface
        self.address.set(str(configured.ip) if configured else "")
        self.mask.set(str(configured.network.netmask) if configured else "")

    def _refresh(self):
        selected = self._selected_port()
        self.table.delete(*self.table.get_children())
        ports = self.controller.ports
        for index, port in enumerate(ports):
            self.table.insert("", "end", iid=str(index), values=(
                index,
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

    def _apply(self):
        port = self._selected_port()
        if port is None:
            messagebox.showinfo("No interface", "Select an interface first.")
            return
        try:
            self.controller.set_address(port, self.address.get(), self.mask.get())
        except ValueError as exc:
            messagebox.showerror("Invalid IP configuration", str(exc))
            return
        self._refresh()

    def _clear(self):
        port = self._selected_port()
        if port is None:
            return
        self.controller.clear_address(port)
        self.address.set("")
        self.mask.set("")
        self._refresh()
