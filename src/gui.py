"""Desktop GUI (tkinter, stdlib-only): IPs big and copyable, live state, steps."""
from __future__ import annotations

import logging
import threading
import tkinter as tk
from tkinter import scrolledtext
from typing import Callable, Dict, Optional

log = logging.getLogger("gui")

CONSOLE_STEPS = (
    "STATIC STEPS (do once):\n"
    "  1. PS5 ▸ Settings ▸ Network ▸ Set Up Internet Connection ▸ your network ▸"
    " Advanced ▸ DNS Settings = Manual ▸ Primary DNS = <This PC address>\n"
    "  2. PS5 ▸ Browser ▸ type: http://<This PC address>:8080\n"
    "  3. Tap the big RUN button. Everything else is automatic."
)


class App:
    """Main window: status, addresses, steps, log tail."""

    def __init__(self, status_provider: Callable[[], Dict]) -> None:
        self.root = tk.Tk()
        self.root.title("PS5-JB-14.10 Host")
        self.root.geometry("720x560")
        self.status_provider = status_provider

        big = ("TkDefaultFont", 18, "bold")
        med = ("TkDefaultFont", 12)

        self.ip_ps5 = tk.StringVar(value="PS5 address: discovering…")
        self.ip_pc = tk.StringVar(value="This PC address: —")
        tk.Label(self.root, textvariable=self.ip_pc, font=big, fg="#0064c8",
                 cursor="crosshair").pack(pady=(14, 0))

        tk.Label(self.root, textvariable=self.ip_ps5, font=big, fg="#12861d",
                 cursor="crosshair").pack(pady=(0, 10))

        self.url = tk.StringVar(value="")
        tk.Label(self.root, textvariable=self.url, font=med, fg="#4444aa",
                 cursor="crosshair").pack()

        self.state_lbl = tk.Label(self.root, text="State: IDLE", font=med)
        self.state_lbl.pack(pady=8)
        self.detail_lbl = tk.Label(self.root, text="", font=("TkDefaultFont", 10),
                                   wraplength=660, justify="left")
        self.detail_lbl.pack()

        steps_lbl = tk.Label(self.root, text=CONSOLE_STEPS, font=("TkDefaultFont", 9),
                             anchor="w", justify="left", wraplength=680)
        steps_lbl.pack(fill="x", padx=12, pady=6)

        tk.Label(self.root, text="Log:").pack(anchor="w", padx=12)
        self.logbox = scrolledtext.ScrolledText(self.root, height=10, width=90,
                                                font=("Consolas", 9))
        self.logbox.pack(fill="both", expand=True, padx=12, pady=(0, 10))

        self._poll()

    # ---------- API for main ----------
    def set_ips(self, ps5_ip: str, pc_ip: str, http_port: int) -> None:
        """Update the big address labels."""
        self.ip_ps5.set(f"PS5 address: {ps5_ip or 'not found yet…'}")
        self.ip_pc.set(f"This PC address: {pc_ip}")
        self.url.set(f"Type this on the PS5 browser:  http://{pc_ip}:{http_port}")

    def set_state(self, state: str, detail: str = "") -> None:
        self.state_lbl.config(text=f"State: {state}")
        self.detail_lbl.config(text=detail[:400])

    def log_line(self, line: str) -> None:
        self.logbox.insert("end", line + "\n")
        self.logbox.see("end")

    def run(self) -> None:
        self.root.mainloop()

    def request_close(self) -> None:
        self.root.after(0, self.root.destroy)

    # ---------- internals ----------
    def _poll(self) -> None:
        try:
            st = self.status_provider()
            self.state_lbl.config(text=f"State: {st.get('state', 'IDLE')}")
            self.detail_lbl.config(text=str(st.get("detail", ""))[:400])
            if st.get("ps5_ip"):
                self.ip_ps5.set(f"PS5 address: {st['ps5_ip']}")
        except Exception as exc:  # noqa: BLE001 - GUI poll must never crash
            log.debug("poll failed: %s", exc)
        self.root.after(1000, self._poll)
