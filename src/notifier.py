"""Notifier: exact console toast via notify payload + native PC toast + sound.

The exact strings (spelling matters, copied verbatim from the spec):
  success: "succsecfull jailbrea"
  failure: "failed jailbrea"
"""
from __future__ import annotations

import ctypes
import logging
import os
import subprocess
import sys
import threading

log = logging.getLogger("notifier")

SUCCESS_TEXT = "succsecfull jailbrea"
FAILURE_TEXT = "failed jailbrea"

NO_ENUMERATION = 0x2
NIF_INFO = 0x1


class Notifier:
    """Deliver the mandated notification strings on PC and (payload-gated) console."""

    def __init__(self, settings: dict) -> None:
        self.settings = settings
        self.console_send: object = None  # optional callback set by main (notify payload)

    # ---------- PC side ----------
    def pc_notify(self, text: str, is_success: bool) -> None:
        """Windows balloon via Shell_NotifyIconW; fallbacks elsewhere + sound."""
        if sys.platform == "win32":
            try:
                self._windows_balloon(text)
            except Exception as exc:  # noqa: BLE001
                log.debug("balloon failed: %s", exc)
                subprocess.Popen(
                    ["powershell", "-NoProfile", "-Command",
                     "[reflection.assembly]::loadwithpartialname("
                     "'System.Windows.Forms')|out-void;"
                     "$n=New-Object System.Windows.Forms.NotifyIcon;"
                     "$n.visible=$true;$n.balloontipicon='info';"
                     f"$n.showballoontip(5000,'PS5-JB','{text}')"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif sys.platform == "darwin":
            subprocess.Popen(["osascript", "-e", f'display notification "{text}"'],)
        else:
            try:
                subprocess.Popen(["notify-send", "PS5-JB", text],)
            except FileNotFoundError:
                log.info("PC toast: %s", text)
        threading.Thread(target=self._sound, args=(is_success,), daemon=True).start()

    @staticmethod
    def _windows_balloon(text: str) -> None:
        shell32 = ctypes.windll.shell32  # type: ignore[attr-defined]
        user32 = ctypes.windll.user32  # type: ignore[attr-defined]

        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [
                ("cbSize", ctypes.c_uint), ("hWnd", ctypes.c_void_p),
                ("uID", ctypes.c_uint), ("uFlags", ctypes.c_uint),
                ("uCallbackMessage", ctypes.c_uint), ("hIcon", ctypes.c_void_p),
                ("szTip", ctypes.c_wchar * 128), ("dwState", ctypes.c_uint),
                ("dwStateMask", ctypes.c_uint), ("szInfo", ctypes.c_wchar * 256),
                ("uTimeout", ctypes.c_uint), ("szInfoTitle", ctypes.c_wchar * 64),
                ("dwInfoFlags", ctypes.c_uint), ("guidItem", ctypes.c_char * 16),
            ]

        hwnd = user32.GetForegroundWindow()
        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = hwnd
        nid.uID = 0
        nid.uFlags = NIF_INFO
        nid.szInfo = text[:255]
        nid.szInfoTitle = "PS5-JB-14.10"
        nid.dwInfoFlags = NO_ENUMERATION
        shell32.Shell_NotifyIconW(1, ctypes.byref(nid))  # 1 = NIM_MODIFY

    @staticmethod
    def _sound(is_success: bool) -> None:
        try:
            if sys.platform == "win32":
                import winsound
                freq = 1200 if is_success else 300
                winsound.Beep(freq, 400)
            elif sys.platform == "darwin":
                os.system("afplay /System/Library/Sounds/Tink.aiff &")
        except Exception:  # noqa: BLE001 - sound is best effort
            pass

    # ---------- console side ----------
    def console_notify(self, text: str) -> None:
        """Push a toast on the console via the notify payload, if wired."""
        if self.console_send:
            try:
                self.console_send(text)  # type: ignore[operator]
            except Exception as exc:  # noqa: BLE001
                log.debug("console notify failed: %s", exc)
        else:
            log.info("(console toast queued - notify payload: %s)", text)

    def notify_success(self) -> None:
        self.pc_notify(SUCCESS_TEXT, True)
        self.console_notify(SUCCESS_TEXT)

    def notify_failure(self, text: str = FAILURE_TEXT) -> None:
        self.pc_notify(text, False)
        self.console_notify(text)
