"""Structured logging for PS5-JB-14.10.

Rotating file log at logs/ps5jb.log plus an on-screen handler fed to the GUI.
"""
from __future__ import annotations

import logging
import logging.handlers
import os
from typing import Callable, Optional


class GuiLogHandler(logging.Handler):
    """Forward log records to a GUI callback (never raises)."""

    def __init__(self) -> None:
        super().__init__()
        self.sink: Optional[Callable[[str], None]] = None

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if self.sink:
                self.sink(self.format(record))
        except Exception:  # noqa: BLE001 - logging must never crash the app
            pass


_gui_handler = GuiLogHandler()


def setup_logging(log_file: str = "logs/ps5jb.log", level: int = logging.INFO) -> None:
    """Configure root logging: rotating file + optional GUI sink."""
    os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S"
    )
    fh = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    fh.setFormatter(fmt)
    root.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(sh)
    _gui_handler.setFormatter(fmt)
    root.addHandler(_gui_handler)


def attach_gui_sink(cb: Callable[[str], None]) -> None:
    """Give the GUI a live log tail."""
    _gui_handler.sink = cb
