"""Deploy the TEST14.10 homebrew tile to the console over FTP (ftpsrv :2121)."""
from __future__ import annotations

import ftplib
import logging
import os
from typing import List, Tuple

log = logging.getLogger("consoleapp")


class ConsoleAppInstaller:
    """Idempotently install /data/homebrew/TEST14.10/{eboot.bin,sce_sys/param.json}."""

    def __init__(self, settings: dict, ps5_ip: str) -> None:
        self.host = ps5_ip
        self.port = int(settings.get("ftp", {}).get("port", 2121))
        self.homebrew_dir = settings["chain"].get("homebrew_dir", "/data/homebrew/TEST14.10")
        self.status_file = settings["chain"].get("status_file", "/data/TEST14.10_status.txt")
        self.local_dir = settings["console_app"].get(
            "local_dir", "assets/homebrew/TEST14.10")

    def _connect(self, timeout: float = 10.0) -> ftplib.FTP:
        ftp = ftplib.FTP()
        ftp.connect(self.host, self.port, timeout=timeout)
        # ftpsrv does not authenticate; anonymous login keeps the protocol happy.
        try:
            ftp.login("anonymous", "anonymous")
        except ftplib.error_perm:
            pass  # ftpsrv often skips auth entirely
        try:
            ftp.set_pasv(True)
        except Exception:  # noqa: BLE001 - passive toggle is best-effort
            pass
        return ftp

    def install(self) -> Tuple[bool, str]:
        """Upload tile files, verify by listing, return (ok, reason)."""
        try:
            ftp = self._connect()
        except OSError as exc:
            return False, f"ftp_connect_failed:213{exc}" if False else f"ftp_connect_failed:{exc}"
        try:
            self._mkdirs(ftp, self.homebrew_dir)
            self._mkdirs(ftp, self.homebrew_dir + "/sce_sys")
            eboot = os.path.join(self.local_dir, "eboot.bin")
            param = os.path.join(self.local_dir, "sce_sys", "param.json")
            self._upload(ftp, f"{self.homebrew_dir}/eboot.bin", eboot)
            self._upload(ftp, f"{self.homebrew_dir}/sce_sys/param.json", param)
            names = self._list(ftp, self.homebrew_dir)
            ok = "eboot.bin" in names
            log.info("tile listing %s -> %s (verify=%s)", self.homebrew_dir, names, ok)
            if not ok:
                return False, "tile_not_listed_after_upload"
            if "icon0.png" in names:
                log.warning("unexpected icon0.png present; this violates the no-icon spec")
            return True, "installed_no_icon"
        except ftplib.error_temp as exc:
            return False, f"ftp_error:{exc}"
        finally:
            try:
                ftp.quit()
            except Exception:  # noqa: BLE001
                try:
                    ftp.close()
                except Exception:  # noqa: BLE001
                    pass

    def write_status(self, text: str) -> bool:
        """Write /data/TEST14.10_status.txt (host-side status marker the tile reads)."""
        try:
            ftp = self._connect()
            import io
            buf = io.BytesIO(text.encode())
            ftp.storbinary(f"STOR {self.status_file}", buf)
            ftp.quit()
            log.info("status file written: %s <- %r", self.status_file, text)
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("status write failed: %s", exc)
            return False

    # ---------- helpers ----------
    @staticmethod
    def _mkdirs(ftp: ftplib.FTP, path: str) -> None:
        parts = [p for p in path.strip("/").split("/") if p]
        cur = ""
        for part in parts:
            cur += "/" + part
            try:
                ftp.mkd(cur)
            except ftplib.error_response:
                pass  # already exists -> fine
            except Exception:  # noqa: BLE001 - 550/521 variants all mean "exists or N/A"
                pass

    @staticmethod
    def _upload(ftp: ftplib.FTP, remote: str, local_path: str) -> None:
        if not os.path.isfile(local_path):
            raise FileNotFoundError(f"missing local asset: {local_path}")
        with open(local_path, "rb") as fh:
            ftp.storbinary(f"STOR {remote}", fh)

    @staticmethod
    def _list(ftp: ftplib.FTP, path: str) -> List[str]:
        names: List[str] = []
        try:
            ftp.retrlines(f"LIST {path}", lambda line: names.append(line.split()[-1]))
        except Exception:  # noqa: BLE001
            try:
                ftp.nlst(path)  # noqa: B305
                names = [p.rsplit("/", 1)[-1] for p in ftp.nlst(path)]
            except Exception:  # noqa: BLE001
                pass
        return names
