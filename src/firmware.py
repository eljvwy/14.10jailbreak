"""Firmware detection + data-driven profile matching."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

log = logging.getLogger("firmware")


@dataclass
class Profile:
    """One firmware firmware-range -> exploit-chain mapping row."""

    id: str
    fw_range: str
    userland_stage: str
    kernel_stage: str
    hv_stage: str
    payload_chain: List[str]
    notes: str
    verified_by_user: bool
    experimental: bool
    kernel_stage_fallbacks: List[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.kernel_stage_fallbacks is None:
            self.kernel_stage_fallbacks = []

    @property
    def fw_lo(self) -> float:
        return float(self.fw_range.split("-")[0])

    @property
    def fw_hi(self) -> float:
        return float(self.fw_range.split("-")[1])

    def covers(self, fw: float) -> bool:
        """True if this profile spans the given float firmware version."""
        return self.fw_lo <= fw <= self.fw_hi


def parse_fw(version: str) -> Optional[float]:
    """Parse '5.10.0', '08.20.02.00' etc. -> first numeric triple as float, else None."""
    parts = []
    for token in version.replace("V", "").split("."):
        digits = "".join(c for c in token if c.isdigit())
        if digits:
            parts.append(int(digits))
        else:
            break
    if not parts:
        return None
    # Firmware strings like "08.20.02.00" are major.minor[.build…]: keep the
    # first two numeric components (minor zero-padded to two digits).
    parts = (parts + [0, 0])[:2]
    return float(f"{parts[0]}.{parts[1]:02d}")


def load_profiles(path: str) -> List[Profile]:
    """Load profiles from JSON; corrupt file degrades to empty list with warning."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        out = []
        for row in data.get("profiles", []):
            out.append(
                Profile(
                    id=row["id"],
                    fw_range=row["fw_range"],
                    userland_stage=row.get("userland_stage", "none"),
                    kernel_stage=row.get("kernel_stage", "none"),
                    hv_stage=row.get("hv_stage", "none"),
                    payload_chain=row.get("payload_chain", []),
                    notes=row.get("notes", ""),
                    verified_by_user=bool(row.get("verified_by_user", False)),
                    experimental=bool(row.get("experimental", False)),
                    kernel_stage_fallbacks=row.get("kernel_stage_fallbacks", []),
                )
            )
        return out
    except Exception as exc:  # noqa: BLE001
        log.warning("Could not load firmware profiles (%s): %s", path, exc)
        return []


def match_profile(profiles: List[Profile], fw: Optional[float]) -> Optional[Profile]:
    """Pick the first profile covering fw; prefers verified then non-experimental."""
    cands = match_profile_candidates(profiles, fw)
    return cands[0] if cands else None


def match_profile_candidates(profiles: List[Profile],
                             fw: Optional[float]) -> List[Profile]:
    """All profiles covering fw, best-first (verified > unverified,
    non-experimental > experimental). Empty list = unsupported firmware."""
    if fw is None:
        return []
    candidates = [p for p in profiles if p.covers(fw)]
    candidates.sort(key=lambda p: (not p.verified_by_user, p.experimental))
    return candidates


def detect_firmware(version_hint: str) -> Optional[float]:
    """Best-effort numeric firmware from any network-visible version string."""
    return parse_fw(version_hint)
