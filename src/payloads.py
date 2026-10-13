"""Payload asset validation: existence, size, ELF format, provenance hashes.

A payload must be genuine upstream-provided (or locally compiled with a
recorded provenance entry) before the chain engine will deliver it. Placeholders
(provenance missing) are refused by default so the host can never send an
unverified executable, and can never claim a payload executed just because a
port was open.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

log = logging.getLogger("payloads")

ELF_MAGIC = b"\x7fELF"
ELF_MACHINE_AARCH64 = 183  # EM_AARCH64 — PS5 payload targets aarch64 (ps5-payload-dev/sdk)
ELF_ET_EXEC = 2
ELF_ET_DYN = 3
DEFAULT_MIN_BYTES = 128
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
MANIFEST_NAME = "manifest.json"


@dataclass
class PayloadAsset:
    """A single validated (or failed) payload asset."""

    name: str
    path: str
    ok: bool
    reason: str
    sha256: str = ""
    size: int = 0
    provenance: Dict = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.provenance is None:
            self.provenance = {}


def _load_manifest(payload_dir: str) -> Dict:
    """Provenance manifest: name -> {source_url, revision, kind, sha256?}.

    kind: "upstream" (pinned upstream binary) | "compiled" (built locally via
    build.sh, build log recorded) | "placeholder" (refused by default).
    """
    path = os.path.join(payload_dir, MANIFEST_NAME)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:  # noqa: BLE001 documented: absent manifest refuses everything
        log.warning("payload manifest unusable (%s): %s - payloads refused", path, exc)
        return {}


def validate_payload(
    name: str,
    payload_dir: str,
    allow_placeholder: bool = False,
    min_bytes: int = DEFAULT_MIN_BYTES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    expected_sha256: Optional[str] = None,
) -> PayloadAsset:
    """Full static validation of one payload asset."""
    path = os.path.join(payload_dir, name)
    if not os.path.isfile(path):
        return PayloadAsset(name, path, False, "missing_file")
    size = os.path.getsize(path)
    if not (min_bytes <= size <= max_bytes):
        return PayloadAsset(name, path, False, f"bad_size:{size}", "",
                            size) if size else PayloadAsset(name, path, False, "empty_file")
    with open(path, "rb") as fh:
        data = fh.read()
    digest = hashlib.sha256(data).hexdigest()
    manifest = _load_manifest(payload_dir)
    prov = manifest.get(name)
    prov_kind = (prov or {}).get("kind", "unknown")
    if prov_kind == "placeholder" and not allow_placeholder:
        return PayloadAsset(name, path, False, "unverified_placeholder", digest,
                            size, prov or {})
    if prov_kind == "unknown" and not allow_placeholder:
        return PayloadAsset(name, path, False, "no_provenance_record", digest,
                            size, prov or {})
    if not data.startswith(ELF_MAGIC):
        return PayloadAsset(name, path, False, "not_elf", digest, size, prov or {})
    arch_reason = check_elf_architecture(data)
    if arch_reason:
        return PayloadAsset(name, path, False, arch_reason, digest, size, prov or {})
    if not data.endswith(b"\x00"):
        # elfldr reads raw bytes; a trailing NUL isn't required — informational only.
        pass
    if expected_sha256:
        if not _is_sha256(expected_sha256):
            return PayloadAsset(name, path, False, "sha256_malformed", digest, size,
                                prov or {})
        if digest != expected_sha256.lower():
            return PayloadAsset(name, path, False, "sha256_mismatch", digest, size,
                                prov or {})
    manifest_sha = (prov or {}).get("sha256")
    if prov_kind == "upstream" and not manifest_sha:
        return PayloadAsset(name, path, False, "provenance_incomplete_missing_sha256",
                            digest, size, prov or {})
    if manifest_sha:
        if not _is_sha256(manifest_sha):
            return PayloadAsset(name, path, False, "sha256_malformed_in_manifest",
                                digest, size, prov or {})
        if digest != manifest_sha.lower():
            return PayloadAsset(name, path, False, "sha256_mismatch_vs_manifest",
                                digest, size, prov or {})
    return PayloadAsset(name, path, True, "genuine_artifact", digest, size, prov or {})


def _is_sha256(value: object) -> bool:
    """True only for a 64-character hex string."""
    if not isinstance(value, str):
        return False
    if len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def check_elf_architecture(data: bytes) -> Optional[str]:
    """Static ELF header check for a PS5-loadable payload.

    PS5 payloads (ps5-payload-dev/sdk, elfldr) are 64-bit little-endian
    AArch64 ELF ET_EXEC/ET_DYN objects; any other header is rejected before
    delivery. Field layout is the standard ELF64 header (System V ABI):
    EI_CLASS @4, EI_DATA @5, e_type @16, e_machine @18.
    Returns a rejection reason string, or None when the header checks pass.
    """
    if len(data) < 64:
        return "elf_truncated"
    if data[4] != 2:  # EI_CLASS: 64-bit
        return "elf_not_64bit"
    if data[5] != 1:  # EI_DATA: little-endian
        return "elf_not_little_endian"
    e_type = int.from_bytes(data[16:18], "little")
    e_machine = int.from_bytes(data[18:20], "little")
    if e_machine != ELF_MACHINE_AARCH64:
        return "not_aarch64"
    if e_type not in (ELF_ET_EXEC, ELF_ET_DYN):
        return "elf_bad_type"
    return None


def validate_ladder(
    names: List[str],
    payload_dir: str,
    allow_placeholder: bool = False,
) -> Dict[str, PayloadAsset]:
    """Validate every payload in the configured order; see ChainsEngine."""
    out: Dict[str, PayloadAsset] = {}
    for name in names:
        out[name] = validate_payload(name, payload_dir, allow_placeholder)
        if not out[name].ok:
            log.error("payload %s REJECTED: %s", name, out[name].reason)
            break  # ladder is strictly ordered; first rejection stops it
    return out
