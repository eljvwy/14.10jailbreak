# PAYLOAD_MANIFEST.md — payload inventory and integrity records

Generated from the live asset audit (October 13, 2026). Machine-readable
counterpart: `assets/payloads/manifest.json`. **No binary in this project is
a real PS5 payload today; nothing was fabricated to change that.**

## Executable assets (actual state)

| Asset | Exists | Size | SHA-256 (16) | Kind | Provenance verified |
| --- | --- | --- | --- | --- | --- |
| `assets/payloads/kstuff.elf` | no | — | — | placeholder | no |
| `assets/payloads/ShadowMountPlus.elf` | no | — | — | placeholder | no |
| `assets/payloads/etaHEN.elf` | no | — | — | placeholder | no |
| `assets/payloads/notify.elf` | no | — | — | placeholder | no |
| `assets/payloads/ftpsrv.elf` | no | — | — | placeholder (upstream: github.com/ps5-payload-dev/ftpsrv @ v0.21.1) | no |
| `assets/homebrew/TEST14.10/eboot.bin` | yes | 132 B | `60a27ae18fa8bc7a…` | **placeholder stub** — self-describing text inside a valid ELF64 header | n/a |

## Engine behavior (why the missing files cannot cause a false success)

`src/payloads.py` validates every payload before delivery:

1. existence → `missing_file`
2. size bounds → `empty_file` / `bad_size`
3. ELF magic → `not_elf`
4. **architecture**: 64-bit LE AArch64, `ET_EXEC`/`ET_DYN`
   → `elf_truncated` / `elf_not_64bit` / `elf_not_little_endian` /
   `not_aarch64` / `elf_bad_type`
5. manifest kind: `placeholder` and unknown kinds refused →
   `unverified_placeholder` / `no_provenance_record`
6. `upstream` kind REQUIRES a 64-hex SHA-256 →
   `provenance_incomplete_missing_sha256` / `sha256_malformed_in_manifest`
7. hash must match file → `sha256_mismatch_vs_manifest` (tamper detection)

Ladder stops at the first rejection → `FAILED:payload_rejected` or
`FAILED:missing_assets`. Delivery is never attempted for an unverified file
unless the explicit `security.allow_placeholder_payloads` opt-in is set
(documented, off by default).

## Purpose/spec of each payload (as documented upstream)

| Payload | Purpose | Arch | Build | Entry point | FW compatibility |
| --- | --- | --- | --- | --- | --- |
| kstuff.elf | kernel patches (debug settings etc.) | aarch64 ELF | ps5-payload-dev/sdk | elfldr/9021 | tied to jailbroken console FW |
| ShadowMountPlus.elf | game auto-mount | aarch64 ELF | sdk | 9021 | same |
| etaHEN.elf | homebrew enabler | aarch64 ELF | sdk | 9021 | same |
| notify.elf | toast notifications (`-m "<text>"`) | aarch64 ELF | sdk | 9021 | same |
| ftpsrv.elf | FTP server on :2121 | aarch64 ELF | sdk (upstream v0.21.1) | 9021 | loader infra, not FW-specific |
| TEST14.10/eboot.bin | homebrew tile | aarch64 ELF | `console_app/TEST14.10/build.sh` | homebrew launcher | requires working homebrew loader |

## Intake procedure (for when real binaries are obtained)

1. Obtain from the upstream release page named in `manifest.json`.
2. Record `kind: "upstream"`, exact release/revision, `source_url`, and the
   SHA-256 of the file you actually downloaded.
3. The engine re-hashes at every run; a modified file is rejected with
   `sha256_mismatch_vs_manifest`.
4. Never record a hash for a file you did not obtain. Never copy an
   arbitrary ELF into this tree.

## Honest bottom line

**Provenance verified entries: 0.** Real payload execution on hardware: never
tested (no console). Any future "COMPLETE" must still pass the separate
execution-evidence gate; acked bytes alone never count.
