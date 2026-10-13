Payload drop-in directory.

Place the real ELF payloads here (names must match settings.json
payloads_in_order):
  kstuff.elf           — kernel patch/loader payload (elfldr chain)
  ShadowMountPlus.elf  — game auto-mounter
  etaHEN.elf           — homebrew enabler (debug settings, homebrew menu)
  notify.elf           — toast sender (used for exact on-screen strings)
  ftpsrv.elf           — FTP server on :2121 (used for homebrew tile install)

These are pulled by the console at http://<PC-IP>:8080/payloads/<name> and
executed via the elfldr URI mode, or sent raw per delivery_mode=raw.

IMPORTANT: without the real ELFs the chain will report payload FAILED
(PARTIAL) — the app will never pretend a payload ran.
