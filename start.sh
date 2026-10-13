#!/usr/bin/env bash
# One-click entry point for PS5-JB-14.10 host (macOS/Linux)
set -e
cd "$(dirname "$0")"
if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 not found; install Python 3.9+ first." >&2
  exit 1
fi
python3 -m pip install -r requirements.txt --quiet --disable-pip-version-check 2>/dev/null || true
exec python3 src/main.py
