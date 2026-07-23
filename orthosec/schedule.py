"""Scheduling helpers — run OrthoSec on a cadence and emit scheduler snippets.

Two ways to run scheduled scans:
  * `orthosec watch` — a built-in loop (good for "always running": daily/interval
    reports written to a directory, latest.html always current).
  * `orthosec schedule` — prints ready-to-paste crontab / GitHub Actions / systemd
    snippets so an external scheduler drives it (more robust for servers/CI).
"""
from __future__ import annotations

import re

_DUR = re.compile(r"^\s*(\d+)\s*([smhd])\s*$", re.I)
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(text: str) -> int:
    """'30m' -> 1800, '2h' -> 7200, '1d' -> 86400. Raises ValueError on bad input."""
    m = _DUR.match(text or "")
    if not m:
        raise ValueError(f"bad interval '{text}' (use e.g. 45s, 30m, 6h, 1d)")
    return int(m.group(1)) * _UNIT[m.group(2).lower()]


def cron_snippets(path: str, cron: str, profile: str) -> str:
    scan = f"orthosec scan {path} --profile {profile} --fail-on high --no-exec"
    return f"""\
# ── crontab (crontab -e) ──────────────────────────────────────────
{cron}  cd {path} && {scan} --html /var/log/orthosec/report.html

# ── GitHub Actions (.github/workflows/orthosec-scheduled.yml) ──────
name: OrthoSec scheduled scan
on:
  schedule:
    - cron: "{cron}"
  workflow_dispatch:
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pipx install orthosec
      - run: orthosec scan . --profile {profile} --fail-on high --sarif orthosec.sarif --no-exec
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: {{ sarif_file: orthosec.sarif }}

# ── systemd timer (orthosec.timer + orthosec.service) ─────────────
# /etc/systemd/system/orthosec.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/{scan} --html /var/log/orthosec/report.html
# /etc/systemd/system/orthosec.timer
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
"""
