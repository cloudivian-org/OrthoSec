"""Optional OSV.dev vulnerability lookup for pinned dependencies.

Turns a deterministic "AI/ML dependency X is pinned to 1.2.3" into "…and 1.2.3 has N known
vulnerabilities (CVE-…, GHSA-…)". The data is authoritative and deterministic (a public
vulnerability database), not probabilistic — but it needs a network call, so it's **opt-in**
(`ORTHOSEC_OSV=1`) to keep the core scan fully offline, and **fails open** (any network
error leaves the deterministic pin/source findings untouched). Stdlib-only.
"""
from __future__ import annotations

import json
import os
import urllib.request

_API = "https://api.osv.dev/v1/querybatch"


def enabled() -> bool:
    return (os.environ.get("ORTHOSEC_OSV", "") or "").strip().lower() in ("1", "true", "yes", "on")


def _timeout() -> float:
    try:
        return float(os.environ.get("ORTHOSEC_OSV_TIMEOUT", "8"))
    except ValueError:
        return 8.0


def query(packages):
    """`packages`: list of (ecosystem, name, version). Returns a list aligned to the input —
    each entry a list of vulnerability IDs (possibly empty) — or None on failure (fail open)."""
    if not packages:
        return []
    body = {"queries": [{"package": {"ecosystem": eco, "name": name}, "version": ver}
                        for eco, name, ver in packages]}
    try:
        req = urllib.request.Request(
            _API, data=json.dumps(body).encode("utf-8"), method="POST",
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=_timeout()) as resp:  # noqa: S310
            obj = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None
    results = obj.get("results") or []
    out = []
    for res in results:
        vulns = (res or {}).get("vulns") or []
        out.append([v.get("id") for v in vulns if isinstance(v, dict) and v.get("id")])
    while len(out) < len(packages):   # OSV omits trailing empties in some responses
        out.append([])
    return out
