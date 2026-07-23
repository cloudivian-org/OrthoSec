#!/usr/bin/env python3
"""OrthoSec detection-efficacy benchmark.

Runs OrthoSec against a labeled corpus of vulnerable + safe look-alike samples
and reports precision / recall / F1 per OWASP LLM category. The safe look-alikes
(mitigated code that resembles a vulnerability) are what measure the false-positive
rate — the number a CISO actually cares about.

    python benchmark/run.py            # print the report
    python benchmark/run.py --check    # exit 1 if below thresholds (CI/regression gate)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from orthosec.core.scanner import Scanner  # noqa: E402

CATEGORIES = ["LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM08", "LLM10"]
MIN_PRECISION = 0.95
MIN_RECALL = 0.95


def run_benchmark(base: str | Path | None = None, manifest_name: str = "manifest.json") -> dict:
    base = Path(base) if base else Path(__file__).resolve().parent
    manifest = json.loads((base / manifest_name).read_text())
    scanner = Scanner()

    tp = {c: 0 for c in CATEGORIES}
    fp = {c: 0 for c in CATEGORIES}
    fn = {c: 0 for c in CATEGORIES}
    cases = []

    for case in manifest["cases"]:
        expect = set(case["expect"])
        result = scanner.scan(base / case["file"])
        fired = {f.owasp_llm for f in result.findings}
        for c in CATEGORIES:
            if c in expect and c in fired:
                tp[c] += 1
            elif c in expect and c not in fired:
                fn[c] += 1
            elif c not in expect and c in fired:
                fp[c] += 1
        cases.append({"file": case["file"], "expect": sorted(expect),
                      "fired": sorted(fired), "ok": _rel(expect, fired)})

    def prf(t, f, n):
        p = t / (t + f) if (t + f) else 1.0
        r = t / (t + n) if (t + n) else 1.0
        f1 = 2 * p * r / (p + r) if (p + r) else 0.0
        return p, r, f1

    per_cat = {}
    for c in CATEGORIES:
        p, r, f1 = prf(tp[c], fp[c], fn[c])
        per_cat[c] = {"tp": tp[c], "fp": fp[c], "fn": fn[c], "precision": p, "recall": r, "f1": f1}

    T, F, N = sum(tp.values()), sum(fp.values()), sum(fn.values())
    P, R, F1 = prf(T, F, N)
    return {
        "per_category": per_cat,
        "overall": {"tp": T, "fp": F, "fn": N, "precision": P, "recall": R, "f1": F1},
        "n_cases": len(manifest["cases"]),
        "cases": cases,
    }


def _rel(expect: set, fired: set) -> bool:
    return expect == (fired & set(CATEGORIES))


def run_adversarial(base: str | Path | None = None) -> list[dict]:
    """Run the adversarial evasion/FP-stress set. Cases flagged known_miss are
    documented current limitations (not counted as failures)."""
    base = Path(base) if base else Path(__file__).resolve().parent
    path = base / "manifest_adversarial.json"
    if not path.is_file():
        return []
    manifest = json.loads(path.read_text())
    scanner = Scanner()
    out = []
    for case in manifest["cases"]:
        expect = set(case["expect"])
        fired = {f.owasp_llm for f in scanner.scan(base / case["file"]).findings}
        ok = _rel(expect, fired)
        known = bool(case.get("known_miss"))
        status = "caught" if ok else ("known-miss" if known else "REGRESSION")
        out.append({"file": case["file"], "expect": sorted(expect),
                    "fired": sorted(fired), "known_miss": known, "ok": ok, "status": status})
    return out


def _fmt(x: float) -> str:
    return f"{x * 100:5.1f}%"


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    res = run_benchmark()
    print(f"OrthoSec detection-efficacy benchmark — {res['n_cases']} labeled cases\n")
    print(f"  {'Category':<10} {'TP':>3} {'FP':>3} {'FN':>3}  {'Precision':>9} {'Recall':>8} {'F1':>7}")
    print("  " + "-" * 52)
    for c, m in res["per_category"].items():
        print(f"  {c:<10} {m['tp']:>3} {m['fp']:>3} {m['fn']:>3}  "
              f"{_fmt(m['precision']):>9} {_fmt(m['recall']):>8} {_fmt(m['f1']):>7}")
    o = res["overall"]
    print("  " + "-" * 52)
    print(f"  {'OVERALL':<10} {o['tp']:>3} {o['fp']:>3} {o['fn']:>3}  "
          f"{_fmt(o['precision']):>9} {_fmt(o['recall']):>8} {_fmt(o['f1']):>7}")

    # Surface any misclassified cases for debugging.
    bad = [c for c in res["cases"] if not c["ok"]]
    if bad:
        print("\n  Misclassified:")
        for c in bad:
            print(f"    {c['file']}: expected {c['expect']}, fired {c['fired']}")

    if "--adversarial" in argv:
        adv = run_adversarial()
        print("\n  Adversarial set (evasion + FP stress):")
        for c in adv:
            mark = {"caught": "✓", "known-miss": "○", "REGRESSION": "✗"}[c["status"]]
            print(f"    {mark} {c['file'].split('/')[-1]:26} expect {c['expect']} fired {c['fired']} — {c['status']}")
        regressions = [c for c in adv if c["status"] == "REGRESSION"]
        caught = sum(1 for c in adv if c["status"] == "caught")
        print(f"    {caught}/{len(adv)} handled, {len(adv) - caught} documented known-miss")
        if regressions and "--check" in argv:
            print("\nFAIL: adversarial regression")
            return 1

    if "--check" in argv:
        if o["precision"] < MIN_PRECISION or o["recall"] < MIN_RECALL:
            print(f"\nFAIL: below thresholds (precision ≥ {MIN_PRECISION}, recall ≥ {MIN_RECALL})")
            return 1
        print(f"\nPASS: precision {_fmt(o['precision'])}, recall {_fmt(o['recall'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
