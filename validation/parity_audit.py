#!/usr/bin/env python3
"""Targeted real-world audit for the LLM06/LLM10 nine-language parity work.

random_sample.py proves finding-rate on a random Python sample. This driver instead
targets the languages whose LLM06 (Excessive Agency) / LLM10 (Unbounded Consumption)
detection is newest — Java/Kotlin/C#/Ruby/PHP/Rust use pattern-matching, which carries
more false-positive risk than the AST paths — and captures CODE CONTEXT (+/- lines) for
every finding so each can be triaged TP/FP without re-cloning.

For each language it searches GitHub for real AI repos (openai/anthropic SDK usage),
shallow-clones a seeded-random sample, scans, and records every finding with context,
grouped by detector. Output: a JSON dump + a triage-ready Markdown (findings for the
parity detectors first).

Usage:
  GITHUB_TOKEN=... python validation/parity_audit.py --langs java,kotlin,csharp,ruby,php,rust --per-lang 6 --seed 0
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import tempfile
from pathlib import Path

from validation.random_sample import gh_search, clone, count_loc, _log

# Per-language GitHub search: real AI apps (openai/anthropic SDKs), non-trivial, recent.
_LANG_QUERY = {
    "python": "openai language:Python stars:10..2000 pushed:>2025-01-01",
    "typescript": "openai language:TypeScript stars:10..2000 pushed:>2025-01-01",
    "javascript": "openai language:JavaScript stars:10..2000 pushed:>2025-01-01",
    "go": "openai language:Go stars:5..1500 pushed:>2025-01-01",
    "java": "openai language:Java stars:3..1500 pushed:>2024-06-01",
    "kotlin": "openai language:Kotlin stars:2..1000 pushed:>2024-06-01",
    "csharp": "openai language:C# stars:3..1500 pushed:>2024-06-01",
    "ruby": "openai language:Ruby stars:3..1500 pushed:>2024-06-01",
    "php": "openai language:PHP stars:3..1500 pushed:>2024-06-01",
    "rust": "openai language:Rust stars:3..1500 pushed:>2024-06-01",
}
# The detectors this audit is really stress-testing (newest coverage).
_PARITY_DETECTORS = {"tool-exposure", "unbounded-consumption"}


def _context(root: str, rel: str, line: int, span: int = 5) -> list[str]:
    try:
        text = (Path(root) / rel).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    lo, hi = max(0, line - span - 1), min(len(text), line + span)
    return [f"{n+1:5} {'>' if n+1 == line else ' '} {text[n]}" for n in range(lo, hi)]


def audit_lang(lang: str, per_lang: int, seed: int, pages: int, token, clone_timeout: int):
    query = _LANG_QUERY[lang]
    _log(f"\n=== {lang} :: {query}")
    pool = [r for r in gh_search(query, pages, token) if not r.get("fork") and not r.get("archived")]
    if not pool:
        _log(f"  no repos (rate-limited?)"); return []
    random.seed(seed)
    random.shuffle(pool)
    sample = pool[:per_lang]
    _log(f"  pool {len(pool)} -> sampling {len(sample)}")

    from orthosec.core.scanner import Scanner
    scanner = Scanner()
    results = []
    workdir = tempfile.mkdtemp(prefix=f"orthosec-audit-{lang}-")
    try:
        for i, repo in enumerate(sample, 1):
            full, url = repo["full_name"], repo["clone_url"]
            dest = os.path.join(workdir, full.replace("/", "__"))
            _log(f"  [{i}/{len(sample)}] {full}")
            sha = clone(url, dest, clone_timeout)
            if sha is None:
                results.append({"repo": full, "status": "clone_failed"}); continue
            try:
                res = scanner.scan(Path(dest))
                loc = count_loc(dest)
            except Exception as exc:
                results.append({"repo": full, "status": f"scan_error: {exc}"}); continue
            findings = []
            for f in res.findings:
                findings.append({
                    "detector": f.detector, "rule_id": f.rule_id, "owasp": f.owasp_llm,
                    "severity": f.severity.name, "file": f.file, "line": f.line,
                    "title": f.title, "evidence": (f.evidence or "")[:200],
                    "context": _context(dest, f.file, f.line) if f.detector in _PARITY_DETECTORS else [],
                })
            results.append({"repo": full, "commit": sha, "status": "ok", "lang": lang,
                            "loc": loc, "score": res.score, "grade": res.grade,
                            "findings": findings})
            shutil.rmtree(dest, ignore_errors=True)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return results


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="OrthoSec LLM06/LLM10 parity real-world audit")
    ap.add_argument("--langs", default="java,kotlin,csharp,ruby,php,rust",
                    help="comma-separated languages to audit")
    ap.add_argument("--per-lang", type=int, default=6)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--pages", type=int, default=2)
    ap.add_argument("--clone-timeout", type=int, default=150)
    ap.add_argument("--out", default="validation/results")
    ap.add_argument("--stamp", default="parity-audit")
    args = ap.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    langs = [l.strip() for l in args.langs.split(",") if l.strip() in _LANG_QUERY]

    all_repos = []
    for lang in langs:
        all_repos.extend(audit_lang(lang, args.per_lang, args.seed, args.pages, token, args.clone_timeout))

    ok = [r for r in all_repos if r["status"] == "ok"]
    total_loc = sum(r["loc"] for r in ok)
    flat = [(r["repo"], f) for r in ok for f in r["findings"]]
    parity = [(repo, f) for repo, f in flat if f["detector"] in _PARITY_DETECTORS]
    by_det: dict = {}
    for _, f in flat:
        by_det[f["detector"]] = by_det.get(f["detector"], 0) + 1

    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    (out / f"{args.stamp}.json").write_text(json.dumps(
        {"langs": langs, "seed": args.seed, "scanned_ok": len(ok),
         "total_loc": total_loc, "total_findings": len(flat),
         "parity_findings": len(parity), "by_detector": by_det, "repos": all_repos}, indent=2))
    (out / f"{args.stamp}-triage.md").write_text(_render_triage(parity, by_det, ok, total_loc))
    _log(f"\nScanned {len(ok)} repos, {total_loc:,} LOC, {len(flat)} findings "
         f"({len(parity)} from the parity detectors). Wrote {out/args.stamp}.json + -triage.md")
    return 0


def _render_triage(parity, by_det, ok, total_loc) -> str:
    L = ["# LLM06/LLM10 parity — real-world triage", "",
         f"- Repos scanned OK: {len(ok)} · Total LOC: {total_loc:,}",
         f"- Parity findings (tool-exposure + unbounded-consumption): **{len(parity)}**", "",
         "## All detectors (finding counts)", "", "| Detector | Findings |", "|---|---|"]
    for d, n in sorted(by_det.items(), key=lambda x: -x[1]):
        L.append(f"| {d} | {n} |")
    L += ["", "## Parity findings to triage (TP/FP)", ""]
    if not parity:
        L.append("_No LLM06/LLM10 findings in this sample._")
    for i, (repo, f) in enumerate(parity, 1):
        L += [f"### {i}. {f['rule_id']} · {f['owasp']} · {f['severity']} — {repo}",
              f"`{f['file']}:{f['line']}` — {f['title']}", "", "```",
              *f["context"], "```", "verdict: <TP|FP>", ""]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
