#!/usr/bin/env python3
"""Independent, reproducible random-sample validation for OrthoSec.

Curated repos prove capability; a *random* sample proves it holds on code we didn't pick.
This harness:

  1. Searches GitHub for public AI repos matching a query (default: repos using `openai`),
  2. takes a **seeded-random** sample of N (so a run is reproducible, and the exact repos +
     resolved commits are recorded for audit),
  3. shallow-clones and scans each with OrthoSec,
  4. reports **measured finding rates** — per detector, per severity, per KLOC, and the share
     of repos with a HIGH+ finding — as Markdown + JSON.

What it does NOT claim: a precision figure. Finding-rate is not precision without labels.
For that, `--triage-sample K` dumps K random findings (with code context) for a human to
label TP/FP; the labeled subset then yields a measured precision on a random sample — the
honest number. Everything is reproducible: same query + seed + the recorded commit manifest.

Usage:
  GITHUB_TOKEN=ghp_...  python validation/random_sample.py --n 20 --seed 0
  python validation/random_sample.py --n 20 --seed 0 --triage-sample 30
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

_CODE_EXT = {".py", ".ts", ".tsx", ".jsx", ".js", ".go", ".java", ".kt", ".cs", ".rb", ".php", ".rs"}
_SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv", "venv"}
_DEFAULT_QUERY = "openai language:Python stars:5..1500 pushed:>2025-01-01"


def _log(msg):
    print(msg, flush=True)


def gh_search(query: str, pages: int, token: str | None):
    """Return GitHub repo search items across `pages` (100 each). Rate-limit-friendly."""
    items = []
    for page in range(1, pages + 1):
        url = (f"https://api.github.com/search/repositories?q={urllib.parse.quote(query)}"
               f"&per_page=100&page={page}&sort=updated&order=desc")
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
        except Exception as exc:
            _log(f"  search page {page} failed: {exc}")
            break
        batch = data.get("items", [])
        items.extend(batch)
        if len(batch) < 100:
            break
        time.sleep(2 if not token else 1)   # unauthenticated search is 10/min
    return items


def clone(url: str, dest: str, timeout: int) -> str | None:
    """Shallow-clone; return the resolved commit SHA, or None on failure."""
    try:
        subprocess.run(["git", "clone", "--depth", "1", "-q", url, dest],
                       timeout=timeout, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sha = subprocess.run(["git", "-C", dest, "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=30)
        return sha.stdout.strip()[:12]
    except Exception:
        return None


def count_loc(root: str) -> int:
    loc = 0
    for dp, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            if Path(fn).suffix.lower() in _CODE_EXT:
                try:
                    with open(os.path.join(dp, fn), "rb") as fh:
                        loc += sum(1 for _ in fh)
                except OSError:
                    pass
    return loc


def scan(root: str):
    from orthosec.core.scanner import Scanner
    return Scanner().scan(Path(root))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="OrthoSec random-sample validation")
    ap.add_argument("--n", type=int, default=15, help="number of repos to sample")
    ap.add_argument("--seed", type=int, default=0, help="RNG seed (reproducible sample)")
    ap.add_argument("--query", default=_DEFAULT_QUERY, help="GitHub repo search query")
    ap.add_argument("--pages", type=int, default=3, help="search pages to pool from (100/page)")
    ap.add_argument("--clone-timeout", type=int, default=180)
    ap.add_argument("--out", default="validation/results", help="output directory")
    ap.add_argument("--triage-sample", type=int, default=0,
                    help="also dump K random findings with code context for manual TP/FP labeling")
    ap.add_argument("--stamp", default=None, help="output filename stamp (default: seed+n)")
    args = ap.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    _log(f"Searching GitHub: {args.query!r} ({'authenticated' if token else 'unauthenticated'})")
    pool = gh_search(args.query, args.pages, token)
    pool = [r for r in pool if not r.get("fork") and not r.get("archived")]
    if not pool:
        _log("No repos found (rate-limited? set GITHUB_TOKEN). Aborting."); return 2
    random.seed(args.seed)
    random.shuffle(pool)
    sample = pool[:args.n]
    _log(f"Pool {len(pool)} repos -> sampling {len(sample)} (seed {args.seed})")

    per_repo, by_detector, by_sev = [], {}, {}
    all_findings = []   # (repo, finding) for triage
    total_loc = total_findings = repos_ok = repos_with_high = 0
    workdir = tempfile.mkdtemp(prefix="orthosec-validation-")
    try:
        for i, repo in enumerate(sample, 1):
            full = repo["full_name"]; url = repo["clone_url"]
            dest = os.path.join(workdir, full.replace("/", "__"))
            _log(f"[{i}/{len(sample)}] {full}")
            sha = clone(url, dest, args.clone_timeout)
            if sha is None:
                per_repo.append({"repo": full, "status": "clone_failed"}); continue
            try:
                res = scan(dest)
                loc = count_loc(dest)
            except Exception as exc:
                per_repo.append({"repo": full, "status": f"scan_error: {exc}"}); continue
            repos_ok += 1
            total_loc += loc
            total_findings += len(res.findings)
            sev_counts = {}
            for f in res.findings:
                by_detector[f.detector] = by_detector.get(f.detector, 0) + 1
                by_sev[f.severity.name] = by_sev.get(f.severity.name, 0) + 1
                sev_counts[f.severity.name] = sev_counts.get(f.severity.name, 0) + 1
                all_findings.append((full, f))
            if sev_counts.get("CRITICAL") or sev_counts.get("HIGH"):
                repos_with_high += 1
            per_repo.append({"repo": full, "commit": sha, "status": "ok", "loc": loc,
                             "score": res.score, "grade": res.grade,
                             "findings": len(res.findings), "by_severity": sev_counts})
            shutil.rmtree(dest, ignore_errors=True)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    kloc = total_loc / 1000.0 or 1.0
    summary = {
        "query": args.query, "seed": args.seed, "sampled": len(sample),
        "scanned_ok": repos_ok, "total_loc": total_loc, "total_findings": total_findings,
        "findings_per_kloc": round(total_findings / kloc, 3),
        "repos_with_high_or_critical": repos_with_high,
        "pct_repos_with_high": round(100 * repos_with_high / repos_ok, 1) if repos_ok else 0,
        "by_detector": dict(sorted(by_detector.items(), key=lambda x: -x[1])),
        "by_severity": by_sev, "per_repo": per_repo,
    }

    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    stamp = args.stamp or f"seed{args.seed}-n{args.n}"
    (out / f"{stamp}.json").write_text(json.dumps(summary, indent=2))
    (out / f"{stamp}.md").write_text(_render_md(summary))
    _log(f"\nScanned {repos_ok}/{len(sample)} repos, {total_loc:,} LOC, {total_findings} findings "
         f"({summary['findings_per_kloc']}/KLOC); {summary['pct_repos_with_high']}% had a HIGH+.")
    _log(f"Wrote {out/stamp}.json and .md")

    if args.triage_sample and all_findings:
        _dump_triage(all_findings, args.triage_sample, args.seed, out, stamp)
    return 0


def _render_md(s: dict) -> str:
    lines = ["# OrthoSec — random-sample validation", "",
             f"- Query: `{s['query']}`", f"- Seed: `{s['seed']}` (reproducible sample)",
             f"- Repos sampled: {s['sampled']} · scanned OK: {s['scanned_ok']}",
             f"- Total LOC: {s['total_loc']:,}",
             f"- Total findings: {s['total_findings']}  ·  **{s['findings_per_kloc']} per KLOC**",
             f"- Repos with a HIGH/CRITICAL finding: {s['repos_with_high_or_critical']} "
             f"({s['pct_repos_with_high']}%)", "",
             "## By detector", "", "| Detector | Findings |", "|---|---|"]
    for det, n in s["by_detector"].items():
        lines.append(f"| {det} | {n} |")
    lines += ["", "## By severity", "", "| Severity | Findings |", "|---|---|"]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in s["by_severity"]:
            lines.append(f"| {sev} | {s['by_severity'][sev]} |")
    lines += ["", "## Per repo (reproducible — repo @ commit)", "",
              "| Repo | Commit | LOC | Grade | Findings |", "|---|---|---|---|---|"]
    for r in s["per_repo"]:
        if r["status"] == "ok":
            lines.append(f"| {r['repo']} | `{r['commit']}` | {r['loc']:,} | {r['grade']} | {r['findings']} |")
        else:
            lines.append(f"| {r['repo']} | — | — | — | _{r['status']}_ |")
    lines += ["", "> Finding-rate is **not** precision without labels. Run with "
              "`--triage-sample K` to dump K random findings for manual TP/FP labeling and a "
              "measured precision on this random sample."]
    return "\n".join(lines) + "\n"


def _dump_triage(all_findings, k, seed, out, stamp):
    random.seed(seed + 1)
    picks = random.sample(all_findings, min(k, len(all_findings)))
    lines = ["# Triage sample — label each TP or FP", "",
             "For each finding: read the code, mark `verdict: TP` or `verdict: FP`. "
             "Then precision = TP / (TP + FP) on this random sample.", ""]
    for i, (repo, f) in enumerate(picks, 1):
        lines += [f"## {i}. {f.rule_id}  ({f.severity.name})  —  {repo}",
                  f"- title: {f.title}", f"- file: {f.file}:{f.line}",
                  f"- evidence: `{f.evidence}`", "- verdict: <TP|FP>", ""]
    (out / f"{stamp}-triage.md").write_text("\n".join(lines))
    _log(f"Wrote {len(picks)} findings to {out/stamp}-triage.md for manual labeling")


if __name__ == "__main__":
    raise SystemExit(main())
