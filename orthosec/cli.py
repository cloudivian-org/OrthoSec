"""OrthoSec CLI — stdlib only, runs with zero external dependencies.

    orthosec scan <path>            # scan an AI product, print report + exec briefing
    orthosec scan <path> --json out.json
    orthosec scan <path> --sarif results.sarif
    orthosec scan <path> --no-exec  # skip the LLM briefing
    orthosec ask <path> "question"  # grounded executive Q&A
    orthosec detectors              # list active detectors
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from orthosec import __version__
from orthosec.config import load_dotenv, load_project_config
from orthosec.core.scanner import Scanner
from orthosec.intel.business_risk import annotate_findings
from orthosec.profiles import DEFAULT_PROFILE, PROFILES, get_profile
from orthosec.report import console
from orthosec.report.sarif import to_sarif


def main(argv: list[str] | None = None) -> int:
    load_dotenv()  # pick up ANTHROPIC_API_KEY / ORTHOSEC_MODEL from a .env if present
    parser = argparse.ArgumentParser(
        prog="orthosec",
        description="OrthoSec — the AI Security Architect. Technical AI risk analysis "
                    "with executive business context.",
    )
    parser.add_argument("--version", action="version", version=f"OrthoSec {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="Scan an AI product for security risk")
    p_scan.add_argument("path", help="Path to the AI product (repo / dir / file)")
    p_scan.add_argument("--profile", default=None, choices=list(PROFILES),
                        help=f"Audience view (default: {DEFAULT_PROFILE}, or .orthosec.yml)")
    p_scan.add_argument("--json", metavar="FILE", help="Write full findings as JSON")
    p_scan.add_argument("--sarif", metavar="FILE", help="Write SARIF 2.1.0 for CI/GitHub")
    p_scan.add_argument("--html", metavar="FILE", help="HTML report path (default: orthosec-report.html)")
    p_scan.add_argument("--no-report", action="store_true", help="Do not auto-generate the HTML report")
    p_scan.add_argument("--diff", nargs="?", const="HEAD", metavar="REF",
                        help="Scan only files changed vs git (default HEAD; or a ref like origin/main). "
                             "Fast for pre-commit/PR; cross-module is limited to changed files.")
    p_scan.add_argument("--baseline", metavar="FILE",
                        help="Suppress findings recorded in this baseline (gate on NEW findings only)")
    p_scan.add_argument("--write-baseline", metavar="FILE",
                        help="Record current findings as the baseline (accept them) and exit 0")
    p_scan.add_argument("--no-exec", action="store_true", help="Skip the LLM executive briefing")
    p_scan.add_argument("--open", action="store_true",
                        help="Open the HTML report in your browser after the scan (env: ORTHOSEC_OPEN)")
    p_scan.add_argument("--fail-on", default=None,
                        choices=["critical", "high", "medium", "low", "none"],
                        help="Exit non-zero if a finding at/above this severity exists (default: high)")

    p_ask = sub.add_parser("ask", help="Ask a grounded executive question about a scan")
    p_ask.add_argument("path", help="Path to the AI product")
    p_ask.add_argument("question", help="The executive question")
    p_ask.add_argument("--profile", default="ciso", choices=list(PROFILES),
                       help="Audience view (default: ciso)")

    p_rem = sub.add_parser("remediate", help="Plan or apply fixes via remediation agents")
    p_rem.add_argument("path", help="Path to the AI product")
    p_rem.add_argument("--rule", help="Comma-separated rule ids to target (default: all)")
    p_rem.add_argument("--agent", help="Only findings handled by this remediation agent id")
    p_rem.add_argument("--suggest", action="store_true",
                       help="Show the patch for review (deterministic where possible; no files written)")
    p_rem.add_argument("--auto", action="store_true",
                       help="Apply fixes in place (deterministic first, else LLM; backs up originals to .orig)")
    p_rem.add_argument("--no-verify", action="store_true",
                       help="Skip the re-scan that confirms an applied fix resolved the finding")

    # watch/schedule defaults are env-controllable (.env): ORTHOSEC_WATCH_EVERY,
    # ORTHOSEC_REPORT_DIR, ORTHOSEC_CRON, ORTHOSEC_PROFILE. Flags override env.
    p_watch = sub.add_parser("watch", help="Re-scan on a schedule, writing a report each run")
    p_watch.add_argument("path", help="Path to the AI product")
    p_watch.add_argument("--every", default=None, help="Interval e.g. 45s 30m 6h 1d (env: ORTHOSEC_WATCH_EVERY, default 1d)")
    p_watch.add_argument("--report-dir", default=None, help="Report output dir (env: ORTHOSEC_REPORT_DIR)")
    p_watch.add_argument("--profile", default=None, choices=list(PROFILES))
    p_watch.add_argument("--no-exec", action="store_true", help="Skip the LLM executive briefing")

    p_sched = sub.add_parser("schedule", help="Print crontab / GitHub Actions / systemd scheduling snippets")
    p_sched.add_argument("path", help="Path to the AI product")
    p_sched.add_argument("--cron", default=None, help="Cron expression (env: ORTHOSEC_CRON, default 9am daily)")
    p_sched.add_argument("--profile", default=None, choices=list(PROFILES))

    p_proxy = sub.add_parser("proxy", help="Run the inline runtime gateway (inspect live LLM traffic)")
    p_proxy.add_argument("--upstream", default=None,
                         help="Provider base URL (or ORTHOSEC_UPSTREAM). e.g. https://api.openai.com")
    p_proxy.add_argument("--host", default="127.0.0.1")
    p_proxy.add_argument("--port", type=int, default=8100)
    p_proxy.add_argument("--mode", default="monitor", choices=["monitor", "block"],
                         help="monitor logs risks; block refuses injected requests (default: monitor)")

    sub.add_parser("detectors", help="List active detectors")
    sub.add_parser("profiles", help="List available audience profiles")

    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "ask":
        return _cmd_ask(args)
    if args.command == "remediate":
        return _cmd_remediate(args)
    if args.command == "watch":
        return _cmd_watch(args)
    if args.command == "schedule":
        return _cmd_schedule(args)
    if args.command == "proxy":
        return _cmd_proxy(args)
    if args.command == "detectors":
        return _cmd_detectors()
    if args.command == "profiles":
        return _cmd_profiles()

    parser.print_help()
    return 0


def _cmd_scan(args) -> int:
    import os
    cfg = load_project_config(args.path)  # .orthosec.yml at the target root, if any
    profile = get_profile(args.profile or cfg.get("profile")
                          or os.environ.get("ORTHOSEC_PROFILE") or DEFAULT_PROFILE)
    fail_on = args.fail_on or cfg.get("fail_on") or os.environ.get("ORTHOSEC_FAIL_ON") or "high"
    exclude = cfg.get("exclude") or []

    scanner = Scanner(exclude=exclude)
    if args.diff:
        changed = _git_changed_files(args.path, args.diff)
        if changed is None:
            print("error: --diff needs a git repository (git not found or not a repo)", file=sys.stderr)
            return 2
        if not changed:
            print(f"No changed files vs {args.diff} — nothing to scan.", file=sys.stderr)
            return 0
        print(f"Scanning {len(changed)} changed file(s) vs {args.diff}", file=sys.stderr)
        result = scanner.scan_files(args.path, changed)
    else:
        result = scanner.scan(args.path)
    annotate_findings(result.findings)  # deterministic business_impact on each finding
    from orthosec.remediation import assign
    assign(result.findings)             # attach remediation agent + plan to each finding

    if args.write_baseline:
        fps = sorted({f.fingerprint for f in result.findings})
        with open(args.write_baseline, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "fingerprints": fps}, fh, indent=2)
        print(f"Wrote baseline of {len(fps)} finding(s) -> {args.write_baseline}", file=sys.stderr)
        return 0

    baselined = 0
    if args.baseline:
        from pathlib import Path
        from orthosec.core.scoring import posture_score, grade as _grade
        try:
            base = set(json.loads(Path(args.baseline).read_text()).get("fingerprints", []))
        except Exception:
            base = set()
        before = len(result.findings)
        result.findings = [f for f in result.findings if f.fingerprint not in base]
        baselined = before - len(result.findings)
        result.score = posture_score(result.findings)
        result.grade = _grade(result.score)

    no_exec = args.no_exec or _env_true("ORTHOSEC_NO_EXEC")
    exec_summary = None
    if not no_exec:
        from orthosec.intel.narrative import executive_summary
        exec_summary = executive_summary(result, profile=profile)

    print(console.render(result, exec_summary=exec_summary, profile=profile))
    if baselined:
        print(f"({baselined} finding(s) suppressed by baseline — showing new findings only)",
              file=sys.stderr)

    if args.json:
        payload = {
            "orthosec_version": __version__,
            "root": result.root,
            "score": result.score,
            "grade": result.grade,
            "severity_counts": result.by_severity(),
            "detectors_run": result.detectors_run,
            "findings": [f.to_dict() for f in result.findings],
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"Wrote JSON report -> {args.json}", file=sys.stderr)

    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as fh:
            json.dump(to_sarif(result), fh, indent=2)
        print(f"Wrote SARIF report -> {args.sarif}", file=sys.stderr)

    # Auto-generate the detailed HTML report on every run. Path is env-configurable
    # (ORTHOSEC_REPORT); set it to "off"/"none" to disable. --html / --no-report override.
    report_path = _resolve_report_path(args)
    if report_path:
        from orthosec.report.html import render_html
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(render_html(result, profile=profile.id, exec_summary=exec_summary))
        print(f"Report -> {report_path}", file=sys.stderr)
        if args.open or _env_true("ORTHOSEC_OPEN"):
            try:
                import webbrowser
                webbrowser.open("file://" + os.path.abspath(report_path))
            except Exception:
                pass   # headless / no browser — never fail a scan over opening a viewer

    return _exit_code(result, fail_on)


def _env_true(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _resolve_report_path(args):
    """Where to write the HTML report. Precedence: --html > --no-report > env
    ORTHOSEC_REPORT > default. Env value 'off'/'none'/'0'/'false'/'no' disables."""
    if args.html:
        return args.html
    if args.no_report:
        return None
    env = os.environ.get("ORTHOSEC_REPORT")
    if env is not None:
        return None if env.strip().lower() in ("off", "none", "0", "false", "no", "") else env
    return "orthosec-report.html"


def _cmd_ask(args) -> int:
    from orthosec.intel.narrative import answer_question
    result = Scanner().scan(args.path)
    annotate_findings(result.findings)
    print(answer_question(result, args.question))
    return 0


def _cmd_remediate(args) -> int:
    from pathlib import Path
    from orthosec.remediation import assign, agent_for

    result = Scanner(exclude=(load_project_config(args.path).get("exclude") or [])).scan(args.path)
    assign(result.findings)

    targets = result.findings
    if args.rule:
        wanted = {r.strip() for r in args.rule.split(",")}
        targets = [f for f in targets if f.rule_id in wanted]
    if args.agent:
        targets = [f for f in targets if agent_for(f).id == args.agent]

    if not targets:
        print("No matching findings to remediate.")
        return 0

    from orthosec.remediation_fix import deterministic_fix, has_deterministic_fix

    # Fingerprints present per file BEFORE any fix — the baseline for verification.
    pre_fps: dict[str, set] = {}
    for f in result.findings:
        pre_fps.setdefault(f.file, set()).add(f.fingerprint)

    print(f"Remediation plan — {len(targets)} finding(s)\n")
    root = Path(result.root)
    applied = resolved = regressed = 0
    for f in targets:
        a = agent_for(f)
        det = has_deterministic_fix(f)
        mode = "deterministic auto-fix" if det else ("auto-fixable (LLM)" if a.auto_available else "manual only")
        print(f"● {f.rule_id}  {f.location}")
        print(f"    {f.title}")
        print(f"    agent: {a.name} ({a.id}) — {mode}")
        for i, step in enumerate(a.steps, 1):
            print(f"      {i}. {step}")

        if args.suggest or args.auto:
            new_text, kind = _build_fix(f, root)
            if new_text is None:
                if det:
                    print("    [deterministic fix did not apply cleanly here]")
                else:
                    print("    [no patch: set AZURE_API_KEY/ANTHROPIC_API_KEY + install orthosec[intel]]")
            elif args.auto and (kind == "deterministic" or a.auto_available):
                applied += _apply_patch(root, f.file, new_text)
                if not args.no_verify:
                    ok, new_findings = _verify_fix(result, root, f, pre_fps.get(f.file, set()))
                    resolved += 1 if ok else 0
                    regressed += len(new_findings)
                    _print_verify(ok, new_findings)
            elif args.auto:
                print("    [skipped auto: this agent is manual-only for safety]")
            else:
                print(f"    ── suggested fix ({kind}; review, not written) ──")
                _print_line_diff(f, root, new_text)
        print()

    if args.auto:
        print(f"Applied {applied} fix(es); {resolved} verified resolved by re-scan"
              + (f"; {regressed} new finding(s) introduced — review!" if regressed else "")
              + ". Originals backed up to *.orig.")
    elif not args.suggest:
        print("Run with --suggest to preview fixes, or --auto to apply them "
              "(deterministic fixes need no API key; LLM fixes need the intel layer).")
    return 0


def _build_fix(finding, root):
    """(new_file_text, kind) — a deterministic fix if one applies, else an LLM draft."""
    from pathlib import Path
    from orthosec.remediation_fix import deterministic_fix
    fpath = Path(root) / finding.file
    if not fpath.is_file():
        return None, "none"
    source = fpath.read_text(encoding="utf-8", errors="replace")
    det = deterministic_fix(finding, source)
    if det is not None:
        return det, "deterministic"
    return _draft_patch(finding, root), "LLM"


def _verify_fix(prev_result, root, finding, pre_fps_for_file):
    """Re-scan the fixed file. Returns (resolved?, [new findings introduced])."""
    from pathlib import Path
    fpath = Path(root) / finding.file
    post = Scanner().scan_files(root, [str(fpath)])
    post_fps = {x.fingerprint for x in post.findings}
    resolved = finding.fingerprint not in post_fps
    new = [x for x in post.findings if x.fingerprint not in pre_fps_for_file]
    return resolved, new


def _print_verify(resolved, new_findings):
    print("    ✓ re-scan: finding RESOLVED" if resolved
          else "    ✗ re-scan: finding STILL PRESENT — review the fix")
    for x in new_findings:
        print(f"    ! re-scan: new {x.severity.name} finding introduced at {x.location} ({x.rule_id})")


def _print_line_diff(finding, root, new_text):
    from pathlib import Path
    fpath = Path(root) / finding.file
    old = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
    new = new_text.splitlines()
    idx = finding.line - 1
    if 0 <= idx < len(old) and idx < len(new) and old[idx] != new[idx]:
        print(f"    | - {old[idx].strip()}")
        print(f"    | + {new[idx].strip()}")
    else:                                             # multi-line (LLM) patch — show a window
        for line in new_text.splitlines()[:40]:
            print(f"    | {line}")


def _draft_patch(finding, root):
    try:
        from orthosec.intel.autofix import suggest_patch
    except Exception:
        return None
    from pathlib import Path
    fpath = root / finding.file
    if not fpath.is_file():
        return None
    return suggest_patch(finding, fpath.read_text(encoding="utf-8", errors="replace"))


def _apply_patch(root, rel_file, patch: str) -> int:
    from pathlib import Path
    fpath = Path(root) / rel_file
    backup = fpath.with_suffix(fpath.suffix + ".orig")
    if not backup.exists():
        backup.write_text(fpath.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
    fpath.write_text(patch, encoding="utf-8")
    print(f"    ✓ applied fix to {rel_file} (backup: {backup.name})")
    return 1


def _git_changed_files(path, ref):
    """Files changed vs `ref` (default HEAD) plus untracked, as absolute paths under
    `path`. Returns None if not a git repo / git unavailable, [] if nothing changed."""
    import subprocess
    from pathlib import Path

    def _git(*args):
        return subprocess.run(["git", "-C", str(path), *args],
                              capture_output=True, text=True, timeout=30)
    try:
        top = _git("rev-parse", "--show-toplevel")
    except (OSError, subprocess.SubprocessError):
        return None
    if top.returncode != 0:
        return None
    gitroot = Path(top.stdout.strip())

    rels = set()
    for cmd in (("diff", "--name-only", ref), ("ls-files", "--others", "--exclude-standard")):
        r = _git(*cmd)
        if r.returncode == 0:
            rels.update(x for x in r.stdout.splitlines() if x.strip())

    scan_root = Path(path).resolve()
    out = []
    for rel in rels:
        p = (gitroot / rel).resolve()
        if p.is_file() and (scan_root in p.parents or p == scan_root):
            out.append(p)
    return out


def _cmd_watch(args) -> int:
    import os
    import time
    import datetime
    from pathlib import Path
    from orthosec.schedule import parse_duration
    from orthosec.report.html import render_html
    from orthosec.remediation import assign

    every = args.every or os.environ.get("ORTHOSEC_WATCH_EVERY", "1d")
    report_dir = args.report_dir or os.environ.get("ORTHOSEC_REPORT_DIR", "orthosec-reports")
    profile = get_profile(args.profile or os.environ.get("ORTHOSEC_PROFILE") or DEFAULT_PROFILE)
    try:
        interval = parse_duration(every)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    rdir = Path(report_dir)
    rdir.mkdir(parents=True, exist_ok=True)
    exclude = load_project_config(args.path).get("exclude") or []
    print(f"OrthoSec watch: scanning {args.path} every {every} → {rdir}/  (Ctrl-C to stop)",
          file=sys.stderr)
    try:
        while True:
            result = Scanner(exclude=exclude).scan(args.path)
            annotate_findings(result.findings)
            assign(result.findings)
            exec_summary = None
            if not args.no_exec:
                from orthosec.intel.narrative import executive_summary
                exec_summary = executive_summary(result, profile=profile)
            ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            html = render_html(result, profile=profile.id, exec_summary=exec_summary)
            (rdir / f"report-{ts}.html").write_text(html, encoding="utf-8")
            (rdir / "latest.html").write_text(html, encoding="utf-8")
            payload = {"generated": ts, "score": result.score, "grade": result.grade,
                       "severity_counts": result.by_severity(),
                       "findings": [f.to_dict() for f in result.findings]}
            (rdir / "latest.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
            n = sum(result.by_severity().values())
            print(f"[{ts}] score {result.score}/100 grade {result.grade} — {n} findings "
                  f"→ {rdir}/latest.html", flush=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nstopped.", file=sys.stderr)
        return 0


def _cmd_schedule(args) -> int:
    import os
    from orthosec.schedule import cron_snippets
    cron = args.cron or os.environ.get("ORTHOSEC_CRON", "0 9 * * *")
    profile = args.profile or os.environ.get("ORTHOSEC_PROFILE") or DEFAULT_PROFILE
    print(cron_snippets(args.path, cron, profile))
    return 0


def _cmd_proxy(args) -> int:
    import os
    from orthosec.proxy import run_proxy
    upstream = args.upstream or os.environ.get("ORTHOSEC_UPSTREAM")
    if not upstream:
        print("error: set --upstream or ORTHOSEC_UPSTREAM (e.g. https://api.openai.com)",
              file=sys.stderr)
        return 2
    run_proxy(upstream=upstream, host=args.host, port=args.port, mode=args.mode)
    return 0


def _cmd_detectors() -> int:
    from orthosec.detectors import load_builtin_detectors
    from orthosec.core.taxonomy import owasp_name
    for det in load_builtin_detectors():
        code = getattr(det, "owasp_llm", "")
        print(f"  {det.id:<20} {det.name}  ({code} {owasp_name(code)})")
    return 0


def _cmd_profiles() -> int:
    for p in PROFILES.values():
        print(f"  {p.id:<10} {p.label:<26} — {p.audience}")
    return 0


_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "none": 0}


def _exit_code(result, fail_on: str) -> int:
    if fail_on == "none":
        return 0
    threshold = _ORDER.get(fail_on, _ORDER["high"])
    worst = max((f.severity.value for f in result.findings), default=0)
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    raise SystemExit(main())
