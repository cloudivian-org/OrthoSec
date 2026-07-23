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
    p_scan.add_argument("--no-exec", action="store_true", help="Skip the LLM executive briefing")
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
                       help="Include an LLM-drafted patch for review (no files written)")
    p_rem.add_argument("--auto", action="store_true",
                       help="Apply LLM-drafted patches in place (backs up originals to .orig)")

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
    result = scanner.scan(args.path)
    annotate_findings(result.findings)  # deterministic business_impact on each finding
    from orthosec.remediation import assign
    assign(result.findings)             # attach remediation agent + plan to each finding

    exec_summary = None
    if not args.no_exec:
        from orthosec.intel.narrative import executive_summary
        exec_summary = executive_summary(result, profile=profile)

    print(console.render(result, exec_summary=exec_summary, profile=profile))

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

    # Auto-generate the detailed HTML report on every run unless suppressed.
    report_path = args.html or (None if args.no_report else "orthosec-report.html")
    if report_path:
        from orthosec.report.html import render_html
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(render_html(result, profile=profile.id, exec_summary=exec_summary))
        print(f"Report -> {report_path}", file=sys.stderr)

    return _exit_code(result, fail_on)


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

    print(f"Remediation plan — {len(targets)} finding(s)\n")
    root = Path(result.root)
    applied = 0
    for f in targets:
        a = agent_for(f)
        mode = "auto-fixable" if a.auto_available else "manual only"
        print(f"● {f.rule_id}  {f.location}")
        print(f"    {f.title}")
        print(f"    agent: {a.name} ({a.id}) — {mode}")
        for i, step in enumerate(a.steps, 1):
            print(f"      {i}. {step}")

        if args.suggest or args.auto:
            patch = _draft_patch(f, root)
            if patch is None:
                print("    [no patch: set AZURE_API_KEY/ANTHROPIC_API_KEY + install orthosec[intel]]")
            elif args.auto and a.auto_available:
                applied += _apply_patch(root, f.file, patch)
            elif args.auto:
                print("    [skipped auto: this agent is manual-only for safety]")
            else:
                print("    ── suggested patch (review; not written) ──")
                for line in patch.splitlines()[:40]:
                    print(f"    | {line}")
        print()

    if args.auto:
        print(f"Applied {applied} patch(es). Originals backed up to *.orig. Review the diffs before committing.")
    elif not args.suggest:
        print("Run with --suggest to draft patches, or --auto to apply them (needs the intel layer).")
    return 0


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
