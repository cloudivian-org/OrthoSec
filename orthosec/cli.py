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
from orthosec.config import load_dotenv
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
    p_scan.add_argument("--profile", default=DEFAULT_PROFILE, choices=list(PROFILES),
                        help=f"Audience view (default: {DEFAULT_PROFILE})")
    p_scan.add_argument("--json", metavar="FILE", help="Write full findings as JSON")
    p_scan.add_argument("--sarif", metavar="FILE", help="Write SARIF 2.1.0 for CI/GitHub")
    p_scan.add_argument("--no-exec", action="store_true", help="Skip the LLM executive briefing")
    p_scan.add_argument("--fail-on", default="high",
                        choices=["critical", "high", "medium", "low", "none"],
                        help="Exit non-zero if a finding at/above this severity exists (default: high)")

    p_ask = sub.add_parser("ask", help="Ask a grounded executive question about a scan")
    p_ask.add_argument("path", help="Path to the AI product")
    p_ask.add_argument("question", help="The executive question")
    p_ask.add_argument("--profile", default="ciso", choices=list(PROFILES),
                       help="Audience view (default: ciso)")

    sub.add_parser("detectors", help="List active detectors")
    sub.add_parser("profiles", help="List available audience profiles")

    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "ask":
        return _cmd_ask(args)
    if args.command == "detectors":
        return _cmd_detectors()
    if args.command == "profiles":
        return _cmd_profiles()

    parser.print_help()
    return 0


def _cmd_scan(args) -> int:
    profile = get_profile(args.profile)
    scanner = Scanner()
    result = scanner.scan(args.path)
    annotate_findings(result.findings)  # deterministic business_impact on each finding

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

    return _exit_code(result, args.fail_on)


def _cmd_ask(args) -> int:
    from orthosec.intel.narrative import answer_question
    result = Scanner().scan(args.path)
    annotate_findings(result.findings)
    print(answer_question(result, args.question))
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
    threshold = _ORDER[fail_on]
    worst = max((f.severity.value for f in result.findings), default=0)
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    raise SystemExit(main())
