"""Env-driven report generation: ORTHOSEC_REPORT / ORTHOSEC_OPEN / ORTHOSEC_NO_EXEC."""
import os
import types

from orthosec.cli import _resolve_report_path, _env_true


def _args(html=None, no_report=False):
    return types.SimpleNamespace(html=html, no_report=no_report)


def _clear(monkeypatch):
    monkeypatch.delenv("ORTHOSEC_REPORT", raising=False)


def test_default_report_path(monkeypatch):
    _clear(monkeypatch)
    assert _resolve_report_path(_args()) == "orthosec-report.html"


def test_env_sets_report_path(monkeypatch):
    monkeypatch.setenv("ORTHOSEC_REPORT", "reports/scan.html")
    assert _resolve_report_path(_args()) == "reports/scan.html"


def test_env_off_disables(monkeypatch):
    for val in ("off", "none", "0", "false", "no", ""):
        monkeypatch.setenv("ORTHOSEC_REPORT", val)
        assert _resolve_report_path(_args()) is None


def test_cli_html_overrides_env(monkeypatch):
    monkeypatch.setenv("ORTHOSEC_REPORT", "env.html")
    assert _resolve_report_path(_args(html="cli.html")) == "cli.html"


def test_no_report_flag_wins(monkeypatch):
    monkeypatch.setenv("ORTHOSEC_REPORT", "env.html")
    assert _resolve_report_path(_args(no_report=True)) is None


def test_env_true_parsing(monkeypatch):
    for v in ("1", "true", "yes", "on", "TRUE", "On"):
        monkeypatch.setenv("ORTHOSEC_OPEN", v)
        assert _env_true("ORTHOSEC_OPEN")
    for v in ("0", "off", "no", "", "maybe"):
        monkeypatch.setenv("ORTHOSEC_OPEN", v)
        assert not _env_true("ORTHOSEC_OPEN")


def test_print_css_and_beforeprint_present():
    # guard the print/PDF fixes: light-palette override + details expansion
    from orthosec.report.html import render_html
    from orthosec.core.scanner import Scanner
    html = render_html(Scanner().scan("examples/vulnerable-agent"))
    assert "print-color-adjust:exact" in html
    assert "beforeprint" in html
    assert "::details-content" in html
