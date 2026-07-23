"""Scheduling tests — duration parsing, cron snippets, watch loop, auto-report."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from orthosec.schedule import parse_duration, cron_snippets
from orthosec import cli

EXAMPLE = str(Path(__file__).resolve().parent.parent / "examples" / "vulnerable-agent")


class TestDuration(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(parse_duration("45s"), 45)
        self.assertEqual(parse_duration("30m"), 1800)
        self.assertEqual(parse_duration("6h"), 21600)
        self.assertEqual(parse_duration("1d"), 86400)

    def test_invalid(self):
        for bad in ("", "abc", "10x", "1.5h"):
            with self.assertRaises(ValueError):
                parse_duration(bad)


class TestCronSnippets(unittest.TestCase):
    def test_contains_cron_profile_path(self):
        out = cron_snippets("/srv/app", "0 3 * * *", "ciso")
        self.assertIn("0 3 * * *", out)
        self.assertIn("--profile ciso", out)
        self.assertIn("/srv/app", out)
        self.assertIn("github/codeql-action/upload-sarif", out)
        self.assertIn("OnCalendar", out)


class TestAutoReport(unittest.TestCase):
    def test_scan_writes_report_by_default(self):
        d = tempfile.mkdtemp()
        report = Path(d) / "r.html"
        cli.main(["scan", EXAMPLE, "--no-exec", "--fail-on", "none", "--html", str(report)])
        self.assertTrue(report.is_file())
        self.assertIn("OrthoSec", report.read_text())


class TestWatchLoop(unittest.TestCase):
    def test_one_iteration_writes_latest(self):
        d = tempfile.mkdtemp()
        # Break the loop after the first iteration by making sleep raise.
        with mock.patch("time.sleep", side_effect=KeyboardInterrupt):
            rc = cli.main(["watch", EXAMPLE, "--every", "1s", "--report-dir", d, "--no-exec"])
        self.assertEqual(rc, 0)
        self.assertTrue((Path(d) / "latest.html").is_file())
        self.assertTrue((Path(d) / "latest.json").is_file())


if __name__ == "__main__":
    unittest.main()
