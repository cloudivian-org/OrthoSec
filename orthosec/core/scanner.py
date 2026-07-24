"""Scanner — orchestrates detectors over a target and assembles the result.

Builds a ScanContext once (file list + cached reads), runs every detector, then
scores. Detectors are isolated: one throwing does not sink the scan.
"""
from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from orthosec.core.finding import Finding
from orthosec.core.scoring import grade, posture_score

# Files we never want to read (binaries, vendored, VCS, caches).
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
              "dist", "build", ".idea", ".pytest_cache", "site-packages", "_static",
              ".next", "out", "vendor", "coverage", ".docusaurus", ".turbo", "target",
              # recorded test I/O (not source): VCR cassettes, snapshot fixtures
              "cassettes", "__snapshots__",
              # bundled / vendored front-end assets (compiled output, not app logic)
              "assets"}
_TEXT_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".txt", ".md",
             ".json", ".yaml", ".yml", ".toml", ".env", ".cfg", ".ini", ".sh", ".ipynb", ".prompt"}
_MAX_BYTES = 2_000_000  # skip files larger than 2MB
# Build artifacts / bundles / lockfiles — not source; frequent false-positive sources.
_SKIP_FILE = re.compile(r"(?i)(\.min\.(js|css)$|\.bundle\.|-lock\.json$|package-lock\.json$|"
                        r"yarn\.lock$|\.map$|\.d\.ts$|\.chunk\.)")
# Inline suppression: `# orthosec: ignore` or `# orthosec: ignore LLM06,ORTHO-PI-001`.
_IGNORE = re.compile(r"(?i)(?:#|//)\s*orthosec:\s*ignore\b\s*([A-Za-z0-9,_\-]*)")


@dataclass
class ScanContext:
    """Everything a detector needs. Reads are cached so N detectors read once."""

    root: Path
    files: list[Path]
    _cache: dict[Path, str] = field(default_factory=dict)

    def read(self, path: Path) -> str:
        if path not in self._cache:
            try:
                self._cache[path] = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                self._cache[path] = ""
        return self._cache[path]

    def rel(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.root))
        except ValueError:
            return str(path)

    def files_matching(self, *patterns: str) -> Iterable[Path]:
        for p in self.files:
            name = p.name
            if any(fnmatch.fnmatch(name, pat) for pat in patterns):
                yield p


@dataclass
class ScanResult:
    root: str
    findings: list[Finding]
    score: int
    grade: str
    detectors_run: list[str]
    errors: list[str] = field(default_factory=list)

    def by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity.name] = out.get(f.severity.name, 0) + 1
        return out


class Scanner:
    def __init__(self, detectors=None, exclude: list[str] | None = None):
        if detectors is None:
            from orthosec.detectors import load_builtin_detectors
            detectors = load_builtin_detectors()
        self.detectors = detectors
        self.exclude = exclude or []

    def scan(self, root: str | os.PathLike) -> ScanResult:
        root_path = Path(root).resolve()
        return self._run(root_path, list(_walk(root_path, self.exclude)))

    def scan_files(self, root: str | os.PathLike, file_list) -> ScanResult:
        """Scan an explicit set of files (e.g. a git diff), keeping `root` for module
        keys / relative paths. Cross-module analysis is limited to the listed files."""
        root_path = Path(root).resolve()
        files = []
        for f in file_list:
            p = Path(f).resolve()
            if p.is_file() and (p.suffix.lower() in _TEXT_EXT or p.name == ".env") \
                    and not _SKIP_FILE.search(p.name):
                files.append(p)
        return self._run(root_path, files)

    def _run(self, root_path: Path, files: list) -> ScanResult:
        ctx = ScanContext(root=root_path, files=files)

        findings: list[Finding] = []
        errors: list[str] = []
        ran: list[str] = []
        for det in self.detectors:
            ran.append(getattr(det, "id", det.__class__.__name__))
            try:
                findings.extend(det.scan(ctx))
            except Exception as exc:  # detector isolation
                errors.append(f"{getattr(det, 'id', det)}: {exc!r}")

        findings = [f for f in findings if not _inline_suppressed(ctx, f)]
        # Rank by severity, then confidence (highest-signal first), then location.
        findings.sort(key=lambda f: (-f.severity.value, -f.confidence, f.file, f.line))
        score = posture_score(findings)
        return ScanResult(
            root=str(root_path),
            findings=findings,
            score=score,
            grade=grade(score),
            detectors_run=ran,
            errors=errors,
        )


def _inline_suppressed(ctx: "ScanContext", f: Finding) -> bool:
    """True if the finding's line (or the line above) carries an orthosec-ignore
    directive that matches this finding's OWASP category or rule id (or is bare)."""
    if not f.line:
        return False
    path = ctx.root / f.file
    lines = ctx.read(path).splitlines()
    for ln in (f.line, f.line - 1):
        if not (1 <= ln <= len(lines)):
            continue
        line = lines[ln - 1]
        # A directive on the line above only applies if it's a STANDALONE comment
        # (a trailing `# orthosec: ignore` belongs to its own code line, not the next).
        if ln == f.line - 1 and not line.lstrip().startswith(("#", "//")):
            continue
        m = _IGNORE.search(line)
        if m:
            spec = (m.group(1) or "").strip()
            if not spec:
                return True
            toks = {t.strip().upper() for t in spec.split(",") if t.strip()}
            if f.owasp_llm.upper() in toks or f.rule_id.upper() in toks:
                return True
    return False


def _walk(root: Path, exclude: list[str] | None = None) -> Iterable[Path]:
    exclude = exclude or []
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() not in _TEXT_EXT and p.name != ".env":
                continue
            if _SKIP_FILE.search(fn):          # bundles / minified / lockfiles / maps
                continue
            rel = str(p.relative_to(root)) if p.is_relative_to(root) else str(p)
            if any(_excluded(rel, pat) for pat in exclude):
                continue
            try:
                if p.stat().st_size > _MAX_BYTES:
                    continue
            except OSError:
                continue
            yield p


def _excluded(rel: str, pattern: str) -> bool:
    pattern = pattern.rstrip("/")
    return (fnmatch.fnmatch(rel, pattern) or rel.startswith(pattern + "/")
            or f"/{pattern}/" in f"/{rel}" or pattern in rel.split("/"))
