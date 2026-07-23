"""Audit dependency manifests for AI supply-chain risk.

OWASP LLM03 (Supply Chain). A compromised or repointed release of an AI/ML
dependency runs arbitrary code at install/import time and can swap the model or
tooling underneath you. This detector reads the manifest — not just the code — and
flags AI/ML dependencies that are (1) unpinned (a non-reproducible resolve pulls
whatever is newest, including a compromised release) or (2) installed from an
untrusted source (git/URL/alternate index — the dependency-confusion vector).

Scoped to AI/ML packages on purpose: OrthoSec's lane is AI risk, and flagging every
loose pin in a repo would be noise. Deterministic and fully offline — no vuln DB.
"""
from __future__ import annotations

import json
import re
from typing import Iterable

from orthosec.core.finding import Finding, Severity
from orthosec.core.scanner import ScanContext
from orthosec.detectors import register

# AI/ML ecosystem packages worth pinning tightly (substring match, case-insensitive).
_AI_PKGS = (
    "langchain", "llama-index", "llama_index", "llamaindex", "openai", "anthropic",
    "transformers", "torch", "tensorflow", "keras", "huggingface", "sentence-transformers",
    "chromadb", "pinecone", "weaviate", "qdrant", "faiss", "litellm", "guidance",
    "crewai", "autogen", "semantic-kernel", "instructor", "dspy", "vllm", "ollama",
    "cohere", "google-generativeai", "groq", "mistralai", "haystack", "@anthropic-ai",
    "@langchain", "@huggingface", "@google/generative-ai", "@mistralai", "ai-sdk",
)
# Untrusted install sources.
_PIP_VCS_URL = re.compile(r"(?i)\b(git\+|https?://|file:|svn\+|hg\+)")
_PIP_ALT_INDEX = re.compile(r"(?i)^\s*--(extra-)?index-url\s+(?!https://pypi\.org)")
_NPM_UNTRUSTED = re.compile(r"(?i)^(git\+|https?://|file:|github:|git://|link:)")
# A version specifier that actually pins an exact version.
_PIP_PINNED = re.compile(r"==\s*[0-9]")
_NPM_LOOSE = re.compile(r"^[\^~]|\*|^latest$|^>=|\bx\b|^\s*$")

_FIX_PIN = ("Pin the exact version (pip `==x.y.z`, npm exact `x.y.z`) and verify it via a "
            "lockfile/hashes so a repointed or compromised release can't be pulled silently.")
_FIX_SRC = ("Install AI/ML dependencies only from the canonical registry with a pinned, "
            "hash-verified version — not a git ref, URL, or alternate index (dependency-confusion risk).")


def _is_ai_pkg(name: str) -> bool:
    n = name.strip().lower()
    return any(p in n for p in _AI_PKGS)


@register
class DependencyAuditDetector:
    id = "dependency-audit"
    name = "AI dependency supply-chain audit"
    owasp_llm = "LLM03"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.files:
            name = path.name.lower()
            if re.search(r"requirements.*\.txt$", name) or name == "constraints.txt":
                yield from self._scan_pip(ctx, path)
            elif name == "package.json":
                yield from self._scan_npm(ctx, path)

    # --- pip: requirements*.txt --------------------------------------------
    def _scan_pip(self, ctx, path) -> Iterable[Finding]:
        text = ctx.read(path)
        if not text:
            return
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if _PIP_ALT_INDEX.search(line):
                yield self._finding(ctx, path, lineno, raw,
                                    "Dependency pulled from a non-PyPI index", "ORTHO-DEP-002",
                                    Severity.HIGH, _FIX_SRC, 0.7)
                continue
            pkg = re.split(r"[<>=!~;\[\s]", line, 1)[0]
            if not _is_ai_pkg(pkg) and not _PIP_VCS_URL.search(line):
                continue
            if _PIP_VCS_URL.search(line):
                yield self._finding(ctx, path, lineno, raw,
                                    f"AI/ML dependency installed from an untrusted source ({pkg or 'url'})",
                                    "ORTHO-DEP-002", Severity.HIGH, _FIX_SRC, 0.7)
            elif _is_ai_pkg(pkg) and not _PIP_PINNED.search(line):
                yield self._finding(ctx, path, lineno, raw,
                                    f"AI/ML dependency '{pkg}' is not pinned to an exact version",
                                    "ORTHO-DEP-001", Severity.LOW, _FIX_PIN, 0.6)

    # --- npm: package.json --------------------------------------------------
    def _scan_npm(self, ctx, path) -> Iterable[Finding]:
        text = ctx.read(path)
        if not text:
            return
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return
        lines = text.splitlines()
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for pkg, spec in deps.items():
                if not _is_ai_pkg(pkg) or not isinstance(spec, str):
                    continue
                lineno = _find_line(lines, pkg)
                if _NPM_UNTRUSTED.search(spec):
                    yield self._finding(ctx, path, lineno, f'"{pkg}": "{spec}"',
                                        f"AI SDK '{pkg}' installed from an untrusted source",
                                        "ORTHO-DEP-002", Severity.HIGH, _FIX_SRC, 0.7)
                elif _NPM_LOOSE.search(spec):
                    yield self._finding(ctx, path, lineno, f'"{pkg}": "{spec}"',
                                        f"AI SDK '{pkg}' is not pinned to an exact version",
                                        "ORTHO-DEP-001", Severity.LOW, _FIX_PIN, 0.6)

    def _finding(self, ctx, path, lineno, evidence, title, rule_id, sev, fix, conf) -> Finding:
        return Finding(
            detector=self.id, rule_id=rule_id, title=title, severity=sev,
            owasp_llm="LLM03", atlas=["AML.T0010", "AML.T0016"],
            file=ctx.rel(path), line=lineno, evidence=evidence.strip()[:200],
            remediation=fix, confidence=conf,
        )


def _find_line(lines, pkg: str) -> int:
    needle = f'"{pkg}"'
    for i, ln in enumerate(lines, start=1):
        if needle in ln:
            return i
    return 1
