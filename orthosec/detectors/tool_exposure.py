"""Detect over-privileged agent tools / excessive agency.

OWASP LLM06 (Excessive Agency) / LLM05 (Improper Output Handling).
When an LLM can call a tool that runs a shell, writes files, or hits arbitrary
URLs — with no human confirmation — a single successful injection turns into RCE,
data exfiltration, or destructive action. Highest blast radius in agentic systems.

Python uses AST: it resolves which functions are model-invokable tools and finds
dangerous sinks inside them at any line distance (precise, no distance heuristic).
Every other language uses a proximity regex: a dangerous sink AND a tool marker must
co-occur in a small window. Requiring the tool marker keeps precision high (a bare
shell call with no agent-tool nearby does not fire) at the cost of some recall.
"""
from __future__ import annotations

import re
from typing import Iterable

from orthosec.core.finding import Finding, Severity
from orthosec.core.scanner import ScanContext
from orthosec.detectors import register
from orthosec.detectors._signals import mitigation_present
from orthosec.analysis.pyast import safe_parse, reachable_tool_sinks
from orthosec.analysis.project import cross_file_tool_sinks

# --- regex path (every non-Python language) ---------------------------------
# Per-language dangerous sinks a model-invokable tool must not reach unguarded.
# Capability labels are shared so findings read consistently across languages.
_SHELL, _FILE, _HTTP = ("shell/command execution",
                        "arbitrary file write/delete",
                        "arbitrary outbound HTTP")

_DANGEROUS_JS = {
    _SHELL: re.compile(r"(?i)\b(child_process|exec\(|execSync|spawn\()"),
    _FILE: re.compile(r"(?i)\b(fs\.writeFile|fs\.unlink|fs\.rm)\b"),
    _HTTP: re.compile(r"(?i)\b(fetch\(|axios)\b"),
}
_DANGEROUS_GO = {
    _SHELL: re.compile(r"\bexec\.Command(Context)?\("),
    _FILE: re.compile(r"\b(os\.Remove(All)?\(|os\.WriteFile\(|ioutil\.WriteFile\()"),
    _HTTP: re.compile(r"\bhttp\.(Get|Post|NewRequest)\("),
}
_DANGEROUS_JAVA = {  # also Kotlin (shared JVM APIs)
    _SHELL: re.compile(r"(Runtime\.getRuntime\(\)\s*\.\s*exec\b|new\s+ProcessBuilder\b|ProcessBuilder\()"),
    _FILE: re.compile(r"\b(Files\.(write|delete|deleteIfExists)\(|new\s+FileWriter\(|\.writeText\()"),
    _HTTP: re.compile(r"(HttpClient\b|\.openConnection\(|RestTemplate\b|new\s+URL\()"),
}
_DANGEROUS_CS = {
    _SHELL: re.compile(r"(Process\.Start\(|new\s+Process\()"),
    _FILE: re.compile(r"\bFile\.(WriteAllText|WriteAllBytes|Delete)\("),
    _HTTP: re.compile(r"(HttpClient\b|new\s+WebClient\b|WebRequest\.Create\()"),
}
_DANGEROUS_RUBY = {
    _SHELL: re.compile(r"(\bsystem\(|\bexec\(|\bIO\.popen\(|%x\(|`[^`]*`)"),
    _FILE: re.compile(r"\b(File\.(delete|write|unlink)\(|FileUtils\.rm\b)"),
    _HTTP: re.compile(r"\bNet::HTTP\b"),
}
_DANGEROUS_PHP = {
    _SHELL: re.compile(r"\b(exec|shell_exec|system|passthru|proc_open)\s*\("),
    _FILE: re.compile(r"\b(unlink|file_put_contents|fwrite)\s*\("),
    _HTTP: re.compile(r"\b(curl_exec|fsockopen)\s*\("),
}
_DANGEROUS_RUST = {
    _SHELL: re.compile(r"\bCommand::new\("),
    _FILE: re.compile(r"\b(fs::write\(|fs::remove_file\(|fs::remove_dir_all\()"),
    # A call site, not a bare `use reqwest::...;` import path.
    _HTTP: re.compile(r"\breqwest::(get|post|Client|blocking|ClientBuilder)\b"),
}
_DANGEROUS_PY = {  # only for the parse-error fallback path
    _SHELL: re.compile(r"(subprocess\.|os\.system\(|os\.popen\()"),
    _FILE: re.compile(r"\b(os\.remove\(|shutil\.rmtree\(|open\([^)]*['\"][wa])"),
    _HTTP: re.compile(r"\b(requests\.|urllib\.request|httpx\.)"),
}
_DANGEROUS_BY_SUFFIX = {
    ".js": _DANGEROUS_JS, ".ts": _DANGEROUS_JS, ".tsx": _DANGEROUS_JS, ".jsx": _DANGEROUS_JS,
    ".go": _DANGEROUS_GO, ".java": _DANGEROUS_JAVA, ".kt": _DANGEROUS_JAVA,
    ".cs": _DANGEROUS_CS, ".rb": _DANGEROUS_RUBY, ".php": _DANGEROUS_PHP, ".rs": _DANGEROUS_RUST,
    ".py": _DANGEROUS_PY,
}
# Languages that go through the proximity-regex path (Python uses AST unless it fails to parse).
_REGEX_SUFFIXES = {".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".cs", ".rb", ".php", ".rs"}

# Annotation-based languages: a tool is declared by an annotation ON the function
# (@Tool / [KernelFunction] / #[tool] / @tool), so AST tool-scoping is precise. Value =
# (analyzer module, function node types, body field). Others (Go/Ruby/PHP — no annotation
# convention) keep the validated proximity regex.
_AST_AGENCY = {
    ".java": ("java_ast", {"method_declaration", "constructor_declaration"}, "body"),
    ".kt": ("kotlin_ast", {"function_declaration"}, "function_body"),
    ".cs": ("csharp_ast", {"method_declaration", "local_function_statement"}, "body"),
    ".rs": ("rust_ast", {"function_item"}, "body"),
    # TS/JS/Go/Ruby/PHP declare tools by factory call (`tool({...})`) or registration, not a
    # function annotation, so annotation-AST doesn't fit — they keep the validated regex.
}


def _ast_agency(suffix, src):
    """Precise AST tool-exposure for annotation-based languages; None to fall back to regex."""
    info = _AST_AGENCY.get(suffix)
    if not info:
        return None
    modname, fn_types, body_field = info
    try:
        import importlib
        mod = importlib.import_module("orthosec.analysis." + modname)
    except Exception:
        return None
    if not getattr(mod, "available", lambda: False)():
        return None
    from orthosec.analysis._agency import tool_sinks
    sinks = _DANGEROUS_BY_SUFFIX.get(suffix, _DANGEROUS_JS)
    try:
        return tool_sinks(mod._parse, mod._walk, mod._text, mod._line, src,
                          fn_types, _TOOL_MARKER, sinks, _CONFIRM, _IMPORT_LINE, body_field)
    except Exception:
        return None


def _ts_factory_agency(src, suffix):
    """AST tool-exposure for TS/JS factory-declared tools (`tool({execute})`); None to fall
    back to the regex path (marker/decorator-declared tools)."""
    try:
        from orthosec.analysis import ts_ast
    except Exception:
        return None
    if not ts_ast.available():
        return None
    try:
        return ts_ast.tool_agency_findings(src, tsx=suffix in {".tsx", ".jsx", ".js"})
    except Exception:
        return None

# Agent-tool markers across ecosystems: LangChain/-4j @tool/@Tool, OpenAI function tools,
# Semantic Kernel [KernelFunction], MCP, Vercel AI, rig/rust #[tool]. Deliberately NOT
# `ToolSpec` — it's a common plain-struct name (e.g. an internal CLI descriptor), and
# matching it flagged non-agent code (real-world audit false positive).
_TOOL_MARKER = re.compile(
    r"(?i)(@tool\b|@function_tool|@Tool\b|\[KernelFunction\]|KernelFunction\b|StructuredTool|"
    r"['\"]function['\"]\s*:|['\"]tools['\"]\s*:|register_tool|mcp\.tool|FunctionDeclaration|"
    r"FunctionDefinition|#\[tool\]|new\s+\w*Tool)")
_CONFIRM = re.compile(r"(?i)(confirm|approval|human_in_the_loop|require_approval|allowlist|whitelist)")
# An import/use line is never an actual sink call — a dangerous-looking token there
# (e.g. `use reqwest::StatusCode;`) must not fire.
_IMPORT_LINE = re.compile(r"^\s*(use|import|from|#include|require|require_relative)\b|^\s*using\s+[\w.]+\s*;")

_REMEDIATION = (
    "Scope the tool to the minimum capability, add an allowlist, and gate "
    "irreversible/high-impact actions behind human confirmation. Never pass model "
    "output unsanitized into shell/SQL/file sinks."
)


@register
class ToolExposureDetector:
    id = "tool-exposure"
    name = "Excessive agency / over-privileged tools"
    owasp_llm = "LLM06"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.iter_files():
            suffix = path.suffix.lower()
            text = ctx.read(path)
            if not text:
                continue
            if suffix == ".py":
                yield from self._scan_python(ctx, path, text)
            elif suffix in _REGEX_SUFFIXES:
                yield from self._scan_regex(ctx, path, text, suffix)

    # --- Python: AST dataflow -------------------------------------------
    def _scan_python(self, ctx, path, text) -> Iterable[Finding]:
        tree = safe_parse(text)
        if tree is None:
            yield from self._scan_regex(ctx, path, text, ".py")  # fallback on syntax error
            return
        lines = text.splitlines()
        # reachable_tool_sinks: sinks reachable from a tool directly or through local
        # helpers; cross_file_tool_sinks: through helpers imported from other modules.
        seen: set[tuple] = set()
        for s, mitigated, name in (reachable_tool_sinks(tree, lines)
                                   + cross_file_tool_sinks(ctx, path, tree, lines)):
            if (s.line, s.capability) in seen:
                continue
            seen.add((s.line, s.capability))
            yield Finding(
                detector=self.id,
                rule_id="ORTHO-AGENCY-001",
                title=f"Model-invokable tool '{name}' can reach {s.capability} with no confirmation gate",
                severity=Severity.MEDIUM if mitigated else Severity.CRITICAL,
                owasp_llm="LLM06",
                atlas=["AML.T0053"],
                file=ctx.rel(path),
                line=s.line,
                evidence=s.snippet,
                remediation=_REMEDIATION,
                confidence=0.6 if mitigated else 0.85,
                metadata={"trace": s.trace} if s.trace else {},
            )

    # --- non-Python: AST for annotation langs, else proximity regex -----
    def _scan_regex(self, ctx, path, text, suffix=".ts") -> Iterable[Finding]:
        hits = _ast_agency(suffix, text)
        if hits is None and suffix in {".ts", ".tsx", ".jsx", ".js"}:
            hits = _ts_factory_agency(text, suffix)   # factory-declared tools (tool({execute}))
        if hits is not None:
            for ln, capability, mitigated, name in hits:
                yield Finding(
                    detector=self.id, rule_id="ORTHO-AGENCY-001",
                    title=f"Model-invokable tool '{name}' can reach {capability} with no confirmation gate",
                    severity=Severity.MEDIUM if mitigated else Severity.CRITICAL,
                    owasp_llm="LLM06", atlas=["AML.T0053"], file=ctx.rel(path), line=ln,
                    evidence=(text.splitlines()[ln - 1].strip()[:200] if 0 < ln <= len(text.splitlines()) else ""),
                    remediation=_REMEDIATION, confidence=0.6 if mitigated else 0.8,
                )
            return
        if not _TOOL_MARKER.search(text):
            return
        dangerous = _DANGEROUS_BY_SUFFIX.get(suffix, _DANGEROUS_JS)
        lines = text.splitlines()
        file_has_confirm = mitigation_present(text, _CONFIRM)
        for lineno, line in enumerate(lines, start=1):
            if _IMPORT_LINE.match(line):        # an import is never a sink call
                continue
            for capability, pat in dangerous.items():
                if not pat.search(line):
                    continue
                window = "\n".join(lines[max(0, lineno - 15):lineno + 5])
                if not _TOOL_MARKER.search(window):
                    continue
                mitigated = file_has_confirm and mitigation_present(window, _CONFIRM)
                yield Finding(
                    detector=self.id,
                    rule_id="ORTHO-AGENCY-001",
                    title=f"Model-invokable tool with {capability} and no confirmation gate",
                    severity=Severity.MEDIUM if mitigated else Severity.CRITICAL,
                    owasp_llm="LLM06",
                    atlas=["AML.T0053"],
                    file=ctx.rel(path),
                    line=lineno,
                    evidence=line.strip()[:200],
                    remediation=_REMEDIATION,
                    confidence=0.55 if mitigated else 0.75,
                )
