"""Cross-file (multi-module) taint — link a source in one module to a sink in another.

Intra-file analysis (pyast) sees one tree at a time. Real AI apps split the LLM
call and the dangerous helper across modules: `app.py` gets model output and
passes it to `tools.run(...)`, where `tools.run` sinks it. This module builds a
project-wide index — per-function danger summaries + import resolution — so a
tainted argument crossing a module boundary is caught at the call site.

Scope (honest): single project tree, stdlib `ast`, import resolution by module
stem (filename). Handles `from mod import f [as g]` and `import mod` → `mod.f()`.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field

from orthosec.analysis.pyast import (safe_parse, _function_defs, _dangerous_params,
                                     _prompt_building_params, tainted_vars,
                                     untrusted_vars, _refs_taint, Sink)


@dataclass
class _FuncSummary:
    params: list[str]
    sink_params: set[str]      # params that reach a dangerous sink (LLM05)
    prompt_params: set[str]    # params that build a system prompt (LLM01)


@dataclass
class ProjectIndex:
    modules: dict[str, tuple] = field(default_factory=dict)          # stem -> (tree, lines)
    summaries: dict[tuple, _FuncSummary] = field(default_factory=dict)  # (stem, func) -> summary
    imports: dict[str, dict] = field(default_factory=dict)           # stem -> {alias: (srcstem, func)}


def build_index(ctx) -> ProjectIndex:
    idx = ProjectIndex()
    for path in ctx.files:
        if path.suffix.lower() != ".py":
            continue
        src = ctx.read(path)
        tree = safe_parse(src)
        if tree is None:
            continue
        stem = path.stem
        lines = src.splitlines()
        idx.modules[stem] = (tree, lines)
        for name, fn in _function_defs(tree).items():
            sink_params, params = _dangerous_params(fn, lines)
            prompt_params, _ = _prompt_building_params(fn, lines)
            if sink_params or prompt_params:
                idx.summaries[(stem, name)] = _FuncSummary(params, sink_params, prompt_params)
        imap: dict = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                srcstem = (node.module or "").split(".")[-1]
                for alias in node.names:
                    imap[alias.asname or alias.name] = (srcstem, alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    base = (alias.asname or alias.name.split(".")[-1])
                    imap["mod:" + base] = (alias.name.split(".")[-1], "*")
        idx.imports[stem] = imap
    return idx


def get_index(ctx) -> ProjectIndex:
    """Build once per scan and memoize on the context (shared across detectors)."""
    idx = getattr(ctx, "_project_index", None)
    if idx is None:
        idx = build_index(ctx)
        ctx._project_index = idx
    return idx


def _resolve_call(idx: ProjectIndex, cur_stem: str, call: ast.Call):
    """Resolve a call to an (stem, func) defined in another module, or None."""
    f = call.func
    if isinstance(f, ast.Name):
        t = idx.imports.get(cur_stem, {}).get(f.id)
        if t and t[1] != "*":
            return t
    elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
        t = idx.imports.get(cur_stem, {}).get("mod:" + f.value.id)
        if t:
            return (t[0], f.attr)
    return None


def _args_hit(call: ast.Call, params: list[str], dangerous: set[str], tainted: set[str]) -> bool:
    for i, arg in enumerate(call.args):
        if i < len(params) and params[i] in dangerous and _refs_taint(arg, tainted):
            return True
    return any(kw.arg in dangerous and _refs_taint(kw.value, tainted) for kw in call.keywords)


def _cross_file(idx, cur_stem, tree, lines, taint_of_scope, dangerous_of):
    """Generic cross-file pass: flag calls to imported functions whose dangerous
    parameter receives a tainted argument. `dangerous_of(summary)` selects the
    relevant param set; `taint_of_scope(scope)` computes the taint for that flavor."""
    scopes = [n for n in ast.walk(tree)
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))] or [tree]
    out: list[Sink] = []
    seen: set[int] = set()
    for scope in scopes:
        tainted = taint_of_scope(scope)
        if not tainted:
            continue
        for node in ast.walk(scope):
            if not isinstance(node, ast.Call):
                continue
            target = _resolve_call(idx, cur_stem, node)
            if not target or target[0] == cur_stem or target not in idx.summaries:
                continue
            summ = idx.summaries[target]
            dangerous = dangerous_of(summ)
            if dangerous and _args_hit(node, summ.params, dangerous, tainted):
                line = node.lineno
                if line in seen:
                    continue
                seen.add(line)
                snippet = lines[line - 1].strip()[:160] if 0 < line <= len(lines) else ""
                out.append(Sink(f"a helper in module '{target[0]}' ({target[1]}())", line, snippet))
    return out


def cross_file_output_sinks(ctx, path, tree, lines) -> list[Sink]:
    idx = get_index(ctx)
    return _cross_file(idx, path.stem, tree, lines, tainted_vars, lambda s: s.sink_params)


def cross_file_injection_sinks(ctx, path, tree, lines) -> list[Sink]:
    idx = get_index(ctx)
    return _cross_file(idx, path.stem, tree, lines, untrusted_vars, lambda s: s.prompt_params)
