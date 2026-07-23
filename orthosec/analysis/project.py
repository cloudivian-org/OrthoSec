"""Cross-file (multi-module) taint — link a source in one module to a sink in another.

Intra-file analysis (pyast) sees one tree at a time. Real AI apps split the LLM
call and the dangerous helper across modules: `app.py` gets model output and
passes it to `tools.run(...)`, where `tools.run` sinks it. This module builds a
project-wide index — per-function danger summaries + import resolution — so a
tainted argument crossing a module boundary is caught at the call site.

Modules are keyed by their path relative to the scan root (not bare filename), and
imports resolve only when a target is UNAMBIGUOUS: if two files share a name, the
import is left unresolved (a miss) rather than linked to the wrong file (a false
positive). Handles `from a.b import f [as g]`, `import a.b` → `b.f()`, and relative
`from .mod import f` / `from ..pkg import f`.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from orthosec.analysis.pyast import (safe_parse, _function_defs, _dangerous_params,
                                     _prompt_building_params, tainted_vars,
                                     untrusted_vars, _refs_taint, Sink,
                                     dangerous_sinks, find_tool_functions, has_confirmation)

# A module key is a tuple of path segments without the extension, e.g. ('pkg','tools').
ModKey = tuple


@dataclass
class _FuncSummary:
    params: list[str]
    sink_params: set[str]
    prompt_params: set[str]


@dataclass
class ProjectIndex:
    modules: dict[ModKey, tuple] = field(default_factory=dict)
    summaries: dict[tuple, _FuncSummary] = field(default_factory=dict)   # (modkey, func) -> summary
    imports: dict[ModKey, dict] = field(default_factory=dict)            # modkey -> {alias: (target_modkey, func)}
    func_nodes: dict[tuple, object] = field(default_factory=dict)        # (modkey, func) -> FunctionDef
    module_lines: dict[ModKey, list] = field(default_factory=dict)
    _tool_reach: dict = field(default=None)


def _modkey(root, path) -> ModKey:
    if root is not None:
        try:
            return Path(path).resolve().relative_to(Path(root).resolve()).with_suffix("").parts
        except ValueError:
            pass
    return (Path(path).stem,)


def _import_names(mk: ModKey):
    """The path(s) an import can name this module by: itself, and — for a package
    __init__ — the package path (so `from pkg import x` finds pkg/__init__.py)."""
    yield mk
    if mk and mk[-1] == "__init__":
        yield mk[:-1]


def _resolve_module(name_paths, importer: ModKey, segs: list, level: int):
    """Resolve an import target to a unique module key, or None if ambiguous/absent.
    `name_paths` is a list of (nameable_path, modkey)."""
    if level and level > 0:                        # relative: from .a.b import ...
        base = importer[:-level] if level <= len(importer) else ()
        target = tuple(base) + tuple(segs)
        for npath, mk in name_paths:
            if npath == target:
                return mk
        return None
    if not segs:
        return None
    segt = tuple(segs)                             # absolute: unique module named by segs (suffix)
    cands = {mk for npath, mk in name_paths if npath[-len(segt):] == segt}
    return next(iter(cands)) if len(cands) == 1 else None


def build_index(ctx) -> ProjectIndex:
    idx = ProjectIndex()
    root = getattr(ctx, "root", None)
    parsed = []
    for path in ctx.files:
        if path.suffix.lower() != ".py":
            continue
        src = ctx.read(path)
        tree = safe_parse(src)
        if tree is None:
            continue
        mk = _modkey(root, path)
        lines = src.splitlines()
        idx.modules[mk] = (tree, lines)
        idx.module_lines[mk] = lines
        for name, fn in _function_defs(tree).items():
            idx.func_nodes[(mk, name)] = fn
            sink_params, params = _dangerous_params(fn, lines)
            prompt_params, _ = _prompt_building_params(fn, lines)
            if sink_params or prompt_params:
                idx.summaries[(mk, name)] = _FuncSummary(params, sink_params, prompt_params)
        parsed.append((mk, tree))

    name_paths = [(np, mk) for mk in idx.modules for np in _import_names(mk)]
    for mk, tree in parsed:                        # second pass: resolve imports
        imap: dict = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                segs = (node.module or "").split(".") if node.module else []
                target = _resolve_module(name_paths, mk, segs, node.level or 0)
                if target is None:
                    continue
                for alias in node.names:
                    imap[alias.asname or alias.name] = (target, alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    target = _resolve_module(name_paths, mk, alias.name.split("."), 0)
                    if target is not None:
                        base = alias.asname or alias.name.split(".")[-1]
                        imap["mod:" + base] = (target, "*")
        idx.imports[mk] = imap

    _flatten_reexports(idx)                         # third pass: follow re-export chains
    return idx


def _flatten_reexports(idx: ProjectIndex) -> None:
    """Follow `from .x import f` re-exports so an import of a name that is only
    re-exported by the target module resolves to where `f` is actually defined."""
    for mk, imap in idx.imports.items():
        for alias, (tmod, func) in list(imap.items()):
            if func == "*":
                continue
            seen = {(tmod, func)}
            for _ in range(6):                      # bounded — avoid import cycles
                if (tmod, func) in idx.func_nodes:
                    break
                nxt = idx.imports.get(tmod, {}).get(func)
                if not nxt or nxt[1] == "*" or nxt in seen:
                    break
                tmod, func = nxt
                seen.add((tmod, func))
            imap[alias] = (tmod, func)


def get_index(ctx) -> ProjectIndex:
    idx = getattr(ctx, "_project_index", None)
    if idx is None:
        idx = build_index(ctx)
        ctx._project_index = idx
    return idx


def _modname(mk: ModKey) -> str:
    return ".".join(mk)


def _resolve_call(idx: ProjectIndex, cur: ModKey, call: ast.Call):
    f = call.func
    if isinstance(f, ast.Name):
        t = idx.imports.get(cur, {}).get(f.id)
        if t and t[1] != "*":
            return t
    elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
        t = idx.imports.get(cur, {}).get("mod:" + f.value.id)
        if t:
            return (t[0], f.attr)
    return None


def _resolve_callee(idx: ProjectIndex, cur: ModKey, call: ast.Call):
    f = call.func
    if isinstance(f, ast.Name):
        if (cur, f.id) in idx.func_nodes:
            return (cur, f.id)
        t = idx.imports.get(cur, {}).get(f.id)
        if t and t[1] != "*" and (t[0], t[1]) in idx.func_nodes:
            return (t[0], t[1])
    elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
        t = idx.imports.get(cur, {}).get("mod:" + f.value.id)
        if t and (t[0], f.attr) in idx.func_nodes:
            return (t[0], f.attr)
    return None


def _args_hit(call: ast.Call, params: list[str], dangerous: set[str], tainted: set[str]) -> bool:
    for i, arg in enumerate(call.args):
        if i < len(params) and params[i] in dangerous and _refs_taint(arg, tainted):
            return True
    return any(kw.arg in dangerous and _refs_taint(kw.value, tainted) for kw in call.keywords)


def _cross_file(idx, cur: ModKey, tree, lines, taint_of_scope, dangerous_of):
    scopes = [n for n in ast.walk(tree)
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))] or [tree]
    out, seen = [], set()
    for scope in scopes:
        tainted = taint_of_scope(scope)
        if not tainted:
            continue
        for node in ast.walk(scope):
            if not isinstance(node, ast.Call):
                continue
            target = _resolve_call(idx, cur, node)
            if not target or target[0] == cur or target not in idx.summaries:
                continue
            summ = idx.summaries[target]
            dangerous = dangerous_of(summ)
            if dangerous and _args_hit(node, summ.params, dangerous, tainted):
                if node.lineno in seen:
                    continue
                seen.add(node.lineno)
                snippet = lines[node.lineno - 1].strip()[:160] if 0 < node.lineno <= len(lines) else ""
                out.append(Sink(f"a helper in module '{_modname(target[0])}' ({target[1]}())",
                                node.lineno, snippet))
    return out


def _tool_reachability(idx: ProjectIndex) -> dict:
    if idx._tool_reach is not None:
        return idx._tool_reach
    direct, edges = {}, {}
    for (mk, name), fn in idx.func_nodes.items():
        lines = idx.module_lines.get(mk, [])
        direct[(mk, name)] = {(mk, s.line, s.capability, s.snippet)
                              for s in dangerous_sinks(fn, lines)}
        e = set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                tgt = _resolve_callee(idx, mk, node)
                if tgt:
                    e.add(tgt)
        edges[(mk, name)] = e
    reach = {k: set(v) for k, v in direct.items()}
    changed = True
    while changed:
        changed = False
        for k, e in edges.items():
            for c in e:
                for s in reach.get(c, ()):
                    if s not in reach[k]:
                        reach[k].add(s)
                        changed = True
    idx._tool_reach = reach
    return reach


def cross_file_tool_sinks(ctx, path, tree, lines):
    idx = get_index(ctx)
    reach = _tool_reachability(idx)
    cur = _modkey(getattr(ctx, "root", None), path)
    out, seen = [], set()
    for name, fn in find_tool_functions(tree).items():
        mitigated = has_confirmation(fn)
        for (sinkmk, line, cap, snip) in reach.get((cur, name), ()):
            if sinkmk == cur:
                continue
            key = (name, sinkmk, line, cap)
            if key in seen:
                continue
            seen.add(key)
            out.append((Sink(f"{cap} (in imported module '{_modname(sinkmk)}')", fn.lineno, snip),
                        mitigated, name))
    return out


def cross_file_output_sinks(ctx, path, tree, lines) -> list[Sink]:
    idx = get_index(ctx)
    cur = _modkey(getattr(ctx, "root", None), path)
    return _cross_file(idx, cur, tree, lines, tainted_vars, lambda s: s.sink_params)


def cross_file_injection_sinks(ctx, path, tree, lines) -> list[Sink]:
    idx = get_index(ctx)
    cur = _modkey(getattr(ctx, "root", None), path)
    return _cross_file(idx, cur, tree, lines, untrusted_vars, lambda s: s.prompt_params)
