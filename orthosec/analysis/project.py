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


# --- parallel index build (SlimIndex) --------------------------------------
#
# build_index() above is serial and holds ast trees / FunctionDef nodes, which are
# expensive to build (per-function ast walks) and not worth pickling. For parallel
# scanning we split that work: each worker parses its file shard and emits a small
# PICKLABLE record (summaries + raw imports + per-function call edges + direct
# sinks — all primitives, no ast), and the parent reduces the records into a
# ProjectIndex that fills exactly the three fields the per-file cross-module queries
# read (summaries, imports, _tool_reach) and leaves the heavy fields empty. The
# reducer reuses the SAME resolvers as build_index (_resolve_module, _import_names,
# _flatten_reexports logic), so a SlimIndex is equivalent to a serial index for every
# query the detectors make. `test_slimindex.py` asserts that equivalence on real code.


def _raw_call(call) -> tuple | None:
    """Reduce a Call's callee to the primitive shape _resolve_callee cares about."""
    f = call.func
    if isinstance(f, ast.Name):
        return ("name", f.id)
    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
        return ("attr", f.value.id, f.attr)
    return None


def extract_record(root, path, src: str) -> dict | None:
    """Per-file, picklable index record. Mirrors build_index's first pass plus the
    per-function data _tool_reachability needs, but emits only primitives."""
    tree = safe_parse(src)
    if tree is None:
        return None
    mk = _modkey(root, path)
    lines = src.splitlines()
    funcs = _function_defs(tree)

    summaries: dict = {}
    edges: dict = {}
    direct: dict = {}
    for name, fn in funcs.items():
        sink_params, params = _dangerous_params(fn, lines)
        prompt_params, _ = _prompt_building_params(fn, lines)
        if sink_params or prompt_params:
            summaries[name] = (params, sorted(sink_params), sorted(prompt_params))
        direct[name] = [(s.line, s.capability, s.snippet) for s in dangerous_sinks(fn, lines)]
        raws = []
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                r = _raw_call(node)
                if r is not None:
                    raws.append(r)
        edges[name] = raws

    imports_from, imports_plain = [], []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            segs = (node.module or "").split(".") if node.module else []
            imports_from.append((node.level or 0, tuple(segs),
                                 tuple((a.name, a.asname) for a in node.names)))
        elif isinstance(node, ast.Import):
            for a in node.names:
                imports_plain.append((a.name, a.asname))

    return {
        "mk": mk,
        "func_names": list(funcs.keys()),
        "summaries": summaries,
        "imports_from": imports_from,
        "imports_plain": imports_plain,
        "edges": edges,
        "direct": direct,
    }


def extract_records(root, paths) -> list:
    """Extract records for a list of paths (read + parse + summarize). Runs in a worker."""
    out = []
    for p in paths:
        p = Path(p)
        if p.suffix.lower() != ".py":
            continue
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rec = extract_record(root, p, src)
        if rec is not None:
            out.append(rec)
    return out


def _resolve_callee_prim(imports: dict, func_exists: set, cur, raw):
    """_resolve_callee, but over primitives (no ast) + a func-existence set."""
    if raw[0] == "name":
        fid = raw[1]
        if (cur, fid) in func_exists:
            return (cur, fid)
        t = imports.get(cur, {}).get(fid)
        if t and t[1] != "*" and (t[0], t[1]) in func_exists:
            return (t[0], t[1])
    else:  # ("attr", value_id, attr)
        _, vid, attr = raw
        t = imports.get(cur, {}).get("mod:" + vid)
        if t and (t[0], attr) in func_exists:
            return (t[0], attr)
    return None


def _flatten_reexports_prim(imports: dict, func_exists: set) -> None:
    """_flatten_reexports over a func-existence set (SlimIndex has no func_nodes)."""
    for mk, imap in imports.items():
        for alias, (tmod, func) in list(imap.items()):
            if func == "*":
                continue
            seen = {(tmod, func)}
            for _ in range(6):
                if (tmod, func) in func_exists:
                    break
                nxt = imports.get(tmod, {}).get(func)
                if not nxt or nxt[1] == "*" or nxt in seen:
                    break
                tmod, func = nxt
                seen.add((tmod, func))
            imap[alias] = (tmod, func)


def assemble_slim(records: list) -> ProjectIndex:
    """Reduce per-file records into a query-equivalent ProjectIndex (summaries,
    imports, _tool_reach filled; modules/func_nodes/module_lines empty)."""
    idx = ProjectIndex()
    mks = [r["mk"] for r in records]
    # a stand-in modules dict so _import_names / name_paths see every module key
    idx.modules = {mk: None for mk in mks}
    func_exists = {(r["mk"], name) for r in records for name in r["func_names"]}

    for r in records:
        for name, (params, sp, pp) in r["summaries"].items():
            idx.summaries[(r["mk"], name)] = _FuncSummary(params, set(sp), set(pp))

    name_paths = [(np, mk) for mk in idx.modules for np in _import_names(mk)]
    for r in records:                                   # resolve imports (reused resolver)
        mk = r["mk"]
        imap: dict = {}
        for level, segs, names in r["imports_from"]:
            target = _resolve_module(name_paths, mk, list(segs), level)
            if target is None:
                continue
            for name, asname in names:
                imap[asname or name] = (target, name)
        for dotted, asname in r["imports_plain"]:
            target = _resolve_module(name_paths, mk, dotted.split("."), 0)
            if target is not None:
                base = asname or dotted.split(".")[-1]
                imap["mod:" + base] = (target, "*")
        idx.imports[mk] = imap
    _flatten_reexports_prim(idx.imports, func_exists)

    direct, edges = {}, {}                              # tool reachability from primitives
    for r in records:
        mk = r["mk"]
        for name in r["func_names"]:
            direct[(mk, name)] = {(mk, line, cap, snip) for (line, cap, snip) in r["direct"].get(name, [])}
            e = set()
            for raw in r["edges"].get(name, []):
                tgt = _resolve_callee_prim(idx.imports, func_exists, mk, raw)
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
    idx.modules = {}                                    # drop the stand-in; keep it Slim
    return idx
