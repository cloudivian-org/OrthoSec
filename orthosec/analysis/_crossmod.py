"""Shared cross-module (cross-file) taint index for the tree-sitter analyzers.

Builds a project-wide function summary so taint can flow across files: a value tainted
in file A, passed to a helper DEFINED in file B, that sinks the parameter (or returns
model output), is caught. Uses UNAMBIGUOUS-ONLY resolution — a function name defined in
exactly one file resolves; a name defined in several files is left unresolved rather than
linked to the wrong file (the same rule the Python engine uses to avoid wrong-file FPs).

Each analyzer plugs in its own primitives (`_parse`, `_functions`, `_returns_output`,
`_dangerous_params`); this computes the project-wide `returns_out` set and the
per-function `(params, dangerous)` summaries once, to be handed to `interprocedural(...)`
as `extra_returns_out` / `extra_summaries` when analyzing each file.
"""
from __future__ import annotations


def build_index(mod, sources):
    """(returns_out, summaries) across all `sources` (file texts of one language),
    restricted to unambiguously-named functions. `mod` is the language analyzer module."""
    roots = []
    for s in sources:
        try:
            r = mod._parse(s)
        except Exception:
            r = None
        if r is not None:
            roots.append(r)

    name_fns = {}
    for r in roots:
        try:
            fns = mod._functions(r)
        except Exception:
            fns = {}
        for name, fn in fns.items():
            name_fns.setdefault(name, []).append(fn)
    # unambiguous: defined in exactly one place project-wide
    unambiguous = {name: fns[0] for name, fns in name_fns.items() if len(fns) == 1}
    if not unambiguous:
        return frozenset(), {}

    returns_out = set()
    changed = True
    while changed:
        changed = False
        for name, fn in unambiguous.items():
            if name not in returns_out and mod._returns_output(fn, returns_out):
                returns_out.add(name)
                changed = True

    summaries = {}
    for name, fn in unambiguous.items():
        params, dangerous = mod._dangerous_params(fn, returns_out)
        if dangerous:
            summaries[name] = (params, dangerous)
    return frozenset(returns_out), summaries
