"""Shared interprocedural (intra-file) taint engine for the tree-sitter analyzers.

The Python engine already does this natively; each tree-sitter language plugs its
node-specific primitives into `interprocedural(...)` so the multi-function logic —
(1) a helper that RETURNS model output taints the caller's var, and (2) model output
passed to a local helper whose PARAMETER reaches a sink is flagged at the call site —
is written and verified once, not re-implemented per language.
"""
from __future__ import annotations


def interprocedural(*, functions, scopes, taint_in_scope, find_sinks,
                    returns_output, dangerous_params, iter_calls, refs, line,
                    extra_returns_out=(), extra_summaries=None):
    # `extra_returns_out` / `extra_summaries` carry CROSS-MODULE knowledge: function
    # names defined in OTHER files of the same project (unambiguous only) that return
    # model output / sink a parameter. Local definitions take precedence.
    # 1. Fixpoint: which functions return model output — local, seeded with cross-module.
    returns_out = set(extra_returns_out)
    changed = True
    while changed:
        changed = False
        for name, fn in functions.items():
            if name not in returns_out and returns_output(fn, returns_out):
                returns_out.add(name)
                changed = True

    # 2. Which functions sink one of their parameters — cross-module first, local overrides.
    summaries = dict(extra_summaries or {})
    for name, fn in functions.items():
        params, dangerous = dangerous_params(fn, returns_out)
        if dangerous:
            summaries[name] = (params, dangerous)

    out, seen = [], set()

    def add(ln, cap):
        if (ln, cap) not in seen:
            seen.add((ln, cap))
            out.append((ln, cap))

    for scope in scopes:
        tainted = taint_in_scope(scope, returns_out)   # includes return-value taint
        if tainted:
            find_sinks(scope, tainted, add)
        if not summaries:
            continue
        for call, name, args in iter_calls(scope):
            if name not in summaries:
                continue
            params, dangerous = summaries[name]
            for i, arg in enumerate(args):
                if i < len(params) and params[i] in dangerous and refs(arg, tainted):
                    add(line(call), "a helper that passes it to a dangerous sink (via %s())" % name)
                    break
    return out
