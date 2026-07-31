"""Shared AST core for LLM06 (excessive agency) in annotation-based languages.

The Python engine resolves which functions are model-invokable tools and finds dangerous
sinks reachable from them. For languages where a tool is declared by an annotation ON the
function — Java/Kotlin `@Tool`, C# `[KernelFunction]`, Rust `#[tool]`, TS `@tool` — this does
the AST equivalent, which is strictly more precise than a proximity-window regex:

  - the tool marker must appear in the function's HEADER (its annotations/signature), not
    merely somewhere nearby, so a `@tool` mention in unrelated code cannot make a plain
    function look tool-exposed, and
  - a dangerous sink is credited only when it sits in that tool function's BODY, at any line
    distance (better recall than a fixed window, no cross-function bleed).

Returns a list of (line, capability, mitigated, tool_name), or None if the source won't
parse (the caller then falls back to the regex path).
"""
from __future__ import annotations


# Some grammars attach a decorator/attribute as a PRECEDING SIBLING of the function rather
# than inside it (notably Rust `#[tool]`). Scan a few siblings back for the marker too.
_DECO_SIBLING = {"attribute_item", "decorator", "annotation", "marker_annotation", "attribute"}


def tool_sinks(parse, walk, text, line, src, fn_types, tool_re, sinks, confirm_re,
               import_re=None, body_field="body", name_field="name"):
    root = parse(src)
    if root is None:
        return None
    out = []
    for fn in [n for n in walk(root) if n.type in fn_types]:
        body = fn.child_by_field_name(body_field)
        ftext = text(fn)
        btext = text(body) if body is not None else ""
        # Header = everything before the body: the annotations + signature. The tool marker
        # must live here, not in the body.
        header = ftext[:ftext.rfind(btext)] if btext else ftext
        sib, hops = fn.prev_sibling, 0
        while sib is not None and hops < 4 and sib.type in _DECO_SIBLING:
            header = text(sib) + "\n" + header
            sib, hops = sib.prev_sibling, hops + 1
        if not tool_re.search(header):
            continue
        nm = fn.child_by_field_name(name_field)
        tool_name = text(nm) if nm is not None else "tool"
        scope = btext or ftext
        mitigated = bool(confirm_re.search(scope))
        base_line = line(body) if body is not None else line(fn)
        for i, ln in enumerate(scope.splitlines()):
            if import_re is not None and import_re.match(ln):
                continue
            for cap, sink_re in sinks.items():
                if sink_re.search(ln):
                    out.append((base_line + i, cap, mitigated, tool_name))
                    break                 # one capability per line is enough
    return out
