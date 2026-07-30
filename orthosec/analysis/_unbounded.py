"""Shared AST core for LLM10 (uncapped completion call).

Two request styles across languages:

- literal-style (PHP array, Ruby hash, JS/TS object): the request is an inline literal
  whose fields we can fully see — each analyzer checks the literal subtree directly.
- builder-style (Java/Kotlin/C#/Rust): the request is built via a builder chain
  (`ChatCompletionCreateParams.builder().maxTokens(n).build()`, `new ChatCompletionOptions
  { MaxOutputTokenCount = n }`), usually in the same method as the call. `builder_style`
  below flags a completion call only when NO cap keyword appears anywhere in its enclosing
  method — the cap, if set, lives in that method's builder. If the call sits in no method
  scope we fall back to the call node's own text. Precision over recall: when a cap might be
  set out of view we do not flag (the same rule the Go analyzer uses for variable requests).
"""
from __future__ import annotations


def _enclosing_text(node, scope_types, text_fn):
    p = node.parent
    while p is not None:
        if p.type in scope_types:
            return text_fn(p)
        p = p.parent
    return None


def builder_style(parse, walk, text, line, src, call_types, completion_re, cap_re, scope_types):
    """Return line numbers of uncapped completion calls, or None if the source won't parse."""
    root = parse(src)
    if root is None:
        return None
    out = set()
    for n in walk(root):
        if n.type not in call_types:
            continue
        if not completion_re.search(text(n)):
            continue
        scope_txt = _enclosing_text(n, scope_types, text)
        haystack = scope_txt if scope_txt is not None else text(n)
        if not cap_re.search(haystack):
            out.add(line(n))          # dedupe: a chained call can match at nested nodes
    return sorted(out)
