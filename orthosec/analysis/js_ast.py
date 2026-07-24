"""Optional JavaScript AST analysis (esprima) — precise detection for `.js` files.

The core ships regex for JS/TS. When the optional `orthosec[js]` extra is installed,
plain JavaScript is parsed to an AST so detection keys on real call nodes and
dataflow instead of line proximity — e.g. an uncapped `client.chat.completions
.create({...})` is a real CallExpression, not a string or comment mentioning it.

TypeScript/JSX (types, decorators) is out of esprima's scope; those files fall back
to regex automatically (a parse failure returns None and the caller uses regex).
"""
from __future__ import annotations

import re

# `model`/`llm` name the client, not its output (caught call-based) — excluded to avoid FPs.
# `output` excludes file/path-ish names (outputPath/outputFile/...) — not model output.
_OUTPUT_NAME = re.compile(
    r"(?i)(completion|response|answer|reply|generated|assistant|"
    r"output(?!path|file|dir|name|buf|stream|writer|target|location|dest)|resp|choices|content)")


def available() -> bool:
    try:
        import esprima  # noqa: F401
        return True
    except Exception:
        return False


def _parse(src: str):
    try:
        import esprima
    except Exception:
        return None
    for fn in ("parseModule", "parseScript"):
        try:
            return getattr(esprima, fn)(src, loc=True, tolerant=True).toDict()
        except Exception:
            continue
    return None


def _walk(node):
    if isinstance(node, list):
        for x in node:
            yield from _walk(x)
    elif isinstance(node, dict):
        if "type" in node:
            yield node
        for v in node.values():
            yield from _walk(v)


def _line(node) -> int:
    try:
        return node["loc"]["start"]["line"]
    except Exception:
        return 0


def _member_chain(node) -> list:
    parts = []
    while isinstance(node, dict) and node.get("type") == "MemberExpression":
        prop = node.get("property") or {}
        parts.append(prop.get("name") or prop.get("value"))
        node = node.get("object")
    if isinstance(node, dict) and node.get("type") == "Identifier":
        parts.append(node.get("name"))
    return [p for p in reversed(parts) if p]


def _prop_name(member) -> str:
    prop = member.get("property") or {}
    return prop.get("name") or prop.get("value") or ""


def _is_completion(chain: list) -> bool:
    if not chain or chain[-1] not in ("create", "generate", "acreate"):
        return False
    return bool(set(chain) & {"completions", "messages", "responses", "chat"})


# Calls that neutralize taint (escape / sanitize / render-with-escaping).
_SANITIZER = {"rendertostring", "rendertostaticmarkup", "sanitize", "purify", "escape",
              "escapehtml", "encodeuri", "encodeuricomponent", "striptags", "dompurify"}


def _is_sanitizer_call(node) -> bool:
    if not isinstance(node, dict) or node.get("type") != "CallExpression":
        return False
    chain = _member_chain(node.get("callee"))
    return bool(chain) and str(chain[-1]).lower() in _SANITIZER


def _has_cap(call: dict) -> bool:
    for arg in call.get("arguments", []) or []:
        if isinstance(arg, dict) and arg.get("type") == "ObjectExpression":
            for prop in arg.get("properties", []) or []:
                key = (prop.get("key") or {})
                name = key.get("name") or key.get("value") or ""
                if str(name).lower() in ("max_tokens", "maxtokens", "max_output_tokens", "max_completion_tokens"):
                    return True
    return False


def _refs(node, names: set) -> bool:
    for n in _walk(node):
        if n.get("type") == "Identifier" and n.get("name") in names:
            return True
    return False


def unbounded_findings(src: str):
    """Uncapped LLM completion calls. Returns list of line numbers, or None to fall back."""
    tree = _parse(src)
    if tree is None:
        return None
    out = []
    for n in _walk(tree):
        if n.get("type") == "CallExpression" and _is_completion(_member_chain(n.get("callee"))) \
                and not _has_cap(n):
            out.append(_line(n))
    return out


def _expr_is_output(node, tainted: set) -> bool:
    if _is_sanitizer_call(node):        # a sanitized value is clean, even if it wraps output
        return False
    for n in _walk(node):
        if n.get("type") == "CallExpression" and _is_completion(_member_chain(n.get("callee"))):
            return True
        if n.get("type") == "Identifier" and n.get("name") in tainted:
            return True
    return False


def output_findings(src: str):
    """Model output flowing into innerHTML / eval / document.write. Returns list of
    (line, capability), or None to fall back to regex."""
    tree = _parse(src)
    if tree is None:
        return None

    decls = []   # (target_name, value_node)
    for n in _walk(tree):
        if n.get("type") == "VariableDeclarator" and (n.get("id") or {}).get("type") == "Identifier":
            decls.append((n["id"]["name"], n.get("init")))
        elif n.get("type") == "AssignmentExpression" and (n.get("left") or {}).get("type") == "Identifier":
            decls.append((n["left"]["name"], n.get("right")))

    tainted = {name for name, val in decls
               if _OUTPUT_NAME.search(name) and not _is_sanitizer_call(val)}
    changed = True
    while changed:
        changed = False
        for name, val in decls:
            if name in tainted or val is None:
                continue
            if _expr_is_output(val, tainted):
                tainted.add(name)
                changed = True
    if not tainted:
        return []

    out = []
    for n in _walk(tree):
        t = n.get("type")
        if t == "AssignmentExpression":
            left = n.get("left") or {}
            if left.get("type") == "MemberExpression" and _prop_name(left) == "innerHTML" \
                    and _refs(n.get("right"), tainted):
                out.append((_line(n), "HTML injection (innerHTML)"))
        elif t == "CallExpression":
            chain = _member_chain(n.get("callee"))
            if chain[-1:] == ["eval"] and _refs(n.get("arguments"), tainted):
                out.append((_line(n), "code execution (eval)"))
            elif chain[-2:] == ["document", "write"] and _refs(n.get("arguments"), tainted):
                out.append((_line(n), "HTML injection (document.write)"))
    return out
