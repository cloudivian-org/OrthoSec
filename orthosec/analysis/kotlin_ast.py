"""Optional Kotlin AST analysis (tree-sitter).

Kotlin runs Android AI apps and Ktor/Spring backends, usually against the same JVM LLM
SDKs as Java (LangChain4j, Spring AI, OpenAI-Java). With the optional `orthosec[kotlin]`
extra (tree-sitter + tree-sitter-kotlin), `.kt` files are parsed to a real syntax tree
for LLM05 (model output flowing into a dangerous sink).

Same contract as the other `*_ast` modules (None => regex fallback), per-function scoping,
and it reuses Java's receiver / method / sanitizer vocabulary since the SDKs are shared.
The Kotlin grammar exposes no named fields, so chains are read by collecting identifiers
in source order.
"""
from __future__ import annotations

from orthosec.analysis.java_ast import (
    _OUTPUT_NAME, _LLM_RECEIVER, _LLM_METHODS, _LLM_GATED, _SANITIZER, _DB_RECEIVER)

_CACHE: dict = {}


def available() -> bool:
    try:
        import tree_sitter, tree_sitter_kotlin  # noqa: F401
        return True
    except Exception:
        return False


def _parser():
    if "kotlin" in _CACHE:
        return _CACHE["kotlin"]
    try:
        import tree_sitter_kotlin as tsk
        from tree_sitter import Language, Parser
        lang = Language(tsk.language())
        try:
            parser = Parser(lang)
        except Exception:
            parser = Parser(); parser.set_language(lang)
    except Exception:
        parser = None
    _CACHE["kotlin"] = parser
    return parser


def _parse(src: str):
    parser = _parser()
    if parser is None:
        return None
    try:
        root = parser.parse(bytes(src, "utf-8")).root_node
    except Exception:
        return None
    if root is None or (root.has_error and root.child_count == 0):
        return None
    return root


def _walk(node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def _line(node) -> int:
    return node.start_point[0] + 1


def _text(node) -> str:
    return node.text.decode("utf-8", "replace")


_ID_TYPES = ("simple_identifier", "identifier", "type_identifier")


def _idents(node) -> list:
    """Identifier segments in SOURCE order (base receiver first, method name last).
    Must be an in-order recursion — the stack-based _walk yields children reversed."""
    if node is None:
        return []
    out = []

    def rec(n):
        if n.type in _ID_TYPES:
            out.append(_text(n))
        for c in n.children:
            rec(c)

    rec(node)
    return out


def _callee(call):
    """The callee sub-node of a call_expression (everything before its value_arguments)."""
    for c in call.children:
        if c.type != "value_arguments" and c.type != "call_suffix":
            return c
    return None


def _call_chain(call) -> list:
    """Receiver + method-name identifier segments of a call_expression, base-first.
    Chained inner-arg identifiers may leak in; the method name is the last segment."""
    return _idents(_callee(call))


def _call_args(call):
    for c in call.children:
        if c.type == "value_arguments":
            return c
    return None


def _is_sanitizer_call(node) -> bool:
    if node is None or node.type != "call_expression":
        return False
    chain = _call_chain(node)
    return bool(chain) and chain[-1].lower() in _SANITIZER


def _is_llm_output_call(chain: list) -> bool:
    if not chain:
        return False
    last = chain[-1].lower()
    if last in _LLM_METHODS:
        return True
    if last in _LLM_GATED:
        return any(_LLM_RECEIVER.search(p) for p in chain[:-1])
    return False


def _refs(node, tainted: set) -> bool:
    if node is None:
        return False
    for n in _walk(node):
        if n.type in _ID_TYPES and _text(n) in tainted:
            return True
    return False


def _expr_is_output(node, tainted: set) -> bool:
    if _is_sanitizer_call(node):
        return False
    for n in _walk(node):
        if n.type == "call_expression" and _is_llm_output_call(_call_chain(n)):
            return True
        if n.type in _ID_TYPES and _text(n) in tainted:
            return True
    return False


_SCOPE_TYPES = ("function_declaration", "anonymous_function", "lambda_literal")


def _scopes(root):
    scopes = [n for n in _walk(root) if n.type in _SCOPE_TYPES]
    return scopes or [root]


def _first_ident(node):
    for n in _walk(node):
        if n.type in _ID_TYPES:
            return _text(n)
    return None


def _decls(scope):
    """(name, value_node) from `val/var x = …` and `x = …` assignments."""
    out = []
    for n in _walk(scope):
        if n.type == "property_declaration":
            vd = next((c for c in n.children if c.type == "variable_declaration"), None)
            name = _first_ident(vd) if vd is not None else None
            value = n.children[-1] if n.children else None
            if name and value is not None and value.type not in ("variable_declaration",) \
                    and _text(value) not in ("val", "var"):
                out.append((name, value))
        elif n.type == "assignment":
            kids = [c for c in n.children if c.type not in ("=",)]
            if len(kids) >= 2 and kids[0].type in _ID_TYPES:
                out.append((_text(kids[0]), kids[-1]))
    return out


def _taint_in_scope(scope):
    decls = _decls(scope)
    tainted = {name for name, val in decls
               if _OUTPUT_NAME.search(name) and not (val is not None and _is_sanitizer_call(val))}
    changed = True
    while changed:
        changed = False
        for name, val in decls:
            if name in tainted or val is None:
                continue
            if _expr_is_output(val, tainted):
                tainted.add(name)
                changed = True
    return tainted


def unbounded_findings(src: str):
    """Kotlin LLM10 deferred (builder-configured cap, like Java)."""
    return None


def output_findings(src: str):
    root = _parse(src)
    if root is None:
        return None

    out, seen = [], set()

    def add(line, cap):
        if (line, cap) not in seen:
            seen.add((line, cap))
            out.append((line, cap))

    for scope in _scopes(root):
        tainted = _taint_in_scope(scope)
        if not tainted:
            continue
        for n in _walk(scope):
            if n.type != "call_expression":
                continue
            chain = _call_chain(n)
            if not chain or not _refs(_call_args(n), tainted):
                continue
            method = chain[-1].lower()
            recv = [p.lower() for p in chain[:-1]]
            if method == "exec" and any(p in ("runtime", "getruntime") for p in recv):
                add(_line(n), "shell/command execution")
            elif method == "processbuilder":            # constructor call (no `new` in Kotlin)
                add(_line(n), "shell/command execution")
            elif method in ("executequery", "executeupdate", "executelargeupdate",
                            "createquery", "createnativequery"):
                add(_line(n), "raw SQL execution")
            elif method == "execute" and any(_DB_RECEIVER.search(p) for p in recv):
                add(_line(n), "raw SQL execution")
            elif method == "eval" and any("script" in p or "engine" in p for p in recv):
                add(_line(n), "script execution (eval)")
    return out
