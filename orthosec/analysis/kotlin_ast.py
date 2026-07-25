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


def _expr_is_output(node, tainted: set, returns_out=()) -> bool:
    if _is_sanitizer_call(node):
        return False
    for n in _walk(node):
        if n.type == "call_expression":
            chain = _call_chain(n)
            if _is_llm_output_call(chain):
                return True
            if len(chain) == 1 and chain[0] in returns_out:   # val x = localHelperReturningOutput()
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


def _fixpoint(decls, tainted, returns_out):
    changed = True
    while changed:
        changed = False
        for name, val in decls:
            if name in tainted or val is None:
                continue
            if _expr_is_output(val, tainted, returns_out):
                tainted.add(name)
                changed = True
    return tainted


def _taint_in_scope(scope, returns_out=()):
    decls = _decls(scope)
    seed = {name for name, val in decls
            if _OUTPUT_NAME.search(name) and not (val is not None and _is_sanitizer_call(val))}
    return _fixpoint(decls, seed, returns_out)


def _propagate_from(scope, seed, returns_out=()):
    return _fixpoint(_decls(scope), set(seed), returns_out)


def _find_sinks(scope, tainted, add):
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


# ---- interprocedural (intra-file) -------------------------------------------

def _functions(root):
    """name -> function_declaration node. Kotlin has no fields; the function name is the
    first simple_identifier direct child (after the `fun` keyword)."""
    funcs = {}
    for n in _walk(root):
        if n.type == "function_declaration":
            name = next((_text(c) for c in n.children if c.type in _ID_TYPES), None)
            if name:
                funcs[name] = n
    return funcs


def _formal_params(fn):
    params = next((c for c in fn.children if c.type == "function_value_parameters"), None)
    names = []
    if params is not None:
        for p in params.children:
            if p.type == "parameter":
                # param NAME is the first DIRECT simple_identifier child (before `:` type);
                # _walk is reverse-order and would return the type instead.
                nm = next((_text(c) for c in p.children if c.type in _ID_TYPES), None)
                if nm:
                    names.append(nm)
    return names


_SINK_METHODS = {"exec", "processbuilder", "executequery", "executeupdate",
                 "executelargeupdate", "createquery", "createnativequery", "execute", "eval"}


def _has_sink_call(fn):
    for n in _walk(fn):
        if n.type == "call_expression":
            chain = _call_chain(n)
            if chain and chain[-1].lower() in _SINK_METHODS:
                return True
    return False


def _single_expr_body(fn):
    """`fun f(...) = <expr>` — the body expression after `=` (wrapped in a
    `function_body` node), or None for block bodies."""
    body = next((c for c in fn.children if c.type == "function_body"), None)
    if body is None:
        return None
    seen_eq = False
    for c in body.children:
        if seen_eq:
            return c
        if c.type == "=":
            seen_eq = True
    return None


def _returns_output(fn, returns_out):
    tainted = _taint_in_scope(fn, returns_out)
    body = _single_expr_body(fn)
    if body is not None and _expr_is_output(body, tainted, returns_out):
        return True
    for n in _walk(fn):
        if n.type == "return_expression":               # Kotlin `return <expr>`
            expr = next((c for c in n.children if c.type not in ("return",)), None)
            if expr is not None and _expr_is_output(expr, tainted, returns_out):
                return True
    return False


def _dangerous_params(fn, returns_out):
    params = _formal_params(fn)
    if not params or not _has_sink_call(fn):
        return params, set()
    dangerous = set()
    for p in params:
        found = []
        _find_sinks(fn, _propagate_from(fn, {p}, returns_out), lambda l, c: found.append(1))
        if found:
            dangerous.add(p)
    return params, dangerous


def _iter_calls(scope):
    # method NAME for a bare `foo(...)` or a STATIC `Helper.run(...)` (receiver Capitalized).
    # An instance `obj.run(...)` is NOT resolved cross-module by name.
    for n in _walk(scope):
        if n.type != "call_expression":
            continue
        chain = _call_chain(n)
        if not chain:
            continue
        if len(chain) >= 2 and not chain[-2][:1].isupper():
            continue
        args = _call_args(n)
        arg_nodes = [a for a in (args.children if args else []) if a.type not in ("(", ")", ",")]
        yield n, chain[-1], arg_nodes


def unbounded_findings(src: str):
    """Kotlin LLM10 deferred (builder-configured cap, like Java)."""
    return None


def output_findings(src: str, project=None):
    root = _parse(src)
    if root is None:
        return None
    p_returns, p_summaries = project if project else ((), None)
    from orthosec.analysis._interproc import interprocedural
    return interprocedural(
        functions=_functions(root), scopes=_scopes(root),
        taint_in_scope=_taint_in_scope, find_sinks=_find_sinks,
        returns_output=_returns_output, dangerous_params=_dangerous_params,
        iter_calls=_iter_calls, refs=_refs, line=_line,
        extra_returns_out=p_returns, extra_summaries=p_summaries)


# ---- LLM01: untrusted input -> system prompt --------------------------------

import re as _re
_UNTRUSTED_NAME = _re.compile(
    r"(?i)(\buser|\binput\b|query|question|\bmessage\b|\bprompt\b|\breq\b|request|"
    r"\bbody\b|payload|\bmsg\b|userinput|usermessage)")
_REQ_ROOT = {"req", "request", "ctx", "context", "call", "params"}
_SYS_PROMPT_NAME = _re.compile(
    r"(?i)(systemprompt|system_prompt|systemmessage|system_message|sysprompt|sys_prompt|"
    r"systeminstruction|instruction)")
_INJ_HARDENING = _re.compile(
    r"(?i)(untrusted|do not follow|ignore (any|previous|all)|delimited by|<user_input>|"
    r"treat .* as data|never reveal|as data,? not|do not obey|sanitiz|escapehtml)")


def _refs_request(node) -> bool:
    if node is None:
        return False
    for n in _walk(node):
        if n.type in _ID_TYPES and _text(n) in _REQ_ROOT:
            return True
    return False


def _untrusted_in_scope(fnscope):
    seed = {p for p in _formal_params(fnscope) if _UNTRUSTED_NAME.search(p)}
    decls = _decls(fnscope)
    for name, val in decls:
        if _refs_request(val):
            seed.add(name)
    tainted = set(seed)
    changed = True
    while changed:
        changed = False
        for name, val in decls:
            if name in tainted or val is None:
                continue
            if _is_sanitizer_call(val):
                continue
            if _refs(val, tainted):
                tainted.add(name)
                changed = True
    return tainted


def injection_findings(src: str):
    """LLM01 — untrusted input reaching a system prompt (a system-prompt-named assignment,
    or a `SystemMessage(untrusted)` construction) with no trust boundary."""
    root = _parse(src)
    if root is None:
        return None
    out, seen = [], set()

    def add(line):
        cap = "untrusted input in system prompt (no trust boundary)"
        if (line, cap) not in seen:
            seen.add((line, cap))
            out.append((line, cap))

    for scope in _scopes(root):
        if _INJ_HARDENING.search(_text(scope)):
            continue
        untrusted = _untrusted_in_scope(scope)
        if not untrusted:
            continue
        # (a) system-prompt-named val/var assignment referencing untrusted
        for name, val in _decls(scope):
            if _SYS_PROMPT_NAME.search(name) and _refs(val, untrusted):
                add(_line(val) if val is not None else 0)
        # (b) SystemMessage(untrusted) / SystemMessage.from(untrusted)
        for n in _walk(scope):
            if n.type != "call_expression":
                continue
            chain = [c.lower() for c in _call_chain(n)]
            if "systemmessage" in chain and _refs(_call_args(n), untrusted):
                add(_line(n))
    return out
