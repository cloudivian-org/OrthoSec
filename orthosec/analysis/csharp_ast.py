"""Optional C# / .NET AST analysis (tree-sitter).

C# runs enterprise and Azure-native AI — Semantic Kernel, the Azure OpenAI and OpenAI
.NET SDKs. With the optional `orthosec[csharp]` extra (tree-sitter + tree-sitter-c-sharp),
`.cs` files are parsed to a real syntax tree for LLM05 (model output into a dangerous
sink). Same contract as the other `*_ast` modules; per-method scoping.

C# v1 covers LLM05. LLM10 (output-token cap) is set on an options object / builder, not a
plain per-call argument in the dominant SDKs, so it's deferred.
"""
from __future__ import annotations

import re

from orthosec.analysis.java_ast import _OUTPUT_NAME  # PascalCase names match case-insensitively

_LLM_RECEIVER = re.compile(
    r"(?i)(chatclient|ichatclient|kernel|semantickernel|chatcompletion|openai|azureopenai|"
    r"anthropic|bedrock|llm|model|assistant|agent|completion|chatgpt|gpt)")
# .NET SDK methods that unconditionally return model output.
_LLM_METHODS = {"completechat", "completechatasync", "getchatcompletions",
                "getchatcompletionsasync", "getchatmessagecontentasync",
                "getchatmessagecontentsasync", "invokepromptasync", "getresponseasync"}
# Generic verbs that return model output only on an LLM-ish receiver.
_LLM_GATED = {"complete", "chat", "invoke", "invokeasync", "generate", "ask",
              "getresponse", "run", "runasync"}
_SANITIZER = {"htmlencode", "encode", "escapedatastring", "escapeuristring", "escape",
              "sanitize", "urlencode"}
_SQL_CMD_TYPES = {"sqlcommand", "mysqlcommand", "npgsqlcommand", "oraclecommand",
                  "sqlitecommand", "oledbcommand"}
_SQL_METHODS = {"fromsqlraw", "executesqlraw", "executesqlrawasync",
                "query", "queryasync", "queryfirst", "queryfirstasync", "querysingle",
                "execute", "executeasync", "executereader", "executescalar"}
_DB_RECEIVER = re.compile(r"(?i)(conn|connection|db|database|context|dapper|session)")

_CACHE: dict = {}


def available() -> bool:
    try:
        import tree_sitter, tree_sitter_c_sharp  # noqa: F401
        return True
    except Exception:
        return False


def _parser():
    if "cs" in _CACHE:
        return _CACHE["cs"]
    try:
        import tree_sitter_c_sharp as tscs
        from tree_sitter import Language, Parser
        lang = Language(tscs.language())
        try:
            parser = Parser(lang)
        except Exception:
            parser = Parser(); parser.set_language(lang)
    except Exception:
        parser = None
    _CACHE["cs"] = parser
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


def _chain(node) -> list:
    """Receiver + member segments (base-first) of a member/invocation/element chain."""
    parts = []
    while node is not None and node.type in (
            "member_access_expression", "element_access_expression",
            "invocation_expression", "conditional_access_expression"):
        if node.type == "member_access_expression":
            nm = node.child_by_field_name("name")
            if nm is not None:
                parts.append(_text(nm))
            node = node.child_by_field_name("expression")
        elif node.type == "invocation_expression":
            node = node.child_by_field_name("function")
        else:
            node = node.child_by_field_name("expression")
    if node is not None and node.type == "identifier":
        parts.append(_text(node))
    return list(reversed(parts))


def _callee_chain(call) -> list:
    fn = call.child_by_field_name("function")
    if fn is None:
        return []
    if fn.type == "identifier":
        return [_text(fn)]
    return _chain(fn)


def _is_sanitizer_call(node) -> bool:
    if node is None or node.type != "invocation_expression":
        return False
    chain = _callee_chain(node)
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
        if n.type == "identifier" and _text(n) in tainted:
            return True
    return False


def _expr_is_output(node, tainted: set, returns_out=()) -> bool:
    if _is_sanitizer_call(node):
        return False
    for n in _walk(node):
        if n.type == "invocation_expression":
            chain = _callee_chain(n)
            if _is_llm_output_call(chain):
                return True
            if len(chain) == 1 and chain[0] in returns_out:   # var x = LocalHelperReturningOutput(...)
                return True
        if n.type == "identifier" and _text(n) in tainted:
            return True
    return False


_SCOPE_TYPES = ("method_declaration", "constructor_declaration",
                "local_function_statement", "lambda_expression")


def _scopes(root):
    scopes = [n for n in _walk(root) if n.type in _SCOPE_TYPES]
    return scopes or [root]


def _decl_value(vd):
    """The initializer expression of a variable_declarator, or None."""
    name = vd.child_by_field_name("name")
    kids = [c for c in vd.children if c is not name and c.type not in ("=",)]
    return kids[-1] if kids else None


def _decls(scope):
    decls = []
    for n in _walk(scope):
        if n.type == "variable_declarator":
            name = n.child_by_field_name("name")
            if name is not None and name.type == "identifier":
                decls.append((_text(name), _decl_value(n)))
        elif n.type == "assignment_expression":
            # Skip object-initializer members (`new T { Output = true }`) — a field name
            # like RedirectStandardOutput is not a variable holding model output.
            if n.parent is not None and n.parent.type == "initializer_expression":
                continue
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is not None and left.type == "identifier":
                decls.append((_text(left), right))
    return decls


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
    tainted = {name for name, val in decls
               if _OUTPUT_NAME.search(name) and not (val is not None and _is_sanitizer_call(val))}
    return _fixpoint(decls, tainted, returns_out)


def _propagate_from(scope, seed, returns_out=()):
    return _fixpoint(_decls(scope), set(seed), returns_out)


def unbounded_findings(src: str):
    """C# LLM10 (output-token cap) is options-object/builder-configured — deferred."""
    return None


def _find_sinks(scope, tainted, add):
    for n in _walk(scope):
        if n.type == "object_creation_expression":
            typ = n.child_by_field_name("type")
            if typ is not None and _text(typ).lower() in _SQL_CMD_TYPES \
                    and _refs(n.child_by_field_name("arguments"), tainted):
                add(_line(n), "raw SQL execution")
        elif n.type == "invocation_expression":
            chain = _callee_chain(n)
            if not chain or not _refs(n.child_by_field_name("arguments"), tainted):
                continue
            name = chain[-1].lower()
            recv = [p.lower() for p in chain[:-1]]
            if name == "start" and any("process" in p for p in recv):
                add(_line(n), "shell/command execution")
            elif name in ("fromsqlraw", "executesqlraw", "executesqlrawasync"):
                add(_line(n), "raw SQL execution")
            elif name in _SQL_METHODS and any(_DB_RECEIVER.search(p) for p in recv):
                add(_line(n), "raw SQL execution")
            elif name == "raw" and any("html" in p for p in recv):
                add(_line(n), "HTML injection (Html.Raw)")
            elif name in ("evaluateasync", "runasync") and any("script" in p for p in recv):
                add(_line(n), "script execution (eval)")


# ---- interprocedural (intra-file) -------------------------------------------

def _functions(root):
    funcs = {}
    for n in _walk(root):
        if n.type in ("method_declaration", "constructor_declaration",
                      "local_function_statement"):
            nm = n.child_by_field_name("name")
            if nm is not None:
                funcs[_text(nm)] = n
    return funcs


def _formal_params(fn):
    p = fn.child_by_field_name("parameters")
    names = []
    if p is not None:
        for pd in p.children:
            if pd.type == "parameter":
                nm = pd.child_by_field_name("name")
                if nm is not None:
                    names.append(_text(nm))
    return names


def _has_sink_call(fn):
    for n in _walk(fn):
        if n.type == "object_creation_expression":
            typ = n.child_by_field_name("type")
            if typ is not None and _text(typ).lower() in _SQL_CMD_TYPES:
                return True
        elif n.type == "invocation_expression":
            chain = _callee_chain(n)
            last = chain[-1].lower() if chain else ""
            if last in ("start", "raw", "evaluateasync", "runasync") or last in _SQL_METHODS:
                return True
    return False


def _returns_output(fn, returns_out):
    tainted = _taint_in_scope(fn, returns_out)
    for n in _walk(fn):
        if n.type == "return_statement":
            expr = next((c for c in n.children if c.type not in ("return", ";")), None)
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
    for n in _walk(scope):
        if n.type != "invocation_expression":
            continue
        chain = _callee_chain(n)
        if len(chain) != 1:                     # only bare local calls: Foo(x)
            continue
        argnode = n.child_by_field_name("arguments")
        args = [a for a in (argnode.children if argnode else []) if a.type not in ("(", ")", ",")]
        yield n, chain[0], args


def output_findings(src: str):
    root = _parse(src)
    if root is None:
        return None
    from orthosec.analysis._interproc import interprocedural
    return interprocedural(
        functions=_functions(root), scopes=_scopes(root),
        taint_in_scope=_taint_in_scope, find_sinks=_find_sinks,
        returns_output=_returns_output, dangerous_params=_dangerous_params,
        iter_calls=_iter_calls, refs=_refs, line=_line)
