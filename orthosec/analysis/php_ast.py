"""Optional PHP AST analysis (tree-sitter).

PHP runs AI features in Laravel/Symfony apps via openai-php and LLPhant. With the optional
`orthosec[php]` extra (tree-sitter + tree-sitter-php), `.php` files are parsed to a real
syntax tree for LLM05 (model output flowing into a dangerous sink).

Same contract as the other `*_ast` modules (None => regex fallback); per-function scoping.
"""
from __future__ import annotations

import re

from orthosec.analysis.java_ast import _OUTPUT_NAME

_LLM_RECEIVER = re.compile(
    r"(?i)(client|llm|openai|anthropic|model|chain|assistant|agent|chat|completion|"
    r"langchain|gpt|cohere|bedrock|gemini|ollama|llphant)")
_LLM_METHODS = {"chat", "create", "complete", "completions", "generate", "generatetext",
                "ask", "invoke", "predict", "messages", "run", "call"}
_SANITIZER = {"htmlspecialchars", "htmlentities", "addslashes", "mysqli_real_escape_string",
              "real_escape_string", "escapeshellarg", "escapeshellcmd", "urlencode",
              "rawurlencode", "filter_var", "e", "strip_tags", "quote"}
_SHELL_FUNCS = {"exec", "shell_exec", "system", "passthru", "proc_open", "popen"}
_SQL_METHODS = {"query", "exec", "prepare", "statement", "unprepared",
                "whereraw", "selectraw", "fromraw", "havingraw", "orderbyraw", "raw"}
_DB_RECEIVER = re.compile(r"(?i)(pdo|mysqli|\bdb\b|conn|connection|database|dbh|eloquent|capsule)")

_CACHE: dict = {}


def available() -> bool:
    try:
        import tree_sitter, tree_sitter_php  # noqa: F401
        return True
    except Exception:
        return False


def _parser():
    if "php" in _CACHE:
        return _CACHE["php"]
    try:
        import tree_sitter_php as tsp
        from tree_sitter import Language, Parser
        raw = tsp.language_php() if hasattr(tsp, "language_php") else tsp.language()
        lang = Language(raw)
        try:
            parser = Parser(lang)
        except Exception:
            parser = Parser(); parser.set_language(lang)
    except Exception:
        parser = None
    _CACHE["php"] = parser
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


def _var_name(vn) -> str:
    return _text(vn).lstrip("$")


def _names(node) -> list:
    if node is None:
        return []
    out = []
    for n in _walk(node):
        if n.type == "name":
            out.append(_text(n))
        elif n.type == "variable_name":
            out.append(_var_name(n))
    return out


_CALL_TYPES = ("function_call_expression", "member_call_expression",
               "scoped_call_expression", "nullsafe_member_call_expression")


def _call_method(call) -> str:
    if call.type == "function_call_expression":
        fn = call.child_by_field_name("function")
        return _text(fn) if fn is not None else ""
    nm = call.child_by_field_name("name")
    return _text(nm) if nm is not None else ""


def _call_receiver(call) -> list:
    obj = call.child_by_field_name("object") or call.child_by_field_name("scope")
    return _names(obj) if obj is not None else []


def _is_sanitizer_call(node) -> bool:
    return node is not None and node.type in _CALL_TYPES \
        and _call_method(node).lower() in _SANITIZER


def _is_llm_output_call(call) -> bool:
    if call.type not in _CALL_TYPES:
        return False
    meth = _call_method(call).lower()
    if meth not in _LLM_METHODS:
        return False
    return any(_LLM_RECEIVER.search(p) for p in _call_receiver(call))


def _refs(node, tainted: set) -> bool:
    if node is None:
        return False
    for n in _walk(node):
        if n.type == "variable_name" and _var_name(n) in tainted:
            return True
    return False


def _first_arg(args):
    """The first argument node of an `arguments` list — the injection payload for a
    shell/SQL/eval sink. Later args (e.g. exec()'s by-ref $output, $exitCode) are not."""
    if args is None:
        return None
    for c in args.children:
        if c.type not in ("(", ")", ","):
            return c
    return None


def _expr_is_output(node, tainted: set) -> bool:
    if _is_sanitizer_call(node):
        return False
    for n in _walk(node):
        if n.type in _CALL_TYPES and _is_llm_output_call(n):
            return True
        if n.type == "variable_name" and _var_name(n) in tainted:
            return True
    return False


_SCOPE_TYPES = ("method_declaration", "function_definition", "anonymous_function_creation_expression",
                "arrow_function")


def _scopes(root):
    scopes = [n for n in _walk(root) if n.type in _SCOPE_TYPES]
    return scopes or [root]


def _taint_in_scope(scope):
    decls = []
    for n in _walk(scope):
        if n.type == "assignment_expression":
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is not None and left.type == "variable_name":
                decls.append((_var_name(left), right))
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
            # NB: `echo`/`print` of model output is intentionally NOT flagged — it is
            # context-dependent (a CLI script echoes to a terminal, not HTML) and produced
            # overwhelming noise on real code. Only unambiguous exec/SQL/eval sinks fire.
            if n.type not in _CALL_TYPES:
                continue
            # Only the first argument is the injection payload (command / SQL string).
            if not _refs(_first_arg(n.child_by_field_name("arguments")), tainted):
                continue
            meth = _call_method(n).lower()
            recv = [p.lower() for p in _call_receiver(n)]
            if n.type == "function_call_expression":
                if meth in _SHELL_FUNCS:
                    add(_line(n), "shell/command execution")
                elif meth == "eval":
                    add(_line(n), "code execution (eval)")
            else:  # member / scoped / nullsafe call
                if meth in _SQL_METHODS and (any(_DB_RECEIVER.search(r) for r in recv)
                                             or meth.endswith("raw") or meth == "statement"):
                    add(_line(n), "raw SQL execution")
    return out
