"""Optional Ruby AST analysis (tree-sitter).

Ruby runs AI features in Rails apps and via ruby-openai / langchainrb. With the optional
`orthosec[ruby]` extra (tree-sitter + tree-sitter-ruby), `.rb` files are parsed to a real
syntax tree for LLM05 (model output flowing into a dangerous sink).

Same contract as the other `*_ast` modules (None => regex fallback); per-method scoping.
"""
from __future__ import annotations

import re

from orthosec.analysis.java_ast import _OUTPUT_NAME

_LLM_RECEIVER = re.compile(
    r"(?i)(client|llm|openai|anthropic|model|chain|assistant|agent|chat|completion|"
    r"langchain|gpt|cohere|bedrock|gemini|ollama)")
_LLM_METHODS = {"chat", "complete", "completions", "generate", "ask", "invoke",
                "predict", "messages", "run", "call"}
_SANITIZER = {"escape", "sanitize", "html_escape", "escape_html", "h", "quote",
              "sanitize_sql", "sanitize_sql_for_conditions", "quote_string"}
_SHELL_BARE = {"system", "exec", "spawn", "syscall"}
_SHELL_RECV = {"popen", "capture2", "capture3", "capture2e", "popen3", "popen2"}
# Clearly-raw-SQL ActiveRecord/connection methods. NB: `delete`/`update` are excluded —
# File.delete / Array#delete / Hash#delete etc. are far more common than a raw-SQL delete.
_SQL_METHODS = {"execute", "find_by_sql", "exec_query", "select_all", "select_rows",
                "select_values"}
_EVAL_METHODS = {"eval", "instance_eval", "class_eval", "module_eval"}
_HTML_METHODS = {"raw", "html_safe"}

_CACHE: dict = {}


def available() -> bool:
    try:
        import tree_sitter, tree_sitter_ruby  # noqa: F401
        return True
    except Exception:
        return False


def _parser():
    if "ruby" in _CACHE:
        return _CACHE["ruby"]
    try:
        import tree_sitter_ruby as tsr
        from tree_sitter import Language, Parser
        lang = Language(tsr.language())
        try:
            parser = Parser(lang)
        except Exception:
            parser = Parser(); parser.set_language(lang)
    except Exception:
        parser = None
    _CACHE["ruby"] = parser
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


def _idents(node) -> list:
    if node is None:
        return []
    out = []

    def rec(n):
        if n.type in ("identifier", "constant"):
            out.append(_text(n))
        for c in n.children:
            rec(c)
    rec(node)
    return out


def _method_name(call) -> str:
    m = call.child_by_field_name("method")
    if m is not None:
        return _text(m)
    recv = call.child_by_field_name("receiver")
    for c in call.children:
        if c.type in ("identifier", "constant") and c is not recv:
            return _text(c)
    return ""


def _receiver_idents(call) -> list:
    return _idents(call.child_by_field_name("receiver"))


def _is_sanitizer_call(node) -> bool:
    return node is not None and node.type == "call" and _method_name(node).lower() in _SANITIZER


def _is_llm_output_call(call) -> bool:
    meth = _method_name(call).lower()
    if meth not in _LLM_METHODS:
        return False
    recv = _receiver_idents(call)
    return any(_LLM_RECEIVER.search(p) for p in recv)


def _refs(node, tainted: set) -> bool:
    if node is None:
        return False
    for n in _walk(node):
        if n.type == "identifier" and _text(n) in tainted:
            return True
    return False


def _expr_is_output(node, tainted: set) -> bool:
    if _is_sanitizer_call(node):
        return False
    for n in _walk(node):
        if n.type == "call" and _is_llm_output_call(n):
            return True
        if n.type == "identifier" and _text(n) in tainted:
            return True
    return False


_SCOPE_TYPES = ("method", "singleton_method", "do_block", "block", "lambda")


def _scopes(root):
    scopes = [n for n in _walk(root) if n.type in _SCOPE_TYPES]
    return scopes or [root]


def _taint_in_scope(scope):
    decls = []
    for n in _walk(scope):
        if n.type == "assignment":
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is not None and left.type == "identifier":
                decls.append((_text(left), right))
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
            if n.type != "call":
                continue
            args = n.child_by_field_name("arguments")
            if not _refs(args, tainted):
                continue
            meth = _method_name(n).lower()
            recv = [p.lower() for p in _receiver_idents(n)]
            if meth in _SHELL_BARE and not recv:
                add(_line(n), "shell/command execution")
            elif meth in _SHELL_RECV:
                add(_line(n), "shell/command execution")
            elif meth in _SQL_METHODS and (not recv or any(r not in ("params",) for r in recv)):
                add(_line(n), "raw SQL execution")
            elif meth in _EVAL_METHODS:
                add(_line(n), "code execution (eval)")
            elif meth in _HTML_METHODS:
                add(_line(n), "HTML injection (raw/html_safe)")
    return out
