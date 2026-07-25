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


def _expr_is_output(node, tainted: set, returns_out=()) -> bool:
    if _is_sanitizer_call(node):
        return False
    for n in _walk(node):
        if n.type == "call":
            if _is_llm_output_call(n):
                return True
            # bare local method call foo(args) whose helper returns model output
            if not _receiver_idents(n) and _method_name(n) in returns_out:
                return True
        if n.type == "identifier" and _text(n) in tainted:
            return True
    return False


_SCOPE_TYPES = ("method", "singleton_method", "do_block", "block", "lambda")


def _scopes(root):
    scopes = [n for n in _walk(root) if n.type in _SCOPE_TYPES]
    return scopes or [root]


def _decls(scope):
    """(name, value_node) pairs from `name = value` assignments in the scope."""
    decls = []
    for n in _walk(scope):
        if n.type == "assignment":
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
    seed = {name for name, val in decls
            if _OUTPUT_NAME.search(name) and not (val is not None and _is_sanitizer_call(val))}
    return _fixpoint(decls, seed, returns_out)


def _propagate_from(scope, seed, returns_out=()):
    return _fixpoint(_decls(scope), set(seed), returns_out)


def _find_sinks(scope, tainted, add):
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


def unbounded_findings(src: str):
    return None


# ---- interprocedural (intra-file) -------------------------------------------

_SINK_METHODS = _SHELL_BARE | _SHELL_RECV | _SQL_METHODS | _EVAL_METHODS | _HTML_METHODS


def _functions(root):
    funcs = {}
    for n in _walk(root):
        if n.type in ("method", "singleton_method"):
            nm = n.child_by_field_name("name")
            if nm is not None:
                funcs[_text(nm)] = n
    return funcs


def _formal_params(fn):
    p = fn.child_by_field_name("parameters")
    names = []
    if p is None:
        return names
    for pd in p.children:
        if pd.type in ("(", ")", ","):
            continue
        if pd.type == "identifier":
            names.append(_text(pd))
        else:                       # optional/keyword/splat/block params: first identifier is the name
            for c in pd.children:
                if c.type == "identifier":
                    names.append(_text(c))
                    break
    return names


def _has_sink_call(fn):
    for n in _walk(fn):
        if n.type == "call" and _method_name(n).lower() in _SINK_METHODS:
            return True
    return False


def _returns_output(fn, returns_out):
    tainted = _taint_in_scope(fn, returns_out)
    for n in _walk(fn):
        if n.type == "return":
            for c in n.children:
                if c.type == "argument_list":
                    if any(_expr_is_output(e, tainted, returns_out)
                           for e in c.children if e.type not in ("(", ")", ",")):
                        return True
    # Implicit return: Ruby returns the last evaluated expression of the body.
    body = fn.child_by_field_name("body")
    if body is not None:
        last = None
        for c in reversed(body.children):
            if c.type != "comment":
                last = c
                break
        if last is not None and _expr_is_output(last, tainted, returns_out):
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
        if n.type != "call" or _receiver_idents(n):
            continue                                     # only bare local method calls
        argnode = n.child_by_field_name("arguments")
        args = [a for a in (argnode.children if argnode else []) if a.type not in ("(", ")", ",")]
        yield n, _method_name(n), args


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


# ---- LLM01: untrusted input -> system prompt --------------------------------

# NB: bare `message`/`msg` are intentionally NOT here (unlike the TS engine): in the Ruby
# LLM ecosystem `message`/`msg` name the *prompt message struct* the app assembles, not raw
# end-user input, so they explode across ruby-openai/langchainrb provider dialects. End-user
# intent still matches via `user`/`usermessage`/`query`/`prompt`/`request`/`params`.
_UNTRUSTED_NAME = re.compile(
    r"(?i)(\buser|\binput\b|query|question|\bprompt\b|\breq\b|request|"
    r"\bbody\b|payload|userinput|usermessage)")
# Rails / request-object roots: `params[:x]`, `request.body`, `req.params`.
_REQ_ROOT = {"params", "request", "req"}
_SYS_PROMPT_NAME = re.compile(
    r"(?i)(systemprompt|system_prompt|systemmessage|system_message|sysprompt|sys_prompt|"
    r"systeminstruction|instruction)")
# Trust-boundary / hardening language that mitigates injection (skip the method).
_INJ_HARDENING = re.compile(
    r"(?i)(untrusted|do not follow|ignore (any|previous|all)|delimited by|<user_input>|"
    r"treat .* as data|never reveal|as data,? not|do not obey|sanitiz|escape_html)")


def _refs_request(node) -> bool:
    """True if any identifier in the subtree is a request root (Rails `params[:x]` etc.)."""
    if node is None:
        return False
    for n in _walk(node):
        if n.type == "identifier" and _text(n) in _REQ_ROOT:
            return True
    return False


def _untrusted_in_scope(fnscope, request_only=False):
    """Names carrying untrusted input in a method: user-ish params + vars read from a
    request object (`params`/`request`/`req`), propagated through plain reference
    (sanitizer values clear taint).

    `request_only=True` narrows the seed to request-derived taint alone (Rails
    `params[:x]` etc.) — used for the message-hash sink, which stays conservative so
    provider-dialect helpers that assemble a static system message don't fire."""
    seed = {p for p in _formal_params(fnscope) if p in _REQ_ROOT}
    if not request_only:
        seed |= {p for p in _formal_params(fnscope) if _UNTRUSTED_NAME.search(p)}
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


def _hash_system_content(hashnode):
    """For a Ruby hash literal, return the `content` value node iff it also carries
    `role: "system"` (a ruby-openai message hash). Handles symbol keys (`role:` /
    `:role =>`) and string keys (`"role" =>`)."""
    role_system, content = False, None
    for pair in hashnode.children:
        if pair.type != "pair":
            continue
        key = pair.child_by_field_name("key")
        val = pair.child_by_field_name("value")
        if key is None and pair.children:
            key = pair.children[0]
        if val is None and pair.children:
            val = pair.children[-1]
        kt = _text(key).strip("\"'`:") if key is not None else ""
        if kt == "role":
            if val is not None and _text(val).strip("\"'`:") == "system":
                role_system = True
        elif kt == "content":
            content = val
    return content if role_system else None


def injection_findings(src: str):
    """LLM01 — untrusted input reaching a system prompt (a system-prompt-named assignment
    or a `{ role: "system", content: <untrusted> }` message hash) with no trust boundary.
    Returns list of (line, capability), or None to fall back to regex."""
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
        # The system-prompt-variable sink is the reliable core and keeps name-based
        # (user-ish) taint. The message-hash sink stays conservative: only request-derived
        # taint, so the many provider-dialect helpers that build a `{ role: "system", ... }`
        # from an internal prompt struct don't fire.
        untrusted = _untrusted_in_scope(scope)
        req_untrusted = _untrusted_in_scope(scope, request_only=True)
        for n in _walk(scope):
            if n.type == "assignment":
                left = n.child_by_field_name("left")
                if left is not None and left.type == "identifier" \
                        and _SYS_PROMPT_NAME.search(_text(left)) \
                        and _refs(n.child_by_field_name("right"), untrusted):
                    add(_line(n))
            elif n.type == "hash":
                content = _hash_system_content(n)
                # Fire when content is request-derived: either an inline request read
                # (`params[:x]`, the common Rails-controller case where `params` is an
                # implicit method, not a local) or a var carrying request-derived taint.
                if content is not None \
                        and (_refs_request(content) or _refs(content, req_untrusted)):
                    add(_line(n))
    return out
