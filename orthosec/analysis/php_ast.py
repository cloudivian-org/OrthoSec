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
# NB: `prepare` is deliberately NOT a sink — a prepared statement is the parameterized,
# SAFE API (values are bound via execute(), not interpolated). Flagging it false-positives
# on every PDO/DB helper (real audit: an `db_update()`/`db_insert()` wrapper). Raw,
# string-interpolated execution (query/exec/statement/unprepared/Laravel *raw) stays flagged.
_SQL_METHODS = {"query", "exec", "statement", "unprepared",
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


_PARSE_CACHE: dict = {}


def _parse(src: str):
    from orthosec.analysis._parsecache import cached

    def _do():
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
    return cached(_PARSE_CACHE, src, "", _do)


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


def _expr_is_output(node, tainted: set, returns_out=()) -> bool:
    if _is_sanitizer_call(node):
        return False
    for n in _walk(node):
        if n.type in _CALL_TYPES and _is_llm_output_call(n):
            return True
        # A bare local call `foo($x)` (function_call_expression, plain `name` function)
        # to a helper that returns model output taints the result.
        if n.type == "function_call_expression" and _call_method(n) in returns_out:
            return True
        if n.type == "variable_name" and _var_name(n) in tainted:
            return True
    return False


_SCOPE_TYPES = ("method_declaration", "function_definition", "anonymous_function_creation_expression",
                "arrow_function")


def _scopes(root):
    scopes = [n for n in _walk(root) if n.type in _SCOPE_TYPES]
    return scopes or [root]


def _decls(scope):
    """(name, value_node) pairs from `$x = ...` assignments (variable_name left)."""
    decls = []
    for n in _walk(scope):
        if n.type == "assignment_expression":
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is not None and left.type == "variable_name":
                decls.append((_var_name(left), right))
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


# ---- interprocedural (intra-file) -------------------------------------------

def _functions(root):
    funcs = {}
    for n in _walk(root):
        if n.type in ("function_definition", "method_declaration"):
            nm = n.child_by_field_name("name")
            if nm is not None:
                funcs[_text(nm)] = n
    return funcs


def _formal_params(fn):
    p = fn.child_by_field_name("parameters")
    names = []
    if p is not None:
        for pd in p.children:
            if pd.type in ("simple_parameter", "property_promotion_parameter", "variadic_parameter"):
                for c in pd.children:
                    if c.type == "variable_name":
                        names.append(_var_name(c))
                        break
    return names


def _has_sink_call(fn):
    for n in _walk(fn):
        if n.type == "function_call_expression":
            meth = _call_method(n).lower()
            if meth in _SHELL_FUNCS or meth == "eval":
                return True
        elif n.type in _CALL_TYPES:            # member / scoped / nullsafe
            if _call_method(n).lower() in _SQL_METHODS:
                return True
    return False


def _returns_output(fn, returns_out):
    tainted = _taint_in_scope(fn, returns_out)
    for n in _walk(fn):
        if n.type != "return_statement":
            continue
        expr = None
        for c in n.children:
            if c.type not in ("return", ";"):
                expr = c
                break
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
        if n.type != "function_call_expression":
            continue
        fn = n.child_by_field_name("function")
        if fn is None or fn.type != "name":     # bare local call foo(...), not $fn()/method
            continue
        argnode = n.child_by_field_name("arguments")
        args = [a for a in (argnode.children if argnode else []) if a.type not in ("(", ")", ",")]
        yield n, _call_method(n), args


def unbounded_findings(src: str):
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

# User-ish param names. NB: `request`/`message`/`msg`/`body` are excluded — in the PHP
# LLM SDKs those name typed DTOs (InferenceRequest, Message, ...), not raw user text.
_UNTRUSTED_NAME = re.compile(
    r"(?i)(\buser|\binput\b|query|question|\bprompt\b|payload|userinput|usermessage)")
# PHP request superglobals, and request-accessor methods on a $request/$req object — a
# real read of HTTP input, not merely a variable named `request` (which is often a DTO).
_SUPERGLOBAL = {"_get", "_post", "_request", "_cookie", "_server", "_files"}
_REQ_READ = {"input", "query", "get", "post", "all", "cookie", "header", "headers",
             "json", "getparsedbody", "getqueryparams", "getparam", "query_params"}
_SYS_PROMPT_NAME = re.compile(
    r"(?i)(systemprompt|system_prompt|systemmessage|system_message|sysprompt|sys_prompt|"
    r"systeminstruction|instruction)")
# Trust-boundary / hardening language that mitigates injection (skip the scope).
_INJ_HARDENING = re.compile(
    r"(?i)(untrusted|do not follow|ignore (any|previous|all)|delimited by|<user_input>|"
    r"treat .* as data|never reveal|as data,? not|do not obey|sanitiz|escapehtml)")


def _refs_request(node) -> bool:
    """True if `node` reads HTTP input: a superglobal ($_GET/$_POST/...), or a
    request-accessor call like $request->input(...) / $req->query(...). A bare
    `$request->messages()` (a DTO method) is NOT a request read."""
    if node is None:
        return False
    for n in _walk(node):
        if n.type == "variable_name" and _var_name(n).lower() in _SUPERGLOBAL:
            return True
        if n.type in ("member_call_expression", "nullsafe_member_call_expression"):
            obj = n.child_by_field_name("object")
            if obj is not None and obj.type == "variable_name" \
                    and _var_name(obj).lower() in ("request", "req") \
                    and _call_method(n).lower() in _REQ_READ:
                return True
    return False


def _untrusted_in_scope(fnscope):
    """Names carrying untrusted input: user-ish params + vars read from a request/
    superglobal, propagated through plain reference (sanitizers clear)."""
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


def _str_lit(node):
    """Inner text of a PHP `string` / `encapsed_string` literal (quotes stripped), else None."""
    if node is None or node.type not in ("string", "encapsed_string"):
        return None
    for c in node.children:
        if c.type == "string_content":
            return _text(c)
    return _text(node).strip("'\"")


def _array_elem_kv(elem):
    """(key_node, value_node) for an `array_element_initializer`. key is None when the
    element has no `=>`."""
    key, val, seen_arrow = None, None, False
    parts = [c for c in elem.children if c.type != ","]
    for i, c in enumerate(parts):
        if c.type == "=>":
            seen_arrow = True
            key = parts[i - 1] if i > 0 else None
            val = parts[i + 1] if i + 1 < len(parts) else None
            break
    if not seen_arrow:
        non_tok = [c for c in parts if c.type not in ("=>",)]
        val = non_tok[0] if non_tok else None
    return key, val


def _sys_content_from_array(arr):
    """For an `array_creation_expression`, return the `content` value node iff the array
    also declares `'role' => 'system'` (an openai-php system message). Else None."""
    role_system, content = False, None
    for elem in arr.children:
        if elem.type != "array_element_initializer":
            continue
        key, val = _array_elem_kv(elem)
        kt = _str_lit(key)
        if kt == "role" and _str_lit(val) == "system":
            role_system = True
        elif kt == "content":
            content = val
    return content if role_system else None


def injection_findings(src: str):
    """LLM01 — untrusted input reaching a system prompt (a system-prompt-named `$var`
    assignment or a `['role' => 'system', 'content' => <untrusted>]` message) with no
    trust boundary. Returns list of (line, capability), or None to fall back to regex."""
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
        for n in _walk(scope):
            if n.type == "assignment_expression":
                left = n.child_by_field_name("left")
                if left is not None and left.type == "variable_name" \
                        and _SYS_PROMPT_NAME.search(_var_name(left)) \
                        and _refs(n.child_by_field_name("right"), untrusted):
                    add(_line(n))
            elif n.type == "array_creation_expression":
                content = _sys_content_from_array(n)
                if content is not None and (_refs(content, untrusted) or _refs_request(content)):
                    add(_line(n))
    return out
