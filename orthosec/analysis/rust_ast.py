"""Optional Rust AST analysis (tree-sitter).

Rust powers performance-critical AI infrastructure — inference engines, agent runtimes,
tool servers (async-openai, rig, ollama-rs, genai, llm-chain). With the optional
`orthosec[rust]` extra (tree-sitter + tree-sitter-rust), `.rs` files are parsed to a real
syntax tree so LLM05 (model output into a dangerous sink) and LLM01 (untrusted input into
a system prompt) key on actual call nodes and dataflow — intra-function, interprocedural,
and cross-module — not line proximity.

Same contract as the other analyzers: every entry point returns None when the grammar is
unavailable or the source won't parse, and the caller falls back to regex.
"""
from __future__ import annotations

import re

# Var names carrying model output even without a recognizable call. `output` excludes
# file/path-ish names (output_path/output_file/…) which are not model output.
_OUTPUT_NAME = re.compile(
    r"(?i)(completion|response|answer|reply|generated|assistant|"
    r"output(?!_?(?:path|file|dir|name|buf|stream|writer|target|location|dest))|"
    r"\bresp\b|choices|content|message)")
# Receiver hint for gated generic verbs (create/generate/chat/…) — mirrors the Python engine.
_LLM_RECEIVER = re.compile(
    r"(?i)(llm|chain|agent|chat|model|client|openai|anthropic|gemini|bedrock|ollama|"
    r"cohere|mistral|\brig\b|genai|completion|assistant)")
# Rust SDK methods that (on an LLM-ish receiver) return model output.
_LLM_GATED = {"create", "generate", "chat", "complete", "completion", "prompt", "send",
              "invoke", "call", "run", "exec_chat", "create_message"}
# Methods that unconditionally return model output (specific enough to not need a receiver).
_LLM_METHODS = {"exec_chat", "chat_completion", "create_message"}
# Calls that neutralize taint (escape / structured-encode).
_SANITIZER = {"escape", "encode", "encode_text", "encode_safe", "encode_unquoted_attribute",
              "quote", "shell_escape", "escape_default"}
# Receiver hint gating generic SQL verbs (query/execute) to a real DB handle.
_DB_RECEIVER = re.compile(r"(?i)(conn|connection|\bpool\b|\bdb\b|\btx\b|transaction|executor|sqlx|diesel)")
_SQL_ALWAYS = {"raw_sql", "sql_query"}
_SQL_GATED = {"query", "query_as", "query_scalar", "execute"}

_CACHE: dict = {}


def available() -> bool:
    """True only if the grammar imports AND actually parses. A grammar wheel whose ABI
    doesn't match the installed tree-sitter core imports fine but parses to garbage —
    verifying a trivial parse here makes that case degrade to the regex fallback instead
    of emitting nonsense findings."""
    if "avail" in _CACHE:
        return _CACHE["avail"]
    ok = False
    try:
        import tree_sitter, tree_sitter_rust  # noqa: F401
        root = _parse("fn __orthosec_probe__() {}")
        ok = root is not None and any(n.type == "function_item" for n in _walk(root))
    except Exception:
        ok = False
    _CACHE["avail"] = ok
    return ok


def _parser():
    if "rust" in _CACHE:
        return _CACHE["rust"]
    try:
        import tree_sitter_rust as tsr
        from tree_sitter import Language, Parser
        lang = Language(tsr.language())
        try:
            parser = Parser(lang)
        except Exception:
            parser = Parser(); parser.set_language(lang)
    except Exception:
        parser = None
    _CACHE["rust"] = parser
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
    """Receiver→method chain for a call's `function` node.
    `client.chat().create` -> [client, chat, create];  `Command::new` -> [Command, new]."""
    parts = []
    while node is not None:
        t = node.type
        if t == "field_expression":
            fld = node.child_by_field_name("field")
            if fld is not None:
                parts.append(_text(fld))
            node = node.child_by_field_name("value")
        elif t == "call_expression":
            node = node.child_by_field_name("function")
        elif t == "generic_function":
            node = node.child_by_field_name("function")
        elif t == "scoped_identifier":
            nm = node.child_by_field_name("name")
            if nm is not None:
                parts.append(_text(nm))
            node = node.child_by_field_name("path")
        elif t in ("identifier", "type_identifier", "field_identifier"):
            parts.append(_text(node))
            node = None
        else:
            node = None
    return list(reversed(parts))


def _callee_chain(call) -> list:
    fn = call.child_by_field_name("function")
    return _chain(fn) if fn is not None else []


def _args(call):
    a = call.child_by_field_name("arguments")
    return [c for c in (a.children if a else []) if c.is_named]


def _first_arg(call):
    a = _args(call)
    return a[0] if a else None


def _is_sanitizer_call(node) -> bool:
    if node is None or node.type != "call_expression":
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
        return any(_LLM_RECEIVER.search(p) for p in chain)
    return False


def _refs(node, tainted: set) -> bool:
    """True if a tainted identifier appears in `node` — but taint that flows through a
    sanitizer call (`shell_escape::escape(x)`, `html_escape::encode(x)`) is neutralized,
    so a sanitized argument at a sink does not fire."""
    if node is None:
        return False
    if node.type == "call_expression" and _is_sanitizer_call(node):
        return False
    if node.type == "identifier" and _text(node) in tainted:
        return True
    return any(_refs(c, tainted) for c in node.children)


def _expr_is_output(node, tainted: set, returns_out=()) -> bool:
    if node is not None and node.type == "call_expression" and _is_sanitizer_call(node):
        return False
    for n in _walk(node):
        if n.type == "call_expression":
            chain = _callee_chain(n)
            if _is_llm_output_call(chain):
                return True
            if len(chain) == 1 and chain[0] in returns_out:   # let x = local_helper_returning_output();
                return True
        if n.type == "identifier" and _text(n) in tainted:
            return True
    return False


def _decls(root):
    """(name, value_node) from `let x = …;` and `x = …;` reassignments (simple binders)."""
    out = []
    for n in _walk(root):
        if n.type == "let_declaration":
            pat, val = n.child_by_field_name("pattern"), n.child_by_field_name("value")
            if pat is not None and pat.type == "identifier" and val is not None:
                out.append((_text(pat), val))
        elif n.type == "assignment_expression":
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is None or right is None:   # fields may be unnamed on some grammars
                kids = [c for c in n.children if c.is_named]
                if len(kids) == 2:
                    left, right = kids
            if left is not None and left.type == "identifier" and right is not None:
                out.append((_text(left), right))
    return out


# ---- taint core (per-function scope) ----------------------------------------

def _scopes(root):
    scopes = [n for n in _walk(root) if n.type in ("function_item", "closure_expression")]
    return scopes or [root]


def _taint_in_scope(scope, returns_out=()):
    seed = {name for name, val in _decls(scope)
            if _OUTPUT_NAME.search(name) and not _is_sanitizer_call(val)}
    return _fixpoint(_decls(scope), seed, returns_out)


def _propagate_from(scope, seed, returns_out=()):
    return _fixpoint(_decls(scope), set(seed), returns_out)


def _fixpoint(decls, tainted, returns_out):
    changed = True
    while changed:
        changed = False
        for name, val in decls:
            if name in tainted:
                continue
            if _expr_is_output(val, tainted, returns_out):
                tainted.add(name)
                changed = True
    return tainted


def _sink_of(chain):
    """Capability string for a sink call's chain, or None. (Receiver/DB gating applied.)"""
    if not chain:
        return None
    last = chain[-1].lower()
    low = [p.lower() for p in chain]
    if last == "new" and "command" in low:
        return "shell/command execution"          # Command::new(<tainted>)
    if last in ("arg", "args") and "command" in low:
        return "shell/command execution"          # Command::new("sh").arg(<tainted>)
    if last in _SQL_ALWAYS:
        return "raw SQL execution"
    if last in _SQL_GATED and any(_DB_RECEIVER.search(p) for p in chain):
        return "raw SQL execution"
    if last == "html":
        return "HTML injection (unescaped)"       # axum/actix Html(<tainted>)
    return None


def _find_sinks(scope, tainted, add):
    for n in _walk(scope):
        if n.type != "call_expression":
            continue
        chain = _callee_chain(n)
        cap = _sink_of(chain)
        if cap is None:
            continue
        # Parameterized queries bind data safely — only the query STRING (first arg) is
        # injectable. Shell/HTML sinks check the whole argument list.
        target = _first_arg(n) if cap == "raw SQL execution" else n.child_by_field_name("arguments")
        if _refs(target, tainted):
            add(_line(n), cap)


# ---- interprocedural (intra-file) -------------------------------------------

def _functions(root):
    funcs = {}
    for n in _walk(root):
        if n.type == "function_item":
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
                pat = pd.child_by_field_name("pattern")
                if pat is not None and pat.type == "identifier":
                    names.append(_text(pat))
    return names


def _has_sink_call(fn):
    for n in _walk(fn):
        if n.type == "call_expression" and _sink_of(_callee_chain(n)):
            return True
    return False


def _block_tail_exprs(fn):
    """A Rust fn returns its block's trailing expression (no `return`, no `;`). Yield it."""
    body = fn.child_by_field_name("body")
    if body is None or body.type != "block":
        return
    stmt_types = {"expression_statement", "let_declaration", "empty_statement", "{", "}"}
    named = [c for c in body.children if c.is_named]
    if named and named[-1].type not in stmt_types:
        yield named[-1]


def _returns_output(fn, returns_out):
    tainted = _taint_in_scope(fn, returns_out)
    for n in _walk(fn):
        if n.type == "return_expression":
            for c in n.children:
                if c.is_named and _expr_is_output(c, tainted, returns_out):
                    return True
    for tail in _block_tail_exprs(fn):
        if _expr_is_output(tail, tainted, returns_out):
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
    """Bare free-function calls `foo(x)` — resolved to local/cross-module functions by name."""
    for n in _walk(scope):
        if n.type != "call_expression":
            continue
        chain = _callee_chain(n)
        if len(chain) != 1:
            continue
        yield n, chain[0], _args(n)


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

# Deliberately tight: only clearly-user-controlled names seed untrusted. Ambiguous
# domain terms common in LLM libraries — `prompt`, `message`, `request`/`req`
# (e.g. an internal `completion_request` struct) — are NOT seeded, or a framework like
# rig floods with false positives on its own request-plumbing.
_UNTRUSTED_NAME = re.compile(
    r"(?i)(\buser\b|user_?input|user_?message|user_?content|user_?query|user_?prompt|"
    r"\binput\b|\bquery\b|\bquestion\b|\bbody\b|payload|\bform\b)")
# Variable-name sink for a system prompt. Only the explicit `system_*` forms — bare
# `instruction`/`preamble` are plumbing names (`let preamble = req.preamble.clone()`); the
# real injection surface for those is the `.preamble()` / `.system()` call sink below.
_SYS_PROMPT_NAME = re.compile(
    r"(?i)(system_?prompt|systemprompt|system_?message|systemmessage|sys_?prompt|"
    r"system_?instruction)")
# rig `.preamble(x)`, a `.system(x)` builder, or `.content(x)` on a *System* message builder.
_INJ_HARDENING = re.compile(
    r"(?i)(untrusted|do not follow|ignore (any|previous|all)|delimited by|<user_input>|"
    r"treat .* as data|never reveal|as data,? not|do not obey|sanitiz|escape)")


def _untrusted_in_scope(scope):
    seed = {p for p in _formal_params(scope) if _UNTRUSTED_NAME.search(p)}
    decls = _decls(scope)
    tainted = set(seed)
    changed = True
    while changed:
        changed = False
        for name, val in decls:
            if name in tainted or val is None:
                continue
            if val.type == "call_expression" and _is_sanitizer_call(val):
                continue
            if _refs(val, tainted):
                tainted.add(name)
                changed = True
    return tainted


def _is_system_prompt_sink(call):
    """A call that sets a system prompt: `.preamble(x)`, `.system(x)`, or `.content(x)` on a
    builder whose receiver chain mentions 'system'. Returns the value node arg, or None."""
    chain = _callee_chain(call)
    if not chain:
        return None
    last = chain[-1].lower()
    if last in ("preamble", "system") or (last == "content" and any("system" in p.lower() for p in chain)):
        return call.child_by_field_name("arguments")
    return None


def injection_findings(src: str):
    """LLM01 — untrusted input reaching a system prompt (a system-prompt-named `let`/assign,
    or a `.preamble()`/`.system()`/system-message `.content()` builder call) with no trust
    boundary. Returns list of (line, capability), or None to fall back to regex."""
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
            if n.type == "let_declaration":
                pat, val = n.child_by_field_name("pattern"), n.child_by_field_name("value")
                if pat is not None and _SYS_PROMPT_NAME.search(_text(pat)) and _refs(val, untrusted):
                    add(_line(n))
            elif n.type == "assignment_expression":
                kids = [c for c in n.children if c.is_named]
                if len(kids) == 2 and _SYS_PROMPT_NAME.search(_text(kids[0])) and _refs(kids[1], untrusted):
                    add(_line(n))
            elif n.type == "call_expression":
                arg = _is_system_prompt_sink(n)
                if arg is not None and _refs(arg, untrusted):
                    add(_line(n))
    return out
