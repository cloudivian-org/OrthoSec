"""Optional TypeScript / JSX AST analysis (tree-sitter).

The core ships regex for TS/TSX. With the optional `orthosec[ts]` extra installed
(`tree-sitter` + `tree-sitter-typescript`), `.ts` / `.tsx` / `.jsx` — and `.js` — are
parsed to a real syntax tree so LLM05 (model output → sink) and LLM10 (uncapped
completion) key on actual call nodes and dataflow, not line proximity. A string or
comment that merely mentions `.innerHTML` or `.create()` no longer fires.

Same contract as `js_ast`: every entry point returns None when the grammar is
unavailable or the source won't parse, and the caller falls back to regex. So this
is purely additive precision — nothing breaks without the extra.
"""
from __future__ import annotations

import re

# `model`/`llm` name the client, not its output (caught call-based) — excluded to avoid FPs.
# `output` excludes file/path-ish names (outputPath/outputFile/...) — not model output.
_OUTPUT_NAME = re.compile(
    r"(?i)(completion|response|answer|reply|generated|assistant|"
    r"output(?!path|file|dir|name|buf|stream|writer|target|location|dest)|resp|choices|content)")
# Receiver hint for gated generic verbs (run/query/call) — mirrors the Python engine.
_LLM_RECEIVER = re.compile(
    r"(?i)(llm|chain|agent|chat|model|openai|anthropic|gemini|bedrock|ollama|groq|"
    r"cohere|mistral|queryengine|conversation|\brag\b|\bqa\b|assistant|completion)")
_DB_RECEIVER = re.compile(r"(?i)(cursor|conn|connection|\bdb\b|database|session|sql|knex|prisma|pool|client)")
# Calls that neutralize taint (escape / sanitize / render-with-escaping). A value
# produced by one of these is safe to place in an HTML sink — e.g. React's
# renderToString auto-escapes, DOMPurify.sanitize strips scripts.
_SANITIZER = {"rendertostring", "rendertostaticmarkup", "sanitize", "purify", "escape",
              "escapehtml", "encodeuri", "encodeuricomponent", "striptags", "dompurify"}


def _is_sanitizer_call(node) -> bool:
    if node is None or node.type != "call_expression":
        return False
    chain = _callee_chain(node)
    return bool(chain) and chain[-1].lower() in _SANITIZER

_CACHE: dict = {}


def available() -> bool:
    try:
        import tree_sitter, tree_sitter_typescript  # noqa: F401
        return True
    except Exception:
        return False


def _parser(tsx: bool):
    key = "tsx" if tsx else "ts"
    if key in _CACHE:
        return _CACHE[key]
    try:
        import tree_sitter_typescript as tsts
        from tree_sitter import Language, Parser
        lang = Language(tsts.language_tsx() if tsx else tsts.language_typescript())
        try:
            parser = Parser(lang)                 # tree-sitter >= 0.22
        except Exception:
            parser = Parser()                     # older API
            parser.set_language(lang)
    except Exception:
        parser = None
    _CACHE[key] = parser
    return parser


def _parse(src: str, tsx: bool):
    parser = _parser(tsx)
    if parser is None:
        return None
    try:
        tree = parser.parse(bytes(src, "utf-8"))
    except Exception:
        return None
    root = tree.root_node
    if root is None or root.has_error and root.child_count == 0:
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
    """Identifier segments of a member/subscript chain, base first:
    model.chat.completions.create -> ['model','chat','completions','create']."""
    parts = []
    while node is not None and node.type in ("member_expression", "subscript_expression"):
        if node.type == "member_expression":
            prop = node.child_by_field_name("property")
            if prop is not None:
                parts.append(_text(prop))
        node = node.child_by_field_name("object")
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


def _is_completion(chain: list) -> bool:
    """A completion-style create() — the LLM10 (uncapped) surface."""
    if not chain:
        return False
    return chain[-1] in ("create", "acreate", "generateContent") and \
        bool(set(chain) & {"completions", "messages", "responses", "chat"} or chain[-1] == "generateContent")


def _is_llm_output_call(chain: list) -> bool:
    """Any call that yields model output (LangChain/LlamaIndex/OpenAI/Anthropic)."""
    if not chain:
        return False
    last = chain[-1]
    if _is_completion(chain):
        return True
    if last in ("generate", "complete", "invoke", "ainvoke", "stream", "createMessage", "chat"):
        return True
    if last in ("run", "query", "call", "predict"):        # generic — gate on receiver
        return any(_LLM_RECEIVER.search(p) for p in chain)
    return False


def _args(call):
    a = call.child_by_field_name("arguments")
    return a.children if a is not None else []


def _has_cap(call) -> bool:
    for arg in _args(call):
        if arg.type == "object":
            for pair in arg.children:
                if pair.type != "pair":
                    continue
                key = pair.child_by_field_name("key")
                name = _text(key).strip('"\'').lower() if key is not None else ""
                if name in ("max_tokens", "maxtokens", "max_output_tokens",
                            "maxoutputtokens", "max_completion_tokens"):
                    return True
    return False


def _refs(node, tainted: set) -> bool:
    if node is None:
        return False
    for n in _walk(node):
        if n.type == "identifier" and _text(n) in tainted:
            return True
    return False


def _expr_is_output(node, tainted: set) -> bool:
    return _expr_is_output_ip(node, tainted, ())


def _expr_is_output_ip(node, tainted: set, returns_out) -> bool:
    # A value produced by a sanitizer is clean, even if it wraps model output.
    if node is not None and node.type == "call_expression" and _is_sanitizer_call(node):
        return False
    for n in _walk(node):
        if n.type == "call_expression":
            chain = _callee_chain(n)
            if _is_llm_output_call(chain):
                return True
            if len(chain) == 1 and chain[0] in returns_out:   # x = localHelperReturningOutput()
                return True
        if n.type == "identifier" and _text(n) in tainted:
            return True
    return False


# ---- public entry points ----------------------------------------------------

def unbounded_findings(src: str, tsx: bool = True):
    """Uncapped completion calls. Returns list of line numbers, or None to fall back."""
    root = _parse(src, tsx)
    if root is None:
        return None
    out = []
    for n in _walk(root):
        if n.type == "call_expression" and _is_completion(_callee_chain(n)) and not _has_cap(n):
            out.append(_line(n))
    return out


_TS_SCOPE_TYPES = ("function_declaration", "method_definition", "arrow_function",
                   "function_expression", "generator_function_declaration")


def _ts_scopes(root):
    """Per function/method so same-named vars in different functions don't conflate taint."""
    scopes = [n for n in _walk(root) if n.type in _TS_SCOPE_TYPES]
    return scopes or [root]


def _taint_in_scope(scope, returns_out=()):
    decls = []   # (name, value_node)
    for n in _walk(scope):
        if n.type == "variable_declarator":
            name, val = n.child_by_field_name("name"), n.child_by_field_name("value")
            if name is not None and name.type == "identifier":
                decls.append((_text(name), val))
        elif n.type == "assignment_expression":
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is not None and left.type == "identifier":
                decls.append((_text(left), right))
    return _fixpoint(decls, {name for name, val in decls
                             if _OUTPUT_NAME.search(name)
                             and not (val is not None and _is_sanitizer_call(val))}, returns_out)


def _propagate_from(scope, seed, returns_out=()):
    """Taint set when `seed` names start tainted (used to test a function's parameters)."""
    decls = []
    for n in _walk(scope):
        if n.type == "variable_declarator":
            name, val = n.child_by_field_name("name"), n.child_by_field_name("value")
            if name is not None and name.type == "identifier":
                decls.append((_text(name), val))
        elif n.type == "assignment_expression":
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is not None and left.type == "identifier":
                decls.append((_text(left), right))
    return _fixpoint(decls, set(seed), returns_out)


def _fixpoint(decls, tainted, returns_out):
    changed = True
    while changed:
        changed = False
        for name, val in decls:
            if name in tainted or val is None:
                continue
            if _expr_is_output_ip(val, tainted, returns_out):
                tainted.add(name)
                changed = True
    return tainted


def _find_sinks(scope, tainted, add):
    for n in _walk(scope):
        t = n.type
        if t == "assignment_expression":
            left = n.child_by_field_name("left")
            if left is not None and left.type == "member_expression" \
                    and _prop(left) == "innerHTML" and _refs(n.child_by_field_name("right"), tainted):
                add(_line(n), "HTML injection (innerHTML)")
        elif t == "jsx_attribute":
            if n.child_count and _text(n.children[0]) == "dangerouslySetInnerHTML" and _refs(n, tainted):
                add(_line(n), "HTML injection (dangerouslySetInnerHTML)")
        elif t == "call_expression":
            chain = _callee_chain(n)
            argnode = n.child_by_field_name("arguments")
            if not chain or not _refs(argnode, tainted):
                continue
            last = chain[-1]
            if last == "eval" or last == "Function":
                add(_line(n), "code execution (eval/Function)")
            elif chain[-2:] == ["document", "write"]:
                add(_line(n), "HTML injection (document.write)")
            elif last in ("exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"):
                add(_line(n), "shell execution")
            elif last in ("query", "raw", "execute") and any(_DB_RECEIVER.search(p) for p in chain):
                add(_line(n), "raw SQL execution")


# ---- interprocedural (intra-file) helpers -----------------------------------

def _formal_params(fn):
    p = fn.child_by_field_name("parameters")
    names = []
    if p is not None:
        for c in p.children:
            if c.type in ("required_parameter", "optional_parameter"):
                pat = c.child_by_field_name("pattern")
                if pat is not None and pat.type == "identifier":
                    names.append(_text(pat))
                else:
                    ids = [d for d in _walk(c) if d.type == "identifier"]
                    if ids:
                        names.append(_text(ids[0]))
    return names


def _functions(root):
    """name -> function node, for plain functions and `const foo = (…) => …` helpers."""
    funcs = {}
    for n in _walk(root):
        if n.type in ("function_declaration", "generator_function_declaration"):
            nm = n.child_by_field_name("name")
            if nm is not None:
                funcs[_text(nm)] = n
        elif n.type == "variable_declarator":
            nm, val = n.child_by_field_name("name"), n.child_by_field_name("value")
            if nm is not None and nm.type == "identifier" and val is not None \
                    and val.type in ("arrow_function", "function_expression"):
                funcs[_text(nm)] = val
    return funcs


def _has_sink_call(fn):
    for n in _walk(fn):
        if n.type == "call_expression":
            last = _callee_chain(n)[-1:]
            if last and last[0] in ("eval", "Function", "exec", "execSync", "spawn",
                                    "spawnSync", "execFile", "execFileSync", "query", "raw", "execute"):
                return True
        if n.type == "assignment_expression":
            left = n.child_by_field_name("left")
            if left is not None and left.type == "member_expression" and _prop(left) == "innerHTML":
                return True
    return False


def _returns_output(fn, returns_out):
    tainted = _taint_in_scope(fn, returns_out)
    for n in _walk(fn):
        if n.type == "return_statement":
            val = next((c for c in n.children if c.type not in ("return", ";")), None)
            if val is not None and _expr_is_output_ip(val, tainted, returns_out):
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


def output_findings(src: str, tsx: bool = True):
    """Model output flowing into a dangerous sink, including across local function calls
    (interprocedural, intra-file). Returns list of (line, capability), or None to fall back."""
    root = _parse(src, tsx)
    if root is None:
        return None

    funcs = _functions(root)
    # Which local functions return model output (fixpoint: a helper returning another
    # output-helper's result counts too).
    returns_out = set()
    changed = True
    while changed:
        changed = False
        for name, fn in funcs.items():
            if name not in returns_out and _returns_output(fn, returns_out):
                returns_out.add(name)
                changed = True
    # Which local functions sink a parameter.
    summaries = {name: _dangerous_params(fn, returns_out) for name, fn in funcs.items()}
    summaries = {k: v for k, v in summaries.items() if v[1]}

    out, seen = [], set()

    def add(line, cap):
        if (line, cap) not in seen:
            seen.add((line, cap))
            out.append((line, cap))

    for scope in _ts_scopes(root):
        tainted = _taint_in_scope(scope, returns_out)
        if tainted:
            _find_sinks(scope, tainted, add)
        # Interprocedural: a tainted argument passed to a helper that sinks that parameter.
        if not summaries:
            continue
        for n in _walk(scope):
            if n.type != "call_expression":
                continue
            chain = _callee_chain(n)
            if len(chain) != 1 or chain[0] not in summaries:
                continue
            params, dangerous = summaries[chain[0]]
            argnode = n.child_by_field_name("arguments")
            actual = [a for a in (argnode.children if argnode else []) if a.type not in ("(", ")", ",")]
            for i, arg in enumerate(actual):
                if i < len(params) and params[i] in dangerous and _refs(arg, tainted):
                    add(_line(n), "a helper that passes it to a dangerous sink (via %s())" % chain[0])
                    break
    return out


def _prop(member) -> str:
    prop = member.child_by_field_name("property")
    return _text(prop) if prop is not None else ""
