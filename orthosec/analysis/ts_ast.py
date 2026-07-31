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
# Receiver that makes `.exec`/`.spawn` a real shell call (not a regex's .exec()).
_SHELL_RECEIVER = re.compile(r"(?i)(child_?process|^cp$|^cproc$|shelljs|execa)")
# Calls that neutralize taint (escape / sanitize / render-with-escaping). A value
# produced by one of these is safe to place in an HTML sink — e.g. React's
# renderToString auto-escapes, DOMPurify.sanitize strips scripts.
_SANITIZER = {"rendertostring", "rendertostaticmarkup", "sanitize", "purify", "escape",
              "escapehtml", "encodeuri", "encodeuricomponent", "striptags", "dompurify"}
# Custom wrappers are ubiquitous (escapePreviewHtml, sanitizeInput, htmlEscape). A call
# whose name begins with escape/sanitize/htmlescape neutralizes taint for our HTML/SQL
# sinks. Over-matching here costs recall (a benign name that doesn't truly sanitize), never
# a false positive — the right trade under a 0-FP mandate.
_SANITIZER_NAME = re.compile(r"(?i)^(escape|sanitize|htmlescape)")


def _is_sanitizer_call(node) -> bool:
    if node is None or node.type != "call_expression":
        return False
    chain = _callee_chain(node)
    if not chain:
        return False
    name = chain[-1].lower()
    return name in _SANITIZER or bool(_SANITIZER_NAME.match(name))

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


# Parse cache: several detectors (output-handling, prompt-hardening) and the cross-module
# index each analyze the same file, so a file was being parsed ~5x. Caching the tree by
# content collapses that to one parse — ~2x faster on large TS repos, identical results.
# Bounded so a long-running process (watch / SDK) can't grow unboundedly.
_PARSE_CACHE: dict = {}
_PARSE_CACHE_MAX = 8192


def _parse(src: str, tsx: bool = True):
    key = (hash(src), len(src), tsx)          # normalized — hits regardless of call style
    cached = _PARSE_CACHE.get(key, False)
    if cached is not False:
        return cached
    parser = _parser(tsx)
    root = None
    if parser is not None:
        try:
            tree = parser.parse(bytes(src, "utf-8"))
            r = tree.root_node
            if r is not None and not (r.has_error and r.child_count == 0):
                root = r
        except Exception:
            root = None
    if len(_PARSE_CACHE) >= _PARSE_CACHE_MAX:
        _PARSE_CACHE.clear()
    _PARSE_CACHE[key] = root
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

# ---- LLM06: factory-declared agent tools ------------------------------------
# TS/JS agent tools are declared by a factory call — Vercel AI `tool({ execute })`,
# LangChain.js `tool(fn, {...})` / `new DynamicStructuredTool({ func })`. We find the tool's
# executor callback and credit a dangerous sink only inside it (precise scope, any distance),
# instead of a proximity window. Requiring an executor function keeps it precise — a plain
# `tool(x)` with no callback is not treated as a tool.
_TOOL_FACTORY = re.compile(r"^(tool|DynamicStructuredTool|DynamicTool|StructuredTool|FunctionTool)$", re.I)
_EXEC_KEY = {"execute", "func", "function", "handler", "call", "_call", "run"}
_FN_TYPES = ("arrow_function", "function_expression", "function_declaration")
_TS_SINKS = {
    "shell/command execution": re.compile(r"(?i)\b(child_process|exec\(|execSync|spawn\()"),
    "arbitrary file write/delete": re.compile(r"(?i)\b(fs\.writeFile|fs\.unlink|fs\.rm)\b"),
    "arbitrary outbound HTTP": re.compile(r"(?i)\b(fetch\(|axios)\b"),
}
_TS_CONFIRM = re.compile(r"(?i)(confirm|approval|human_in_the_loop|require_approval|allowlist|whitelist)")
_TS_IMPORT = re.compile(r"^\s*(import|export\s+\{|const\s+\{[^}]*\}\s*=\s*require)")


def _callee_name(call) -> str:
    fn = call.child_by_field_name("function") or call.child_by_field_name("constructor")
    return _text(fn).split(".")[-1].strip() if fn is not None else ""


def _find_executor(node):
    """The executor callback of a tool factory call + the tool's name, or (None, None)."""
    args = node.child_by_field_name("arguments")
    if args is None:
        return None, None
    name = "tool"
    for arg in args.children:
        if arg.type in _FN_TYPES:
            return arg, name
        if arg.type == "object":
            execfn = None
            for pair in arg.children:
                if pair.type != "pair":
                    continue
                k, v = pair.child_by_field_name("key"), pair.child_by_field_name("value")
                kn = _text(k).strip("'\"`") if k is not None else ""
                if kn == "name" and v is not None:
                    name = _text(v).strip("'\"`")
                if kn.lower() in _EXEC_KEY and v is not None and v.type in _FN_TYPES:
                    execfn = v
            if execfn is not None:
                return execfn, name
    return None, None


def tool_agency_findings(src: str, tsx: bool = True):
    """LLM06 — dangerous sinks inside a factory-declared tool's executor. Returns
    (line, capability, mitigated, name) list, or None when no tool factory is present
    (so the caller falls back to the regex path for marker/decorator-declared tools)."""
    root = _parse(src, tsx)
    if root is None:
        return None
    out, found = [], False
    for n in _walk(root):
        if n.type not in ("call_expression", "new_expression"):
            continue
        if not _TOOL_FACTORY.match(_callee_name(n)):
            continue
        execfn, name = _find_executor(n)
        if execfn is None:
            continue
        found = True
        body = execfn.child_by_field_name("body")
        scope = _text(body) if body is not None else _text(execfn)
        base = _line(body) if body is not None else _line(execfn)
        mitigated = bool(_TS_CONFIRM.search(scope))
        for i, ln in enumerate(scope.splitlines()):
            if _TS_IMPORT.match(ln):
                continue
            for cap, sink_re in _TS_SINKS.items():
                if sink_re.search(ln):
                    out.append((base + i, cap, mitigated, name))
                    break
    return out if found else None


def _has_inline_request(call) -> bool:
    """True if a call passes an inline object literal — the request whose fields we can
    fully see. When the request is a bare variable (built elsewhere), a cap may be set in
    that builder, so judging it uncapped would be an interprocedural false positive (this
    is the same rule the Go analyzer uses). Real audit: LLM SDK adapters call
    `create(createParams)` with a variable that carries the caller's max_tokens."""
    return any(arg.type == "object" for arg in _args(call))


def unbounded_findings(src: str, tsx: bool = True):
    """Uncapped completion calls. Returns list of line numbers, or None to fall back."""
    root = _parse(src, tsx)
    if root is None:
        return None
    out = []
    for n in _walk(root):
        if (n.type == "call_expression" and _is_completion(_callee_chain(n))
                and _has_inline_request(n) and not _has_cap(n)):
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


_SAFE_INNERHTML_TAG = re.compile(r"""(?i)^['"](textarea|title)['"]$""")


def _is_create_textarea(val) -> bool:
    """A `createElement("textarea"|"title")` call. Setting `.innerHTML` on such an
    element is RCDATA (text-only, script-inert) — the HTML-entity-decode idiom, not XSS."""
    if val is None or val.type != "call_expression":
        return False
    fn = val.child_by_field_name("function")
    if fn is None:
        return False
    name = _prop(fn) if fn.type == "member_expression" else (_text(fn) if fn.type == "identifier" else "")
    if name != "createElement":
        return False
    args = val.child_by_field_name("arguments")
    first = next((a for a in (args.children if args else []) if a.type not in ("(", ")", ",")), None)
    return first is not None and _SAFE_INNERHTML_TAG.search(_text(first).strip()) is not None


def _textarea_vars(scope) -> set:
    """Identifiers bound to a <textarea>/<title> element — their `.innerHTML` is safe."""
    out = set()
    for n in _walk(scope):
        if n.type == "variable_declarator":
            nm, val = n.child_by_field_name("name"), n.child_by_field_name("value")
            if nm is not None and nm.type == "identifier" and _is_create_textarea(val):
                out.add(_text(nm))
        elif n.type == "assignment_expression":
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is not None and left.type == "identifier" and _is_create_textarea(right):
                out.add(_text(left))
    return out


def _innerhtml_safe(left, safe_vars) -> bool:
    """True when `left` is `<textarea-var>.innerHTML` — a script-inert decode target."""
    obj = left.child_by_field_name("object")
    return obj is not None and obj.type == "identifier" and _text(obj) in safe_vars


def _find_sinks(scope, tainted, add):
    safe_vars = _textarea_vars(scope)
    for n in _walk(scope):
        t = n.type
        if t == "assignment_expression":
            left = n.child_by_field_name("left")
            if left is not None and left.type == "member_expression" \
                    and _prop(left) == "innerHTML" and not _innerhtml_safe(left, safe_vars) \
                    and _refs(n.child_by_field_name("right"), tainted):
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
                # Gate to a real child_process call. `/regex/.exec(x)` and `str.exec` are
                # NOT shell — only a bare imported `execSync(x)` or a `cp.exec`/`child_process.exec`
                # receiver counts. This kills a large false-positive class (regex .exec()).
                fn = n.child_by_field_name("function")
                if fn is not None and (
                        fn.type == "identifier"
                        or (fn.type == "member_expression"
                            and (fn.child_by_field_name("object") is not None
                                 and fn.child_by_field_name("object").type == "identifier"
                                 and _SHELL_RECEIVER.search(_text(fn.child_by_field_name("object")))))):
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
    safe_vars = _textarea_vars(fn)
    for n in _walk(fn):
        if n.type == "call_expression":
            last = _callee_chain(n)[-1:]
            if last and last[0] in ("eval", "Function", "exec", "execSync", "spawn",
                                    "spawnSync", "execFile", "execFileSync", "query", "raw", "execute"):
                return True
        if n.type == "assignment_expression":
            left = n.child_by_field_name("left")
            if left is not None and left.type == "member_expression" and _prop(left) == "innerHTML" \
                    and not _innerhtml_safe(left, safe_vars):
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


def output_findings(src: str, tsx: bool = True, project=None):
    """Model output flowing into a dangerous sink, including across local function calls
    (interprocedural) and, when `project` (returns_out, summaries) is supplied, across
    files (cross-module). Returns list of (line, capability), or None to fall back."""
    root = _parse(src, tsx)
    if root is None:
        return None

    p_returns, p_summaries = project if project else (frozenset(), {})
    funcs = _functions(root)
    # Which functions return model output — local, seeded with cross-module (other files).
    returns_out = set(p_returns)
    changed = True
    while changed:
        changed = False
        for name, fn in funcs.items():
            if name not in returns_out and _returns_output(fn, returns_out):
                returns_out.add(name)
                changed = True
    # Which functions sink a parameter — cross-module first, local definitions override.
    summaries = dict(p_summaries)
    for name, fn in funcs.items():
        dp = _dangerous_params(fn, returns_out)
        if dp[1]:
            summaries[name] = dp

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
            fn = n.child_by_field_name("function")
            # Only a bare free-function call `foo(x)` resolves to a local/cross-module
            # function. A method call like `/regex/.exec(x)` or `obj.foo(x)` does NOT —
            # its callee is a member_expression, not a plain identifier.
            if fn is None or fn.type != "identifier":
                continue
            name = _text(fn)
            if name not in summaries:
                continue
            params, dangerous = summaries[name]
            argnode = n.child_by_field_name("arguments")
            actual = [a for a in (argnode.children if argnode else []) if a.type not in ("(", ")", ",")]
            for i, arg in enumerate(actual):
                if i < len(params) and params[i] in dangerous and _refs(arg, tainted):
                    add(_line(n), "a helper that passes it to a dangerous sink (via %s())" % name)
                    break
    return out


def _prop(member) -> str:
    prop = member.child_by_field_name("property")
    return _text(prop) if prop is not None else ""


# ---- LLM01: untrusted input -> system prompt --------------------------------

_UNTRUSTED_NAME = re.compile(
    r"(?i)(\buser|\binput\b|query|question|\bmessage\b|\bprompt\b|\breq\b|request|"
    r"\bbody\b|payload|\bmsg\b|userinput|usermessage)")
_REQ_ROOT = {"req", "request", "ctx", "context", "event", "params"}
_SYS_PROMPT_NAME = re.compile(
    r"(?i)(systemprompt|system_prompt|systemmessage|system_message|sysprompt|sys_prompt|"
    r"systeminstruction|instruction)")
# Trust-boundary / hardening language that mitigates injection (skip the scope).
_INJ_HARDENING = re.compile(
    r"(?i)(untrusted|do not follow|ignore (any|previous|all)|delimited by|<user_input>|"
    r"treat .* as data|never reveal|as data,? not|do not obey|sanitiz|escapehtml)")


def _refs_request(node) -> bool:
    if node is None:
        return False
    for n in _walk(node):
        if n.type == "identifier" and _text(n) in _REQ_ROOT:
            return True
    return False


def _untrusted_in_scope(fnscope):
    """Names carrying untrusted input in a function: user-ish params + vars read from a
    request object, propagated through plain reference (sanitizers clear)."""
    seed = {p for p in _formal_params(fnscope) if _UNTRUSTED_NAME.search(p)}
    decls = []
    for n in _walk(fnscope):
        if n.type == "variable_declarator":
            name, val = n.child_by_field_name("name"), n.child_by_field_name("value")
            if name is not None and name.type == "identifier":
                decls.append((_text(name), val))
                if _refs_request(val):
                    seed.add(_text(name))
        elif n.type == "assignment_expression":
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is not None and left.type == "identifier":
                decls.append((_text(left), right))
                if _refs_request(right):
                    seed.add(_text(left))
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


def _obj_role_system_content(obj):
    """For an object literal, return the `content` value node if it also has role:'system'."""
    role_system, content = False, None
    for pair in obj.children:
        if pair.type != "pair":
            continue
        key, val = pair.child_by_field_name("key"), pair.child_by_field_name("value")
        kt = _text(key).strip('"\'`') if key is not None else ""
        if kt == "role" and val is not None and _text(val).strip('"\'`') == "system":
            role_system = True
        elif kt == "content":
            content = val
    return content if role_system else None


def injection_findings(src: str, tsx: bool = True):
    """LLM01 — untrusted input reaching a system prompt (a system-prompt-named assignment
    or a `{role:'system', content: <untrusted>}` message) with no trust boundary.
    Returns list of (line, capability), or None to fall back to regex."""
    root = _parse(src, tsx)
    if root is None:
        return None

    out, seen = [], set()

    def add(line):
        cap = "untrusted input in system prompt (no trust boundary)"
        if (line, cap) not in seen:
            seen.add((line, cap))
            out.append((line, cap))

    for scope in _ts_scopes(root):
        if _INJ_HARDENING.search(_text(scope)):
            continue
        untrusted = _untrusted_in_scope(scope)
        if not untrusted:
            continue
        for n in _walk(scope):
            if n.type == "variable_declarator":
                name, val = n.child_by_field_name("name"), n.child_by_field_name("value")
                # Require a simple identifier target. A destructuring pattern like
                # `const { system_prompt } = input` EXTRACTS the system prompt from the
                # input — it does not inject untrusted input into a system prompt (real
                # audit: every LLM SDK adapter destructures its input this way).
                if name is not None and name.type == "identifier" \
                        and _SYS_PROMPT_NAME.search(_text(name)) and _refs(val, untrusted):
                    add(_line(n))
            elif n.type == "assignment_expression":
                left = n.child_by_field_name("left")
                if left is not None and left.type == "identifier" \
                        and _SYS_PROMPT_NAME.search(_text(left)) \
                        and _refs(n.child_by_field_name("right"), untrusted):
                    add(_line(n))
            elif n.type == "object":
                content = _obj_role_system_content(n)
                if content is not None and _refs(content, untrusted):
                    add(_line(n))
    return out
