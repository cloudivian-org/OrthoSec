"""Optional Java AST analysis (tree-sitter).

Java runs enterprise AI services — Spring AI, LangChain4j, the Azure OpenAI and AWS
Bedrock Java SDKs. With the optional `orthosec[java]` extra (tree-sitter +
tree-sitter-java), `.java` files are parsed to a real syntax tree so LLM05 (model
output flowing into a dangerous sink) keys on actual call nodes and dataflow.

Same contract as the other `*_ast` modules: entry points return None when the grammar
is unavailable or the source won't parse, and the caller falls back to regex. Analysis
is per method/constructor so same-named locals in different methods don't conflate taint.

Java v1 covers LLM05. LLM10 (output-token cap) is configured on a builder at model
construction in the dominant frameworks, not per call, so it's deferred.
"""
from __future__ import annotations

import re

# Var names carrying model output. `output` excludes file/path-ish names.
_OUTPUT_NAME = re.compile(
    r"(?i)(completion|response|answer|reply|generated|assistant|"
    r"output(?!path|file|dir|name|buf|stream|writer|target|location|dest)|resp|choices|content)")
_LLM_RECEIVER = re.compile(
    r"(?i)(chatmodel|chatclient|llm|model|openai|anthropic|bedrock|azure|vertex|gemini|"
    r"cohere|mistral|aiservice|assistant|chain|agent|completion|langchain|springai)")
# Java SDK methods that unconditionally return model output.
_LLM_METHODS = {"createchatcompletion", "getchatcompletions", "chatcompletions",
                "generatecontent"}
# Generic verbs that return model output only on an LLM-ish receiver.
_LLM_GATED = {"generate", "call", "chat", "complete", "invoke", "predict", "run", "ask"}
# Calls that neutralize taint (escape / encode).
_SANITIZER = {"escapehtml", "escapesql", "escapejava", "htmlescape", "encode",
              "escape", "sanitize", "quote"}
_DB_RECEIVER = re.compile(r"(?i)(stmt|statement|conn|connection|entitymanager|session|jdbc|template)")

_CACHE: dict = {}


def available() -> bool:
    try:
        import tree_sitter, tree_sitter_java  # noqa: F401
        return True
    except Exception:
        return False


def _parser():
    if "java" in _CACHE:
        return _CACHE["java"]
    try:
        import tree_sitter_java as tsj
        from tree_sitter import Language, Parser
        lang = Language(tsj.language())
        try:
            parser = Parser(lang)
        except Exception:
            parser = Parser(); parser.set_language(lang)
    except Exception:
        parser = None
    _CACHE["java"] = parser
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


def _minv_chain(node) -> list:
    """Receiver + method-name segments of a (possibly chained) method_invocation:
    Runtime.getRuntime().exec -> ['Runtime','getRuntime','exec']."""
    parts = []
    cur = node
    while cur is not None and cur.type == "method_invocation":
        nm = cur.child_by_field_name("name")
        if nm is not None:
            parts.append(_text(nm))
        cur = cur.child_by_field_name("object")
    if cur is not None:
        if cur.type == "identifier":
            parts.append(_text(cur))
        elif cur.type == "field_access":
            fld = cur.child_by_field_name("field")
            parts.append(_text(fld) if fld is not None else _text(cur))
    return list(reversed(parts))


def _is_sanitizer_call(node) -> bool:
    if node is None or node.type != "method_invocation":
        return False
    nm = node.child_by_field_name("name")
    return nm is not None and _text(nm).lower() in _SANITIZER


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
        if n.type == "method_invocation":
            chain = _minv_chain(n)
            if _is_llm_output_call(chain):
                return True
            # bare local call `foo(x)` — no object field, name in returns_out
            if len(chain) == 1 and n.child_by_field_name("object") is None \
                    and chain[0] in returns_out:
                return True
        if n.type == "identifier" and _text(n) in tainted:
            return True
    return False


_SCOPE_TYPES = ("method_declaration", "constructor_declaration", "lambda_expression")


def _scopes(root):
    scopes = [n for n in _walk(root) if n.type in _SCOPE_TYPES]
    return scopes or [root]


def _decls(scope):
    """(name, value_node) pairs from variable_declarator and assignment_expression."""
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
        if n.type == "object_creation_expression":
            typ = n.child_by_field_name("type")
            if typ is not None and _text(typ) == "ProcessBuilder" \
                    and _refs(n.child_by_field_name("arguments"), tainted):
                add(_line(n), "shell/command execution")
        elif n.type == "method_invocation":
            chain = _minv_chain(n)
            if not chain or not _refs(n.child_by_field_name("arguments"), tainted):
                continue
            name = chain[-1].lower()
            recv = [p.lower() for p in chain[:-1]]
            if name == "exec" and any(p in ("runtime", "getruntime") for p in recv):
                add(_line(n), "shell/command execution")
            elif name in ("executequery", "executeupdate", "executelargeupdate",
                          "createquery", "createnativequery"):
                add(_line(n), "raw SQL execution")
            elif name == "execute" and any(_DB_RECEIVER.search(p) for p in recv):
                add(_line(n), "raw SQL execution")
            elif name == "eval" and any("script" in p or "engine" in p for p in recv):
                add(_line(n), "script execution (eval)")


# LLM10 (uncapped completion). OpenAI Java: `client.chat().completions().create(params)`;
# Anthropic: `client.messages().create(params)`. The cap is a `.maxTokens(n)` on the request
# builder in the same method, so flag a completion call only when no cap keyword appears
# anywhere in its enclosing method.
_JAVA_COMPLETION = re.compile(r"\.(completions|messages)\(\)\s*\.\s*create\s*\(")
_JAVA_CAP = re.compile(r"(?i)(max_?tokens|max_?output_?tokens|max_?completion_?tokens)")


def unbounded_findings(src: str):
    from orthosec.analysis._unbounded import builder_style
    return builder_style(_parse, _walk, _text, _line, src,
                         {"method_invocation"}, _JAVA_COMPLETION, _JAVA_CAP, _SCOPE_TYPES)


# ---- interprocedural (intra-file) -------------------------------------------

def _functions(root):
    funcs = {}
    for n in _walk(root):
        if n.type in ("method_declaration", "constructor_declaration"):
            nm = n.child_by_field_name("name")
            if nm is not None:
                funcs[_text(nm)] = n
    return funcs


def _formal_params(fn):
    p = fn.child_by_field_name("parameters")
    names = []
    if p is not None:
        for pd in p.children:
            if pd.type == "formal_parameter":
                nm = pd.child_by_field_name("name")
                if nm is not None:
                    names.append(_text(nm))
    return names


def _has_sink_call(fn):
    for n in _walk(fn):
        if n.type == "object_creation_expression":
            typ = n.child_by_field_name("type")
            if typ is not None and _text(typ) == "ProcessBuilder":
                return True
        elif n.type == "method_invocation":
            nm = n.child_by_field_name("name")
            if nm is not None and _text(nm).lower() in (
                    "exec", "executequery", "executeupdate", "executelargeupdate",
                    "createquery", "createnativequery", "execute", "eval"):
                return True
    return False


def _returns_output(fn, returns_out):
    tainted = _taint_in_scope(fn, returns_out)
    for n in _walk(fn):
        if n.type == "return_statement":
            for c in n.children:
                if c.type not in (";", "return") and _expr_is_output(c, tainted, returns_out):
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
    # Yield method NAME for a bare `foo()` (local helper) or a STATIC `Helper.run()` call
    # (receiver is a Capitalized class name). An instance call `obj.run()` is NOT resolved
    # cross-module by name — that would collide with unrelated same-named methods.
    for n in _walk(scope):
        if n.type != "method_invocation":
            continue
        nm = n.child_by_field_name("name")
        if nm is None:
            continue
        obj = n.child_by_field_name("object")
        if obj is not None and not (obj.type == "identifier" and _text(obj)[:1].isupper()):
            continue
        argnode = n.child_by_field_name("arguments")
        args = [a for a in (argnode.children if argnode else []) if a.type not in ("(", ")", ",")]
        yield n, _text(nm), args


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

_UNTRUSTED_NAME = re.compile(
    r"(?i)(\buser|\binput\b|query|question|\bmessage\b|\bprompt\b|\breq\b|request|"
    r"\bbody\b|payload|\bmsg\b|userinput|usermessage)")
# Request-object roots: a var read from one of these carries untrusted input
# (HttpServletRequest / Spring @RequestBody / server exchange / handler ctx).
_REQ_ROOT = {"request", "req", "httpRequest", "exchange", "ctx"}
# HttpServletRequest / exchange read accessors. Precision gate: `request.foo()` only
# carries untrusted input when `foo` is an actual request-read accessor — otherwise a
# framework domain object named `request` (ChatRequest.messages(), EmbeddingRequest.
# getInstructions()) would be misread as HTTP input.
_REQ_READ = {"getparameter", "getparametervalues", "getparametermap", "getheader",
             "getheaders", "getinputstream", "getreader", "getquerystring", "getpart",
             "getparts", "getcookies", "getrequesturi", "getrequesturl", "getpathinfo",
             "getbody", "getquery", "getrequestbody", "getformparams", "getqueryparams"}
# A system prompt is built from untrusted *text*; only string-typed params seed taint,
# so a typed domain object (ChatMessage, ChatRequest, Prompt) named user-ishly is ignored.
_STRING_TYPE = re.compile(r"(?i)(string|charsequence)")
_SYS_PROMPT_NAME = re.compile(
    r"(?i)(systemprompt|system_prompt|systemmessage|system_message|sysprompt|sys_prompt|"
    r"systeminstruction|instruction)")
# Trust-boundary / hardening language that mitigates injection (skip the scope).
_INJ_HARDENING = re.compile(
    r"(?i)(untrusted|do not follow|ignore (any|previous|all)|delimited by|<user_input>|"
    r"treat .* as data|never reveal|as data,? not|do not obey|sanitiz|escapehtml)")


def _refs_request(node) -> bool:
    """True if the value reads untrusted input from a request-like object, i.e. a call
    `request.getParameter(...)` where the receiver root is in `_REQ_ROOT` and the accessor
    is a real request-read (`_REQ_READ`) — not any incidental identifier named `request`."""
    if node is None:
        return False
    for n in _walk(node):
        if n.type != "method_invocation":
            continue
        obj, nm = n.child_by_field_name("object"), n.child_by_field_name("name")
        if obj is not None and obj.type == "identifier" and _text(obj) in _REQ_ROOT \
                and nm is not None and _text(nm).lower() in _REQ_READ:
            return True
    return False


def _string_param_names(fn) -> set:
    """Formal-parameter names whose declared type is String / CharSequence-ish."""
    p = fn.child_by_field_name("parameters")
    out = set()
    if p is not None:
        for pd in p.children:
            if pd.type == "formal_parameter":
                nm, ty = pd.child_by_field_name("name"), pd.child_by_field_name("type")
                if nm is not None and ty is not None and _STRING_TYPE.search(_text(ty)):
                    out.add(_text(nm))
    return out


def _untrusted_in_scope(fnscope):
    """Names carrying untrusted input in a method: user-ish *string* params + vars read
    from a request object, propagated through plain reference (sanitizers clear)."""
    strings = _string_param_names(fnscope)
    seed = {p for p in _formal_params(fnscope) if _UNTRUSTED_NAME.search(p) and p in strings}
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
            if val.type == "method_invocation" and _is_sanitizer_call(val):
                continue
            if _refs(val, tainted):
                tainted.add(name)
                changed = True
    return tainted


def _is_system_message_construction(node):
    """The argument node of a LangChain4j SystemMessage construction, or None:
    SystemMessage.from(x) / SystemMessage.systemMessage(x) / new SystemMessage(x)."""
    if node.type == "method_invocation":
        chain = _minv_chain(node)
        if chain and chain[-1] in ("from", "systemMessage") and "SystemMessage" in chain[:-1]:
            return node.child_by_field_name("arguments")
    elif node.type == "object_creation_expression":
        typ = node.child_by_field_name("type")
        if typ is not None and _text(typ) == "SystemMessage":
            return node.child_by_field_name("arguments")
    return None


def injection_findings(src: str):
    """LLM01 — untrusted input reaching a system prompt (a system-prompt-named assignment
    or a LangChain4j SystemMessage construction) with no trust boundary.
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
        untrusted = _untrusted_in_scope(scope)
        if not untrusted:
            continue
        for n in _walk(scope):
            if n.type == "variable_declarator":
                name, val = n.child_by_field_name("name"), n.child_by_field_name("value")
                if name is not None and _SYS_PROMPT_NAME.search(_text(name)) \
                        and _refs(val, untrusted):
                    add(_line(n))
            elif n.type == "assignment_expression":
                left = n.child_by_field_name("left")
                if left is not None and left.type == "identifier" \
                        and _SYS_PROMPT_NAME.search(_text(left)) \
                        and _refs(n.child_by_field_name("right"), untrusted):
                    add(_line(n))
            elif n.type in ("method_invocation", "object_creation_expression"):
                args = _is_system_message_construction(n)
                if args is not None and _refs(args, untrusted):
                    add(_line(n))
    return out
