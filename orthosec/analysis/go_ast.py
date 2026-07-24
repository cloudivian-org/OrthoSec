"""Optional Go AST analysis (tree-sitter).

Go is widely used to build AI-product backends — inference gateways, agent
orchestrators, tool servers. With the optional `orthosec[go]` extra (tree-sitter +
tree-sitter-go), `.go` files are parsed to a real syntax tree so LLM05 (model output
into a dangerous sink) and LLM10 (uncapped completion) key on actual call nodes and
dataflow, not line proximity.

Same contract as `ts_ast` / `js_ast`: every entry point returns None when the grammar
is unavailable or the source won't parse, and the caller falls back to regex. Purely
additive precision — nothing breaks without the extra.
"""
from __future__ import annotations

import re

# Var names that carry model output even without a recognizable call. `output` excludes
# file/path-ish names (outputPath/outputFile/outputDir/...) which are not model output.
_OUTPUT_NAME = re.compile(
    r"(?i)(completion|response|answer|reply|generated|assistant|"
    r"output(?!path|file|dir|name|buf|stream|writer|target|location|dest)|resp|choices|content)")
# Receiver hint for gated generic methods (Generate/Call/Run) — mirrors the Python engine.
_LLM_RECEIVER = re.compile(
    r"(?i)(llm|chain|agent|chat|model|client|openai|anthropic|gemini|bedrock|ollama|"
    r"cohere|mistral|llms|langchain|queryengine|assistant|completion)")
# Go SDK methods that unconditionally return model output.
_LLM_METHODS = {"createchatcompletion", "createcompletion", "createchatcompletionstream",
                "generatecontent", "generatefromsingleprompt", "createmessage"}
# Generic verbs that return model output only on an LLM-ish receiver.
_LLM_GATED = {"generate", "call", "run", "invoke", "complete", "chat", "new"}
# Completion calls whose request struct should carry a max-tokens cap (LLM10 surface).
_COMPLETION_METHODS = {"createchatcompletion", "createcompletion",
                       "createchatcompletionstream", "generatecontent"}
_CAP_KEYS = {"maxtokens", "maxcompletiontokens", "maxoutputtokens"}
# Calls that neutralize taint (escape / structured-encode).
_SANITIZER = {"escapestring", "htmlescapestring", "queryescape", "quote", "marshal", "pathescape"}
_DB_METHODS = {"query", "querycontext", "queryrow", "queryrowcontext", "exec", "execcontext"}

_CACHE: dict = {}


def available() -> bool:
    try:
        import tree_sitter, tree_sitter_go  # noqa: F401
        return True
    except Exception:
        return False


def _parser():
    if "go" in _CACHE:
        return _CACHE["go"]
    try:
        import tree_sitter_go as tsg
        from tree_sitter import Language, Parser
        lang = Language(tsg.language())
        try:
            parser = Parser(lang)
        except Exception:
            parser = Parser(); parser.set_language(lang)
    except Exception:
        parser = None
    _CACHE["go"] = parser
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
    parts = []
    while node is not None and node.type in ("selector_expression", "index_expression"):
        if node.type == "selector_expression":
            fld = node.child_by_field_name("field")
            if fld is not None:
                parts.append(_text(fld))
            node = node.child_by_field_name("operand")
        else:
            node = node.child_by_field_name("operand")
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
        if last == "new":                       # anthropic-sdk-go: client.Messages.New(...)
            return any(p.lower() == "messages" for p in chain) or \
                any(_LLM_RECEIVER.search(p) for p in chain)
        return any(_LLM_RECEIVER.search(p) for p in chain)
    return False


def _refs(node, tainted: set) -> bool:
    if node is None:
        return False
    for n in _walk(node):
        if n.type == "identifier" and _text(n) in tainted:
            return True
    return False


def _expr_is_output(node, tainted: set) -> bool:
    if node is not None and node.type == "call_expression" and _is_sanitizer_call(node):
        return False
    for n in _walk(node):
        if n.type == "call_expression" and _is_llm_output_call(_callee_chain(n)):
            return True
        if n.type == "identifier" and _text(n) in tainted:
            return True
    return False


def _decls(root):
    """(name, value_node) pairs from := and = statements, handling multi-assignment."""
    out = []
    for n in _walk(root):
        if n.type not in ("short_var_declaration", "assignment_statement"):
            continue
        L, R = n.child_by_field_name("left"), n.child_by_field_name("right")
        if L is None or R is None:
            continue
        lefts = [c for c in L.children if c.type == "identifier"]
        rights = [c for c in R.children if c.type != ","]
        if lefts and len(lefts) == len(rights):
            out.extend((_text(l), r) for l, r in zip(lefts, rights))
        else:                                   # e.g. `resp, err := call()` — one call, many targets
            for l in lefts:
                for r in rights:
                    out.append((_text(l), r))
    return out


def _has_cap(call) -> bool:
    for n in _walk(call):
        if n.type == "keyed_element" and n.children:
            key = n.children[0]
            if _text(key).strip().lower() in _CAP_KEYS:
                return True
    return False


def _is_completion(chain: list) -> bool:
    return bool(chain) and chain[-1].lower() in _COMPLETION_METHODS


# ---- public entry points ----------------------------------------------------

def _request_literal(call):
    """The inline request STRUCT (composite_literal of a `*Request` type) in a call's
    args, if any. Only a `...Request{...}` literal is the completion config — a messages
    slice literal or a config passed as a variable is not judged (would misread the cap,
    or the cap may be set via functional options / a builder we can't see)."""
    args = call.child_by_field_name("arguments")
    if args is None:
        return None
    for a in args.children:
        if a.type == "composite_literal":
            typ = a.child_by_field_name("type")
            if typ is not None and _text(typ).endswith("Request"):
                return a
    return None


def unbounded_findings(src: str):
    root = _parse(src)
    if root is None:
        return None
    out = []
    for n in _walk(root):
        if n.type != "call_expression" or not _is_completion(_callee_chain(n)):
            continue
        # Only judge when the request is an inline literal whose fields we can fully see.
        # If the request is passed as a variable (config built elsewhere), a cap may be set
        # in that builder — flagging it would be an interprocedural false positive.
        lit = _request_literal(n)
        if lit is not None and not _has_cap(lit):
            out.append(_line(n))
    return out


def _scopes(root):
    """Analyze per function/method so same-named vars in different functions don't
    conflate taint (mirrors the Python engine's per-scope analysis)."""
    scopes = [n for n in _walk(root)
              if n.type in ("function_declaration", "method_declaration", "func_literal")]
    return scopes or [root]


def _taint_in_scope(scope):
    decls = _decls(scope)
    tainted = {name for name, val in decls
               if _OUTPUT_NAME.search(name) and not _is_sanitizer_call(val)}
    changed = True
    while changed:
        changed = False
        for name, val in decls:
            if name in tainted:
                continue
            if _expr_is_output(val, tainted):
                tainted.add(name)
                changed = True
    return tainted


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
            if n.type != "call_expression":
                continue
            chain = _callee_chain(n)
            argnode = n.child_by_field_name("arguments")
            if not chain or not _refs(argnode, tainted):
                continue
            last = chain[-1].lower()
            if last in ("command", "commandcontext") and any(p.lower() == "exec" for p in chain):
                add(_line(n), "shell/command execution")
            elif last in _DB_METHODS:
                add(_line(n), "raw SQL execution")
            elif last == "html" and any(p.lower() == "template" for p in chain):
                add(_line(n), "HTML injection (template.HTML)")
    return out
