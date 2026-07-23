"""Python AST helpers — tool-function discovery + dangerous-sink detection.

Precise where regex is not: it resolves *which* functions the model can invoke
as tools (by decorator, by `func=`/`fn=` reference, or by name in a tool-def
dict) and finds dangerous calls inside them at any line distance.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass

# Decorator names (last segment) that expose a function as a model tool.
_TOOL_DECORATORS = {"tool", "function_tool", "beta_tool", "beta_async_tool", "ai_function"}
# Keys whose value is a callable reference to a tool implementation.
_FUNC_KEYS = {"fn", "func", "function", "handler", "coroutine"}
# Keys whose string value names a tool.
_NAME_KEYS = {"name", "tool", "function"}
# Confirmation / gating call or name fragments inside a tool body.
_CONFIRM = {"confirm", "approval", "approve", "require_approval", "human_in_the_loop",
            "allowlist", "whitelist", "requires_confirmation"}

# (object, method) call chains that hand real-world capability to the model.
_DANGEROUS_METHODS = {
    ("os", "system"): "shell/command execution",
    ("subprocess", "run"): "shell/command execution",
    ("subprocess", "call"): "shell/command execution",
    ("subprocess", "Popen"): "shell/command execution",
    ("subprocess", "check_output"): "shell/command execution",
    ("os", "remove"): "arbitrary file delete",
    ("os", "unlink"): "arbitrary file delete",
    ("shutil", "rmtree"): "arbitrary file delete",
    ("requests", "get"): "arbitrary outbound HTTP",
    ("requests", "post"): "arbitrary outbound HTTP",
    ("requests", "put"): "arbitrary outbound HTTP",
    ("requests", "delete"): "arbitrary outbound HTTP",
}
_DANGEROUS_BUILTINS = {"eval": "code execution", "exec": "code execution"}
_SQL_METHODS = {"execute", "executemany", "executescript", "raw"}


@dataclass
class Sink:
    capability: str
    line: int
    snippet: str


def _seg(node) -> str:
    """Last identifier of a Name/Attribute chain (e.g. subprocess.run -> 'run')."""
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _chain(node) -> tuple[str, str]:
    """(object, method) for an Attribute call like subprocess.run -> ('subprocess','run')."""
    if isinstance(node, ast.Attribute):
        return _seg(node.value), node.attr
    return "", _seg(node)


def find_tool_functions(tree: ast.AST) -> dict[str, ast.FunctionDef]:
    """Map name -> FunctionDef for every function exposed to the model as a tool."""
    funcs: dict[str, ast.FunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs[node.name] = node

    tool_names: set[str] = set()

    # 1. Decorated tool functions.
    for node in funcs.values():
        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            if _seg(target).lower() in _TOOL_DECORATORS or "tool" in _seg(target).lower():
                tool_names.add(node.name)

    # 2. Tool-definition dicts and Tool(...) constructor calls.
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            kv = {}
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    kv[k.value] = v
            strong = (_dict_is_tool(kv))
            if not strong:
                continue
            for key in _FUNC_KEYS:
                v = kv.get(key)
                if isinstance(v, ast.Name):
                    tool_names.add(v.id)
            for key in _NAME_KEYS:
                v = kv.get(key)
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    tool_names.add(v.value)
        elif isinstance(node, ast.Call):
            callee = _seg(node.func)
            if callee.endswith("Tool") or callee.lower().endswith("tool"):
                for kw in node.keywords:
                    if kw.arg in _FUNC_KEYS and isinstance(kw.value, ast.Name):
                        tool_names.add(kw.value.id)
                    if kw.arg == "name" and isinstance(kw.value, ast.Constant) \
                            and isinstance(kw.value.value, str):
                        tool_names.add(kw.value.value)

    return {n: funcs[n] for n in tool_names if n in funcs}


def _dict_is_tool(kv: dict) -> bool:
    """A dict is a tool definition if it carries a strong tool signal."""
    if any(k in kv for k in _FUNC_KEYS):
        return True
    t = kv.get("type")
    if isinstance(t, ast.Constant) and isinstance(t.value, str) and t.value in {"function", "tool"}:
        return True
    return False


def dangerous_sinks(fn: ast.AST, source_lines: list[str]) -> list[Sink]:
    """Dangerous calls anywhere inside a function body."""
    sinks: list[Sink] = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        cap = _classify_call(node)
        if cap:
            line = getattr(node, "lineno", 0)
            snippet = source_lines[line - 1].strip()[:160] if 0 < line <= len(source_lines) else ""
            sinks.append(Sink(cap, line, snippet))
    return sinks


def _classify_call(node: ast.Call) -> str | None:
    # Builtins: eval / exec
    if isinstance(node.func, ast.Name) and node.func.id in _DANGEROUS_BUILTINS:
        return _DANGEROUS_BUILTINS[node.func.id]
    obj, meth = _chain(node.func)
    if (obj, meth) in _DANGEROUS_METHODS:
        return _DANGEROUS_METHODS[(obj, meth)]
    # SQL execution on a cursor/connection-like object (gated to avoid block.execute etc.)
    if meth in _SQL_METHODS and _is_sql_sink(node, meth):
        return "raw SQL execution"
    # shell=True on any call
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return "shell/command execution"
    # open(path, "w"/"a") → arbitrary file write
    if isinstance(node.func, ast.Name) and node.func.id == "open" and len(node.args) >= 2:
        mode = node.args[1]
        if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and \
                any(c in mode.value for c in ("w", "a")):
            return "arbitrary file write"
    return None


def has_confirmation(fn: ast.AST) -> bool:
    """True if the function body contains a confirmation / approval gate."""
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            name = _seg(node.func).lower()
            if any(c in name for c in _CONFIRM):
                return True
        if isinstance(node, ast.Name) and any(c in node.id.lower() for c in _CONFIRM):
            return True
    return False


def safe_parse(source: str):
    """Parse Python source; return the tree or None on syntax error."""
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError):
        return None


# --- LLM05 taint analysis: model output -> dangerous sink -------------------

# Variable/param names that carry model output (seed taint even without a call).
_OUTPUT_NAME = re.compile(
    r"(?i)(\bllm|model|completion|response|\banswer|reply|generated|assistant|"
    r"\boutput|\bresp\b|choices)")
# Calls that produce model output.
_LLM_CALL_METHODS = {"create", "generate", "complete", "acreate", "chat",
                     "invoke", "ainvoke", "predict", "apredict"}
# Calls that neutralize taint (validate / escape / parse to structured data).
_SANITIZERS = {"loads", "load", "escape", "clean", "sanitize", "validate",
               "parse", "model_validate", "quote", "quote_plus"}
# Dangerous sinks for model output (a subset of tool sinks — the injection-relevant ones).
_TAINT_SINK_BUILTINS = {"eval": "code execution (eval/exec)", "exec": "code execution (eval/exec)"}
_TAINT_SINK_METHODS = {
    ("os", "system"): "shell execution",
    ("subprocess", "run"): "shell execution",
    ("subprocess", "call"): "shell execution",
    ("subprocess", "Popen"): "shell execution",
    ("subprocess", "check_output"): "shell execution",
}
_SQL_SINKS = {"execute", "executemany", "executescript", "raw"}
_TEMPLATE_SINKS = {"render_template_string", "Template"}
# `.execute()` is common on non-DB objects (blocks, futures, playwright). Only treat
# a bare execute()/executemany() as SQL when the receiver looks database-ish.
_DB_RECEIVER = re.compile(r"(?i)(cursor|conn|connection|\bdb\b|database|session|\bcur\b|sql|engine)")


def _is_sql_sink(call: ast.Call, meth: str) -> bool:
    if meth in ("executescript", "raw"):
        return True
    if meth in ("execute", "executemany"):
        recv = _seg(call.func.value) if isinstance(call.func, ast.Attribute) else ""
        return bool(_DB_RECEIVER.search(recv))
    return False


def _is_llm_call(call: ast.Call) -> bool:
    _, meth = _chain(call.func)
    if isinstance(call.func, ast.Name) and call.func.id in _LLM_CALL_METHODS:
        return True
    return meth in _LLM_CALL_METHODS


def _refs_taint(expr: ast.AST, tainted: set[str]) -> bool:
    for node in ast.walk(expr):
        if isinstance(node, ast.Name) and node.id in tainted:
            return True
    return False


def _expr_tainted(expr: ast.AST, tainted: set[str]) -> bool:
    # A top-level sanitizer call cleans the value.
    if isinstance(expr, ast.Call):
        _, meth = _chain(expr.func)
        if meth in _SANITIZERS:
            return False
        if _is_llm_call(expr):
            return True
    for node in ast.walk(expr):
        if isinstance(node, ast.Call) and _is_llm_call(node):
            return True
        if isinstance(node, ast.Name) and node.id in tainted:
            return True
    return False


def _assigned_names(target: ast.AST) -> list[str]:
    out = []
    for node in ast.walk(target):
        if isinstance(node, ast.Name):
            out.append(node.id)
    return out


def _seed_output(scope: ast.AST) -> set[str]:
    """Names seeded as model output by naming convention (params + stores)."""
    seed: set[str] = set()
    for node in ast.walk(scope):
        if isinstance(node, ast.arg) and _OUTPUT_NAME.search(node.arg):
            seed.add(node.arg)
        if isinstance(node, ast.Name) and isinstance(getattr(node, "ctx", None), ast.Store) \
                and _OUTPUT_NAME.search(node.id):
            seed.add(node.id)
    return seed


def _propagate_with(scope: ast.AST, seed: set[str], is_source) -> set[str]:
    """Propagate a taint seed through assignments to a fixpoint, using `is_source`
    (a `(expr, tainted) -> bool` predicate) to decide when a value carries taint."""
    tainted = set(seed)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(scope):
            if isinstance(node, ast.Assign) and is_source(node.value, tainted):
                for t in node.targets:
                    for nm in _assigned_names(t):
                        if nm not in tainted:
                            tainted.add(nm)
                            changed = True
    return tainted


def _propagate(scope: ast.AST, seed: set[str]) -> set[str]:
    """Propagate model-output taint (sanitizers clear it)."""
    return _propagate_with(scope, seed, _expr_tainted)


def _sinks_with_taint(scope: ast.AST, tainted: set[str], source_lines: list[str],
                      label: str = "") -> list[Sink]:
    sinks: list[Sink] = []
    for node in ast.walk(scope):
        if not isinstance(node, ast.Call):
            continue
        cap = _taint_sink_capability(node)
        if not cap:
            continue
        args = list(node.args) + [kw.value for kw in node.keywords]
        if any(_refs_taint(a, tainted) for a in args):
            line = getattr(node, "lineno", 0)
            snippet = source_lines[line - 1].strip()[:160] if 0 < line <= len(source_lines) else ""
            sinks.append(Sink(cap + label, line, snippet))
    return sinks


def tainted_vars(scope: ast.AST) -> set[str]:
    """Names carrying model output within a scope (name-seeded + call-seeded, fixpoint)."""
    return _propagate(scope, _seed_output(scope))


def _taint_sink_capability(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        if call.func.id in _TAINT_SINK_BUILTINS:
            return _TAINT_SINK_BUILTINS[call.func.id]
        if call.func.id in _TEMPLATE_SINKS:
            return "template/HTML injection"
    obj, meth = _chain(call.func)
    if (obj, meth) in _TAINT_SINK_METHODS:
        return _TAINT_SINK_METHODS[(obj, meth)]
    if meth in _SQL_SINKS and _is_sql_sink(call, meth):
        return "raw SQL execution"
    if meth in _TEMPLATE_SINKS:
        return "template/HTML injection"
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return "shell execution"
    return None


def output_taint_sinks(scope: ast.AST, source_lines: list[str]) -> list[Sink]:
    """Dangerous sinks (in this scope) whose argument carries tainted model output."""
    tainted = tainted_vars(scope)
    return _sinks_with_taint(scope, tainted, source_lines) if tainted else []


def _function_defs(tree: ast.AST) -> dict[str, ast.AST]:
    return {n.name: n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _callees(fn: ast.AST, funcnames: set[str]) -> set[str]:
    out = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            n = _seg(node.func)
            if n in funcnames:
                out.add(n)
    return out


def reachable_tool_sinks(tree: ast.AST, source_lines: list[str]):
    """For each model-invokable tool, the dangerous sinks reachable from it —
    directly or through local helper functions it calls (transitive, fixpoint).

    Returns a list of (Sink, mitigated, tool_name). Capability-reachability, not
    taint: an over-privileged tool is a problem regardless of the argument value.
    """
    funcs = _function_defs(tree)
    names = set(funcs)
    reach = {name: {(s.line, s.capability): s for s in dangerous_sinks(fn, source_lines)}
             for name, fn in funcs.items()}
    callees = {name: _callees(fn, names) for name, fn in funcs.items()}
    changed = True
    while changed:
        changed = False
        for name in funcs:
            for c in callees[name]:
                for k, s in reach[c].items():
                    if k not in reach[name]:
                        reach[name][k] = s
                        changed = True

    tool_fns = find_tool_functions(tree)
    results = []
    seen = set()
    for name, fn in tool_fns.items():
        mitigated = has_confirmation(fn)
        for k, s in reach.get(name, {}).items():
            if k in seen:
                continue
            seen.add(k)
            results.append((s, mitigated, name))
    return results


def _has_taint_sink(fn: ast.AST) -> bool:
    """Cheap single-walk check: does the function contain any dangerous sink call?"""
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and _taint_sink_capability(node):
            return True
    return False


def _dangerous_params(fn: ast.AST, source_lines: list[str]) -> tuple[set[str], list[str]]:
    """Params of `fn` that, if tainted, reach a dangerous sink inside `fn`."""
    params = [a.arg for a in fn.args.args] + [a.arg for a in getattr(fn.args, "kwonlyargs", [])]
    if not params or not _has_taint_sink(fn):     # fast path: most functions have no sink
        return set(), params
    dangerous = set()
    for p in params:
        if _sinks_with_taint(fn, _propagate(fn, {p}), source_lines):
            dangerous.add(p)
    return dangerous, params


def interprocedural_output_sinks(tree: ast.AST, source_lines: list[str]) -> list[Sink]:
    """Model output passed as an argument to a helper function that sinks that
    parameter — an intra-file interprocedural dataflow the single-scope pass misses."""
    funcs = _function_defs(tree)
    summaries = {}
    for name, fn in funcs.items():
        dangerous, params = _dangerous_params(fn, source_lines)
        if dangerous:
            summaries[name] = (dangerous, params)
    if not summaries:
        return []

    scopes = [n for n in ast.walk(tree)
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))] or [tree]
    out: list[Sink] = []
    seen: set[int] = set()
    for scope in scopes:
        tainted = tainted_vars(scope)
        if not tainted:
            continue
        for node in ast.walk(scope):
            if not isinstance(node, ast.Call):
                continue
            fname = _seg(node.func)
            if fname not in summaries:
                continue
            dangerous, params = summaries[fname]
            hit = False
            for i, arg in enumerate(node.args):
                if i < len(params) and params[i] in dangerous and _refs_taint(arg, tainted):
                    hit = True
            for kw in node.keywords:
                if kw.arg in dangerous and _refs_taint(kw.value, tainted):
                    hit = True
            if hit and node.lineno not in seen:
                line = node.lineno
                snippet = source_lines[line - 1].strip()[:160] if 0 < line <= len(source_lines) else ""
                out.append(Sink(f"a helper that passes it to a dangerous sink (via {fname}())",
                                line, snippet))
                seen.add(line)
    return out


# --- LLM01 taint analysis: untrusted input -> system prompt -----------------

# Param/var names that carry untrusted user-controlled input.
_USER_NAME = re.compile(
    r"(?i)(\buser|\binput\b|query|question|\bmessage\b|request|\bprompt\b|\bmsg\b|"
    r"payload|\bbody\b|user_input|user_query|user_message|user_content)")
# Targets that name a system prompt.
_SYS_PROMPT_TARGET = re.compile(
    r"(?i)(system_prompt|system_message|system_instruction|sys_prompt|systemprompt|sys_msg)")
# Trust-boundary / hardening language that mitigates injection.
_HARDENING = re.compile(
    r"(?i)(untrusted|do not follow|ignore any instructions|delimited by|<user_input>|"
    r"treat .* as data|never reveal|do not disclose|as data, not|do not obey)")


def _expr_untrusted(expr: ast.AST, untrusted: set[str]) -> bool:
    for node in ast.walk(expr):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "input":
            return True
        if isinstance(node, ast.Name) and (node.id in untrusted or node.id == "request"):
            return True
    return False


def _seed_untrusted(scope: ast.AST) -> set[str]:
    seed: set[str] = set()
    for node in ast.walk(scope):
        if isinstance(node, ast.arg) and _USER_NAME.search(node.arg):
            seed.add(node.arg)
        if isinstance(node, ast.Name) and isinstance(getattr(node, "ctx", None), ast.Store) \
                and _USER_NAME.search(node.id):
            seed.add(node.id)
    return seed


def untrusted_vars(scope: ast.AST) -> set[str]:
    """Names carrying untrusted input within a scope (name + call seeded, fixpoint)."""
    return _propagate_with(scope, _seed_untrusted(scope), _expr_untrusted)


def _has_hardening(scope: ast.AST) -> bool:
    for node in ast.walk(scope):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and _HARDENING.search(node.value):
            return True
    return False


def _dict_role_content(node: ast.Dict):
    role, content = None, None
    for k, v in zip(node.keys, node.values):
        if isinstance(k, ast.Constant) and k.value == "role" and isinstance(v, ast.Constant):
            role = v.value
        if isinstance(k, ast.Constant) and k.value == "content":
            content = v
    return role, content


def _injection_in_scope(scope: ast.AST, untrusted: set[str], source_lines: list[str],
                        seen: set[int]) -> list[Sink]:
    """System-prompt constructions in `scope` embedding the given untrusted names."""
    if not untrusted or _has_hardening(scope):
        return []

    def snip(line):
        return source_lines[line - 1].strip()[:160] if 0 < line <= len(source_lines) else ""

    out: list[Sink] = []
    flagged_vars: set[str] = set()
    _MSG = "untrusted input in system prompt (no trust boundary)"
    for node in ast.walk(scope):
        if isinstance(node, ast.Assign):
            names = [nm for t in node.targets for nm in _assigned_names(t)]
            if any(_SYS_PROMPT_TARGET.search(nm) for nm in names) \
                    and _refs_taint(node.value, untrusted):
                if node.lineno not in seen:
                    out.append(Sink(_MSG, node.lineno, snip(node.lineno)))
                    seen.add(node.lineno)
                flagged_vars.update(names)
    for node in ast.walk(scope):
        if isinstance(node, ast.Dict):
            role, content = _dict_role_content(node)
            if role != "system" or content is None:
                continue
            if isinstance(content, ast.Name) and content.id in flagged_vars:
                continue
            if _refs_taint(content, untrusted):
                line = getattr(content, "lineno", node.lineno)
                if line not in seen:
                    out.append(Sink(_MSG, line, snip(line)))
                    seen.add(line)
    return out


def injection_sinks(tree: ast.AST, source_lines: list[str]) -> list[Sink]:
    """System-prompt constructions that embed untrusted input with no trust boundary."""
    scopes = [n for n in ast.walk(tree)
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))] or [tree]
    out: list[Sink] = []
    seen: set[int] = set()
    for scope in scopes:
        out += _injection_in_scope(scope, untrusted_vars(scope), source_lines, seen)
    return out


def _has_prompt_construction(fn: ast.AST) -> bool:
    """Cheap single-walk check: does the function build a system prompt at all?"""
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            if any(_SYS_PROMPT_TARGET.search(nm)
                   for t in node.targets for nm in _assigned_names(t)):
                return True
        elif isinstance(node, ast.Dict):
            role, content = _dict_role_content(node)
            if role == "system" and content is not None:
                return True
    return False


def _prompt_building_params(fn: ast.AST, source_lines: list[str]) -> tuple[set[str], list[str]]:
    """Params of `fn` that, if untrusted, reach a system-prompt construction inside `fn`."""
    params = [a.arg for a in fn.args.args] + [a.arg for a in getattr(fn.args, "kwonlyargs", [])]
    if not params or not _has_prompt_construction(fn):   # fast path
        return set(), params
    dangerous = set()
    for p in params:
        seed = _propagate_with(fn, {p}, _expr_untrusted)
        if _injection_in_scope(fn, seed, source_lines, set()):
            dangerous.add(p)
    return dangerous, params


def interprocedural_injection_sinks(tree: ast.AST, source_lines: list[str]) -> list[Sink]:
    """Untrusted input passed to a helper whose parameter builds a system prompt."""
    funcs = _function_defs(tree)
    summaries = {}
    for name, fn in funcs.items():
        dangerous, params = _prompt_building_params(fn, source_lines)
        if dangerous:
            summaries[name] = (dangerous, params)
    if not summaries:
        return []
    scopes = [n for n in ast.walk(tree)
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))] or [tree]
    out: list[Sink] = []
    seen: set[int] = set()
    for scope in scopes:
        untrusted = untrusted_vars(scope)
        if not untrusted:
            continue
        for node in ast.walk(scope):
            if not isinstance(node, ast.Call):
                continue
            fname = _seg(node.func)
            if fname not in summaries:
                continue
            dangerous, params = summaries[fname]
            hit = any(i < len(params) and params[i] in dangerous and _refs_taint(a, untrusted)
                      for i, a in enumerate(node.args))
            hit = hit or any(kw.arg in dangerous and _refs_taint(kw.value, untrusted)
                             for kw in node.keywords)
            if hit and node.lineno not in seen:
                line = node.lineno
                snippet = source_lines[line - 1].strip()[:160] if 0 < line <= len(source_lines) else ""
                out.append(Sink(f"untrusted input into a system prompt via {fname}()", line, snippet))
                seen.add(line)
    return out
