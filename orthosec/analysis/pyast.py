"""Python AST helpers — tool-function discovery + dangerous-sink detection.

Precise where regex is not: it resolves *which* functions the model can invoke
as tools (by decorator, by `func=`/`fn=` reference, or by name in a tool-def
dict) and finds dangerous calls inside them at any line distance.
"""
from __future__ import annotations

import ast
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
    # SQL execution on a cursor/connection-like object
    if meth in _SQL_METHODS:
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
