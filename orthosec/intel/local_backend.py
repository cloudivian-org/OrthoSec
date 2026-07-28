"""Optional local / self-hosted LLM backend for the intel + remediation layer.

Point `ORTHOSEC_LOCAL_MODEL_URL` at an OpenAI-compatible chat endpoint you run yourself
(Ollama's `/v1`, vLLM, llama.cpp server) to power the executive briefing, `ask`, and
`remediate --auto` with a **local** model — e.g. a security-specialized model like
Foundation-Sec-8B — so your source code never leaves the machine.

It presents the minimal `client.messages.create(...)` surface the intel code already
uses (returning an object with `.content[].text`), so nothing downstream changes. When
this backend is active the intel layer needs **no** `anthropic` dependency — it's
stdlib-only HTTP. It fails loudly (the caller already wraps calls in try/except and
degrades to the deterministic fallback).

Env:
  ORTHOSEC_LOCAL_MODEL_URL   OpenAI-compatible chat endpoint (enables this backend)
  ORTHOSEC_LOCAL_MODEL       model name (default: foundation-sec-8b)
  ORTHOSEC_LOCAL_API_KEY     optional bearer token (Ollama needs none)
  ORTHOSEC_LOCAL_TIMEOUT     per-call seconds (default: 120 — local 8B gen can be slow)
"""
from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass, field


def enabled() -> bool:
    return bool(os.environ.get("ORTHOSEC_LOCAL_MODEL_URL"))


@dataclass
class _Block:
    text: str
    type: str = "text"


@dataclass
class _Resp:
    content: list = field(default_factory=list)


def _post(url: str, payload: dict, timeout: float, api_key: str | None) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (user-configured URL)
        return json.loads(resp.read().decode("utf-8", "replace"))


def _as_text(content) -> str:
    """Flatten a message 'content' into a string (handles Anthropic-style block lists)."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(b.get("text", "") if isinstance(b, dict) else str(b) for b in content)
    return "" if content is None else str(content)


def _content_of(obj) -> str:
    if not isinstance(obj, dict):
        return ""
    choices = obj.get("choices")                       # OpenAI-compatible
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        msg = choices[0].get("message")
        if isinstance(msg, dict):
            return str(msg.get("content", ""))
    if isinstance(obj.get("message"), dict):            # ollama /api/chat
        return str(obj["message"].get("content", ""))
    return ""


class LocalChatClient:
    """Anthropic-Messages-shaped adapter over an OpenAI-compatible chat endpoint."""

    def __init__(self, url: str, model: str, api_key: str | None = None, timeout: float = 120.0):
        self.url, self.model, self.api_key, self.timeout = url, model, api_key, timeout
        self.messages = self                            # so `client.messages.create(...)` works

    def create(self, model: str | None = None, messages=None, max_tokens: int = 4096,
               system: str | None = None, **_ignored):
        # `_ignored` swallows Anthropic-only params (thinking=, output_config=).
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        for m in (messages or []):
            msgs.append({"role": m.get("role", "user"), "content": _as_text(m.get("content"))})
        payload = {"model": model or self.model, "messages": msgs,
                   "max_tokens": max_tokens, "temperature": 0.2, "stream": False}
        obj = _post(self.url, payload, self.timeout, self.api_key)
        return _Resp(content=[_Block(text=_content_of(obj))])


def resolve():
    """Return (LocalChatClient, model) when configured, else (None, None)."""
    url = os.environ.get("ORTHOSEC_LOCAL_MODEL_URL")
    if not url:
        return None, None
    model = os.environ.get("ORTHOSEC_LOCAL_MODEL", "foundation-sec-8b")
    try:
        timeout = float(os.environ.get("ORTHOSEC_LOCAL_TIMEOUT", "120"))
    except ValueError:
        timeout = 120.0
    return LocalChatClient(url, model, os.environ.get("ORTHOSEC_LOCAL_API_KEY"), timeout), model
