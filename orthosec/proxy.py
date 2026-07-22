"""OrthoSec runtime gateway — inline AI-security proxy.

Sit between your app and the model provider. Point the app's base URL at OrthoSec
(`OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL`), and every request/response is inspected
for prompt injection and unsafe output at the wire, provider-agnostic. In `block`
mode an injected request is refused before it reaches the provider; in `monitor`
mode it is forwarded and logged. Findings share the same taxonomy as the scanner.

Stdlib only (http.server + urllib). Non-streaming JSON requests are inspected;
streaming or non-JSON bodies are forwarded untouched (and noted). This is a live
tripwire — pair with the static scanner and least-privilege tools.
"""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field

from orthosec.sdk import scan_prompt, scan_output

# Hop-by-hop headers must not be forwarded (per RFC 7230).
_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length"}


@dataclass
class Verdict:
    allow: bool
    prompt_risks: list[str] = field(default_factory=list)
    prompt_text_len: int = 0


def extract_prompt(body: dict) -> str:
    """Pull the user-facing prompt text out of an OpenAI/Anthropic-style request."""
    parts: list[str] = []
    msgs = body.get("messages")
    if isinstance(msgs, list):
        for m in msgs:
            c = m.get("content") if isinstance(m, dict) else None
            if isinstance(c, str):
                parts.append(c)
            elif isinstance(c, list):  # Anthropic content blocks
                for block in c:
                    if isinstance(block, dict) and isinstance(block.get("text"), str):
                        parts.append(block["text"])
    if isinstance(body.get("prompt"), str):  # legacy completions
        parts.append(body["prompt"])
    if isinstance(body.get("input"), str):    # responses API
        parts.append(body["input"])
    return "\n".join(parts)


def extract_output(body: dict) -> str:
    """Pull the assistant text out of an OpenAI/Anthropic-style response."""
    parts: list[str] = []
    # OpenAI chat: choices[].message.content
    for ch in body.get("choices", []) or []:
        msg = ch.get("message", {}) if isinstance(ch, dict) else {}
        if isinstance(msg.get("content"), str):
            parts.append(msg["content"])
        if isinstance(ch.get("text"), str):
            parts.append(ch["text"])
    # Anthropic messages: content[] text blocks
    for block in body.get("content", []) or []:
        if isinstance(block, dict) and isinstance(block.get("text"), str):
            parts.append(block["text"])
    return "\n".join(parts)


def inspect_request(raw: bytes) -> Verdict:
    """Decide whether to allow a request body. Never raises on bad input."""
    try:
        body = json.loads(raw)
    except Exception:
        return Verdict(allow=True)  # non-JSON: forward untouched
    prompt = extract_prompt(body)
    res = scan_prompt(prompt)
    return Verdict(allow=res.ok, prompt_risks=res.risks, prompt_text_len=len(prompt))


def inspect_response(raw: bytes) -> list[str]:
    """Return output risks for a response body (empty if clean / unparseable)."""
    try:
        body = json.loads(raw)
    except Exception:
        return []
    return scan_output(extract_output(body)).risks


def build_handler(upstream: str, mode: str, audit):
    """Create a BaseHTTPRequestHandler class bound to an upstream + mode."""
    from http.server import BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # silence default noisy logging
            pass

        def _relay(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length) if length else b""

            verdict = inspect_request(raw)
            if not verdict.allow:
                audit({"event": "prompt_injection", "path": self.path,
                       "mode": mode, "risks": verdict.prompt_risks})
                if mode == "block":
                    return self._json(403, {
                        "error": {"type": "orthosec_blocked",
                                  "message": "Request blocked by OrthoSec: prompt injection detected.",
                                  "risks": verdict.prompt_risks}})

            # Forward upstream.
            url = upstream.rstrip("/") + self.path
            fwd = {k: v for k, v in self.headers.items() if k.lower() not in _HOP}
            req = urllib.request.Request(url, data=raw or None, headers=fwd, method=self.command)
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    status = resp.status
                    body = resp.read()
                    resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in _HOP}
            except urllib.error.HTTPError as e:
                status, body = e.code, e.read()
                resp_headers = {k: v for k, v in e.headers.items() if k.lower() not in _HOP}
            except Exception as e:
                return self._json(502, {"error": {"type": "orthosec_upstream_error", "message": str(e)}})

            out_risks = inspect_response(body)
            if out_risks:
                audit({"event": "unsafe_output", "path": self.path, "risks": out_risks})

            self.send_response(status)
            for k, v in resp_headers.items():
                self.send_header(k, v)
            self.send_header("X-OrthoSec-Prompt-Risk", "yes" if verdict.prompt_risks else "no")
            self.send_header("X-OrthoSec-Output-Risk", "yes" if out_risks else "no")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_POST = _relay
        do_GET = _relay
        do_PUT = _relay

        def _json(self, status, obj):
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


def run_proxy(upstream: str, host: str = "127.0.0.1", port: int = 8100,
              mode: str = "monitor", audit=None) -> None:
    from http.server import ThreadingHTTPServer

    def _default_audit(rec):
        print("[orthosec] " + json.dumps(rec), flush=True)

    handler = build_handler(upstream, mode, audit or _default_audit)
    server = ThreadingHTTPServer((host, port), handler)
    print(f"OrthoSec gateway on http://{host}:{port} → {upstream}  (mode: {mode})", flush=True)
    print(f"Point your app: OPENAI_BASE_URL=http://{host}:{port}/v1  "
          f"(or ANTHROPIC_BASE_URL=http://{host}:{port})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
