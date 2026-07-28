"""Local / self-hosted model backend for intel + remediation (Foundation-Sec-8B etc.):
opt-in via env, presents the Anthropic-Messages surface over an OpenAI-compatible endpoint."""
import os
import types
import unittest

from orthosec.intel import local_backend, narrative, autofix


class _Env:
    def __init__(self, **kw):
        self.kw, self.old = kw, {}

    def __enter__(self):
        for k, v in self.kw.items():
            self.old[k] = os.environ.get(k)
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.old.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def _openai_resp(text):
    return {"choices": [{"message": {"role": "assistant", "content": text}}]}


class TestResolve(unittest.TestCase):
    def test_disabled_without_env(self):
        with _Env(ORTHOSEC_LOCAL_MODEL_URL=None):
            self.assertFalse(local_backend.enabled())
            self.assertEqual(local_backend.resolve(), (None, None))

    def test_enabled_and_default_model(self):
        with _Env(ORTHOSEC_LOCAL_MODEL_URL="http://x/v1/chat/completions", ORTHOSEC_LOCAL_MODEL=None):
            self.assertTrue(local_backend.enabled())
            client, model = local_backend.resolve()
            self.assertIsInstance(client, local_backend.LocalChatClient)
            self.assertEqual(model, "foundation-sec-8b")

    def test_narrative_resolver_prefers_local(self):
        with _Env(ORTHOSEC_LOCAL_MODEL_URL="http://x/v1/chat/completions",
                  ORTHOSEC_LOCAL_MODEL="foundation-sec"):
            client, model = narrative._resolve_client_and_model()
            self.assertIsInstance(client, local_backend.LocalChatClient)
            self.assertEqual(model, "foundation-sec")


class TestAdapter(unittest.TestCase):
    def setUp(self):
        self._orig = local_backend._post

    def tearDown(self):
        local_backend._post = self._orig

    def test_create_builds_openai_payload_and_parses(self):
        seen = {}

        def fake(url, payload, timeout, api_key):
            seen.update(payload=payload, url=url, api_key=api_key)
            return _openai_resp("hello world")

        local_backend._post = fake
        c = local_backend.LocalChatClient("http://x/v1/chat/completions", "foundation-sec", api_key="k")
        # called the way narrative._call does — with Anthropic-only kwargs that must be ignored
        resp = c.messages.create(model="foundation-sec", max_tokens=256, system="SYS",
                                 messages=[{"role": "user", "content": "fix this"}],
                                 thinking={"type": "adaptive"}, output_config={"effort": "high"})
        self.assertEqual(narrative._text_of(resp), "hello world")
        self.assertEqual(seen["payload"]["messages"][0], {"role": "system", "content": "SYS"})
        self.assertEqual(seen["payload"]["messages"][1], {"role": "user", "content": "fix this"})
        self.assertEqual(seen["api_key"], "k")

    def test_parses_ollama_chat_shape(self):
        local_backend._post = lambda *a, **k: {"message": {"content": "ollama-text"}}
        c = local_backend.LocalChatClient("http://x/api/chat", "m")
        self.assertEqual(narrative._text_of(c.messages.create(messages=[])), "ollama-text")

    def test_as_text_flattens_block_list(self):
        self.assertEqual(local_backend._as_text([{"type": "text", "text": "a"}, {"text": "b"}]), "ab")


class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self._orig = local_backend._post

    def tearDown(self):
        local_backend._post = self._orig

    def test_suggest_patch_via_local(self):
        local_backend._post = lambda *a, **k: _openai_resp(
            "```python\nimport torch\ntorch.load(f, weights_only=True)\n```")
        finding = types.SimpleNamespace(
            rule_id="ORTHO-LOAD-001", title="unsafe torch.load",
            severity=types.SimpleNamespace(name="HIGH"), owasp_llm="LLM03",
            location="m.py:2", remediation="use weights_only=True", file="m.py")
        original = "import torch\nmodel = torch.load(f)\ndo_more()\nkeep_going()\n"
        with _Env(ORTHOSEC_LOCAL_MODEL_URL="http://x/v1/chat/completions"):
            fixed = autofix.suggest_patch(finding, original)
        self.assertIsNotNone(fixed)
        self.assertIn("weights_only=True", fixed)

    def test_executive_summary_via_local(self):
        local_backend._post = lambda *a, **k: _openai_resp("Posture is weak; fix the shell sink first.")
        from orthosec.core.scanner import Scanner
        import tempfile
        from pathlib import Path
        d = tempfile.mkdtemp()
        Path(d, "a.py").write_text("import os\ndef h(c):\n    o=c.chat.completions.create(messages=[])\n    os.system(o.choices[0].message.content)\n")
        res = Scanner().scan(Path(d))
        with _Env(ORTHOSEC_LOCAL_MODEL_URL="http://x/v1/chat/completions"):
            out = narrative.executive_summary(res)
        self.assertIn("Posture is weak", out)


if __name__ == "__main__":
    unittest.main()
