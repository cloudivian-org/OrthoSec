"""Secrets detector precision — false-positive classes found by the real-world audit.

A placeholder key (repeated/sequential chars), a value that is an env/config reference,
a key inside a test (by path or an inline `#[test]`/`func Test`/spec marker), and common
placeholder words must NOT be flagged. A genuine high-entropy key in application code MUST.
"""
import unittest
from pathlib import Path

from orthosec.detectors.secrets import SecretsDetector


class _Ctx:
    def __init__(self, name, src):
        self.name, self.src, self.shard = name, src, None

    def iter_files(self):
        return [Path(self.name)]

    def read(self, _p):
        return self.src

    def rel(self, _p):
        return self.name


def _n(name, src):
    return len(list(SecretsDetector().scan(_Ctx(name, src))))


class TestSecretsPrecision(unittest.TestCase):
    def test_repeated_char_placeholder_not_flagged(self):
        self.assertEqual(_n("app/main.rs",
            'let k = "sk-proj-aaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbb";'), 0)

    def test_sequential_placeholder_not_flagged(self):
        self.assertEqual(_n("app/main.rs", 'let k = "sk-proj-abcdef123456ABCDEFGHIJKL";'), 0)

    def test_env_reference_not_flagged(self):
        self.assertEqual(_n("config.toml", 'openai_api_key = "env(OPENAI_API_KEY)"'), 0)
        self.assertEqual(_n("config.yml", 'api_key: "${OPENAI_API_KEY}"'), 0)

    def test_placeholder_words_not_flagged(self):
        self.assertEqual(_n("a.rb", 'token = "invalid-token"'), 0)
        self.assertEqual(_n("a.rs", 'access_token: "expired-access".into()'), 0)
        self.assertEqual(_n("a.rs", '"apiKey": "sk-session-should-not-own",'), 0)

    def test_inline_test_marker_downgrades_not_critical(self):
        # A real-looking key inside an inline #[test] is a fixture — still reported, but LOW.
        src = ('#[test]\nfn t() {\n'
               '    let api_key = "RKm4diizuJflPLZT-ugFzuTTJWfkj-as9EmwJPEq";\n}\n')
        findings = list(SecretsDetector().scan(_Ctx("crates/x/src/redaction.rs", src)))
        self.assertTrue(findings)
        self.assertEqual(findings[0].severity.name, "LOW")

    def test_real_key_in_app_code_flagged(self):
        # High-entropy key, non-test path -> a real leak.
        findings = list(SecretsDetector().scan(_Ctx(
            "src/bot.js", 'const apiKey = "RKm4diizuJflPLZT-ugFzuTTJWfkj-as9EmwJPEq";')))
        self.assertTrue(findings)
        self.assertIn(findings[0].severity.name, ("CRITICAL", "MEDIUM"))


if __name__ == "__main__":
    unittest.main()
