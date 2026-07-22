"""Precision regression tests — false-positive fixes found by real-world validation.

Each test pins a false positive that OrthoSec produced on a real public AI repo
(AutoGPT, openai-cookbook, anthropic-quickstarts) and now correctly suppresses,
while a paired true positive still fires.
"""
import tempfile
import unittest
from pathlib import Path

from orthosec.core.scanner import Scanner


def _scan(src: str, name: str = "t.py"):
    d = tempfile.mkdtemp()
    (Path(d) / name).write_text(src)
    return Scanner().scan(Path(d) / name).findings


def _cats(findings):
    return {f.owasp_llm for f in findings}


class TestLLM10Precision(unittest.TestCase):
    def test_mock_assignment_not_flagged(self):
        # `mock.messages.create = fake` is an assignment, not an uncapped call.
        self.assertNotIn("LLM10", _cats(_scan("mock_client.messages.create = fake_create\n")))

    def test_string_literal_not_flagged(self):
        self.assertNotIn("LLM10", _cats(_scan('require_contains(patch, "responses.create")\n')))

    def test_docstring_mention_not_flagged(self):
        self.assertNotIn("LLM10", _cats(_scan('def f():\n    """Calls client.messages.create()."""\n    return 1\n')))

    def test_real_uncapped_call_flagged(self):
        src = "def f(client):\n    return client.chat.completions.create(model='x', messages=[])\n"
        self.assertIn("LLM10", _cats(_scan(src)))

    def test_capped_call_not_flagged(self):
        src = "def f(client):\n    return client.chat.completions.create(model='x', messages=[], max_tokens=50)\n"
        self.assertNotIn("LLM10", _cats(_scan(src)))


class TestSqlSinkPrecision(unittest.TestCase):
    def test_block_execute_not_sql(self):
        # `block.execute(model_output)` is not raw SQL.
        src = ("def h(client, q):\n"
               "    resp = client.messages.create(model='m', max_tokens=9, messages=[])\n"
               "    out = resp.content\n"
               "    node_block.execute(out)\n")
        self.assertNotIn("LLM05", _cats(_scan(src)))

    def test_cursor_execute_is_sql(self):
        src = ("def h(client, q, cursor):\n"
               "    resp = client.messages.create(model='m', max_tokens=9, messages=[])\n"
               "    out = resp.content\n"
               "    cursor.execute(out)\n")
        self.assertIn("LLM05", _cats(_scan(src)))


class TestRagPrecision(unittest.TestCase):
    def test_db_upsert_not_rag(self):
        src = "async def seed():\n    await prisma.profile.upsert(where={}, data={})\n"
        self.assertNotIn("LLM08", _cats(_scan(src)))

    def test_vectorstore_upsert_is_rag(self):
        src = ("import requests\n"
               "def index(embeddings, url):\n"
               "    page = requests.get(url).text\n"
               "    pinecone_index.upsert([(embeddings, page)])\n")
        self.assertIn("LLM08", _cats(_scan(src)))


class TestSecretTestPath(unittest.TestCase):
    def test_secret_in_test_file_is_low(self):
        d = tempfile.mkdtemp()
        (Path(d) / "config_test.py").write_text('KEY = "sk-proj-Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78"\n')
        findings = Scanner().scan(d).findings
        sev = [f.severity.name for f in findings if f.owasp_llm == "LLM02"]
        self.assertTrue(sev and all(s == "LOW" for s in sev))

    def test_secret_in_source_is_critical(self):
        d = tempfile.mkdtemp()
        (Path(d) / "config.py").write_text('KEY = "sk-proj-Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78"\n')
        findings = Scanner().scan(d).findings
        self.assertTrue(any(f.owasp_llm == "LLM02" and f.severity.name == "CRITICAL" for f in findings))


class TestInnerHtmlPrecision(unittest.TestCase):
    def test_innerhtml_read_not_flagged(self):
        src = ("async function t() {\n"
               "  const answer = resp.choices[0].message.content;\n"
               "  expect(container.innerHTML).toBe(answer);\n"
               "}\n")
        self.assertNotIn("LLM05", _cats(_scan(src, "t.test.tsx")))

    def test_innerhtml_write_flagged(self):
        src = ("async function t(client, p) {\n"
               "  const answer = (await client.chat.completions.create({messages:[]})).choices[0].message.content;\n"
               "  document.getElementById('o').innerHTML = answer;\n"
               "}\n")
        self.assertIn("LLM05", _cats(_scan(src, "app.js")))


if __name__ == "__main__":
    unittest.main()
