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


class TestSecretNamePrecision(unittest.TestCase):
    def test_env_var_name_not_secret(self):
        for val in ('OPENAI_API_KEY', 'openai_api_key', 'MY_SECRET_NAME', 'apiKey'):
            src = f'const x = {{ apiKey: "{val}" }}\n'
            self.assertNotIn("LLM02", _cats(_scan(src, "t.ts")),
                             msg=f"{val!r} should not be flagged as a secret")

    def test_real_generic_secret_flagged(self):
        # A high-entropy value assigned to a secret field is still caught.
        src = 'api_key = "aB3xK9mZ2pQ7rT5w"\n'
        self.assertIn("LLM02", _cats(_scan(src)))


class TestLLM10Severity(unittest.TestCase):
    def test_bare_complete_is_low(self):
        src = "def f(self):\n    return self._llm.complete(prompt)\n"
        sev = [f.severity.name for f in _scan(src) if f.owasp_llm == "LLM10"]
        self.assertTrue(sev and all(s == "LOW" for s in sev))

    def test_explicit_provider_call_is_medium(self):
        src = "def f(client):\n    return client.chat.completions.create(model='x', messages=[])\n"
        sev = [f.severity.name for f in _scan(src) if f.owasp_llm == "LLM10"]
        self.assertIn("MEDIUM", sev)


class TestBundleSkip(unittest.TestCase):
    def test_minified_file_skipped(self):
        import tempfile
        from pathlib import Path
        from orthosec.core.scanner import Scanner
        d = tempfile.mkdtemp()
        Path(d, "app.min.js").write_text('const k = "aB3xK9mZ2pQ7rT5w"; var api_key="aB3xK9mZ2pQ7rT5w";')
        self.assertEqual(Scanner().scan(d).findings, [])


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


class TestParameterizedSqlPrecision(unittest.TestCase):
    """Parameterized queries bind data safely — taint in the params tuple is not
    injectable (found on crewAI kickoff_task_outputs_storage.py)."""

    def test_parameterized_execute_not_flagged(self):
        src = ("def save(cursor, model):\n"
               "    out = model.generate()\n"
               "    cursor.execute('INSERT INTO t (v) VALUES (?)', (out,))\n")
        self.assertNotIn("LLM05", _cats(_scan(src)))

    def test_fstring_execute_flagged(self):
        src = ("def bad(cursor, model):\n"
               "    out = model.generate()\n"
               "    cursor.execute(f'SELECT * FROM t WHERE v = {out}')\n")
        self.assertIn("LLM05", _cats(_scan(src)))


class TestRegexFallbackRolePrecision(unittest.TestCase):
    """When the AST path is unavailable (e.g. a file using newer Python syntax than
    the host interpreter), the regex fallback must still respect message roles:
    untrusted input in a `"role": "user"` message is not injection (found on
    gpt-researcher under Python 3.9)."""

    # A syntax error forces the regex fallback path.
    _BROKEN = "\ndef broken(: pass\n"

    def test_user_message_fstring_not_flagged(self):
        src = ('messages = [\n'
               '    {"role": "system", "content": "You are a bot."},\n'
               '    {"role": "user", "content": f"Query: {user_query}"},\n'
               ']\n') + self._BROKEN
        self.assertNotIn("LLM01", _cats(_scan(src)))

    def test_system_message_fstring_flagged(self):
        src = ('messages = [\n'
               '    {"role": "system", "content": f"You are a bot. {user_query}"},\n'
               ']\n') + self._BROKEN
        self.assertIn("LLM01", _cats(_scan(src)))


class TestOutputNameFilesystemPrecision(unittest.TestCase):
    """A variable named like a file path (`output_wav_path`, `output_dir`) is not
    model output — the name-seed must not treat it as tainted (found on
    openai-cookbook: a hardcoded ffmpeg `subprocess.run` was flagged as LLM shell)."""

    def test_output_path_subprocess_not_flagged(self):
        src = ("import subprocess\n"
               "def encode(output_wav_path):\n"
               "    command = ['ffmpeg', '-i', 'in.pcm', str(output_wav_path)]\n"
               "    subprocess.run(command, check=True)\n")
        self.assertNotIn("LLM05", _cats(_scan(src)))

    def test_bare_output_from_llm_still_flagged(self):
        src = ("import subprocess\n"
               "def h(model):\n"
               "    output = model.generate()\n"
               "    subprocess.run(output, shell=True)\n")
        self.assertIn("LLM05", _cats(_scan(src)))


class TestSelfAttributeTaintPrecision(unittest.TestCase):
    """Assigning tainted data to `self.x` must not taint the object `self` and thus
    poison every `self.*` read (found on crewAI: an i18n system prompt using
    `self.agent.role` was wrongly flagged)."""

    def test_self_attribute_does_not_poison_system_prompt(self):
        src = ("class A:\n"
               "    def run(self, model):\n"
               "        out = model.generate()\n"
               "        self.state.answer = out\n"
               "        role = self.agent.role\n"
               "        system_prompt = I18N.retrieve('k').format(role=role)\n"
               "        return system_prompt\n")
        self.assertNotIn("LLM01", _cats(_scan(src)))

    def test_real_untrusted_into_system_prompt_flagged(self):
        src = ("def h(request):\n"
               "    q = request.json['q']\n"
               "    system_prompt = 'You are a bot. ' + q\n"
               "    return system_prompt\n")
        self.assertIn("LLM01", _cats(_scan(src)))


class TestLLM10TestPathPrecision(unittest.TestCase):
    """An uncapped LLM call in test/example code is not a production denial-of-wallet risk —
    downgraded to INFO (found by the random-sample harness: LLM10 dominated, mostly in tests)."""

    _CALL = "def h(client):\n    return client.chat.completions.create(model='x', messages=[])\n"

    def _sev(self, name):
        findings = _scan(self._CALL, name)
        return next((f.severity.name for f in findings if f.owasp_llm == "LLM10"), None)

    def test_production_llm10_kept(self):
        self.assertEqual(self._sev("service.py"), "MEDIUM")

    def test_test_file_llm10_downgraded(self):
        self.assertEqual(self._sev("test_service.py"), "INFO")   # test_ prefix
        self.assertEqual(self._sev("svc_test.py"), "INFO")       # _test. suffix

    def test_still_a_finding_not_removed(self):
        # downgraded, not dropped — still visible for completeness
        self.assertIn("LLM10", _cats(_scan(self._CALL, "test_x.py")))


if __name__ == "__main__":
    unittest.main()
