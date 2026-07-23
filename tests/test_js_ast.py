"""JavaScript AST tests — precise .js analysis, skipped when esprima isn't installed."""
import tempfile
import unittest
from pathlib import Path

from orthosec.analysis import js_ast
from orthosec.core.scanner import Scanner

_HAS_JS = js_ast.available()


@unittest.skipUnless(_HAS_JS, "esprima not installed (orthosec[js])")
class TestJsAst(unittest.TestCase):
    def test_string_and_comment_not_flagged_as_call(self):
        src = ('function f(client) {\n'
               '  const note = "call client.messages.create() later";  // messages.create()\n'
               '  const bad = client.chat.completions.create({ model: "x", messages: [] });\n'
               '  return bad;\n}\n')
        self.assertEqual(js_ast.unbounded_findings(src), [3])   # only the real call

    def test_capped_call_not_flagged(self):
        src = ('function f(client) {\n'
               '  return client.messages.create({ model: "x", messages: [], max_tokens: 50 });\n}\n')
        self.assertEqual(js_ast.unbounded_findings(src), [])

    def test_output_into_innerhtml(self):
        src = ('function f(client) {\n'
               '  const bad = client.chat.completions.create({ model: "x", messages: [] });\n'
               '  const answer = bad.choices[0].message.content;\n'
               '  el.innerHTML = answer;\n}\n')
        sinks = js_ast.output_findings(src)
        self.assertTrue(any("innerHTML" in cap for _ln, cap in sinks))

    def test_ts_falls_back_without_crash(self):
        d = tempfile.mkdtemp()
        Path(d, "a.ts").write_text("const x: number = 1;\nfunction f(): void {}\n")
        Scanner().scan(d)  # must not raise

    def test_end_to_end_js_scan(self):
        d = tempfile.mkdtemp()
        Path(d, "app.js").write_text(
            'function f(client) {\n'
            '  const bad = client.chat.completions.create({ model: "x", messages: [] });\n'
            '  el.innerHTML = bad.choices[0].message.content;\n}\n')
        cats = {f.owasp_llm for f in Scanner().scan(d).findings}
        self.assertIn("LLM05", cats)
        self.assertIn("LLM10", cats)


if __name__ == "__main__":
    unittest.main()
