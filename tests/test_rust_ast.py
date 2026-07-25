"""Rust AST tests — precise .rs analysis via tree-sitter, skipped when the optional
`orthosec[rust]` grammar isn't installed."""
import unittest

from orthosec.analysis import rust_ast

_HAS_RUST = rust_ast.available()
_C = "fn f(client: Client){ let out = client.chat().create(req); "  # tainted `out` prelude


@unittest.skipUnless(_HAS_RUST, "tree-sitter-rust not installed (orthosec[rust])")
class TestRustOutput(unittest.TestCase):
    def _caps(self, body):
        return {cap for _, cap in rust_ast.output_findings(_C + body + " }")}

    def test_command_new(self):
        self.assertTrue(any("shell" in c for c in self._caps("std::process::Command::new(out);")))

    def test_command_arg(self):
        self.assertTrue(any("shell" in c for c in self._caps('Command::new("sh").arg("-c").arg(out);')))

    def test_sqlx_raw(self):
        self.assertTrue(any("SQL" in c for c in self._caps("sqlx::query(&out);")))

    def test_conn_execute(self):
        self.assertTrue(any("SQL" in c for c in self._caps("conn.execute(&out);")))

    def test_html_xss(self):
        self.assertTrue(any("HTML" in c for c in self._caps("Html(out)")))

    def test_parameterized_query_not_flagged(self):
        self.assertEqual(self._caps('sqlx::query("SELECT $1").bind(&out);'), set())

    def test_inline_sanitizer_not_flagged(self):
        self.assertEqual(self._caps("Command::new(shell_escape::escape(out));"), set())

    def test_non_llm_value_not_flagged(self):
        src = "fn f(){ let out = read_config(); Command::new(out); }"
        self.assertEqual(rust_ast.output_findings(src), [])


@unittest.skipUnless(_HAS_RUST, "tree-sitter-rust not installed (orthosec[rust])")
class TestRustInterprocedural(unittest.TestCase):
    def test_output_into_helper_param_sink(self):
        src = ("fn sink(x: String){ Command::new(x); }\n"
               "fn run(client: Client){ let out = client.chat().create(req); sink(out); }\n")
        hits = rust_ast.output_findings(src)
        self.assertTrue(hits and any("helper" in c for _, c in hits))

    def test_helper_return_value_tainted(self):
        src = ("fn gen(client: Client) -> String { client.chat().create(req) }\n"
               "fn run(client: Client){ let out = gen(client); Command::new(out); }\n")
        hits = rust_ast.output_findings(src)
        self.assertTrue(hits and any("shell" in c for _, c in hits))

    def test_untainted_arg_to_same_helper_not_flagged(self):
        src = ("fn sink(x: String){ Command::new(x); }\n"
               "fn run(){ let safe = String::from(\"ls\"); sink(safe); }\n")
        self.assertEqual(rust_ast.output_findings(src), [])


@unittest.skipUnless(_HAS_RUST, "tree-sitter-rust not installed (orthosec[rust])")
class TestRustInjection(unittest.TestCase):
    def test_preamble_untrusted(self):
        hits = rust_ast.injection_findings("fn build(user_input: String){ agent.preamble(user_input); }")
        self.assertTrue(hits)

    def test_system_prompt_var(self):
        hits = rust_ast.injection_findings(
            'fn build(query: String){ let system_prompt = format!("You are a bot {}", query); }')
        self.assertTrue(hits)

    def test_user_message_not_flagged(self):
        self.assertEqual(
            rust_ast.injection_findings("fn build(user_input: String){ agent.user_message(user_input); }"),
            [])

    def test_static_preamble_not_flagged(self):
        self.assertEqual(
            rust_ast.injection_findings('fn build(){ agent.preamble("You are a helpful bot."); }'),
            [])


if __name__ == "__main__":
    unittest.main()
