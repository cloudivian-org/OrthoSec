"""Ruby AST tests — precise .rb analysis via tree-sitter, skipped without orthosec[ruby]."""
import tempfile, unittest
from pathlib import Path
from orthosec.analysis import ruby_ast
from orthosec.core.scanner import Scanner

_HAS = ruby_ast.available()


@unittest.skipUnless(_HAS, "tree-sitter-ruby not installed (orthosec[ruby])")
class TestRubyAst(unittest.TestCase):
    def test_output_into_shell_sql_eval(self):
        src = ("class A\n  def h(client, conn)\n"
               "    answer = client.chat(p).dig(\"choices\", 0, \"message\", \"content\")\n"
               "    system(\"echo \" + answer)\n"
               "    conn.execute(\"SELECT \" + answer)\n"
               "    eval(answer)\n  end\nend\n")
        caps = {c for _, c in ruby_ast.output_findings(src)}
        assert any("shell" in c for c in caps) and any("SQL" in c for c in caps) and any("eval" in c for c in caps)

    def test_sanitizer_clears(self):
        src = ("class C\n  def h(client, conn)\n"
               "    answer = CGI.escape(client.chat(p).dig(\"content\"))\n"
               "    conn.execute(\"SELECT \" + answer)\n  end\nend\n")
        assert ruby_ast.output_findings(src) == []

    def test_non_llm_sql_not_flagged(self):
        assert ruby_ast.output_findings("class D\n def h(conn); conn.execute(\"SELECT 1\"); end\nend\n") == []

    def test_per_method_scoping(self):
        src = ("class E\n  def a(client); answer = client.chat(p).dig(\"content\"); end\n"
               "  def b(conn, answer); conn.execute(answer); end\nend\n")
        assert ruby_ast.output_findings(src) == []

    def test_interproc_return_value(self):
        # helper RETURNS model output; caller sinks the returned value -> flagged
        src = ("class T\n"
               "  def get_answer(client)\n"
               "    return client.chat(p).dig(\"content\")\n"
               "  end\n"
               "  def run(client, conn)\n"
               "    answer = get_answer(client)\n"
               "    conn.execute(answer)\n"
               "  end\nend\n")
        assert ruby_ast.output_findings(src)  # non-empty

    def test_interproc_param_sink(self):
        # model output passed to a local helper whose PARAM reaches a sink -> flagged at call site
        src = ("class T\n"
               "  def sink(x)\n"
               "    system(x)\n"
               "  end\n"
               "  def run(client)\n"
               "    answer = client.chat(p).dig(\"content\")\n"
               "    sink(answer)\n"
               "  end\nend\n")
        caps = {c for _, c in ruby_ast.output_findings(src)}
        assert any("helper" in c for c in caps)

    def test_interproc_precision_non_output(self):
        # same dangerous helper, but a non-output value is passed -> no finding
        src = ("class T\n"
               "  def sink(x)\n"
               "    system(x)\n"
               "  end\n"
               "  def run\n"
               "    cfg = read_config\n"
               "    sink(cfg)\n"
               "  end\nend\n")
        assert ruby_ast.output_findings(src) == []

    def test_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.rb").write_text(
                "class H\n def h(client)\n  answer = client.chat(p).dig(\"content\")\n  system(answer)\n end\nend\n")
            assert any(f.owasp_llm == "LLM05" for f in Scanner().scan(d).findings)


class TestRubyFallback(unittest.TestCase):
    def test_no_crash_without_grammar(self):
        import orthosec.analysis.ruby_ast as mod
        orig = mod.available; mod.available = lambda: False
        try:
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "a.rb").write_text("def m; system('ls'); end\n")
                assert Scanner().scan(d).errors == []
        finally:
            mod.available = orig
