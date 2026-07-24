"""Java AST tests — precise .java analysis via tree-sitter, skipped when the optional
`orthosec[java]` grammar isn't installed."""
import tempfile
import unittest
from pathlib import Path

from orthosec.analysis import java_ast
from orthosec.core.scanner import Scanner

_HAS_JAVA = java_ast.available()


@unittest.skipUnless(_HAS_JAVA, "tree-sitter-java not installed (orthosec[java])")
class TestJavaAst(unittest.TestCase):
    def test_langchain4j_output_into_sinks(self):
        src = ('class A {\n'
               '  void h(ChatModel chatModel, Statement stmt) throws Exception {\n'
               '    String answer = chatModel.generate(userMessage);\n'
               '    Runtime.getRuntime().exec(answer);\n'
               '    stmt.executeQuery("SELECT * FROM t WHERE x=" + answer);\n'
               '    new ProcessBuilder("sh", "-c", answer).start();\n'
               '  }\n}\n')
        caps = {cap for _, cap in java_ast.output_findings(src)}
        assert any("shell" in c for c in caps)
        assert any("SQL" in c for c in caps)

    def test_spring_ai_call_content(self):
        src = ('class B {\n'
               '  void h(ChatClient chatClient, Statement stmt) throws Exception {\n'
               '    String out = chatClient.prompt().user(q).call().content();\n'
               '    stmt.executeQuery("SELECT " + out);\n'
               '  }\n}\n')
        assert java_ast.output_findings(src)  # non-empty

    def test_sanitizer_clears_taint(self):
        src = ('class C {\n'
               '  void h(ChatModel model, Statement stmt) throws Exception {\n'
               '    String answer = StringEscapeUtils.escapeSql(model.generate(q));\n'
               '    stmt.executeQuery("SELECT " + answer);\n'
               '  }\n}\n')
        assert java_ast.output_findings(src) == []

    def test_non_llm_sql_not_flagged(self):
        src = 'class D { void h(Statement stmt) throws Exception { stmt.executeQuery("SELECT 1"); } }\n'
        assert java_ast.output_findings(src) == []

    def test_per_method_scoping_no_cross_taint(self):
        # `answer` tainted in a() must not taint a same-named parameter in b()
        src = ('class E {\n'
               '  void a(ChatModel m){ String answer = m.generate(q); }\n'
               '  void b(Statement stmt, String answer) throws Exception { stmt.executeQuery(answer); }\n'
               '}\n')
        assert java_ast.output_findings(src) == []

    def test_output_path_var_not_model_output(self):
        src = ('class F {\n'
               '  void h(Statement stmt) throws Exception {\n'
               '    String outputPath = dir + "/x.txt";\n'
               '    stmt.executeQuery(outputPath);\n'
               '  }\n}\n')
        assert java_ast.output_findings(src) == []

    def test_detector_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "H.java").write_text(
                'public class H {\n'
                '  public void h(ChatModel chatModel) throws Exception {\n'
                '    String answer = chatModel.generate(q);\n'
                '    Runtime.getRuntime().exec(answer);\n'
                '  }\n}\n')
            findings = Scanner().scan(d).findings
            assert any(f.owasp_llm == "LLM05" for f in findings)

    def test_interproc_return_value_taint(self):
        # helper RETURNS model output; caller assigns it, feeds to a SQL sink
        src = ('class G {\n'
               '  String getAnswer(ChatModel m){ return m.generate(q); }\n'
               '  void h(Statement stmt) throws Exception {\n'
               '    String answer = getAnswer(model);\n'
               '    stmt.executeQuery(answer);\n'
               '  }\n}\n')
        assert java_ast.output_findings(src)  # non-empty

    def test_interproc_param_sink(self):
        # model output passed to a local helper whose param reaches a sink
        src = ('class H {\n'
               '  void sink(String x) throws Exception { Runtime.getRuntime().exec(x); }\n'
               '  void h(ChatModel model) throws Exception {\n'
               '    String answer = model.generate(q);\n'
               '    sink(answer);\n'
               '  }\n}\n')
        caps = {cap for _, cap in java_ast.output_findings(src)}
        assert any("helper" in c for c in caps)

    def test_interproc_precision_non_model_arg(self):
        # same helper, but the arg is NOT model output — no finding
        src = ('class I {\n'
               '  void sink(String x) throws Exception { Runtime.getRuntime().exec(x); }\n'
               '  void h() throws Exception {\n'
               '    String cfg = readConfig();\n'
               '    sink(cfg);\n'
               '  }\n}\n')
        assert java_ast.output_findings(src) == []


class TestJavaFallback(unittest.TestCase):
    def test_no_crash_without_grammar(self):
        import orthosec.analysis.java_ast as mod
        orig = mod.available
        mod.available = lambda: False
        try:
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "H.java").write_text('class H { void m(){ Runtime.getRuntime().exec("ls"); } }\n')
                assert Scanner().scan(d).errors == []
        finally:
            mod.available = orig
