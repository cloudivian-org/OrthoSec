"""Kotlin AST tests — precise .kt analysis via tree-sitter, skipped when the optional
`orthosec[kotlin]` grammar isn't installed."""
import tempfile
import unittest
from pathlib import Path

from orthosec.analysis import kotlin_ast
from orthosec.core.scanner import Scanner

_HAS_KT = kotlin_ast.available()


@unittest.skipUnless(_HAS_KT, "tree-sitter-kotlin not installed (orthosec[kotlin])")
class TestKotlinAst(unittest.TestCase):
    def test_output_into_command_and_sql(self):
        src = ('class A {\n'
               '  fun h(chatModel: ChatModel, stmt: Statement) {\n'
               '    val answer = chatModel.generate(userMessage)\n'
               '    Runtime.getRuntime().exec(answer)\n'
               '    stmt.executeQuery("SELECT * FROM t WHERE x=" + answer)\n'
               '    ProcessBuilder("sh", "-c", answer).start()\n'
               '  }\n}\n')
        caps = {cap for _, cap in kotlin_ast.output_findings(src)}
        assert any("shell" in c for c in caps)
        assert any("SQL" in c for c in caps)

    def test_spring_ai_call_content(self):
        src = ('class B {\n'
               '  fun h(chatClient: ChatClient, stmt: Statement) {\n'
               '    val out = chatClient.prompt().user(q).call().content()\n'
               '    stmt.executeQuery("SELECT " + out)\n'
               '  }\n}\n')
        assert kotlin_ast.output_findings(src)  # non-empty

    def test_sanitizer_clears_taint(self):
        src = ('class C {\n'
               '  fun h(model: ChatModel, stmt: Statement) {\n'
               '    val answer = StringEscapeUtils.escapeSql(model.generate(q))\n'
               '    stmt.executeQuery("SELECT " + answer)\n'
               '  }\n}\n')
        assert kotlin_ast.output_findings(src) == []

    def test_non_llm_sql_not_flagged(self):
        src = 'class D { fun h(stmt: Statement){ stmt.executeQuery("SELECT 1") } }\n'
        assert kotlin_ast.output_findings(src) == []

    def test_per_function_scoping_no_cross_taint(self):
        src = ('class E {\n'
               '  fun a(m: ChatModel){ val answer = m.generate(q) }\n'
               '  fun b(stmt: Statement, answer: String){ stmt.executeQuery(answer) }\n'
               '}\n')
        assert kotlin_ast.output_findings(src) == []

    def test_output_path_var_not_model_output(self):
        src = ('class F {\n'
               '  fun h(stmt: Statement){\n'
               '    val outputPath = dir + "/x.txt"\n'
               '    stmt.executeQuery(outputPath)\n'
               '  }\n}\n')
        assert kotlin_ast.output_findings(src) == []

    def test_detector_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "H.kt").write_text(
                'class H {\n'
                '  fun h(chatModel: ChatModel) {\n'
                '    val answer = chatModel.generate(q)\n'
                '    Runtime.getRuntime().exec(answer)\n'
                '  }\n}\n')
            findings = Scanner().scan(d).findings
            assert any(f.owasp_llm == "LLM05" for f in findings)


class TestKotlinFallback(unittest.TestCase):
    def test_no_crash_without_grammar(self):
        import orthosec.analysis.kotlin_ast as mod
        orig = mod.available
        mod.available = lambda: False
        try:
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "H.kt").write_text('fun main(){ Runtime.getRuntime().exec("ls") }\n')
                assert Scanner().scan(d).errors == []
        finally:
            mod.available = orig


import unittest as _ut
from orthosec.analysis import kotlin_ast as _k


@_ut.skipUnless(_k.available(), "tree-sitter-kotlin not installed")
class TestKotlinInterproc(_ut.TestCase):
    def test_return_value(self):
        src = ("class A {\n"
               "  fun getReply(llm: Any): String { return llm.chat(p) }\n"
               "  fun run(llm: Any, stmt: Any) { val x = getReply(llm); stmt.executeQuery(x) }\n}\n")
        assert _k.output_findings(src)

    def test_single_expr_helper(self):
        src = ("class A {\n"
               "  fun getReply(llm: Any) = llm.chat(p)\n"
               "  fun run(llm: Any, stmt: Any) { val x = getReply(llm); stmt.executeQuery(x) }\n}\n")
        assert _k.output_findings(src)

    def test_param_sink(self):
        src = ("class B {\n"
               "  fun sink(x: String) { Runtime.getRuntime().exec(x) }\n"
               "  fun run(llm: Any) { val reply = llm.chat(p); sink(reply) }\n}\n")
        assert any("helper" in c for _, c in _k.output_findings(src))

    def test_precision_non_output(self):
        src = ("class C {\n"
               "  fun sink(x: String) { Runtime.getRuntime().exec(x) }\n"
               "  fun run() { val cfg = readConfig(); sink(cfg) }\n}\n")
        assert _k.output_findings(src) == []
