"""C# AST tests — precise .cs analysis via tree-sitter, skipped when the optional
`orthosec[csharp]` grammar isn't installed."""
import tempfile
import unittest
from pathlib import Path

from orthosec.analysis import csharp_ast
from orthosec.core.scanner import Scanner

_HAS_CS = csharp_ast.available()


@unittest.skipUnless(_HAS_CS, "tree-sitter-c-sharp not installed (orthosec[csharp])")
class TestCSharpAst(unittest.TestCase):
    def test_output_into_process_and_sql(self):
        src = ('class A {\n'
               '  void H(IChatClient chat, SqlConnection conn) {\n'
               '    var answer = chat.CompleteChat(userMessage).Value.Content[0].Text;\n'
               '    Process.Start("sh", answer);\n'
               '    var cmd = new SqlCommand("SELECT * FROM t WHERE x=" + answer, conn);\n'
               '  }\n}\n')
        caps = {cap for _, cap in csharp_ast.output_findings(src)}
        assert any("shell" in c for c in caps)
        assert any("SQL" in c for c in caps)

    def test_semantic_kernel_html_raw(self):
        src = ('class B {\n'
               '  void H(Kernel kernel) {\n'
               '    var response = kernel.InvokePromptAsync(prompt).Result;\n'
               '    Html.Raw(response);\n'
               '  }\n}\n')
        assert any("Html.Raw" in cap for _, cap in csharp_ast.output_findings(src))

    def test_dapper_query(self):
        src = ('class B2 {\n'
               '  void H(IChatClient chat, IDbConnection conn) {\n'
               '    var answer = chat.CompleteChat(q).Value.Content[0].Text;\n'
               '    conn.Query("SELECT " + answer);\n'
               '  }\n}\n')
        assert any("SQL" in cap for _, cap in csharp_ast.output_findings(src))

    def test_sanitizer_clears_taint(self):
        src = ('class C {\n'
               '  void H(IChatClient chat, SqlConnection conn) {\n'
               '    var answer = HttpUtility.HtmlEncode(chat.CompleteChat(q).Value.Content[0].Text);\n'
               '    var cmd = new SqlCommand("SELECT " + answer, conn);\n'
               '  }\n}\n')
        assert csharp_ast.output_findings(src) == []

    def test_non_llm_sql_not_flagged(self):
        src = 'class D { void H(SqlConnection conn){ var cmd = new SqlCommand("SELECT 1", conn); } }\n'
        assert csharp_ast.output_findings(src) == []

    def test_per_method_scoping_no_cross_taint(self):
        src = ('class E {\n'
               '  void A(IChatClient chat){ var answer = chat.CompleteChat(q).Value.Content[0].Text; }\n'
               '  void B(SqlConnection conn, string answer){ var cmd = new SqlCommand(answer, conn); }\n'
               '}\n')
        assert csharp_ast.output_findings(src) == []

    def test_output_path_var_not_model_output(self):
        src = ('class F {\n'
               '  void H(SqlConnection conn){\n'
               '    var outputPath = dir + "/x.txt";\n'
               '    var cmd = new SqlCommand(outputPath, conn);\n'
               '  }\n}\n')
        assert csharp_ast.output_findings(src) == []

    def test_object_initializer_output_field_not_seeded(self):
        # RedirectStandardOutput is an object-initializer field, not a model-output var
        src = ('class G {\n'
               '  void H(string[] packages) {\n'
               '    var startInfo = new ProcessStartInfo { FileName = "pip", RedirectStandardOutput = true };\n'
               '    Process.Start(startInfo);\n'
               '  }\n}\n')
        assert csharp_ast.output_findings(src) == []

    def test_llm_response_deserialized_into_sql(self):
        # real-world shape (BotSharp SqlDriver): AI response -> args -> connection.Query
        src = ('class H2 {\n'
               '  async void Run(Agent agent, IDbConnection connection) {\n'
               '    var response = await GetAiResponse(agent);\n'
               '    var args = response.Content.JsonContent<Lookup>();\n'
               '    connection.Query(args.SqlStatement);\n'
               '  }\n}\n')
        assert any("SQL" in cap for _, cap in csharp_ast.output_findings(src))

    def test_detector_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "H.cs").write_text(
                'public class H {\n'
                '  public void Handle(IChatClient chat) {\n'
                '    var answer = chat.CompleteChat(q).Value.Content[0].Text;\n'
                '    Process.Start("sh", answer);\n'
                '  }\n}\n')
            findings = Scanner().scan(d).findings
            assert any(f.owasp_llm == "LLM05" for f in findings)


class TestCSharpFallback(unittest.TestCase):
    def test_no_crash_without_grammar(self):
        import orthosec.analysis.csharp_ast as mod
        orig = mod.available
        mod.available = lambda: False
        try:
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "H.cs").write_text('class H { void M(){ Process.Start("ls"); } }\n')
                assert Scanner().scan(d).errors == []
        finally:
            mod.available = orig
