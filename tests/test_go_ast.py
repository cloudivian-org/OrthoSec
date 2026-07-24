"""Go AST tests — precise .go analysis via tree-sitter, skipped when the optional
`orthosec[go]` grammar isn't installed."""
import tempfile
import unittest
from pathlib import Path

from orthosec.analysis import go_ast
from orthosec.core.scanner import Scanner

_HAS_GO = go_ast.available()


@unittest.skipUnless(_HAS_GO, "tree-sitter-go not installed (orthosec[go])")
class TestGoAst(unittest.TestCase):
    def test_model_output_into_exec_and_sql(self):
        src = ('package main\n'
               'func h(client *openai.Client, db *sql.DB) {\n'
               '  resp, _ := client.CreateChatCompletion(ctx, req)\n'
               '  out := resp.Choices[0].Message.Content\n'
               '  exec.Command("sh", "-c", out)\n'
               '  db.Query("SELECT * FROM t WHERE x=" + out)\n'
               '}\n')
        caps = {cap for _, cap in go_ast.output_findings(src)}
        assert any("shell" in c for c in caps)
        assert any("SQL" in c for c in caps)

    def test_template_html_injection(self):
        src = ('package main\n'
               'func h(c *openai.Client){\n'
               '  resp, _ := c.CreateChatCompletion(ctx, req)\n'
               '  answer := resp.Choices[0].Message.Content\n'
               '  w.Write([]byte(template.HTML(answer)))\n'
               '}\n')
        assert any("template.HTML" in cap for _, cap in go_ast.output_findings(src))

    def test_sanitizer_clears_taint(self):
        src = ('package main\n'
               'func h(c *openai.Client){\n'
               '  resp, _ := c.CreateChatCompletion(ctx, req)\n'
               '  out := html.EscapeString(resp.Choices[0].Message.Content)\n'
               '  exec.Command("echo", out)\n'
               '}\n')
        assert go_ast.output_findings(src) == []

    def test_non_llm_sql_not_flagged(self):
        src = 'package main\nfunc h(db *sql.DB){ rows, _ := db.Query("SELECT 1"); _ = rows }\n'
        assert go_ast.output_findings(src) == []

    def test_langchaingo_gated_verb(self):
        src = ('package main\n'
               'func h(llm *ollama.LLM){\n'
               '  out, _ := llms.GenerateFromSinglePrompt(ctx, llm, p)\n'
               '  exec.Command(out)\n'
               '}\n')
        assert go_ast.output_findings(src)  # non-empty

    def test_output_path_var_is_not_model_output(self):
        # `outputPath` is a file path, not model output -> must not taint into a sink
        src = ('package main\n'
               'func h() {\n'
               '  outputPath := cfg.Dir + "/out.txt"\n'
               '  exec.Command("cat", outputPath)\n'
               '}\n')
        assert go_ast.output_findings(src) == []

    def test_llm10_variable_config_not_flagged(self):
        # cap may be set in a config builder -> a var-config completion call is not judged
        varcfg = ('package main\n'
                  'func h(c *genai.Client){ c.Models.GenerateContent(ctx, model, contents, cfg) }\n')
        assert go_ast.unbounded_findings(varcfg) == []

    def test_unbounded_uncapped_vs_capped(self):
        uncapped = ('package main\nfunc h(c *openai.Client){ '
                    'c.CreateChatCompletion(ctx, openai.ChatCompletionRequest{Model: "x", Messages: m}) }\n')
        capped = ('package main\nfunc h(c *openai.Client){ '
                  'c.CreateChatCompletion(ctx, openai.ChatCompletionRequest{Model: "x", MaxTokens: 256}) }\n')
        assert go_ast.unbounded_findings(uncapped) == [2]
        assert go_ast.unbounded_findings(capped) == []

    def test_detector_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "main.go").write_text(
                'package main\n'
                'func h(client *openai.Client) {\n'
                '  resp, _ := client.CreateChatCompletion(ctx, req)\n'
                '  exec.Command("sh", "-c", resp.Choices[0].Message.Content)\n'
                '}\n')
            findings = Scanner().scan(d).findings
            assert any(f.owasp_llm == "LLM05" for f in findings)


class TestGoFallback(unittest.TestCase):
    def test_no_crash_without_grammar(self):
        import orthosec.analysis.go_ast as mod
        orig = mod.available
        mod.available = lambda: False
        try:
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "main.go").write_text('package main\nfunc main(){ exec.Command("ls") }\n')
                assert Scanner().scan(d).errors == []
        finally:
            mod.available = orig
