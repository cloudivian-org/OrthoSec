"""PHP AST tests — precise .php analysis via tree-sitter, skipped without orthosec[php]."""
import tempfile, unittest
from pathlib import Path
from orthosec.analysis import php_ast
from orthosec.core.scanner import Scanner

_HAS = php_ast.available()


@unittest.skipUnless(_HAS, "tree-sitter-php not installed (orthosec[php])")
class TestPhpAst(unittest.TestCase):
    def test_output_into_shell_and_sql(self):
        src = ("<?php class A {\n  function h($client, $pdo) {\n"
               "    $answer = $client->chat()->create($p)->choices[0]->message->content;\n"
               "    exec(\"echo \" . $answer);\n"
               "    $pdo->query(\"SELECT \" . $answer);\n  }\n}\n")
        caps = {c for _, c in php_ast.output_findings(src)}
        assert any("shell" in c for c in caps) and any("SQL" in c for c in caps)

    def test_echo_not_flagged(self):
        # echo of model output is intentionally not a sink (CLI vs web ambiguity)
        src = ("<?php class Z {\n  function h($client) {\n"
               "    $answer = $client->chat()->create($p)->content;\n"
               "    echo $answer;\n  }\n}\n")
        assert php_ast.output_findings(src) == []

    def test_sanitizer_clears(self):
        src = ("<?php class C {\n  function h($client) {\n"
               "    $answer = htmlspecialchars($client->chat()->create($p)->content);\n"
               "    echo $answer;\n  }\n}\n")
        assert php_ast.output_findings(src) == []

    def test_non_llm_sql_not_flagged(self):
        assert php_ast.output_findings("<?php class D { function h($pdo){ $pdo->query(\"SELECT 1\"); } }") == []

    def test_per_method_scoping(self):
        src = ("<?php class E {\n  function a($client){ $answer = $client->chat()->create($p)->content; }\n"
               "  function b($pdo, $answer){ $pdo->query($answer); }\n}\n")
        assert php_ast.output_findings(src) == []

    def test_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.php").write_text(
                "<?php class H {\n function h($client) {\n  $answer = $client->chat()->create($p)->content;\n  exec($answer);\n }\n}\n")
            assert any(f.owasp_llm == "LLM05" for f in Scanner().scan(d).findings)


class TestPhpFallback(unittest.TestCase):
    def test_no_crash_without_grammar(self):
        import orthosec.analysis.php_ast as mod
        orig = mod.available; mod.available = lambda: False
        try:
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "a.php").write_text("<?php exec('ls');\n")
                assert Scanner().scan(d).errors == []
        finally:
            mod.available = orig
