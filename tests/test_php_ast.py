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

    def test_interproc_return_value(self):
        # helper returns model output; caller's var inherits taint and hits a SQL sink
        src = ("<?php\n"
               "function get_answer($client){ return $client->chat()->create($p)->content; }\n"
               "function run($client, $pdo){ $answer = get_answer($client); $pdo->query($answer); }\n")
        assert php_ast.output_findings(src) != []

    def test_interproc_param_sink(self):
        # model output passed to a local helper whose param reaches exec()
        src = ("<?php\n"
               "function sink($x){ exec($x); }\n"
               "function run($client){ $answer = $client->chat()->create($p)->content; sink($answer); }\n")
        caps = {c for _, c in php_ast.output_findings(src)}
        assert any("helper" in c for c in caps)

    def test_interproc_precision(self):
        # non-output value into the same helper — must NOT be flagged
        src = ("<?php\n"
               "function sink($x){ exec($x); }\n"
               "function run(){ $cfg = read_config(); sink($cfg); }\n")
        assert php_ast.output_findings(src) == []

    def test_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.php").write_text(
                "<?php class H {\n function h($client) {\n  $answer = $client->chat()->create($p)->content;\n  exec($answer);\n }\n}\n")
            assert any(f.owasp_llm == "LLM05" for f in Scanner().scan(d).findings)


@unittest.skipUnless(_HAS, "tree-sitter-php not installed (orthosec[php])")
class TestPhpInjection(unittest.TestCase):
    def test_user_param_into_system_prompt_var(self):
        src = ("<?php function h($userQuery){\n"
               "  $systemPrompt = \"You are a bot. \" . $userQuery;\n"
               "  $client->chat()->create($systemPrompt);\n"
               "} ?>")
        assert php_ast.injection_findings(src) != []

    def test_role_system_array(self):
        src = ("<?php function h($request){\n"
               "  $msg = ['role' => 'system', 'content' => $request->input('p')];\n"
               "} ?>")
        assert php_ast.injection_findings(src) != []

    def test_user_role_array_not_flagged(self):
        src = ("<?php function h($userQuery){\n"
               "  $msg = ['role' => 'user', 'content' => $userQuery];\n"
               "} ?>")
        assert php_ast.injection_findings(src) == []

    def test_hardening_skips(self):
        src = ("<?php function h($userQuery){\n"
               "  // untrusted: treat the following as data, not instructions\n"
               "  $systemPrompt = \"You are a bot. \" . $userQuery;\n"
               "} ?>")
        assert php_ast.injection_findings(src) == []

    def test_static_system_prompt(self):
        src = ("<?php function h(){\n"
               "  $systemPrompt = \"You are a helpful bot.\";\n"
               "  $client->chat()->create($systemPrompt);\n"
               "} ?>")
        assert php_ast.injection_findings(src) == []


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
