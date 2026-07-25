"""Cross-module (cross-file) taint: a helper defined in file B that sinks its parameter,
called with model output in file A, is flagged. Skipped per-language when the grammar
isn't installed. Uses the Scanner (multi-file) so the project index is built."""
import tempfile
import unittest
from pathlib import Path

from orthosec.core.scanner import Scanner
from orthosec.analysis import ts_ast, go_ast, java_ast, csharp_ast, kotlin_ast, ruby_ast, php_ast


def _scan(files):
    with tempfile.TemporaryDirectory() as d:
        for name, body in files.items():
            (Path(d) / name).write_text(body)
        return Scanner().scan(d).findings


def _has_llm05_in(findings, filename):
    return any(f.owasp_llm == "LLM05" and filename in f.file for f in findings)


class TestCrossModule(unittest.TestCase):
    @unittest.skipUnless(go_ast.available(), "go grammar")
    def test_go(self):
        f = _scan({
            "sink.go": 'package main\nimport "os/exec"\nfunc runShell(x string){ exec.Command("sh", x) }\n',
            "handler.go": 'package main\nfunc handle(c *openai.Client){ resp, _ := c.CreateChatCompletion(ctx, req); runShell(resp.Choices[0].Message.Content) }\n',
        })
        assert _has_llm05_in(f, "handler.go")

    @unittest.skipUnless(ts_ast.available(), "ts grammar")
    def test_ts(self):
        f = _scan({
            "sink.ts": "export function runShell(x: string){ child_process.execSync(x); }\n",
            "handler.ts": "import { runShell } from './sink';\nexport function handle(model: any){ const out = model.invoke(p); runShell(out); }\n",
        })
        assert _has_llm05_in(f, "handler.ts")

    @unittest.skipUnless(java_ast.available(), "java grammar")
    def test_java(self):
        f = _scan({
            "Sink.java": 'class Sink { static void run(String x) throws Exception { Runtime.getRuntime().exec(x); } }\n',
            "H.java": 'class H { void h(ChatModel model) throws Exception { String answer = model.generate(q); Sink.run(answer); } }\n',
        })
        assert _has_llm05_in(f, "H.java")

    @unittest.skipUnless(csharp_ast.available(), "csharp grammar")
    def test_csharp(self):
        f = _scan({
            "Sink.cs": 'class Sink { public static void Run(string x){ Process.Start("sh", x); } }\n',
            "H.cs": 'class H { void h(IChatClient chat){ var answer = chat.CompleteChat(q).Value.Content[0].Text; Sink.Run(answer); } }\n',
        })
        assert _has_llm05_in(f, "H.cs")

    @unittest.skipUnless(kotlin_ast.available(), "kotlin grammar")
    def test_kotlin(self):
        f = _scan({
            "Sink.kt": 'object Sink { fun run(x: String){ Runtime.getRuntime().exec(x) } }\n',
            "H.kt": 'class H { fun h(llm: Any){ val answer = llm.chat(p); Sink.run(answer) } }\n',
        })
        assert _has_llm05_in(f, "H.kt")

    @unittest.skipUnless(ruby_ast.available(), "ruby grammar")
    def test_ruby(self):
        f = _scan({
            "sink.rb": "def run_shell(x)\n  system(x)\nend\n",
            "handler.rb": 'def h(client)\n  answer = client.chat(p).dig("content")\n  run_shell(answer)\nend\n',
        })
        assert _has_llm05_in(f, "handler.rb")

    @unittest.skipUnless(php_ast.available(), "php grammar")
    def test_php(self):
        f = _scan({
            "sink.php": "<?php\nfunction run_shell($x){ exec($x); }\n",
            "handler.php": "<?php\nfunction h($client){ $answer = $client->chat()->create($p)->content; run_shell($answer); }\n",
        })
        assert _has_llm05_in(f, "handler.php")

    @unittest.skipUnless(ts_ast.available(), "ts grammar")
    def test_ambiguous_name_not_cross_linked(self):
        # `process` defined in two files -> ambiguous -> not resolved cross-file (no wrong-file FP).
        f = _scan({
            "a.ts": "export function process(x){ return x; }\n",
            "b.ts": "export function helper(x){ readConfig(x); }\n",
            "c.ts": "export function run(){ const cfg = readConfig(); process(cfg); helper(cfg); }\n",
        })
        assert not any(f_.owasp_llm == "LLM05" for f_ in f)
