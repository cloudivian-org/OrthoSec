"""LLM06 tree-sitter AST for annotation-based languages (Java/Kotlin/C#/Rust).

A tool is a function carrying a tool annotation (@Tool / [KernelFunction] / #[tool]). A
dangerous sink counts only when it sits in that tool function's body — at any line distance
(recall the proximity window would miss) and never bleeding in from a non-tool function
(precision). A confirmation gate downgrades CRITICAL -> MEDIUM.
"""
import unittest

from orthosec.detectors.tool_exposure import _ast_agency
from orthosec.analysis import java_ast, csharp_ast, rust_ast, kotlin_ast, ts_ast


def _caps(hits):
    return [(cap, mit) for _l, cap, mit, _n in (hits or [])]


@unittest.skipUnless(java_ast.available(), "java grammar")
class TestJava(unittest.TestCase):
    def test_distant_sink_in_tool_fires(self):
        src = ('class T { @Tool("run") void run(String x) throws Exception {\n'
               + '\n'.join(f'    int a{i} = {i};' for i in range(12))
               + '\n    Runtime.getRuntime().exec(x);\n  } }')
        self.assertTrue(_ast_agency(".java", src))

    def test_sink_in_non_tool_method_not_flagged(self):
        src = 'class T { void deploy(String x) throws Exception { Runtime.getRuntime().exec(x); } }'
        self.assertEqual(_ast_agency(".java", src), [])


@unittest.skipUnless(csharp_ast.available(), "csharp grammar")
class TestCsharp(unittest.TestCase):
    def test_kernel_function_shell_fires(self):
        src = 'class T { [KernelFunction] public void Run(string x){ Process.Start(x); } }'
        self.assertEqual(_caps(_ast_agency(".cs", src)), [("shell/command execution", False)])

    def test_confirmation_downgrades(self):
        src = ('class T { [KernelFunction] public void Run(string x){ '
               'if (!RequireApproval()) return; Process.Start(x); } }')
        caps = _caps(_ast_agency(".cs", src))
        self.assertTrue(caps and caps[0][1] is True)   # mitigated


@unittest.skipUnless(rust_ast.available(), "rust grammar")
class TestRust(unittest.TestCase):
    def test_tool_attr_shell_fires(self):
        src = '#[tool]\nfn run(cmd: &str) {\n    Command::new("sh").arg(cmd).status().unwrap();\n}'
        self.assertTrue(_ast_agency(".rs", src))

    def test_reqwest_import_not_a_sink(self):
        src = 'use reqwest::StatusCode;\n#[tool]\nfn ping() -> u16 { 200 }'
        self.assertEqual(_ast_agency(".rs", src), [])

    def test_non_tool_command_not_flagged(self):
        src = 'fn deploy(cmd: &str) { Command::new("sh").arg(cmd).status().unwrap(); }'
        self.assertEqual(_ast_agency(".rs", src), [])


@unittest.skipUnless(kotlin_ast.available(), "kotlin grammar")
class TestKotlin(unittest.TestCase):
    def test_tool_shell_fires(self):
        src = 'class T { @Tool fun run(cmd: String) { Runtime.getRuntime().exec(cmd) } }'
        self.assertTrue(_ast_agency(".kt", src))


@unittest.skipUnless(ts_ast.available(), "ts grammar")
class TestTsFactory(unittest.TestCase):
    def test_vercel_tool_executor_sink_fires(self):
        src = 'const t = tool({ execute: async (a) => { execSync(a.cmd); } });'
        self.assertTrue(ts_ast.tool_agency_findings(src))

    def test_dynamic_structured_tool_fires(self):
        src = 'const t = new DynamicStructuredTool({ name:"run", func: async (i) => { child_process.exec(i.x); } });'
        hits = ts_ast.tool_agency_findings(src)
        self.assertTrue(hits and hits[0][3] == "run")

    def test_distant_sink_in_executor_fires(self):
        body = '\n'.join(f'  let v{i} = {i};' for i in range(14))
        src = 'const t = tool({ execute: async (a) => {\n' + body + '\n  fs.writeFile(a.p, a.d);\n} });'
        self.assertTrue(ts_ast.tool_agency_findings(src))

    def test_confirmation_downgrades(self):
        src = 'const t = tool({ execute: async (a) => { if(!requireApproval()) return; execSync(a.cmd); } });'
        hits = ts_ast.tool_agency_findings(src)
        self.assertTrue(hits and hits[0][2] is True)

    def test_sink_outside_factory_returns_none(self):
        # No tool factory -> None so the caller falls back to the marker regex.
        self.assertIsNone(ts_ast.tool_agency_findings('function deploy(cmd){ execSync(cmd); }'))

    def test_factory_without_executor_returns_none(self):
        self.assertIsNone(ts_ast.tool_agency_findings('const t = tool(myFunc);'))


if __name__ == "__main__":
    unittest.main()
