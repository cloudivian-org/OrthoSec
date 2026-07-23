"""TypeScript / JSX AST tests — precise .ts/.tsx analysis via tree-sitter,
skipped when the optional `orthosec[ts]` grammar isn't installed."""
import tempfile
import unittest
from pathlib import Path

from orthosec.analysis import ts_ast
from orthosec.core.scanner import Scanner

_HAS_TS = ts_ast.available()


@unittest.skipUnless(_HAS_TS, "tree-sitter not installed (orthosec[ts])")
class TestTsAst(unittest.TestCase):
    def test_ts_model_output_into_sinks(self):
        src = ("async function h(model: any) {\n"
               "  const resp = await model.chat.completions.create({messages: m});\n"
               "  const out: string = resp.choices[0].message.content;\n"
               "  eval(out);\n"
               "  el.innerHTML = out;\n"
               "  cp.execSync(out);\n"
               "  db.query(out);\n"
               "}\n")
        caps = {cap for _, cap in ts_ast.output_findings(src, tsx=False)}
        assert any("eval" in c for c in caps)
        assert any("innerHTML" in c for c in caps)
        assert any("shell" in c for c in caps)
        assert any("SQL" in c for c in caps)

    def test_tsx_dangerously_set_inner_html(self):
        src = ("export function C({model, q}: any) {\n"
               "  const answer = model.invoke(q);\n"
               "  return <div dangerouslySetInnerHTML={{__html: answer}} />;\n"
               "}\n")
        hits = ts_ast.output_findings(src, tsx=True)
        assert any("dangerouslySetInnerHTML" in cap for _, cap in hits)

    def test_string_and_non_llm_not_flagged(self):
        # a string literal that mentions a sink + a non-LLM db.query must NOT fire
        src = ('function h(db: any) {\n'
               '  const note = "el.innerHTML = evil";\n'
               '  const rows = db.query("SELECT 1");\n'
               '  el.innerHTML = rows;\n'
               '}\n')
        assert ts_ast.output_findings(src, tsx=False) == []

    def test_gated_generic_verb_needs_llm_receiver(self):
        # chain.invoke is output; db.query is not — so only the tainted-from-invoke path fires
        src = ("function h(chain: any, db: any) {\n"
               "  const out = chain.run(prompt);\n"
               "  eval(out);\n"
               "}\n")
        assert ts_ast.output_findings(src, tsx=False)  # non-empty
        src2 = ("function h(worker: any) {\n"
                "  const r = worker.run(task);\n"     # worker not LLM-ish -> not output
                "  eval(r);\n"
                "}\n")
        assert ts_ast.output_findings(src2, tsx=False) == []

    def test_unbounded_uncapped_vs_capped(self):
        uncapped = "const r = await client.chat.completions.create({messages: m});\n"
        capped = "const r = await client.chat.completions.create({messages: m, max_tokens: 100});\n"
        assert ts_ast.unbounded_findings(uncapped, tsx=False) == [1]
        assert ts_ast.unbounded_findings(capped, tsx=False) == []

    def test_detector_end_to_end_on_tsx(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "C.tsx").write_text(
                "export function C({model, q}: any) {\n"
                "  const out = model.invoke(q);\n"
                "  return <div dangerouslySetInnerHTML={{__html: out}} />;\n"
                "}\n")
            findings = Scanner().scan(d).findings
            assert any(f.owasp_llm == "LLM05" for f in findings)


class TestTsFallback(unittest.TestCase):
    def test_regex_fallback_when_grammar_unavailable(self):
        """With tree-sitter forced off, .ts scanning must not crash and still uses regex."""
        import orthosec.analysis.ts_ast as mod
        orig = mod.available
        mod.available = lambda: False
        try:
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "h.ts").write_text(
                    "const answer = llm.completions.create({});\n"
                    "el.innerHTML = answer;\n")
                # must complete without error; regex path may or may not fire, but no crash
                result = Scanner().scan(d)
                assert result.errors == []
        finally:
            mod.available = orig
