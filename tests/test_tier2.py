"""Tier-2 tests: D. dependency-manifest supply-chain audit  E. framework-aware taint."""
import textwrap

from orthosec.core.scanner import Scanner
from orthosec.analysis.pyast import safe_parse, output_taint_sinks, injection_sinks, _is_llm_call
import ast


def _scan_text(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(textwrap.dedent(body))
    return Scanner().scan(str(p)).findings


# ---- D: dependency manifest audit -------------------------------------------

def test_pip_unpinned_ai_dep_flagged(tmp_path):
    f = _scan_text(tmp_path, "requirements.txt", "langchain\nopenai>=1.0\n")
    assert {x.rule_id for x in f} == {"ORTHO-DEP-001"}
    assert all(x.owasp_llm == "LLM03" for x in f)


def test_pip_git_source_flagged_high(tmp_path):
    f = _scan_text(tmp_path, "requirements.txt", "torch @ git+https://example.com/torch.git\n")
    assert any(x.rule_id == "ORTHO-DEP-002" and x.severity.name == "HIGH" for x in f)


def test_pip_alt_index_flagged(tmp_path):
    f = _scan_text(tmp_path, "requirements.txt", "--extra-index-url https://mirror.example.com\nopenai==1.3.5\n")
    assert any(x.rule_id == "ORTHO-DEP-002" for x in f)


def test_pip_pinned_ai_deps_clean(tmp_path):
    f = _scan_text(tmp_path, "requirements.txt", "langchain==0.1.0\nopenai==1.3.5\n")
    assert f == []


def test_pip_non_ai_dep_ignored(tmp_path):
    # unpinned, but not an AI/ML package — out of scope, must not flag.
    f = _scan_text(tmp_path, "requirements.txt", "requests\nflask>=2\n")
    assert f == []


def test_npm_loose_ai_sdk_flagged(tmp_path):
    body = '{"dependencies": {"openai": "^4.0.0", "@anthropic-ai/sdk": "0.20.0", "react": "^18"}}'
    f = _scan_text(tmp_path, "package.json", body)
    rules = {(x.rule_id) for x in f}
    assert "ORTHO-DEP-001" in rules
    # exact-pinned anthropic SDK and non-AI react must NOT be flagged
    assert not any("anthropic" in x.title and x.rule_id == "ORTHO-DEP-001" for x in f)
    assert not any("react" in x.title for x in f)


def test_npm_untrusted_source_flagged(tmp_path):
    body = '{"dependencies": {"langchain": "git+https://example.com/x.git"}}'
    f = _scan_text(tmp_path, "package.json", body)
    assert any(x.rule_id == "ORTHO-DEP-002" for x in f)


# ---- E: framework-aware taint -----------------------------------------------

def _c(src):
    return ast.parse(src, mode="eval").body


def test_llm_gated_methods_need_llm_receiver():
    assert _is_llm_call(_c("agent.run(x)"))
    assert _is_llm_call(_c("chain.invoke(x)"))
    assert _is_llm_call(_c("query_engine.query(q)"))
    assert _is_llm_call(_c("llm.call(p)"))
    # generic receivers must NOT be treated as model output
    assert not _is_llm_call(_c("db.query('SELECT 1')"))
    assert not _is_llm_call(_c("executor.run(task)"))


def test_framework_output_reaches_sink_llm05():
    src = "def h(agent):\n import os\n out = agent.run(task)\n os.system(out)\n"
    sinks = output_taint_sinks(safe_parse(src), src.splitlines())
    assert any(s.line == 4 for s in sinks)


def test_flask_request_reaches_prompt_llm01():
    src = ("import flask\n"
           "def h():\n"
           " text = flask.request.form['q']\n"
           " system_prompt = 'You are a bot. ' + text\n"
           " return system_prompt\n")
    sinks = injection_sinks(safe_parse(src), src.splitlines())
    assert any(s.line == 4 for s in sinks)


def test_non_llm_run_output_is_not_tainted():
    # executor.run() is not model output -> its result into a shell must NOT fire LLM05
    src = "def h(executor):\n import os\n r = executor.run(task)\n os.system(r)\n"
    assert output_taint_sinks(safe_parse(src), src.splitlines()) == []
