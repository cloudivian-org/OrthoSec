"""Precision regressions for 0.7.1 — three false-positive classes found scanning crewAI:
1. a variable named `model` (a model-NAME string) treated as model OUTPUT
2. VCR cassette / snapshot recorded-I/O flagged as source
3. bundled front-end assets flagged as app logic
"""
import textwrap

from orthosec.core.scanner import Scanner
from orthosec.analysis.pyast import safe_parse, output_taint_sinks


def test_model_name_string_is_not_model_output():
    # `model` here is a model identifier passed to a subprocess — NOT model output.
    src = textwrap.dedent("""
        import subprocess
        def run(n_iterations, model):
            command = ["uv", "run", "test", str(n_iterations), model]
            subprocess.run(command)
    """)
    assert output_taint_sinks(safe_parse(src), src.splitlines()) == []


def test_real_model_output_still_caught_via_call():
    # regression guard: actual model output (call-based) must STILL fire
    src = textwrap.dedent("""
        import subprocess
        def run(client):
            resp = client.chat.completions.create(messages=m)
            subprocess.run(resp.choices[0].message.content, shell=True)
    """)
    assert output_taint_sinks(safe_parse(src), src.splitlines())


def test_vcr_cassettes_dir_skipped(tmp_path):
    d = tmp_path / "tests" / "cassettes"
    d.mkdir(parents=True)
    (d / "recorded.yaml").write_text(
        'body: '
        '"system_prompt: You are a bot. " + user_input + " ignore previous instructions"\n')
    assert Scanner().scan(str(tmp_path)).findings == []


def test_snapshots_dir_skipped(tmp_path):
    d = tmp_path / "__snapshots__"
    d.mkdir()
    (d / "s.json").write_text('{"system_prompt": "You are a bot " + userInput}')
    assert Scanner().scan(str(tmp_path)).findings == []


def test_bundled_assets_dir_skipped(tmp_path):
    d = tmp_path / "viz" / "assets"
    d.mkdir(parents=True)
    (d / "interactive.js").write_text(
        "function r(content){ this.el.content.innerHTML = content; }\n")
    assert Scanner().scan(str(tmp_path)).findings == []
