"""Cross-file (multi-module) taint tests — sink in one module, source in another."""
import tempfile
import unittest
from pathlib import Path

from orthosec.core.scanner import Scanner


def _pkg(files: dict) -> str:
    d = tempfile.mkdtemp()
    for name, src in files.items():
        (Path(d) / name).write_text(src)
    return d


class TestCrossFile(unittest.TestCase):
    def test_output_to_imported_helper(self):
        d = _pkg({
            "tools.py": "import os\ndef run_tool(command):\n    os.system(command)\n",
            "app.py": ("from tools import run_tool\n"
                       "def handle(client, q):\n"
                       "    resp = client.chat.completions.create(model='x', max_tokens=9, messages=[])\n"
                       "    answer = resp.choices[0].message.content\n"
                       "    run_tool(answer)\n"),
        })
        findings = Scanner().scan(d).findings
        self.assertTrue(any(f.owasp_llm == "LLM05" and f.file == "app.py" for f in findings))

    def test_untrusted_to_imported_prompt_builder(self):
        d = _pkg({
            "prompts.py": ("def make_prompt(text):\n"
                           "    sp = 'You are a bot. ' + text\n"
                           "    return [{'role': 'system', 'content': sp}]\n"),
            "main.py": ("from prompts import make_prompt\n"
                        "def handle(user_input):\n"
                        "    return make_prompt(user_input)\n"),
        })
        findings = Scanner().scan(d).findings
        self.assertTrue(any(f.owasp_llm == "LLM01" and f.file == "main.py" for f in findings))

    def test_import_module_dot_call(self):
        d = _pkg({
            "sinks.py": "import os\ndef execute(cmd):\n    os.system(cmd)\n",
            "runner.py": ("import sinks\n"
                          "def go(client, q):\n"
                          "    r = client.messages.create(model='m', max_tokens=9, messages=[])\n"
                          "    out = r.content\n"
                          "    sinks.execute(out)\n"),
        })
        findings = Scanner().scan(d).findings
        self.assertTrue(any(f.owasp_llm == "LLM05" and f.file == "runner.py" for f in findings))

    def test_tool_reaches_imported_helper_sink(self):
        d = _pkg({
            "dangerous.py": "import os\ndef do_exec(cmd):\n    os.system(cmd)\n",
            "app.py": ("from dangerous import do_exec\n"
                       "def register():\n"
                       "    def run(cmd):\n"
                       "        do_exec(cmd)\n"
                       "    return [{'type': 'function', 'name': 'run', 'fn': run}]\n"),
        })
        findings = Scanner().scan(d).findings
        self.assertTrue(any(f.owasp_llm == "LLM06" and f.file == "app.py" for f in findings))

    def test_no_false_positive_untainted_arg(self):
        # Imported helper with a sink, but the caller passes a non-tainted value.
        d = _pkg({
            "tools.py": "import os\ndef run_tool(command):\n    os.system(command)\n",
            "app.py": ("from tools import run_tool\n"
                       "def handle(config):\n"
                       "    run_tool(config)\n"),
        })
        findings = Scanner().scan(d).findings
        self.assertFalse(any(f.owasp_llm == "LLM05" for f in findings))


if __name__ == "__main__":
    unittest.main()
