"""Precision on LLM SDK adapter code — false positives found by the real-world audit.

An SDK adapter destructures/forwards its caller's `system_prompt` to a provider and calls
`create(requestVar)` with a request built elsewhere. Neither is a vulnerability:
  - forwarding the system prompt is not "untrusted input reaching a system prompt" (the
    system prompt is not untrusted user input — source == sink), and
  - a completion call whose request is a variable may carry a max-tokens cap set in the
    builder, so flagging it uncapped would be an interprocedural false positive.
A genuine `system = "..." + userInput` and an inline uncapped `create({...})` still fire.
"""
import unittest

from orthosec.analysis import ts_ast, go_ast, rust_ast


@unittest.skipUnless(ts_ast.available(), "ts grammar")
class TestTsSdkAdapter(unittest.TestCase):
    def test_destructured_system_prompt_not_injection(self):
        src = ('function convert(input, modelId){ const { messages, system_prompt } = input;'
               ' if (system_prompt) { params.system = system_prompt; } }')
        self.assertEqual(ts_ast.injection_findings(src), [])

    def test_real_user_input_into_system_prompt_fires(self):
        src = ('function h(req){ const userInput = req.body.text;'
               ' const systemPrompt = `You are a bot. ${userInput}`; call(systemPrompt); }')
        self.assertTrue(ts_ast.injection_findings(src))

    def test_variable_request_not_unbounded(self):
        self.assertEqual(ts_ast.unbounded_findings(
            'async function f(){ await this.openai.chat.completions.create(createParams); }'), [])

    def test_inline_uncapped_request_fires(self):
        self.assertTrue(ts_ast.unbounded_findings(
            'async function f(){ await openai.chat.completions.create({ model:"m", messages }); }'))

    def test_inline_capped_request_ok(self):
        self.assertEqual(ts_ast.unbounded_findings(
            'async function f(){ await openai.chat.completions.create('
            '{ model:"m", messages, max_tokens: 256 }); }'), [])


@unittest.skipUnless(go_ast.available(), "go grammar")
class TestGoSdkAdapter(unittest.TestCase):
    def test_system_prompt_field_passthrough_not_injection(self):
        src = 'func convert(input *LanguageModelInput){ systemPrompt := makeSys(input.SystemPrompt); _ = systemPrompt }'
        self.assertEqual(go_ast.injection_findings(src), [])

    def test_real_user_input_fires(self):
        src = 'func h(userInput string){ systemPrompt := "You are a bot " + userInput; call(systemPrompt) }'
        self.assertTrue(go_ast.injection_findings(src))


@unittest.skipUnless(rust_ast.available(), "rust grammar")
class TestRustSdkAdapter(unittest.TestCase):
    def test_destructured_system_prompt_not_injection(self):
        src = ('fn convert(input: LanguageModelInput){ '
               'let LanguageModelInput { system_prompt, messages } = input; use_it(system_prompt); }')
        self.assertEqual(rust_ast.injection_findings(src), [])

    def test_real_user_input_fires(self):
        src = 'fn h(user_input: String){ let system_prompt = format!("You are a bot {}", user_input); call(system_prompt); }'
        self.assertTrue(rust_ast.injection_findings(src))


if __name__ == "__main__":
    unittest.main()
