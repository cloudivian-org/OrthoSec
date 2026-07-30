"""LLM10 tree-sitter AST for the six non-Go/TS languages.

The AST path scopes the cap check precisely: to the inline request literal (PHP/Ruby) or to
the enclosing method's builder (Java/Kotlin/C#/Rust). An uncapped call fires; a cap set in
the same request/method suppresses it; a bare-variable request (cap possibly out of view)
does not fire.
"""
import unittest

from orthosec.analysis import java_ast, kotlin_ast, csharp_ast, ruby_ast, php_ast, rust_ast


class TestBuilderStyle(unittest.TestCase):
    @unittest.skipUnless(csharp_ast.available(), "csharp grammar")
    def test_csharp_builder_cap_in_method_suppresses(self):
        capped = ('class C{ void A(ChatClient c){ '
                  'var o = new ChatCompletionOptions { MaxOutputTokenCount = 9 }; '
                  'c.CompleteChat(m, o); } }')
        uncapped = 'class C{ void A(ChatClient c){ c.CompleteChat(m); } }'
        self.assertEqual(csharp_ast.unbounded_findings(capped), [])
        self.assertTrue(csharp_ast.unbounded_findings(uncapped))

    @unittest.skipUnless(java_ast.available(), "java grammar")
    def test_java_builder_cap_in_method_suppresses(self):
        capped = ('class C{ void a(){ var p = Params.builder().maxTokens(9).build(); '
                  'client.chat().completions().create(p); } }')
        uncapped = 'class C{ void a(){ client.chat().completions().create(p); } }'
        self.assertEqual(java_ast.unbounded_findings(capped), [])
        self.assertTrue(java_ast.unbounded_findings(uncapped))

    @unittest.skipUnless(rust_ast.available(), "rust grammar")
    def test_rust_builder_cap_in_fn_suppresses(self):
        capped = ('fn a(c: Client){ let r = Args::default().max_tokens(9u16).build().unwrap(); '
                  'let _ = c.chat().create(r); }')
        uncapped = 'fn a(c: Client){ let _ = c.chat().create(r); }'
        self.assertEqual(rust_ast.unbounded_findings(capped), [])
        self.assertTrue(rust_ast.unbounded_findings(uncapped))


class TestLiteralStyle(unittest.TestCase):
    @unittest.skipUnless(php_ast.available(), "php grammar")
    def test_php_inline_only(self):
        self.assertTrue(php_ast.unbounded_findings("<?php $r = $c->chat()->create(['model'=>'m']);"))
        self.assertEqual(php_ast.unbounded_findings("<?php $r = $c->chat()->create(['max_tokens'=>9]);"), [])
        self.assertEqual(php_ast.unbounded_findings("<?php $r = $c->chat()->create($params);"), [])

    @unittest.skipUnless(ruby_ast.available(), "ruby grammar")
    def test_ruby_inline_only(self):
        self.assertTrue(ruby_ast.unbounded_findings("r = c.chat(parameters: { model: 'm' })"))
        self.assertEqual(ruby_ast.unbounded_findings("r = c.chat(parameters: { max_tokens: 9 })"), [])
        self.assertEqual(ruby_ast.unbounded_findings("r = c.chat(parameters: my_params)"), [])


if __name__ == "__main__":
    unittest.main()
