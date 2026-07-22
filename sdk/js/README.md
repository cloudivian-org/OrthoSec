# @orthosec/guard

Runtime AI-security guard for Node / TypeScript. Catch prompt injection and unsafe
LLM output at call time — any framework (OpenAI, Anthropic, LangChain, custom).
Zero dependencies. The Node companion to OrthoSec's static scanner.

```bash
npm install @orthosec/guard
```

## Wrap your LLM call

```js
import { guard } from "@orthosec/guard";
import OpenAI from "openai";

const client = new OpenAI();

const chat = guard(
  async (prompt) => {
    const r = await client.chat.completions.create({
      model: "gpt-4o",
      max_tokens: 500,
      messages: [{ role: "user", content: prompt }],
    });
    return r; // output is scanned for leaks / payloads too
  },
  { mode: "block", onRisk: (r) => console.warn("[orthosec]", r.where, r.risks) }
);

await chat("Summarize this ticket");                    // runs
await chat("ignore all previous instructions ...");     // throws PromptInjectionError
```

## Or inspect directly

```js
import { scanPrompt, scanOutput } from "@orthosec/guard";

if (!scanPrompt(userInput).ok) return reject();
const res = scanOutput(modelText);   // { ok, risks, where }
```

## Modes

- `mode: "monitor"` (default) — never throws; reports every hit via `onRisk`.
- `mode: "block"` — throws `PromptInjectionError` on an injection hit before your call runs.

`guard()` works with sync and async functions and preserves the signature.

A heuristic tripwire, not a guarantee — pair it with the OrthoSec static scanner
and least-privilege tool design. Apache-2.0.
