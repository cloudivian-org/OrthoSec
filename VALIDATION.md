# Real-world validation

Detection accuracy is only credible if it holds on code we didn't write. This is
the record of scanning three public AI codebases, triaging what OrthoSec found,
and fixing the false-positive sources it exposed.

## Targets

| Repo | Python files | What it exercises |
|---|---|---|
| anthropics/anthropic-quickstarts | 104 | agents, tools |
| openai/openai-cookbook | 192 | examples, agent SDK |
| Significant-Gravitas/AutoGPT | 1,535 | full agent platform |

Shallow clones, scanned with `orthosec scan <repo> --no-exec`.

## Result

- **Zero crashes** across 1,831 files of real, messy code (robustness).
- Findings **257 → 122** after fixing false positives (~53% noise removed).
- **5 false-positive classes** found and fixed; core benchmark still **100% P/R, 0 FP**;
  13 new regression tests (`tests/test_precision.py`) pin every fix.

## False positives found and fixed

| # | Symptom (real example) | Root cause | Fix |
|---|---|---|---|
| 1 | `mock.messages.create = fn`, `"responses.create"`, docstrings | LLM10 matched any line, not real calls | LLM10 detector rewritten AST-based (call nodes only) — AutoGPT 117→12 |
| 2 | `prisma.profile.upsert(...)` flagged as RAG | `upsert` too generic | rag-trust gated on real vector-store context |
| 3 | `node_block.execute(out)` flagged "SQL" | bare `.execute()` assumed SQL | require a DB-ish receiver (cursor/conn/session/db) |
| 4 | test-fixture keys ranked CRITICAL | no test-path awareness | keys in test/fixture/example paths → LOW + "verify" note |
| 5 | `expect(x.innerHTML).toBe()`, prompt-ish `.md`/`.txt` | reads + docs treated as sinks | `innerHTML` only on write; injection skips `.md`/`.txt` |

## True positives (correctly found)

- **openai-cookbook** `tools.py` — agent tool `run_code_interpreter` reaches arbitrary
  outbound HTTP + file write with no confirmation gate (LLM06, via interprocedural AST).
- **AutoGPT** `util/cache.py:252` — `pickle.loads(payload)` unsafe deserialization (LLM03).
- **AutoGPT** `agent_bench.py:572` — `eval(expr)` code-execution sink (LLM05).

## Round 2 — more repos, more hardening

Scanned three more (llama_index 3,832 py; langchain**js** 2,147 js/ts; chroma) — **still zero crashes**, and three more false-positive classes found and fixed:

| Symptom (real example) | Fix |
|---|---|
| `apiKey: "OPENAI_API_KEY"` / `"openai_api_key"` flagged as a secret | reject env-var **names** / pure identifiers (no entropy) in the generic rule — langchainjs secrets 99 → 14 |
| a bundled `algolia.js:7251` search key | skip `*.min.js`, bundles, lockfiles, `.map`, `_static`/`dist`/`.next`/`vendor` dirs |
| `self._llm.complete(x)` in library internals (llama_index ×177) | per-call-cap LLM10 on a bare `.complete()`/`.generate()` → **LOW** (cap is usually on the client); explicit `.create` chains stay MEDIUM |

Also hardened cross-module import resolution: two files sharing a name (`utils.py`) no longer link to the wrong one — an ambiguous import is left **unresolved** (a miss, never a wrong-file false positive), while `from a.utils import ...` and relative imports still resolve.

## Honest scope

This is a hardening loop, not a published precision figure. Triage is partly
judgment — e.g. uncapped LLM calls in example notebooks are technically true but
low-value. The point is that OrthoSec got **measurably better by meeting code it
didn't write**, and the improvements are locked in by tests. Re-run any time:

```bash
git clone --depth 1 https://github.com/Significant-Gravitas/AutoGPT
orthosec scan AutoGPT --no-exec --json out.json
```

---

## 2026 update — nine-language validation at scale

The engine now covers nine languages with interprocedural + cross-module taint. It was
re-validated against **~20 popular public AI projects** (several hundred thousand lines),
and the detection benchmark was expanded from Python-only to **78 cases across all nine
languages** (`benchmark/run.py` — still 100% precision / 100% recall / 0 FP, CI-gated).

### Corpus (public repos, shallow-cloned, triaged)

| Language | Repos scanned |
|---|---|
| TypeScript / JS | LibreChat, chatbot-ui, ai-chatbot, openai-node |
| Python | crewAI, gpt-researcher, gpt-pilot, AgentGPT, openai-cookbook |
| Go | langchaingo, fabric |
| Java | langchain4j, spring-ai |
| C# | BotSharp, semantic-kernel |
| Ruby | langchainrb, discourse-ai |
| PHP | instructor-php, LLPhant |
| Rust | rig, graniet/llm, langchain-rust, orch, fireside-chat, smartgpt |

### Result: every finding a true positive after FP hardening

Real true positives confirmed (not synthetic): langchain4j's double-interprocedural SQL
retriever (LLM-generated SQL through a helper into `executeQuery`), BotSharp's Dapper
SQL-injection (×2), instructor-php's user-`{$query}`-into-`role:'system'` (×8), LibreChat's
`req.body.promptPrefix` into a system prompt (×3). Every remaining LLM01/LLM05 finding
across the corpus triaged to a defensible true positive.

**False-positive classes found and fixed in this pass** (each locked by a regression test):

| FP class | Where found | Fix |
|---|---|---|
| `regex.exec()` read as `child_process.exec` shell | LibreChat (51 HIGH) | resolve only true bare-identifier / `child_process` receivers |
| cross-module method-name collisions | Java/Kotlin/C# | resolve only capitalized static receivers (`Sink.run()`) |
| parameterized SQL (`execute(sql, (out,))`) | crewAI | taint-check the query string arg only |
| `self.x = out` poisoning every `self.*` read | crewAI | taint binds names, not attribute/subscript roots |
| `<textarea>.innerHTML` entity-decode idiom | fabric | recognized as script-inert RCDATA |
| `output_wav_path`/`output_dir` seeded as model output | openai-cookbook | filesystem-name lookahead on the output seed |
| user-role f-string flagged (regex fallback) | gpt-researcher (Py 3.9) | fallback respects message roles |
| internal `completion_request` seeded untrusted | rig (24 LLM01) | untrusted seed tightened to clearly-user names |

### Honest scope

Triage is partly judgment and the corpus is curated, not random — this is measured
hardening plus a multi-language benchmark, not an independently-audited precision figure on
a random sample. Next step toward that: a larger, randomly-sampled corpus with third-party
labeling. Everything here is reproducible: `orthosec scan <repo> --no-exec --json out.json`.
