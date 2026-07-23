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
