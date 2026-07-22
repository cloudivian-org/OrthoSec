# OrthoSec detection-efficacy benchmark

Measurable accuracy — the number a security leader actually asks for.

```bash
python benchmark/run.py            # print the report
python benchmark/run.py --check    # exit 1 if below thresholds (regression gate)
```

## Current results

30 labeled cases (14 vulnerable, 16 safe / clean), one file per case:

| Category | Precision | Recall | F1 |
|---|---|---|---|
| LLM01 Prompt Injection | 100% | 100% | 100% |
| LLM02 Sensitive Info Disclosure | 100% | 100% | 100% |
| LLM03 Supply Chain | 100% | 100% | 100% |
| LLM05 Improper Output Handling | 100% | 100% | 100% |
| LLM06 Excessive Agency | 100% | 100% | 100% |
| LLM08 Vector & Embedding Weaknesses | 100% | 100% | 100% |
| LLM10 Unbounded Consumption | 100% | 100% | 100% |
| **Overall** | **100%** | **100%** | **100%** |

The signal that matters most is **zero false positives on the safe look-alikes** —
mitigated code that superficially resembles a vulnerability (a prompt with a trust
boundary, a tool behind a confirmation gate, `torch.load(weights_only=True)`,
`json.loads` on model output, a provenance-checked RAG ingest, a capped LLM call).
A scanner that cries wolf on those gets uninstalled.

## Methodology

- Each case is a single file. `manifest.json` labels it with the OWASP LLM
  categories that **should** fire (safe/clean cases label none).
- The harness scans each file and compares fired categories to the label:
  TP (expected + fired), FP (fired + not expected), FN (expected + not fired).
- Precision = TP / (TP+FP), Recall = TP / (TP+FN).
- `tests/test_benchmark.py` runs this as a **regression gate**: precision/recall
  must stay ≥ 95% and FP must be 0, so a detector change that regresses quality
  fails the build.

## Adversarial set — evasions & FP stress

`python benchmark/run.py --adversarial` runs a second corpus of code that *tries*
to beat the detectors: obfuscated attacks that should still be caught, and safe
code crafted to trip a false positive. Current state (11 cases):

| Probe | Expected | Result |
|---|---|---|
| Secret split across `"sk-proj-" + "..."` | LLM02 | ✓ caught (hardened) |
| Injection via `.format()` not `+` | LLM01 | ✓ caught |
| Untrusted input renamed → system prompt (far) | LLM01 | ✓ caught (AST taint) |
| JS model output → `innerHTML` (XSS) | LLM05 | ✓ caught |
| Model output → 4 reassignments + concat → shell | LLM05 | ✓ caught (AST taint) |
| `torch.load(map_location=...)` no `weights_only` | LLM03 | ✓ caught |
| Tool sink far from the tool marker | LLM06 | ✓ caught (AST tool dataflow) |
| `subprocess` in a plain build script (not a tool) | none | ✓ no false positive |
| Injection phrase used as documentation/data | none | ✓ no false positive |
| `eval()` on a config value (not model output) | none | ✓ no false positive |
| System prompt from a static/config value (no user input) | none | ✓ no false positive |

**11/11 handled, 0 known-miss.** Every gap this set exposed is fixed. The three
dataflow-shaped detectors (LLM01 prompt injection, LLM05 output handling, LLM06
excessive agency) run Python **AST taint/dataflow** — untrusted input traced into
a system prompt, model output traced into a sink, and dangerous sinks resolved
inside model-invokable tools — each firing only when the *actual* data reaches the
*actual* sink, at any distance, respecting trust-boundary/sanitizer mitigations
(see `orthosec/analysis/pyast.py`). `tests/test_benchmark.py` and
`tests/test_analysis.py` guard every case against regression.

## Honest limitations

This is a **seed corpus authored alongside the detectors**, so 100% on the core
set reflects internal consistency, not real-world coverage — treat it as a floor
and a regression guard, not a market claim. Known gaps OrthoSec does **not** yet
catch (static, single-file, pattern-based):

- **Cross-file dataflow** — a dangerous sink and its LLM-output source in
  different modules (single-file AST only).
- **Deep obfuscation** — base64, env-indirection, or multi-step reassembly.
- **Semantic-only injection** — malicious instructions with no lexical marker.
- **Languages beyond Python/JS/TS.**

These are the roadmap. **Adversarial cases are the most valuable contribution** —
add a file under `adversarial/` that OrthoSec gets wrong, label it in
`manifest_adversarial.json` (`known_miss: true` if it's a documented gap), and
open a PR. A benchmark is only as honest as its hardest cases.
