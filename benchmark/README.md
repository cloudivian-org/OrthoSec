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

## Honest limitations

This is a **seed corpus authored alongside the detectors**, so 100% reflects
internal consistency, not real-world coverage — treat it as a floor and a
regression guard, not a market claim. Known evasion classes OrthoSec does **not**
yet catch (static, single-file, pattern-based):

- **Obfuscation** — a secret split across concatenation (`"sk-" + rest`), base64,
  or env-indirection that reassembles at runtime.
- **Cross-file dataflow** — a dangerous sink and its LLM-output source in
  different modules.
- **Semantic-only injection** — malicious instructions with no lexical marker.
- **Languages beyond Python/JS/TS.**

These are the roadmap. **Adversarial cases are the most valuable contribution** —
add a file under `cases/` that OrthoSec gets wrong, label it in `manifest.json`,
and open a PR. A benchmark is only as honest as its hardest cases.
