<h1 align="center">OrthoSec</h1>
<p align="center"><b>The AI Security Architect</b><br>
Technical AI-risk analysis with executive business context. Open source.</p>

---

OrthoSec scans any AI product and answers two questions at once:

- **For engineers** — *where is this AI system exposed, and how do I fix it?* Deterministic detectors map every finding to the OWASP LLM Top-10 and MITRE ATLAS, with `file:line` evidence and concrete remediation.
- **For executives** — *are we exposed, how bad is the blast radius, and what's the regulatory fallout?* A grounded intel layer translates findings into business risk, a posture score, and compliance mapping (EU AI Act, NIST AI RMF, ISO 42001, SOC 2).

One tool. Technical rigor **and** business impact.

## Why OrthoSec

AI products fail in AI-specific ways — prompt injection, excessive agency, model supply-chain compromise, data leakage — that classic AppSec tools don't see. OrthoSec is purpose-built for that surface, and it speaks to both the engineer shipping the agent and the leader accountable for the risk.

**Trust by design:** detectors are deterministic and evidence-backed. The LLM layer only *explains* findings — it never invents them. So the security facts are always defensible.

## Quick start

Zero dependencies. Clone and run:

```bash
git clone https://github.com/orthosec/orthosec
cd orthosec
python -m orthosec.cli scan ./path/to/your/ai-app
```

Try it on the bundled vulnerable demo:

```bash
python -m orthosec.cli scan examples/vulnerable-agent
```

```
  Posture score: 47/100   Grade:  D
  2 critical   2 high

  [CRITICAL] Model-invokable tool with shell/command execution and no confirmation gate
      agent.py:25
      OWASP LLM06 (Excessive Agency)  ·  ATLAS AML.T0053
      business: Agent takes real-world actions attacker directs — financial/operational loss.
      fix: Scope the tool to the minimum capability, add an allowlist, and gate
           irreversible/high-impact actions behind human confirmation.
```

## The executive layer

The core scan runs offline. Add the intel layer for board-ready narrative + free-form Q&A:

```bash
pip install -e ".[intel]"
export ANTHROPIC_API_KEY=sk-ant-...

python -m orthosec.cli scan ./my-ai-app          # scan + executive briefing
python -m orthosec.cli ask  ./my-ai-app "What's our EU AI Act exposure and what would fix it fastest?"
```

Model defaults to `claude-opus-4-8`; override with `ORTHOSEC_MODEL`.

## CI / GitHub integration

```bash
python -m orthosec.cli scan . --sarif results.sarif --fail-on high
```

Upload `results.sarif` via `github/codeql-action/upload-sarif` to surface AI-security findings inline on pull requests. `--fail-on` sets the severity that breaks the build.

## What it detects today (v0.1)

| Detector | OWASP LLM | Catches |
|---|---|---|
| `prompt-hardening` | LLM01 / LLM07 | Untrusted input concatenated into prompts; secrets embedded in system prompts |
| `secrets` | LLM02 | Hardcoded provider/model API keys |
| `unsafe-model-load` | LLM03 / LLM04 | pickle / `torch.load` / unsafe deserialization; unpinned model fetches |
| `tool-exposure` | LLM06 | Over-privileged agent tools (shell, file, HTTP, SQL) with no confirmation gate |

Detectors are plugins — drop a file in `orthosec/detectors/`, decorate with `@register`, done. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

- **v0.1 — Static scanner** *(now)* — the integration model above: point it at any repo, zero runtime coupling.
- **v0.2** — GitHub Action, more detectors (RAG poisoning, output-handling, unbounded consumption), richer compliance packs.
- **v0.3 — Runtime proxy** — inline gateway that catches live prompt injection / data leakage.
- **v0.4 — SDKs** — drop-in Python/JS middleware for per-call telemetry.

## Design

```
Target AI app ──▶ DETECTORS (deterministic) ──▶ Findings (evidence + OWASP + ATLAS)
                                                      │
                        ┌─────────────────────────────┤
                        ▼                             ▼
                 RISK SCORING                   INTEL LAYER (LLM, grounded)
                 posture 0-100          business $risk · compliance · exec Q&A
                        └──────────────▶ REPORT (console / JSON / SARIF)
```

## Status

Pre-release, building toward product-market fit. Feedback, issues, and detector contributions are the whole point right now — [open an issue](https://github.com/orthosec/orthosec/issues).

## License

Apache-2.0.
