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

## Audience profiles — one scan, four lenses

The same findings, reframed for whoever is reading. `--profile` controls what the report shows, the severity floor, and how the executive briefing is written.

```bash
python -m orthosec.cli scan ./my-ai-app --profile engineer   # default: every issue + fix
python -m orthosec.cli scan ./my-ai-app --profile appsec     # attack paths, ATLAS, CI gates
python -m orthosec.cli scan ./my-ai-app --profile ciso       # posture, $risk, compliance — no line noise
python -m orthosec.cli scan ./my-ai-app --profile product    # must-fix-before-ship vs. fast-follow
```

| Profile | Audience | Emphasis |
|---|---|---|
| `engineer` | AI/ML Engineer | Evidence + remediation on every finding |
| `appsec` | Security / AppSec Engineer | Attack path, MITRE ATLAS, what to gate in CI |
| `ciso` | CISO / Security Leader | Posture, dollar risk, regulatory exposure |
| `product` | AI Product / Eng Leader | Risk vs. ship velocity, quick wins |

`python -m orthosec.cli profiles` lists them.

## The executive layer

The core scan runs offline. Add the intel layer for board-ready narrative + free-form Q&A:

```bash
pip install -e ".[intel]"
cp .env.example .env      # then put your key in .env

python -m orthosec.cli scan ./my-ai-app --profile ciso
python -m orthosec.cli ask  ./my-ai-app "What's our EU AI Act exposure and what would fix it fastest?"
```

**Configuration (`.env`)** — copy `.env.example` to `.env`. Real environment variables always win over the file.

- **Anthropic API** — set `ANTHROPIC_API_KEY`. Model defaults to `claude-opus-4-8` (`ORTHOSEC_MODEL` overrides).
- **Azure AI Foundry** (Claude via the Anthropic Messages API) — set `AZURE_API_KEY`, `AZURE_BASE_URL`, and `AZURE_MODELS` (e.g. `claude-sonnet-4-6`). OrthoSec auto-selects the Azure backend when these are present.

The intel layer is provider-agnostic and degrades to a deterministic briefing (posture, $risk, compliance) when no key is set — the core product never depends on it.

## Docker

```bash
docker build -t orthosec .
docker run --rm -v "$PWD:/scan" orthosec scan /scan --profile ciso
# with the exec layer:
docker run --rm --env-file .env -v "$PWD:/scan" orthosec scan /scan --profile ciso
```

## Visual report

```bash
python -m orthosec.cli scan ./my-ai-app --html report.html
```

A self-contained, theme-aware HTML report (no external requests) with a **built-in profile toggle** — the same file switches between the engineer / appsec / ciso / product views live. Open it in a browser, attach it to a ticket, or drop it in a board deck.

## Integrate with any AI product

OrthoSec matches behavioral patterns, not a specific framework — so it works on LangChain, LlamaIndex, raw provider SDKs, custom agents, or MCP tools alike. Full contract in **[INTEGRATION.md](INTEGRATION.md)**. Four implemented ways in:

1. **CLI** — `python -m orthosec.cli scan .`
2. **Project config** — drop [`.orthosec.yml`](.orthosec.example.yml) at your repo root (profile, `fail_on`, `exclude`).
3. **GitHub Action** — [`.github/workflows/orthosec.yml`](.github/workflows/orthosec.yml); findings post inline on PRs via SARIF.
4. **Python API** — `from orthosec import Scanner`.

```yaml
# .github/workflows/orthosec.yml
- uses: cloudivian-org/OrthoSec@main
  with: { profile: appsec, fail-on: high, sarif-file: orthosec.sarif }
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: orthosec.sarif }
```

Any other CI: `docker run --rm -v "$PWD:/scan" orthosec scan /scan --sarif /scan/orthosec.sarif --fail-on high`.

## What it detects today (v0.1)

| Detector | OWASP LLM | Catches |
|---|---|---|
| `prompt-hardening` | LLM01 / LLM07 | Untrusted input concatenated into prompts; secrets embedded in system prompts |
| `secrets` | LLM02 | Hardcoded provider/model API keys |
| `unsafe-model-load` | LLM03 / LLM04 | pickle / `torch.load` / unsafe deserialization; unpinned model fetches |
| `output-handling` | LLM05 | LLM output flowing unsanitized into eval/shell/SQL/HTML sinks |
| `tool-exposure` | LLM06 | Over-privileged agent tools (shell, file, HTTP, SQL) with no confirmation gate |
| `rag-trust` | LLM08 | Untrusted web/upload content ingested into a retrieval corpus without provenance |

Behavior detectors ignore comments and negation (a `# no confirmation` comment is never read as a mitigation) — false-negative avoidance is a first-class concern.

Detectors are plugins — drop a file in `orthosec/detectors/`, decorate with `@register`, done. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

- **v0.1 — Static scanner** — point it at any repo, zero runtime coupling.
- **v0.2 — Multi-profile + provider-agnostic intel** *(now)* — engineer/appsec/ciso/product views, 6 detectors, Anthropic + Azure Foundry backends, Docker, `.env`.
- **v0.3 — Runtime proxy** — inline gateway that catches live prompt injection / data leakage.
- **v0.4 — SDKs** — drop-in Python/JS middleware for per-call telemetry.
- **Backlog** — GitHub Action, unbounded-consumption (LLM10) + output-XSS detectors, HTML/PDF report export, richer compliance packs.

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
