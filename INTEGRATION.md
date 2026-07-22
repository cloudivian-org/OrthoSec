# Integrating OrthoSec with any AI product

OrthoSec is built to attach to **any** AI product with minimal effort. This page is the concrete contract: what "any AI product" means, and the implemented ways to wire it in today.

## Why it works on any AI product

OrthoSec's detectors match **behavioral patterns**, not a specific framework's API. A prompt built by string concatenation looks the same whether you use LangChain, LlamaIndex, the raw OpenAI/Anthropic SDK, a custom agent loop, or MCP tools. So OrthoSec works across:

- **Frameworks** — LangChain, LlamaIndex, Haystack, Semantic Kernel, DSPy, raw provider SDKs, home-grown agents.
- **Providers** — OpenAI, Anthropic, Azure, Bedrock, Vertex, local models.
- **Languages** — Python, JavaScript/TypeScript today; the taxonomy and engine are language-agnostic and more languages are additive (new detector regexes/patterns).

No SDK to adopt, no code change required for Phase 1. You point it at the code.

## The integration surface (Phase 1 — available now)

### 1. Command line

```bash
python -m orthosec.cli scan /path/to/ai-app --profile appsec
```

Zero dependencies, zero config. This is the fastest way to try it on any repo.

### 2. Project config — `.orthosec.yml`

Drop `.orthosec.yml` at your product's root to declare how OrthoSec scans it (see [.orthosec.example.yml](.orthosec.example.yml)):

```yaml
profile: appsec       # default audience view
fail_on: high         # CI fails at/above this severity
exclude:              # skip vendored code, fixtures, etc.
  - tests/
  - vendor/
```

CLI flags always override the file. Supports `.orthosec.yml`, `.orthosec.yaml`, or `.orthosec.json`.

### 3. CI — GitHub Action (drop-in)

Add [`.github/workflows/orthosec.yml`](.github/workflows/orthosec.yml) to any AI product repo. Findings land inline on the PR via GitHub code scanning:

```yaml
- uses: cloudivian-org/OrthoSec@main
  with:
    profile: appsec
    fail-on: high
    sarif-file: orthosec.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: orthosec.sarif
```

**Any other CI** (GitLab, Jenkins, CircleCI, Buildkite): run the container and consume the SARIF/JSON.

```bash
docker run --rm -v "$PWD:/scan" ghcr.io/cloudivian-org/orthosec \
  scan /scan --fail-on high --sarif /scan/orthosec.sarif
```

### 4. Programmatic API

Embed OrthoSec in your own tooling, platform, or portal:

```python
from orthosec import Scanner
from orthosec.intel.compliance import compliance_exposure
from orthosec.report.html import render_html

result = Scanner(exclude=["tests/"]).scan("/path/to/ai-app")
print(result.score, result.grade)              # posture 0-100
for f in result.findings:
    print(f.severity, f.owasp_llm, f.location)  # structured findings
open("report.html", "w").write(render_html(result, profile="ciso"))
```

Outputs available: console, JSON (`--json`), SARIF (`--sarif`), self-contained HTML (`--html`).

## Runtime integration (roadmap — the contract)

Phase 1 is static (pre-deploy). Two runtime modes are on the roadmap, and the integration contract is deliberately simple:

- **v0.3 — Proxy / gateway.** Point your app's LLM base URL at OrthoSec; it inspects live prompts/responses for injection and data leakage inline, emitting the same `Finding` objects. One config line (`OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL`).
- **v0.4 — SDK middleware.** `from orthosec import guard` wraps LLM calls for per-call telemetry in Python/JS. One decorator.

All three phases speak the same taxonomy (OWASP LLM + MITRE ATLAS) and emit the same `Finding` shape, so dashboards, gates, and reports built on Phase 1 keep working as you add runtime coverage.

## What OrthoSec looks for (framework-agnostic)

| Class | OWASP LLM | Pattern it recognizes anywhere |
|---|---|---|
| Prompt injection surface | LLM01 | Untrusted input concatenated into a prompt without a trust boundary |
| Secret leakage | LLM02 | Provider/model keys committed in source |
| Supply chain | LLM03/04 | pickle/`torch.load`/unsafe deserialization; unpinned model fetches |
| Output handling | LLM05 | Model output into eval/shell/SQL/HTML sinks |
| Excessive agency | LLM06 | Model-invokable tools (shell/file/HTTP/SQL) with no confirmation gate |
| RAG/vector trust | LLM08 | Untrusted content ingested into a retrieval corpus without provenance |

New detectors are plugins — see [CONTRIBUTING.md](CONTRIBUTING.md).
