# Changelog

All notable changes to OrthoSec are documented here. Versions follow semver.

## [Unreleased]

### Added
- **TypeScript / JSX AST analysis** (`orthosec[ts]`, tree-sitter) — `.ts`/`.tsx`/`.jsx`
  (and `.js`) are parsed to a real syntax tree so LLM05 (model output → eval/`Function`/
  shell/`innerHTML`/`dangerouslySetInnerHTML`/SQL) and LLM10 (uncapped completion) key on
  actual call nodes and dataflow, not line proximity — a string or comment mentioning
  `.innerHTML`/`.create()` no longer fires. Framework-aware (LangChain/LlamaIndex/OpenAI/
  Anthropic call shapes, receiver-gated generic verbs). Falls back to regex with no crash
  when the extra isn't installed. Closes the TypeScript coverage gap for LLM05/LLM10.
- **AI dependency supply-chain audit** (`dependency-audit`, LLM03) — reads
  `requirements*.txt` and `package.json` (not just code) and flags AI/ML dependencies
  that are **unpinned** (non-reproducible resolve → a compromised release gets pulled)
  or installed from an **untrusted source** (git/URL/alternate index → dependency
  confusion). Scoped to AI/ML packages to stay on-topic and quiet. 11 detectors now;
  benchmark 46 cases, 100% / 0 FP.
- **Framework-aware taint tracking** — the AST engine now recognizes model output from
  LangChain / LlamaIndex / OpenAI / Anthropic call shapes (`chain.invoke`,
  `query_engine.query`, `agent.run`, `chat.completions.create`, …) and untrusted input
  from Flask / FastAPI / Django request objects (`request.form`, `flask.request`, …).
  Generic verbs (`run`/`query`/`call`) are receiver-gated so `db.query()` /
  `executor.run()` are **not** mistaken for model output — recall up, precision held.
- **Taint-path traces** — every dataflow finding (LLM01/05/06) now carries the
  propagation chain (`source → flows-through → sink`), reconstructed from the AST.
  Rendered as a "Data flow" block in the HTML report and as SARIF `codeFlows`, so
  GitHub code scanning shows *how* tainted data reaches the sink, not just the sink
  line. Turns "trust me" into a visible, reviewable path.
- **Confidence surfaced + risk ranking** — findings are ordered by severity **then
  detector confidence** (highest-signal first). The report shows a high/medium/low
  confidence pill per finding; SARIF carries a `rank` (severity × confidence) so CI
  can sort by risk.
- **Deterministic code fixes** — `orthosec remediate --auto` now applies safe,
  LLM-free fixes for well-understood cases (`torch.load` → `weights_only=True`,
  `yaml.load` → `yaml.safe_load`) with a precise one-line edit — no API key needed,
  fully reproducible. LLM-drafted patches remain the fallback for everything else.
- **Fix verification** — after any applied fix, OrthoSec re-scans the file and reports
  whether the finding is **RESOLVED** and whether the patch **introduced** new findings,
  closing the remediation loop. `--no-verify` skips it.
- **PR-native GitHub Action** — the bundled action is now a composite action that
  `pip install`s OrthoSec from PyPI (no Docker build). On a pull request it scans only
  the changed files (`--diff` vs the PR base SHA); on push it runs a full scan. Either
  way it writes SARIF and the workflow uploads it to GitHub code scanning, so findings
  surface inline on the PR and dedupe across runs via `partialFingerprints`. New action
  inputs: `diff-ref`, `baseline`, `version`.
- **HTML report polish** — the report now shows a stacked severity-distribution bar, an
  OWASP LLM Top-10 coverage strip (each category colored by its worst finding, dimmed
  when clean), and a Print / Save-as-PDF button (print-optimized styles).
- **Full OWASP LLM Top-10 coverage** — added the last two dedicated detectors:
  - **LLM07 `prompt-leakage`** — a system prompt written to logs / stdout (AST dataflow
    for Python; `console.log` regex for JS). Returning the prompt to the LLM is not flagged.
  - **LLM09 `misinformation`** (advisory, INFO) — ungrounded model output returned to
    users in a **high-stakes domain** (medical / legal / financial). Gated to those
    domains so it doesn't flood normal chatbots; static analysis can't judge truth,
    so it's an advisory to add grounding, not a defect.
  Now 10 detectors; benchmark 42 cases, 20/20, 0 FP across all ten categories.
- **Baseline suppression** — `orthosec scan --write-baseline FILE` records current
  findings; `--baseline FILE` suppresses them so CI gates on **new** findings only.
  Matches by a stable fingerprint (rule + file + evidence, not line number), so
  shifting code doesn't resurface a finding. Makes adoption on an existing codebase
  practical.
- **Inline suppression** — `# orthosec: ignore` (or `# orthosec: ignore LLM03,ORTHO-PI-001`)
  on a finding's line, or a standalone comment immediately above it, suppresses it.
- **`--diff` mode** — `orthosec scan . --diff [REF]` scans only files changed vs git
  (default HEAD; or a branch), for fast pre-commit / PR gating.
- **LLM04 detector** (`data-poisoning`) — flags fine-tuning jobs and training on data
  drawn from untrusted sources (web fetch, upload, user input) without verification.
  Added to the benchmark (now 8 detectors, 16/16, 0 FP).
- **SARIF `partialFingerprints`** — each result carries a stable fingerprint so GitHub
  code scanning dedupes findings across runs and line moves.

## [0.6.2]

### Added
- **LLM06 cross-module** — a model tool that delegates to a dangerous sink in an
  *imported* module is now caught (project-wide call-graph reachability). All three
  dataflow detectors (LLM01/05/06) are now interprocedural + cross-module.
- **Auto-generated report** — every `orthosec scan` writes the detailed HTML report
  to `orthosec-report.html` by default (`--html` to relocate, `--no-report` to skip).
- **Scheduling** — `orthosec watch <path> --every 1d` re-scans on a cadence, writing
  `report-<ts>.html` + `latest.html`/`latest.json` (daily report or continuous).
  `orthosec schedule` prints crontab / GitHub Actions / systemd snippets. All
  defaults are `.env`-controllable (`ORTHOSEC_WATCH_EVERY`, `ORTHOSEC_REPORT_DIR`,
  `ORTHOSEC_CRON`, `ORTHOSEC_PROFILE`); CLI flags override.
- **Optional JavaScript AST** (`orthosec[js]`, esprima) — plain `.js` is parsed to an
  AST so LLM10/LLM05 key on real call nodes and dataflow, not line proximity (a
  string or comment mentioning `.create()` is no longer flagged). TypeScript/JSX
  falls back to regex automatically.
- **Re-export chains** — `from pkg import f` resolves through a `pkg/__init__.py`
  that re-exports `f` from a submodule; package imports resolve to `__init__`.

### Performance
- Cross-module index build ~2× faster (90s → ~47s on a 3,832-file repo): functions
  with no sink/prompt skip the expensive per-parameter dataflow analysis.

### Changed
- **Cross-module import resolution by relative module path** (not filename stem):
  ambiguous imports (two files sharing a name) are left unresolved rather than linked
  to the wrong file — no wrong-file false positives; `from a.b import` and relative
  imports resolve. All three dataflow detectors now also cross-module (LLM06 added).
- **Architecture diagram** is now a hand-drawn SVG (`docs/architecture.svg`), not Mermaid.

### Fixed (real-world validation hardening)
Scanning AutoGPT, openai-cookbook, anthropic-quickstarts, llama_index, langchainjs,
and chroma (~8,000 files, 0 crashes) surfaced and fixed **eight** false-positive
classes; core benchmark still 100% / 0 FP. See `VALIDATION.md`. Round 1 (five):
LLM10 non-calls (mock/string/docstring), DB `upsert` as RAG, `.execute()` as SQL,
test-fixture secrets → LOW, `innerHTML` reads / doc files. Round 2 (three): env-var
**names** flagged as secrets, bundled/minified/lockfile skipping, and bare
`llm.complete()` LLM10 → LOW (cap usually on the client). 20+ precision regression tests.
- LLM10 rewritten AST-based: ignores mock assignments, string literals, and docstrings
  that merely mention an LLM method (AutoGPT 117 -> 12).
- rag-trust (LLM08) requires real vector-store context — no longer flags DB `upsert`.
- SQL sink gated to a DB-ish receiver — no longer flags `block.execute(...)`.
- Secrets in test/fixture/example paths reported at LOW severity, not CRITICAL.
- output-handling: `innerHTML` only on write (not reads); injection scanning skips
  `.md`/`.txt` documentation.

## [0.6.1]

### Added
- **AST dataflow analysis for Python** (`orthosec/analysis/`) — resolves which
  functions are model-invokable tools (decorator, `func=`/`fn=` ref, or tool-def
  dict) and finds dangerous sinks inside them at any line distance, with a
  confirmation-gate check.
- **AST taint tracking for LLM05** — follows model output through reassignments
  and attribute chains into eval/exec/shell/SQL/template sinks, firing only when
  the sink's *actual argument* is tainted (fewer false positives than proximity;
  catches sinks at any distance). Replaces the Python regex path; JS/TS keeps regex.
- **AST taint tracking for LLM01** — traces untrusted input (user params, `input()`,
  `request.*`) into a system-prompt construction, respecting trust-boundary language;
  fires only when tainted data actually reaches the prompt. Python path; other file
  types keep regex. Completes AST dataflow for all three dataflow-shaped detectors
  (LLM01, LLM05, LLM06).
- **Interprocedural analysis for all three dataflow detectors** (intra-file
  call graph): LLM05 model output passed to a helper that sinks the parameter;
  LLM06 a tool that delegates to a helper holding the dangerous sink (transitive
  capability reachability); LLM01 untrusted input passed to a helper that builds
  the system prompt. Each fires only when the real data reaches the real sink.
- **Cross-module taint** (`orthosec/analysis/project.py`) — a project-wide index
  resolves imports (`from mod import f`, `import mod` → `mod.f()`) and links a
  tainted argument in one module to a dangerous parameter in another, for LLM01
  (untrusted input → imported prompt builder) and LLM05 (model output → imported
  sink helper). Built once per scan, memoized on the context. Guarded by
  `tests/test_crossfile.py`.
- **Adversarial benchmark set** (`benchmark/adversarial/`, `--adversarial`) — evasion
  and false-positive-stress cases. Now 14/14 handled, 0 known-miss. Guarded by
  `tests/test_benchmark.py` + `tests/test_analysis.py`.

### Fixed
- **Excessive-agency (LLM06)** now catches a dangerous sink far from its tool
  registration (was a documented miss) — via the new AST analysis, with higher
  precision than the old window heuristic.
- **Secrets detector** now catches a provider key split across string concatenation
  (`"sk-proj-" + "..."`), a common single-literal-regex evasion (rule `ORTHO-SECRET-002`).
  Both fixes were found by the adversarial set. Core benchmark stays 100% / 0 FP.

## [0.6.0]

### Added
- **Runtime gateway** (`orthosec proxy`) — inline stdlib proxy between app and provider.
  `block` refuses injected requests before they reach the model; `monitor` logs them.
  Responses scanned for leaks / payloads. Provider-agnostic (OpenAI + Anthropic),
  `X-OrthoSec-*-Risk` headers, JSON audit log. Verified with a forward/block round-trip test.
- **Distribution** — PyPI packaging polished (classifiers, project URLs, `py.typed`);
  npm package `@orthosec/guard`; `PUBLISHING.md` with the publish commands.
- **Detection-efficacy benchmark** (`benchmark/`) — 30 labeled cases (vulnerable +
  safe look-alikes); harness reports precision/recall/F1 per detector (currently
  100%/100%, zero FP). `tests/test_benchmark.py` gates quality at ≥95% / 0 FP.

## [0.5.0]

### Added
- **Runtime SDK guard** (`orthosec.sdk`) — `@guard` decorator and `scan_prompt()` /
  `scan_output()` to catch prompt-injection and unsafe-output patterns at call time,
  in any Python AI app. The runtime integration path, framework-agnostic.
- **LLM10 detector** (`unbounded-consumption`) — flags LLM calls with no output cap,
  unbounded ret/agent loops, and missing timeouts (denial-of-wallet / DoS).
- **Richer compliance packs** — expanded EU AI Act articles plus ISO/IEC 27001 Annex A
  and NIST CSF 2.0 control mappings.
- **GHCR release pipeline** — tagged releases publish `ghcr.io/cloudivian-org/orthosec`.

## [0.4.0]

### Added
- **Remediation agents** (`orthosec.remediation`) — each finding routes to a specialized
  fix agent with a deterministic plan; opt-in LLM auto-fix (`orthosec remediate --auto`)
  applies a minimal patch with a `.orig` backup. Rotation/provenance stay manual.
- **Formatted HTML report** — executive briefing renders markdown → HTML; per-finding
  remediation agents; select findings to build a `remediate` command.

## [0.3.0]

### Added
- **Visual HTML report** (`--html`) — self-contained, theme-aware, profile toggle.
- **Integration surface** — `.orthosec.yml` project config, GitHub Action, `INTEGRATION.md`,
  scanner `exclude` support.

## [0.2.0]

### Added
- **Audience profiles** (`--profile engineer|appsec|ciso|product`).
- **Detectors** — `output-handling` (LLM05), `rag-trust` (LLM08).
- **Provider-agnostic intel** — Anthropic API + Azure AI Foundry, auto-selected.
- Zero-dep `.env` loader; Dockerfile.

## [0.1.0]

### Added
- Deterministic scanner: `prompt-hardening` (LLM01/07), `secrets` (LLM02),
  `unsafe-model-load` (LLM03/04), `tool-exposure` (LLM06).
- OWASP LLM Top-10 + MITRE ATLAS taxonomy; posture score; compliance + business-risk
  intel; grounded LLM executive briefing; console/JSON/SARIF output.
