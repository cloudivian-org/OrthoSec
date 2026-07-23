# Changelog

All notable changes to OrthoSec are documented here. Versions follow semver.

## [Unreleased]

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

### Fixed (real-world validation hardening)
Scanning AutoGPT, openai-cookbook, and anthropic-quickstarts (1,831 files, 0 crashes)
surfaced and fixed five false-positive classes; findings dropped 257 -> 122 with the
core benchmark still 100% / 0 FP. See `VALIDATION.md`. 13 new regression tests.
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
