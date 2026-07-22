# Changelog

All notable changes to OrthoSec are documented here. Versions follow semver.

## [Unreleased]

### Added
- **AST dataflow analysis for Python** (`orthosec/analysis/`) — resolves which
  functions are model-invokable tools (decorator, `func=`/`fn=` ref, or tool-def
  dict) and finds dangerous sinks inside them at any line distance, with a
  confirmation-gate check. Replaces the line-proximity heuristic for Python;
  JS/TS keeps the regex path.
- **Adversarial benchmark set** (`benchmark/adversarial/`, `--adversarial`) — evasion
  and false-positive-stress cases. Now 7/7 handled, 0 known-miss. Guarded by
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
