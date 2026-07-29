# Changelog

All notable changes to OrthoSec are documented here. Versions follow semver.

## [Unreleased]

### Added — performance
- **Process-parallel scanning (`--jobs/-j N`, env `ORTHOSEC_JOBS`).** The taint hot loop is
  pure-Python AST traversal (CPU- and GIL-bound), so scans now shard files across worker
  processes. Each worker emits findings only for its shard but resolves cross-module context
  against the full file set, so results are **byte-for-byte identical to a serial scan** —
  guaranteed by a new `tests/test_parallel.py` that diffs serial vs parallel finding sets
  (including a cross-module case split across shards). Default is auto (parallel on large
  trees, serial on small); `--jobs 1` forces serial. On Linux workers `fork` and inherit the
  prebuilt cross-module index + warm parse cache copy-on-write (no per-worker rebuild);
  macOS/Windows use `spawn` (opt into fork with `ORTHOSEC_PARALLEL_FORK=1`). ~2.5–2.7× on a
  large heavy tree; fully fail-open (any pool problem falls back to a serial scan).

### Fixed — CI
- **py3.9 C# grammar pinned to `tree-sitter-c-sharp==0.23.1`.** Both 0.23.4 and 0.23.5 ship
  binaries missing `_tree_sitter_c_sharp_external_scanner_create`; dlopen fails, the C#
  analyzer silently degrades to regex, and two C# benchmark cases went undetected. It only
  surfaced on the py3.9 CI row (wheel-tag roulette). 0.23.1 is an abi3 wheel covering
  cp39–cp312; benchmark is back to 100%/100%/0 FP on every matrix row.
- **Dogfood gate (`orthosec.yml`) now installs this checkout** instead of the PyPI composite
  action, so it tests the code being committed rather than the last published tag.

## [0.12.3] — 2026-07-29

### Fixed — precision (found by dogfooding OrthoSec on its own code)
- **`unsafe-model-load` now ignores comments.** A `# torch.load(...)` / `# pickle.load(...)`
  mention in a comment no longer fires (it strips comments before matching, like the other
  behavior detectors) — a real general false positive, not just self-referential.
- **OrthoSec now scans itself clean (100/100, grade A).** The remaining self-matches — the
  scanner's own detector *pattern strings* (e.g. `cPickle` in a regex) and two
  `client.messages.create(**base)` calls where `max_tokens` is set via `**base` — are
  documented inline suppressions. The dogfood workflow (`orthosec.yml`) is tightened back to
  `fail-on: high` now that the product source is genuinely clean.

### Added
- **VS Code extension** (`editors/vscode`, v0.2.0). A thin TypeScript client that runs the
  installed `orthosec` CLI (`--json`) and renders its deterministic findings as inline
  diagnostics (squiggles) — scan-on-save plus "Scan Workspace" / "Scan Current File"
  commands and a status-bar count. **Hover** a finding for its OWASP category, severity /
  confidence tier, and fix. **Quick fixes** (💡): *Apply fix* (runs `orthosec remediate
  --auto` for that rule, backs up to `*.orig`, re-scans) and *Suppress* (inserts a
  language-correct `# / // orthosec: ignore <RULE>`). Reuses the real scanner (no analysis
  reimplemented); `orthosec.path` supports `python -m orthosec.cli`. Compiles clean with
  `npm run compile`; package with `vsce`.

## [0.12.2] — 2026-07-29

### Performance
- **~2x faster scans on large repos via a parse cache.** Profiling a LibreChat scan
  (65.8s) showed the same file was parsed ~5× per scan — each dataflow detector and the
  cross-module index re-parsed it. A shared, bounded content-keyed parse cache
  (`orthosec/analysis/_parsecache.py`, wired into every analyzer's `_parse` / `safe_parse`)
  collapses that to one parse per file. **LibreChat: 65.8s → 30.8s (-53%), identical
  findings.** Bounded (clears at 8192 entries) so a long-running `watch` / SDK process can't
  grow unboundedly. Results are unchanged — a parse tree is a pure function of its input.

## [0.12.1] — 2026-07-29

### Fixed — precision
- **LLM10 (uncapped completion) in test/example code is downgraded to INFO.** An uncapped
  LLM call in a `test_*` / `tests/` / `examples/` file is not a production denial-of-wallet
  risk; it now stays visible but out of the gate, the score, and the noise. Surfaced by the
  new random-sample harness (LLM10 dominated a random scan, mostly in test files). Shared
  `is_test_path` helper added to `detectors/_signals.py`. `tests/test_precision.py` +3.

### Added — validation
- **Independent random-sample validation harness** (`validation/random_sample.py`). Searches
  GitHub for public AI repos, takes a **seeded-random** (non-curated) sample, shallow-clones
  and scans each, and reports **measured finding rates** (per detector / severity / KLOC, and
  the share of repos with a HIGH+) as Markdown + JSON. Reproducible: same query + seed → same
  repos, with the exact commit recorded per repo. A `--triage-sample K` mode dumps K random
  findings for manual TP/FP labeling, so precision can be *measured* on a random sample rather
  than asserted. `validation/README.md` documents the methodology and its honest limits.
  Run-specific results (which name individual repos) are gitignored, not published.

## [0.12.0] — 2026-07-25

### Added
- **OSV.dev dependency-CVE enrichment (`ORTHOSEC_OSV=1`).** The `dependency-audit` detector
  now turns "AI/ML dependency pinned to 1.2.3" into "…and 1.2.3 has N known vulnerabilities
  (GHSA-…, CVE-…, PYSEC-…)" by querying the [OSV.dev](https://osv.dev) database for every
  pinned AI/ML dependency (`requirements.txt` / `package.json`). New rule `ORTHO-DEP-003`
  (HIGH) with upgrade guidance. **Deterministic and authoritative** (a public vuln DB, not a
  model), **opt-in** (one network call — keeps the core scan offline by default), and
  **fails open** (a network error leaves the deterministic pin/source findings untouched).
  `orthosec/osv.py` (stdlib-only batch client), `tests/test_osv.py` (7 tests, network mocked).
  Verified live: `langchain==0.0.100` → 45 advisories, `langchain==0.1.0` → 10, a clean
  `openai==1.0.0` → none.

### CI / release hardening
- **CI now enforced.** `ci.yml` runs the test suite + benchmark (`--check` gate, was
  missing) on Python 3.9–3.12 for every push and PR; CI badge re-enabled in the README.
- **Supply-chain-hardened releases.** `release.yml` adds a **SLSA build-provenance
  attestation** (`actions/attest-build-provenance`) for the wheel/sdist, attaches the
  artifacts to the GitHub Release, and publishes to PyPI via **Trusted Publishing (OIDC)**
  with **PEP 740 attestations** — no stored token. Container image still published to GHCR.
- **Self-scan (dogfooding).** `orthosec.yml` scans OrthoSec itself and uploads SARIF to code
  scanning; a repo `.orthosec.yml` excludes the intentional-vuln fixtures (examples,
  benchmark, tests) and the self-scan runs `fail-on: none` (a scanner's own detector code
  contains the patterns it matches). Live sample report (Pages) re-enabled.

## [0.11.3] — 2026-07-25

### Changed — accuracy at scale (validation)
- **Multi-language benchmark.** The detection-efficacy benchmark grew from Python-only
  (46 cases) to **78 cases across all nine languages** — LLM01 + LLM05 pos/safe-lookalike
  cases for TypeScript, Go, Java, Kotlin, C#, Ruby, PHP, and Rust, alongside the full
  Python Top-10. Still **100% precision / 100% recall / 0 FP**, and now CI-gated by
  `tests/test_benchmark.py`, so the multi-language accuracy claim is measured, not asserted.
- **VALIDATION.md refreshed** with the nine-language, ~20-repo validation: the corpus, the
  real true-positives confirmed (langchain4j double-hop SQL retriever, BotSharp SQLi ×2,
  instructor-php system-prompt injection ×8, LibreChat ×3), and the eight false-positive
  classes found and fixed this cycle (each locked by a regression test). Honest about scope:
  curated corpus + self-labeling, with an independently-audited random sample as the stated
  next step.

## [0.11.2] — 2026-07-25

### Added
- **Model-led discovery (`ORTHOSEC_DISCOVER=1`).** A model surfaces *additional* candidate
  findings the pattern/dataflow engine can't see — logic flaws, auth/authz gaps, weak
  crypto, timing attacks, SSRF. These are always **`advisory`**: labelled `model-discovery`
  (`MODEL-DISC-001`), **deduped** against deterministic findings (±2 lines), **excluded
  from the posture score and the `--fail-on` gate** (opt in with `ORTHOSEC_DISCOVER_GATE=1`),
  and confidence 0.5. So models lead discovery for recall while the deterministic set stays
  the reproducible, gated source of truth. Opt-in, capped (`ORTHOSEC_DISCOVER_MAX_FILES`,
  default 8; files ≤24 KB), fail-open. `orthosec/intel/triage.py::discover`,
  `tests/test_triage.py` now 12 tests.
  - `by_severity` and `posture_score` now exclude advisory findings; `_exit_code` skips
    them unless `ORTHOSEC_DISCOVER_GATE`. The console shows a `+ N advisory (not scored)`
    line and an `~advisory` badge.
  - Demoed live: on an auth file with no LLM-dataflow issues (score 100/A) the model found
    4 real issues (MD5 hashing, non-constant-time compare, client-trusted `is_admin` admin
    bypass) — all advisory, score unchanged.

## [0.11.1] — 2026-07-25

### Added
- **Confidence tiers for detection (model corroboration).** Every finding now carries a
  `confidence_tier`: `deterministic` (default — the reproducible, trusted floor). With a
  model backend configured and `ORTHOSEC_CONFIDENCE=1`, an opt-in pass
  (`orthosec/intel/triage.py`) asks the model to corroborate each finding against its code
  context and raises agreed findings to **`confirmed`** (with a reason), or attaches a
  "possible false positive" note for human review. **Additive by design:** a model can
  confirm or comment, but never removes or downgrades a deterministic finding and never
  invents one — the deterministic engine stays the arbiter, preserving the 0-FP guarantee.
  Fails open (model error → plain deterministic results). Tier is surfaced in the console
  report, JSON, and SARIF (`confidence-tier` property). `ORTHOSEC_CONFIDENCE_MAX` caps how
  many findings are corroborated (default 40). `tests/test_triage.py` (7 tests).
  This is the "models confirm, deterministic decides" half of the finding-side design —
  models add insight on detection without becoming the arbiter.

## [0.11.0] — 2026-07-25

### Added
- **Verify-gated remediation cascade — `remediate --auto` now tries fix strategies in
  order and re-scans after every attempt.** A candidate is kept only if the re-scan
  confirms the finding is **resolved with no new HIGH/critical regression**; otherwise it
  is **reverted** and the next strategy runs. Strategies: (1) deterministic codemod,
  (2) local security model (Foundation-Sec-8B via `ORTHOSEC_LOCAL_MODEL_URL`), (3) cloud
  model (Anthropic/Azure) — a true fallback chain. The re-scan is the auto-catch: a fix
  that doesn't verify is undone, not shipped. `*.orig` backup is written only when a fix
  is kept. `tests/test_remediation_cascade.py` (5 tests: deterministic success, revert on
  unverifiable fix, fall-through to the next strategy, and ordering).
- **`ORTHOSEC_FIX_ORDER` posture** — `deterministic-first` (default, most reproducible) or
  `model-first` to try the models ahead of the deterministic codemod. Realizes the
  "strongest-first, auto-catch-and-fall-back" model while keeping the deterministic engine
  as the verification arbiter.
- `autofix.suggest_patch(finding, text, client, model)` now accepts an explicit backend;
  `narrative._resolve_cloud_client_and_model()` added so the cascade can fall back from a
  local model to a cloud model as a distinct, independently-verified strategy.

## [0.10.4] — 2026-07-25

### Added
- **Output-side runtime guard (model-backed) — symmetric to the prompt guard.**
  `scan_output` / `@guard` / `proxy` can now consult an optional local model to catch
  **sensitive data (PII, secrets, credentials) or unsafe content in model output** before
  it reaches a user or a downstream sink — Llama Guard via Ollama, a PII/leak classifier,
  or any OpenAI-compatible endpoint. Independent config: `ORTHOSEC_OUTPUT_MODEL_URL`
  (+ `_KIND`/`_MODEL`/`_THRESHOLD`/`_TIMEOUT`/`_API_KEY`). Same guarantees as the input
  guard — **opt-in, additive, fail-open**: the model only *adds* a signal, never removes a
  deterministic regex hit, and any error degrades to regex so a guarded call is never
  broken. `model_guard.py` refactored to a shared classifier core (`ModelVerdict.flagged`);
  `tests/test_model_guard.py` now 16 tests (input + output).

## [0.10.3] — 2026-07-25

### Added
- **Optional Semgrep engine — a deterministic complement to the built-in detectors.**
  Enable with `pip install "orthosec[semgrep]"` + `ORTHOSEC_SEMGREP=1` to broaden coverage
  to general code-security patterns (command injection, TLS bypass, auth mistakes, …) that
  sit outside OrthoSec's LLM-dataflow surface. Results map straight onto OrthoSec findings,
  score, and report. **Opt-in and zero-cost when off** (the detector returns immediately
  unless the flag is set and the `semgrep` binary is present), and fully **deterministic**
  — no probabilistic false-positive risk. Ships a small bundled starter ruleset
  (`orthosec/rules/semgrep/ai-security.yaml`); point `ORTHOSEC_SEMGREP_CONFIG` at a larger
  config (`p/security-audit`, a path, custom rules) to go broader.
  `orthosec/detectors/semgrep_scan.py`, `tests/test_semgrep.py` (10 tests incl. a real
  `semgrep --validate` check of the bundled rules). Validated end-to-end against real
  semgrep (shell=True / verify=False / mktemp correctly flagged; clean code not).

## [0.10.2] — 2026-07-25

### Added
- **Local / self-hosted model backend for the intel + remediation layer (Foundation-Sec-8B
  and friends).** Set `ORTHOSEC_LOCAL_MODEL_URL` to an OpenAI-compatible chat endpoint you
  run yourself (Ollama `/v1`, vLLM, llama.cpp) and the executive briefing, `ask`, and
  `remediate --auto` all run on a **local** model — source code never leaves the machine.
  Ideal for a security-specialized model like Foundation-Sec-8B. `orthosec/intel/local_backend.py`
  presents the Anthropic-Messages surface over the OpenAI chat API, so nothing downstream
  changes; it's the **highest-precedence** backend (local → Azure → Anthropic) and needs
  **no `anthropic` dependency** (stdlib-only HTTP). Env: `ORTHOSEC_LOCAL_MODEL`,
  `ORTHOSEC_LOCAL_API_KEY`, `ORTHOSEC_LOCAL_TIMEOUT`. `tests/test_local_backend.py` (8 tests).
  - The trust contract is unchanged: deterministic fixes are still preferred, LLM patches
    stay opt-in (`--auto`) and re-scan-verified, and the model never invents a finding.

## [0.10.1] — 2026-07-25

### Added
- **Optional model-backed prompt-injection check for the runtime guard (experimental,
  opt-in, local-first).** `scan_prompt` / `@guard` / `proxy` can call a model you run
  yourself — Meta Prompt Guard (classifier), Llama Guard via Ollama, or any
  OpenAI-compatible endpoint — to raise recall on novel injections
  (`orthosec/model_guard.py`). Enabled only when `ORTHOSEC_GUARD_MODEL_URL` is set;
  configured via `ORTHOSEC_GUARD_MODEL_KIND` (`classifier`/`ollama`/`openai`),
  `ORTHOSEC_GUARD_MODEL`, `ORTHOSEC_GUARD_THRESHOLD`, `ORTHOSEC_GUARD_TIMEOUT`,
  `ORTHOSEC_GUARD_API_KEY`. **Additive and fail-open by design:** the model can only add a
  signal — it never removes a deterministic regex hit, never becomes a source of a static
  finding, and any error/timeout degrades silently to regex so a guarded call is never
  broken. Stdlib-only (no new dependencies). `tests/test_model_guard.py` (10 tests). This
  is the first step of integrating security-specialized OSS models while preserving the
  deterministic-core trust model.

### Fixed
- **Rust grammar ABI robustness.** `rust_ast.available()` now verifies the grammar actually
  *parses* (not just imports), so an ABI-mismatched wheel degrades to the regex fallback
  instead of emitting garbage findings. `tree-sitter-rust` pinned `<0.23.3` (0.23.3+ require
  a newer tree-sitter core than the floor).

## [0.10.0] — 2026-07-25

### Added
- **Rust language support (`orthosec[rust]`, tree-sitter) — the 9th language and the last
  roadmap language.** `.rs` files get full AST taint for **LLM05** (model output into
  `Command::new`/`.arg` shell exec, `sqlx::query` / `sql_query` / `conn.execute` raw SQL,
  `Html(…)` XSS) and **LLM01** (untrusted input into a `.preamble()` / `.system()` builder
  or a `system_prompt` binding), with intra-function + **interprocedural** + **cross-module**
  depth — framework-aware of async-openai, rig, ollama-rs, genai. Sanitizers
  (`shell_escape::escape`, `html_escape::encode`) and parameterized `sqlx::query("…").bind()`
  are recognized as safe. `orthosec/analysis/rust_ast.py`, `tests/test_rust_ast.py` (15 tests).
  - **Validated FP-free on 6 real Rust repos** (rig, graniet/llm, langchain-rust, orch,
    fireside-chat, smartgpt; ~1,700 `.rs`). Fixed two false-positive classes found there:
    an internal `completion_request` struct name matching the untrusted-input seed (rig: 24
    → 0 LLM01), and an inline sanitizer at a sink not clearing taint. Redis `.arg()` is
    correctly not treated as shell.
- **Host-aware token username for private clones.** `orthosec scan <private-url>` now picks
  the right default token username per host — `x-access-token` (GitHub), `oauth2` (GitLab),
  `x-token-auth` (Bitbucket) — still overridable with `--git-username`.

### Packaging
- `tree-sitter-rust` pinned `<0.24` (0.24.x targets a newer tree-sitter core ABI).

## [0.9.2] — 2026-07-25

### Added
- **Scan remote and private repositories directly.** `orthosec scan` now accepts a git
  URL or `owner/repo` shorthand in addition to a local path (`orthosec/gitclone.py`). It
  shallow-clones into a temporary directory, scans, and removes the clone afterward.
  - **Auth, safest-first:** SSH URLs use the ssh-agent; HTTPS uses the user's existing git
    credential helper (gh / keychain) by default; an explicit token can be supplied via
    `--git-token-stdin` (read from stdin) or `ORTHOSEC_GIT_TOKEN` / `GITHUB_TOKEN` /
    `GH_TOKEN` / `GITLAB_TOKEN`.
  - **Credentials never leak:** a token is passed to git only through `GIT_ASKPASS` and the
    child-process environment — never in the clone URL, argv (`ps`), or any log line; URLs
    are redacted before printing. `GIT_TERMINAL_PROMPT=0` avoids hanging on a prompt.
  - New flags: `--branch`, `--git-token-stdin`, `--git-username` (default `x-access-token`),
    `--keep-clone`. `tests/test_gitclone.py` (12 tests) incl. a check that the token never
    reaches argv and a real local clone round-trip.

## [0.9.1] — 2026-07-25

### Fixed — precision (false positives found stress-testing less-mature public repos)
- **`regex.exec()` is no longer mistaken for `child_process.exec` (shell).** A method
  call like `/pattern/.exec(x)` or `str.exec(x)` has a member-expression callee, not a
  bare `exec` identifier, so the TS shell/eval/SQL sinks and interprocedural resolution
  now fire only for true bare-identifier calls (and a `child_process`-ish receiver for
  exec/spawn). This removed 51 → 0 false LLM05 HIGHs on LibreChat.
- **Cross-module method resolution is gated to static, capitalized receivers**
  (`Sink.run(x)`), never instance/regex method calls (`obj.run(x)`, `regex.exec(x)`), in
  Java/Kotlin/C# — preventing method-name collisions across files.
- **Parameterized SQL is no longer flagged (LLM05, Python).** `cursor.execute(sql, params)`
  binds `params` safely; taint is now checked only against the query-string argument, so
  `execute("… VALUES (?)", (model_output,))` is clean while an f-string query still fires.
- **Assigning tainted data to `self.x` no longer poisons the object (Python).** Taint
  propagates only to simple `name`/tuple bindings, not to the root of an attribute/subscript
  target (`self.state.x = out`) — which had wrongly tainted every later `self.*` read (e.g.
  an i18n system prompt built from `self.agent.role`).
- **`<textarea>`/`<title>` `.innerHTML` decode idiom is recognized as safe (LLM05, TS).**
  Setting `.innerHTML` on a detached `createElement('textarea')` element to decode HTML
  entities is RCDATA (script-inert), not XSS.
- **Filesystem-path variables are no longer mistaken for model output (LLM05, Python).**
  The output name-seed no longer matches `output_wav_path`, `output_dir`, `output_csv`,
  `output_file`, etc. (a path is not an LLM response) — `output`, `outputs`, `output_text`
  still seed. Fixed a hardcoded-ffmpeg `subprocess.run` flagged as LLM shell on openai-cookbook.
- **The LLM01 regex fallback now respects message roles.** When the AST path is
  unavailable (a target file uses newer Python syntax than the host interpreter — OrthoSec
  supports 3.9+), untrusted input inside a `"role": "user"` message is no longer flagged;
  only untrusted → system prompt fires, matching the AST path. (Found on gpt-researcher
  under Python 3.9.) Running OrthoSec on Python 3.11+ is recommended for full AST precision.

### Fixed — packaging
- Pinned `tree-sitter-c-sharp` to a build compatible with `tree-sitter` 0.23.x (the 0.23.5
  wheel ships a broken external-scanner binding on some platforms).

### Validation
- Re-validated on 20 public repos (LibreChat, chatbot-ui, crewAI, gpt-researcher, fabric,
  BotSharp, langchain4j, instructor-php, …). Key true positives intact: langchain4j
  double-hop SQL retriever, BotSharp SQLi (×2), instructor-php system-prompt injection (×8).

## [0.9.0] — 2026-07-25

### Added
- **Cross-module (cross-file) taint for all eight tree-sitter languages** — the last
  Python-parity depth gap. Model output tainted in file A, passed to a helper **defined
  in file B** that sinks the parameter, is now flagged (TypeScript/JS, Go, Java, Kotlin,
  C#, Ruby, PHP). A shared, per-language project index (`orthosec/analysis/_crossmod.py`)
  is built once per scan (memoized on the scan context) and fed to the interprocedural
  engine as extra function summaries.
- **Unambiguous-only resolution** keeps it false-positive-safe: a function name defined
  in exactly one file resolves across files; a name defined in several files is left
  unresolved rather than linked to the wrong one (the rule the Python engine already
  uses). Method calls (`Helper.run(x)` in Java/Kotlin/C#) resolve by method name under
  the same guard.
- **Milestone — full depth parity across 8 languages.** OrthoSec's tree-sitter analyzers
  now match the Python engine's dataflow depth: **intra-function + interprocedural +
  cross-module** taint for LLM05, plus **LLM01** (untrusted-input→prompt), across Python,
  TypeScript/JS, Go, Java, Kotlin, C#, Ruby, and PHP. Validated on 10 real repos with
  **0 new false positives** (perf: langchaingo 4.5s, semantic-kernel 32s); benchmark
  100% / 0 FP, adversarial 14/14, 256 tests.

## [0.8.3] — 2026-07-25

### Added
- **LLM01 (prompt injection) for all eight tree-sitter languages** — untrusted input
  reaching a **system prompt** is now caught in TypeScript/JS, Go, Java, Kotlin, C#,
  Ruby, and PHP (the Python engine already did this). Untrusted = user-ish function
  params or real request reads (`req.body`, `params[:x]`, `$_POST`, `request.getParameter`,
  `$request->input()`); sink = a `systemPrompt`-named assignment or a `role:"system"`
  message (JS object / Go `ChatCompletionMessage{Role: ...System}` / Ruby hash / PHP
  array / Java-Kotlin `SystemMessage(...)` / C# `SystemChatMessage(...)`) whose content
  references the untrusted value. Wired through a generic per-suffix dispatch in the
  prompt-hardening detector.
- **Precision is enforced, not assumed.** User input in a *user* message does not fire
  (that's normal); trust-boundary language ("treat as data, not instructions") suppresses
  the scope. Validated on 10 real repos (ai-chatbot, langchaingo, langchain4j, spring-ai,
  semantic-kernel, BotSharp, discourse-ai, langchainrb, instructor-php, LLPhant), which
  drove several precision fixes so the frameworks stay clean: typed-DTO params named
  `request`/`message`/`ChatMessage` are not treated as untrusted text (they're not raw
  user input), a bare `$request->messages()` DTO call is not a request read, and C#/Java
  object-initializer / constructed-domain-object shapes don't trip the system-prompt-name
  heuristic. Real prompt-injection true positives are surfaced — e.g. instructor-php's
  thought-generation examples embed a user `{$query}` into a `role:'system'` message.
  Benchmark 100% / 0 FP, adversarial 14/14, 248 tests.

## [0.8.2] — 2026-07-24

### Added
- **Interprocedural taint for Go, Java, Kotlin, C#, Ruby, and PHP** (LLM05) — completing
  the depth rollout begun with TypeScript in 0.8.1. All eight tree-sitter languages now
  follow model output **across local function calls** within a file, via a shared engine
  (`orthosec/analysis/_interproc.py`): a helper that returns model output taints the
  caller's variable, and model output passed to a local helper whose parameter reaches a
  sink is flagged at the call site. Sanitizers, per-function scoping, and each language's
  precision fixes are preserved.
- This immediately paid off on a real repo: scanning **langchain4j** surfaced a genuine
  finding the intra-function analyzer couldn't see — its experimental
  `SqlDatabaseContentRetriever` runs **LLM-generated SQL** through a local `execute(sqlQuery,
  statement)` helper into `statement.executeQuery(...)`. Validation across langchaingo,
  langchain4j, BotSharp, semantic-kernel, discourse-ai, langchainrb, instructor-php,
  LLPhant and ai-chatbot showed **0 new false positives** and BotSharp's real LLM→SQLi
  findings intact. Benchmark 100% / 0 FP, adversarial 14/14, 213 tests.

## [0.8.1] — 2026-07-24

### Added
- **Interprocedural taint for TypeScript** (LLM05) — the first tree-sitter language to
  gain the multi-function depth the Python engine already has. Within a `.ts`/`.tsx`/`.js`
  file, model output is now followed **across local function calls**:
  - **return-value**: a helper that `return`s model output (e.g. `getAnswer()` →
    `model.invoke(...)`) taints the caller's variable, so `const a = getAnswer(); el.innerHTML = a`
    is caught (fixpoint, so chains of output-returning helpers count).
  - **parameter-sink**: model output passed to a local helper whose parameter reaches a
    sink is flagged at the call site (e.g. `sink(out)` where `function sink(x){ execSync(x) }`).
  Precision held — a non-model value through the same helper does not fire; sanitizers and
  per-function scoping still apply. Verified on vercel/ai-chatbot (still clean, Grade A).
  Go / Java / Kotlin / C# / Ruby / PHP interprocedural, then cross-module + LLM01, follow
  the same template next.

## [0.8.0] — 2026-07-24

### Added
- **Ruby + PHP language support** (`orthosec[ruby]` / `orthosec[php]`, tree-sitter) —
  languages #6 and #7, completing the roadmap's top seven AI-product languages beyond
  Python. `.rb` and `.php` files are parsed to a real AST for **LLM05**:
  - **Ruby** — model output into `system`/`exec`/`spawn` or `` `…` `` (shell), raw SQL
    (`execute`, `find_by_sql`, `exec_query`), `eval`/`instance_eval`, or `raw`/`html_safe`
    (XSS). Aware of ruby-openai (`client.chat(...).dig("choices"…"content")`) and
    langchainrb shapes.
  - **PHP** — model output into `exec`/`shell_exec`/`system`/`passthru` (shell), raw SQL
    (`$pdo->query`, `$db->exec`, Laravel `whereRaw`/`DB::statement`), `eval`, or `echo`
    (XSS). Aware of openai-php (`$client->chat()->create(...)->…->content`) and LLPhant.
  Both are per-function-scoped and sanitizer-aware (`CGI.escape`/`sanitize` for Ruby,
  `htmlspecialchars`/`escapeshellarg` for PHP). `.rb`/`.php` are now scanned file types;
  without the extra they fall back to regex (no crash). LLM10 deferred for both.

  Validated against real repos (langchainrb, discourse-ai, LLPhant, instructor-php —
  ~5,000 files, 0 crashes, 0 false positives) which surfaced and fixed three precision
  classes before release: PHP `echo`/`print` is no longer treated as a sink (CLI output
  vs HTML is ambiguous and it flooded findings); Ruby `delete`/`update` dropped from the
  SQL method set (`File.delete` etc. are far more common); and PHP shell/SQL sinks check
  only the first argument, so `exec($cmd, $output, $exitCode)`'s by-ref `$output` capture
  no longer triggers a finding.

**OrthoSec now has AST-level LLM05 coverage across Python, JS/TS, Go, Java, Kotlin, C#,
Ruby, and PHP** — the eight most common languages for building AI products.

## [0.7.9] — 2026-07-24

### Fixed (Python LLM01 precision — from scanning microsoft/semantic-kernel)
- **Loop / comprehension variables are no longer seeded as untrusted input.** A bare
  `for msg in history` loop var (name matches `\bmsg\b`) iterates an existing collection —
  it isn't the external-input boundary — so it no longer starts a false taint chain into a
  `system_message`-named assignment. Function parameters and real assignments from
  `input()`/`request.*` still seed as before, so genuine prompt-injection still fires.
- **Raised-exception messages are no longer read as prompts.** A `raise
  SomeError(f"…{content}…")` is a diagnostic string, not a system prompt (the regex
  fallback already skipped `logger`/`print`; this extends it to `raise`).
- Together these cut semantic-kernel's LLM01 findings from 7 to 2 (the remaining two are
  a defensible `system_message = convert(message)` weak signal in test code). Benchmark
  and adversarial sets unchanged (100% / 0 FP, 14/14).

## [0.7.8] — 2026-07-24

### Added
- **C# / .NET language support** (`orthosec[csharp]`, tree-sitter) — language #5. `.cs`
  files are parsed to a real AST for **LLM05**: model output flowing into `Process.Start`
  (command), ADO.NET/Dapper/EF raw SQL (`new SqlCommand(...)`, `FromSqlRaw`,
  `ExecuteSqlRaw`, `conn.Query`/`Execute`), or `Html.Raw` (XSS). Taint is seeded from
  Semantic Kernel (`kernel.InvokePromptAsync`), Azure OpenAI, and OpenAI .NET
  (`chat.CompleteChat().Value.Content`) call shapes, cleared by escaping sanitizers
  (`HttpUtility.HtmlEncode`, `Uri.EscapeDataString`, `Regex.Escape`), and analyzed per
  method/constructor. `.cs` is now a scanned file type; without the extra it falls back
  to regex (no crash). C# LLM10 deferred (options-object/builder cap).
  - Precision (found scanning SciSharp/BotSharp): object-initializer members
    (`new ProcessStartInfo { RedirectStandardOutput = true }`) are no longer taint-seeded
    — a field name containing "output" is not a model-output variable. On BotSharp this
    left the real finding standing: the SqlDriver plugin executes **LLM-generated SQL**
    (`connection.Query(args.SqlStatement)` where `args` is deserialized from the model
    response) via Dapper without parameterization — a true LLM→SQL-injection.

### Added
- **Kotlin language support** (`orthosec[kotlin]`, tree-sitter) — completes language #4.
  `.kt` files are parsed to a real AST for **LLM05**: model output into `Runtime.exec` /
  `ProcessBuilder(...)` (command), JDBC/JPA raw SQL, or a script `eval`. Kotlin AI apps
  (Android / Ktor) use the same JVM SDKs, so it reuses Java's Spring AI / LangChain4j
  receiver, method, and sanitizer vocabulary, with per-function scoping. The Kotlin
  grammar exposes no named fields, so call chains are read by in-source-order identifier
  traversal. `.kt` is now a scanned file type; without the extra it falls back to regex.
  Kotlin LLM10 is deferred (builder-configured cap, like Java).

### Added
- **Java language support** (`orthosec[java]`, tree-sitter) — language #4. `.java` files
  are parsed to a real AST for **LLM05**: model output flowing into `Runtime.exec` /
  `new ProcessBuilder(...)` (command execution), JDBC/JPA raw SQL (`executeQuery`,
  `executeUpdate`, `createQuery`, `createNativeQuery`, gated `execute`), or a script
  `eval`. Taint is seeded from Spring AI (`chatClient…call().content()`) and LangChain4j
  (`model.generate()`, gated `call`/`chat`/`invoke` on an LLM-ish receiver) call shapes,
  cleared by escaping sanitizers (`StringEscapeUtils.escapeSql`, `htmlEscape`, `encode`),
  and analyzed per method/constructor so same-named locals don't conflate. `.java` is now
  a scanned file type; without the extra it falls back to regex (no crash).
  Java LLM10 (output-token cap) is deferred — it's a model-builder concern, not per-call,
  in the dominant frameworks. Kotlin is next.

### Added
- **Go language support** (`orthosec[go]`, tree-sitter) — language #3. `.go` files are
  parsed to a real AST for:
  - **LLM05** — model output flowing into `exec.Command`/`exec.CommandContext` (shell),
    raw SQL (`db.Query`/`Exec`/`QueryRow`…), or `template.HTML` (XSS). Taint is seeded
    from go-openai (`CreateChatCompletion`), langchaingo (`GenerateFromSinglePrompt`,
    gated `Call`/`Run`/`Generate`), and anthropic-sdk-go (`Messages.New`) call shapes,
    and cleared by escaping sanitizers (`html.EscapeString`, `url.QueryEscape`, …).
  - **LLM10** — a completion request (`openai.ChatCompletionRequest{…}`) with no
    `MaxTokens`-style cap. Only judged when the request is an **inline literal** whose
    fields are fully visible; a request passed as a variable (cap possibly set in a
    config builder) is not flagged, to avoid interprocedural false positives.
  `.go` is now a scanned file type; without the extra it falls back to regex (no crash).
- **Output-name precision** (all analyzers) — a variable named `outputPath` /
  `outputFile` / `outputDir` / … is a file path, not model output, and is no longer
  seeded as tainted (`outputText` / `llmOutput` still are). Found scanning
  danielmiessler/fabric, which is clean (Grade A) after this.
- **Per-function taint scoping** (Go + TypeScript analyzers) — taint is now analyzed
  per function/method, so a variable named e.g. `stmt` in one function no longer taints
  a same-named parameter in another (the tree-sitter analyzers previously treated a whole
  file as one scope, matching the Python engine now). Removed 10 cross-function SQL false
  positives on tmc/langchaingo (864 Go files across fabric+langchaingo now scan with zero
  go-analyzer false positives).
- **Go LLM10 is conservative** — only a `…Request{…}` struct literal is judged for a
  missing cap; completion calls that pass the request as a variable or set the cap via
  functional options (`llms.WithMaxTokens(…)`, the langchaingo style) are not flagged.

### Added
- **Download button + sandbox-safe printing in the HTML report.** A new "Download .html"
  button saves a self-contained, printable copy of the report (all `<details>` expanded,
  any injected CSP stripped so inline CSS/JS run locally). "Print / PDF" now detects when
  the report is embedded in a sandboxed iframe (e.g. a hosted preview where the print
  dialog is blocked) and opens a standalone tab to print, falling back to download if
  pop-ups are blocked. A report opened directly as a local file prints as before.

## [0.7.3] — 2026-07-24

### Fixed (precision — from scanning vercel/ai-chatbot and gpt-researcher)
- **Sanitizer-awareness in the TS/JS taint engine.** Model output passed through a
  sanitizer before an HTML sink is no longer flagged (LLM05). Recognized sanitizers:
  React `renderToString`/`renderToStaticMarkup` (auto-escape), `DOMPurify.sanitize`,
  `escape`/`escapeHtml`, `encodeURI`/`encodeURIComponent`, `striptags`. Killed the
  `innerHTML = renderToString(...)` false positives; a raw unsanitized sink still fires.
- **Log/print of user input is no longer read as prompt injection.** The LLM01 regex
  fallback skips `logger.*` / `print` / `console.*` / `warnings` / `traceback` lines —
  interpolating user input into a diagnostic log is not a prompt (the AST path already
  ignored these; this brings the regex fallback in line).

### Added
- **Language-coverage roadmap** — a step-by-step plan (Go, Java/Kotlin, C#/.NET, Rust,
  Ruby/PHP) built on the shared tree-sitter AST layer, ordered by AI-product usage.
- **Known-limitation note** — run OrthoSec on Python ≥ the target's syntax (3.11+ for
  modern repos) for full AST precision; older Python falls back to regex on newer files.

## [0.7.2] — 2026-07-24

### Added
- **Env-driven reporting** — every `orthosec scan` already writes the full HTML report;
  now it's pinnable via `.env` with no flags: `ORTHOSEC_REPORT=<path>` (or `off` to
  disable), `ORTHOSEC_OPEN=1` to open it in the browser after each scan, and
  `ORTHOSEC_NO_EXEC=1` to skip the LLM briefing. CLI `--html` / `--no-report` / `--open`
  override. Auto-open is guarded so a headless run never fails over it.

### Fixed
- **Print / Save-as-PDF now renders properly.** Printing forces a legible light palette
  regardless of the on-screen theme (dark-mode text was invisible on white), paints
  severity colors (`print-color-adjust: exact`), avoids splitting finding cards across
  pages, and **expands every collapsed section** (data-flow traces + remediation plans)
  via `beforeprint` JS plus a `::details-content` CSS fallback — so the PDF contains the
  full detail, not collapsed summaries.

## [0.7.1] — 2026-07-24

### Fixed (precision — from scanning crewAI, a 1,269-file public repo)
Three false-positive classes surfaced by a real-world scan; benchmark still 100% / 0 FP.
- **A `model`-named variable is no longer treated as model output.** `model` / `llm`
  name the *client*, not its output (real output is still caught call-based, e.g.
  `model.generate(...)`), so a model-*name* string passed to a subprocess no longer
  trips LLM05. Applied to the Python, TypeScript, and JavaScript analyzers.
- **Recorded test I/O is skipped.** `cassettes/` (VCR) and `__snapshots__/` dirs are
  recorded fixtures, not source — no longer scanned (killed spurious LLM01 hits on
  cassette YAML).
- **Bundled front-end assets are skipped.** `assets/` joins the skip list alongside
  `dist`/`vendor`/`_static` — a vendored `interactive.js` no longer trips LLM05 on a
  library's `innerHTML`.

## [0.7.0] — 2026-07-23

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
