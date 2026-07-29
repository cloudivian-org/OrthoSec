# OrthoSec for VS Code

Inline OWASP LLM Top-10 security findings for AI code, right in the editor — powered by the
[OrthoSec](https://github.com/cloudivian-org/OrthoSec) scanner.

This extension is a **thin client**: it runs your installed `orthosec` CLI and renders its
deterministic findings as diagnostics (squiggles). All the analysis is the real scanner —
the editor just surfaces it where you work.

## Prerequisites

Install OrthoSec (with the language extras you want):

```bash
pip install "orthosec[intel,ts,go,java,kotlin,csharp,ruby,php,rust]"
```

Make sure `orthosec --version` runs in your shell. If it isn't on PATH, set
`orthosec.path` in Settings to an absolute path or to `python -m orthosec.cli`.

## Use

- **Scan on save** (default on): save any supported file and findings appear inline.
- **OrthoSec: Scan Workspace** — scan the whole folder.
- **OrthoSec: Scan Current File** — scan just the active file.
- **OrthoSec: Clear Findings** — clear the squiggles.

Findings show as errors (CRITICAL/HIGH), warnings (MEDIUM), info (LOW), or hints (INFO, e.g.
advisory / model-discovered), each with its OWASP LLM id, rule id, and one-line fix.

## Settings

| Setting | Default | Description |
|---|---|---|
| `orthosec.path` | `orthosec` | Executable, or a command like `python -m orthosec.cli`. |
| `orthosec.scanOnSave` | `true` | Scan a file when it is saved. |
| `orthosec.profile` | `appsec` | Audience profile (`engineer`/`appsec`/`ciso`/`product`). |
| `orthosec.extraArgs` | `[]` | Extra CLI args, e.g. `["--baseline", ".orthosec-baseline.json"]`. |

## Develop

```bash
cd editors/vscode
npm install
npm run compile        # or: npm run watch
# then press F5 in VS Code to launch an Extension Development Host
```

Package a `.vsix` with `npx @vscode/vsce package`.
