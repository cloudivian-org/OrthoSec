# Security Policy

OrthoSec is a security tool, so the security of OrthoSec itself matters. Thank you for
helping keep it and its users safe.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through either channel:

- **GitHub Security Advisories** — [Report a vulnerability](https://github.com/cloudivian-org/OrthoSec/security/advisories/new)
  (preferred; keeps the report private and lets us collaborate on a fix).
- **Email** — vikasj1in@gmail.com with the subject `OrthoSec security`.

Please include:

- A description of the issue and the impact you believe it has.
- Steps to reproduce (a minimal proof of concept helps a lot).
- The OrthoSec version (`orthosec --version`) and how you installed it.

### What to expect

- **Acknowledgement** within 3 business days.
- An initial assessment and severity within 7 business days.
- Coordinated disclosure: we will agree on a timeline with you, fix the issue, publish a
  patched release, and credit you in the advisory unless you prefer to remain anonymous.

## Scope

In scope — the OrthoSec CLI, detectors, analysis engine, runtime SDK/proxy, the HTML
report, and the published packages (`orthosec` on PyPI, `@orthosec/guard` on npm).

Out of scope — vulnerabilities in the code *you scan*, and issues that require a
compromised local machine or a malicious dependency you installed yourself.

## Data handling

The deterministic core runs **fully offline** — it never sends your source anywhere.
The optional intel layer (executive briefing) calls an LLM provider only when enabled;
`--no-exec` disables it entirely. See "Data handling & privacy" in the README for exactly
what is and isn't sent off your machine.

## Supported versions

OrthoSec is pre-1.0 and moving fast. Security fixes land on the latest released version
on PyPI; please upgrade before reporting to confirm the issue still reproduces.
