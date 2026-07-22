# Contributing to OrthoSec

OrthoSec grows through detectors. If you've seen an AI-security failure mode in the wild, teach OrthoSec to catch it.

## Add a detector

1. Create `orthosec/detectors/your_detector.py`.
2. Write a class decorated with `@register`, exposing `id`, `name`, `owasp_llm`, and a `scan(ctx)` generator that yields `Finding`s.
3. Every finding must carry: an OWASP LLM Top-10 id, `file:line` evidence, a concrete `remediation`, and a `confidence`.

Minimal example:

```python
from orthosec.core.finding import Finding, Severity
from orthosec.core.scanner import ScanContext
from orthosec.detectors import register


@register
class MyDetector:
    id = "my-detector"
    name = "What it catches"
    owasp_llm = "LLM01"

    def scan(self, ctx: ScanContext):
        for path in ctx.files:
            for lineno, line in enumerate(ctx.read(path).splitlines(), 1):
                if "dangerous_pattern" in line:
                    yield Finding(
                        detector=self.id, rule_id="ORTHO-MINE-001",
                        title="Human-readable problem",
                        severity=Severity.HIGH, owasp_llm="LLM01", atlas=[],
                        file=ctx.rel(path), line=lineno, evidence=line.strip(),
                        remediation="How to fix it.", confidence=0.7,
                    )
```

The registry auto-loads it — no wiring needed.

## Detector quality bar (this is a security tool)

- **Deterministic.** No LLM calls inside a detector. Findings must be reproducible.
- **Low false-positive rate.** Prefer precision; downgrade or skip on placeholders and mitigated cases. A comment saying "no confirmation" is *not* a mitigation — see `tool_exposure.py` for how we handle negation and comments.
- **Evidence or it didn't happen.** Always cite the exact line.

## Run the checks

```bash
python -m pytest        # or: python -m unittest discover -s tests
python -m orthosec.cli scan examples/vulnerable-agent
```

Add a test in `tests/` for any new detector — assert it fires on a known-bad fixture and stays quiet on a clean one.

## Taxonomy

Map to the existing OWASP LLM / MITRE ATLAS / compliance entries in `orthosec/core/taxonomy.py`. Extend that file if you need a new mapping — keep it the single source of truth.
