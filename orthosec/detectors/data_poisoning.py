"""Detect data / model poisoning surfaces.

OWASP LLM04 (Data and Model Poisoning).
Fine-tuning or training a model on unverified or externally-sourced data lets an
attacker corrupt the model's behavior at the source. Two high-signal cases:
a fine-tuning job (always worth a provenance check), and training whose data is
drawn from an untrusted source (web fetch, upload, user input) with no verification.
"""
from __future__ import annotations

import re
from typing import Iterable

from orthosec.core.finding import Finding, Severity
from orthosec.core.scanner import ScanContext
from orthosec.detectors import register
from orthosec.detectors._signals import strip_comments, mitigation_present

# Fine-tuning / training-job creation.
_FINETUNE = re.compile(
    r"(?i)(fine_tuning\.jobs\.create|fine_tunes\.create|FineTuningJob|create_fine_tune|"
    r"\.finetune\s*\(|SFTTrainer|\.push_to_hub\s*\()")
# Training calls whose data may be poisoned.
_TRAIN = re.compile(r"(?i)\b(Trainer\s*\(|\.fit\s*\(|\.train\s*\(|training_file\s*=|train_dataset\s*=)")
# Untrusted data sources feeding training.
_UNTRUSTED = re.compile(
    r"(?i)\b(requests\.get|httpx|urllib|WebBaseLoader|scrape|crawl|upload|request\.files|"
    r"user_input|user_data|external|load_dataset\s*\([^)]*(http|url|user))")
# Verification / provenance signals.
_VERIFIED = re.compile(
    r"(?i)(verify|validate|checksum|signature|sanitiz|trusted|provenance|allowlist|vetted)")


@register
class DataPoisoningDetector:
    id = "data-poisoning"
    name = "Data / model poisoning surface"
    owasp_llm = "LLM04"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.files:
            if path.suffix.lower() not in {".py", ".ipynb", ".js", ".ts"}:
                continue
            raw = ctx.read(path)
            if not raw:
                continue
            code = strip_comments(raw)          # behavior detector: ignore comments
            lines = code.splitlines()
            raw_lines = raw.splitlines()
            for lineno, line in enumerate(lines, start=1):
                if _FINETUNE.search(line):
                    yield Finding(
                        detector=self.id, rule_id="ORTHO-POISON-001",
                        title="Fine-tuning / model training job — verify training-data provenance",
                        severity=Severity.MEDIUM, owasp_llm="LLM04",
                        atlas=["AML.T0018", "AML.T0020"],
                        file=ctx.rel(path), line=lineno,
                        evidence=raw_lines[lineno - 1].strip()[:200],
                        remediation=(
                            "Only train/fine-tune on vetted, integrity-checked data from trusted "
                            "sources. Version and checksum datasets; review third-party data for "
                            "poisoning before ingestion."),
                        confidence=0.6)
                elif _TRAIN.search(line):
                    window = "\n".join(lines[max(0, lineno - 6):lineno + 3])
                    if _UNTRUSTED.search(window) and not mitigation_present(window, _VERIFIED):
                        yield Finding(
                            detector=self.id, rule_id="ORTHO-POISON-002",
                            title="Model trained on data from an untrusted source (poisoning risk)",
                            severity=Severity.MEDIUM, owasp_llm="LLM04",
                            atlas=["AML.T0018"],
                            file=ctx.rel(path), line=lineno,
                            evidence=raw_lines[lineno - 1].strip()[:200],
                            remediation=(
                                "Establish provenance for training data: restrict to trusted "
                                "sources, sanitize and verify integrity before training."),
                            confidence=0.55)
