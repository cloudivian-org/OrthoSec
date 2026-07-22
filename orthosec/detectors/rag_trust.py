"""Detect untrusted ingestion into RAG / vector stores.

OWASP LLM08 (Vector and Embedding Weaknesses) / LLM04 (Data and Model Poisoning).
If a retrieval corpus ingests content fetched from the web, user uploads, or other
untrusted sources without provenance or sanitization, an attacker can plant
instructions that later surface as 'trusted' context — indirect prompt injection
through the knowledge base.
"""
from __future__ import annotations

import re
from typing import Iterable

from orthosec.core.finding import Finding, Severity
from orthosec.core.scanner import ScanContext
from orthosec.detectors import register
from orthosec.detectors._signals import mitigation_present, strip_comments

# Ingestion CALLS into a vector store / retriever (a method invocation, not just a
# store variable or class name — those are construction, not ingestion of content).
_INGEST = re.compile(
    r"(?i)\b(add_texts|add_documents|from_documents|from_texts|upsert|"
    r"index\.add|embed_documents)\s*\("
)
# Untrusted content sources in the same neighborhood as the ingestion.
_UNTRUSTED_SRC = re.compile(
    r"(?i)\b(requests\.get|httpx|urllib|fetch\(|WebBaseLoader|scrape|crawl|"
    r"upload|request\.files|user_input|external_url|rss|email)\b"
)
# Signals provenance/sanitization is applied to ingested content.
_TRUSTED = re.compile(
    r"(?i)(sanitiz|clean|allowlist|whitelist|verify|signature|provenance|trusted_source|validate)"
)
# The file must actually be about a vector store / retriever — otherwise a generic
# `upsert`/`add_documents` (e.g. a database upsert) is not RAG ingestion.
_VECTOR_CTX = re.compile(
    r"(?i)(vector|embedding|\bembed\b|chroma|faiss|pinecone|weaviate|qdrant|milvus|"
    r"retriever|vectorstore|langchain|llama_?index|semantic|rag\b)"
)


@register
class RagTrustDetector:
    id = "rag-trust"
    name = "Untrusted RAG / vector ingestion"
    owasp_llm = "LLM08"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.files:
            if path.suffix.lower() not in {".py", ".js", ".ts"}:
                continue
            text = ctx.read(path)
            if not text or not _VECTOR_CTX.search(text) or not _INGEST.search(text):
                continue
            lines = strip_comments(text).splitlines()  # behavior detector: code only
            raw_lines = text.splitlines()
            for lineno, line in enumerate(lines, start=1):
                if not _INGEST.search(line):
                    continue
                window = "\n".join(lines[max(0, lineno - 8):lineno + 3])
                if not _UNTRUSTED_SRC.search(window):
                    continue  # only flag ingestion fed by an untrusted source
                if mitigation_present(window, _TRUSTED):
                    continue  # provenance/sanitization present in code (not a comment)
                yield Finding(
                    detector=self.id,
                    rule_id="ORTHO-RAG-001",
                    title="Untrusted content ingested into retrieval corpus without provenance",
                    severity=Severity.MEDIUM,
                    owasp_llm="LLM08",
                    atlas=["AML.T0051.001", "AML.T0018"],
                    file=ctx.rel(path),
                    line=lineno,
                    evidence=raw_lines[lineno - 1].strip()[:200],
                    remediation=(
                        "Establish provenance for everything indexed: sanitize fetched/uploaded "
                        "content, restrict to trusted sources, and treat retrieved chunks as data "
                        "(delimited, non-authoritative) at prompt-assembly time."
                    ),
                    confidence=0.55,
                )
