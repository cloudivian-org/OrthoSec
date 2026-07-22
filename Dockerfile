# OrthoSec — AI Security Architect
# Ships with the executive intel layer (Anthropic SDK) included.
# The core scanner needs no key; the LLM briefing reads ANTHROPIC_API_KEY.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="OrthoSec" \
      org.opencontainers.image.description="The AI Security Architect — AI risk analysis with executive business context" \
      org.opencontainers.image.source="https://github.com/cloudivian-org/OrthoSec" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

# Install first (layer cache), then copy source.
COPY pyproject.toml README.md ./
COPY orthosec ./orthosec
RUN pip install --no-cache-dir ".[intel]"

# Scan a mounted project at /scan by default. Override the command as needed:
#   docker run --rm -v "$PWD:/scan" ghcr.io/cloudivian-org/orthosec scan /scan --profile ciso
WORKDIR /scan
ENTRYPOINT ["orthosec"]
CMD ["--help"]
