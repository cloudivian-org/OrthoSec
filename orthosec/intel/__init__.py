"""Intel layer — turns deterministic findings into executive context.

Two tiers:
  * Deterministic (compliance mapping, business-risk model) — always available.
  * LLM narrative + free-form Q&A (grounded on findings) — needs `intel` extra.

The LLM never invents findings. It only explains, prioritizes, and translates the
facts the detectors already produced.
"""
