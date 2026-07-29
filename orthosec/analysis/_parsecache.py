"""Shared bounded content-keyed parse cache.

Several detectors (output-handling, prompt-hardening, tool-exposure, …) and the
cross-module index each analyze the same file, so a file was parsed multiple times per
scan. Caching the parse result by file content collapses that to one parse per file —
roughly 2x faster on large repos, with identical results (a parse tree is a pure function
of its input). Bounded so a long-running process (watch / SDK) can't grow unboundedly.
"""
from __future__ import annotations

_MAX = 8192


def cached(cache: dict, src, tag, compute):
    """Return `compute()` for `src`, memoized in `cache`. `tag` distinguishes parse
    variants of the same source (e.g. tsx vs ts). Uses a hash+len key (not the raw
    string) to keep the cache small; a `None` result is cached too (don't re-try)."""
    key = (hash(src), len(src), tag)
    val = cache.get(key, _MISS)
    if val is not _MISS:
        return val
    result = compute()
    if len(cache) >= _MAX:
        cache.clear()
    cache[key] = result
    return result


_MISS = object()
