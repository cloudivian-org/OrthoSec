"""Process-parallel scanning.

The taint hot loop is pure-Python AST traversal — CPU-bound and GIL-bound, so
threads don't help; we shard across PROCESSES. Each worker emits findings only for
the files in its shard but resolves cross-module context against the FULL file set,
so the union of worker findings is byte-for-byte the same set a serial scan
produces — just partitioned by which file owns each finding. The parent still does
the one authoritative suppress + sort + score pass, so ordering is deterministic.

Sharing the cross-module index — the important part:
  Naively, every worker would rebuild the project index (re-parse ALL files) before
  touching its shard, which is O(files x workers) and caps the speedup near 2x. On
  Linux we instead build the index ONCE in the parent and `fork`: children inherit
  the built index AND the warmed parse cache via copy-on-write, for free, so a worker
  only walks the taint graph for its shard. macOS/Windows default to `spawn` (fork is
  unsafe there), where the inheritance trick is impossible — those fall back to
  rebuild-per-worker, still correct, just a smaller win.

Fail-open: any problem spinning up the pool raises, and the caller runs serially.
"""
from __future__ import annotations

import multiprocessing
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

# Below this many files the process startup cost (and, on spawn, per-worker index
# rebuild) outweighs the parallel win, so the caller stays serial.
MIN_FILES_FOR_PARALLEL = 200

# Set in the parent BEFORE the pool is created; fork children inherit it via
# copy-on-write. Under spawn the module is re-imported fresh, so it stays None and
# the worker rebuilds the index itself.
_SHARED_INDEX = None


def resolve_jobs(n_files: int, requested) -> int:
    """How many worker processes to use. `requested` is the CLI/env value (None =
    auto). Returns 1 to mean "run serially in-process"."""
    if requested is None:
        env = os.environ.get("ORTHOSEC_JOBS")
        requested = env if env else None
    if requested is not None:
        try:
            requested = int(requested)
        except (TypeError, ValueError):
            requested = None
    if requested is not None:
        return max(1, requested)
    if n_files < MIN_FILES_FOR_PARALLEL:
        return 1
    cores = os.cpu_count() or 1
    # Fork shares the prebuilt index, so more workers keep paying off; spawn rebuilds
    # the index per worker, so returns flatten fast — cap it lower to avoid wasted work.
    cap = 8 if _use_fork() else 4
    return max(1, min(cores - 1, cap))


def _use_fork() -> bool:
    """Fork lets children inherit the prebuilt index for free. It is the default and
    safe on Linux; Python disables it by default on macOS (ObjC fork-safety) so we
    only use it there when explicitly opted in via ORTHOSEC_PARALLEL_FORK=1."""
    if "fork" not in multiprocessing.get_all_start_methods():
        return False
    if sys.platform.startswith("linux"):
        return True
    return os.environ.get("ORTHOSEC_PARALLEL_FORK") == "1"


def _prewarm_index(ctx):
    """Build the Python cross-module index + tool reachability once. This parses every
    .py file (warming the module-global parse cache too) and precomputes the reach
    sets, so fork children inherit a fully-populated, query-only index."""
    from orthosec.analysis.project import get_index, _tool_reachability
    idx = get_index(ctx)
    try:
        _tool_reachability(idx)  # populate idx._tool_reach so children need no func_nodes
    except Exception:
        pass
    return idx


def _scan_shard(root_str: str, all_files: list, shard_files: list):
    """Worker: run every builtin detector, emitting findings for this shard only.

    Under fork, `_SHARED_INDEX` is the parent's prebuilt index (inherited), so we
    reuse it instead of re-parsing every file. Under spawn it is None and the first
    cross-module query rebuilds it from `all_files`.
    """
    from orthosec.core.scanner import ScanContext
    from orthosec.detectors import load_builtin_detectors

    ctx = ScanContext(
        root=Path(root_str),
        files=[Path(f) for f in all_files],
        shard=[Path(f) for f in shard_files],
    )
    if _SHARED_INDEX is not None:
        ctx._project_index = _SHARED_INDEX  # reuse parent's; no rebuild

    detectors = load_builtin_detectors()
    findings, errors, ran = [], [], []
    for det in detectors:
        ran.append(getattr(det, "id", det.__class__.__name__))
        try:
            findings.extend(det.scan(ctx))
        except Exception as exc:  # detector isolation, same as the serial path
            errors.append(f"{getattr(det, 'id', det)}: {exc!r}")
    return findings, errors, ran


def run_parallel(root_path: Path, files: list, jobs: int):
    """Scan `files` across `jobs` processes. Returns (findings, errors, detectors_run).

    Round-robin sharding (files[i::jobs]) balances load even when file sizes vary.
    Raises on pool failure so the caller can fall back to a serial scan.
    """
    global _SHARED_INDEX
    all_files = [str(p) for p in files]
    shards = [all_files[i::jobs] for i in range(jobs)]
    shards = [s for s in shards if s]  # drop empty shards (fewer files than workers)

    mp_ctx = None
    if _use_fork():
        mp_ctx = multiprocessing.get_context("fork")
        # Build the index once in the parent; fork children inherit it (and the warm
        # parse cache) copy-on-write, so no worker re-parses the whole tree.
        from orthosec.core.scanner import ScanContext
        parent_ctx = ScanContext(root=root_path, files=[Path(f) for f in all_files])
        _SHARED_INDEX = _prewarm_index(parent_ctx)

    findings, errors, ran = [], [], []
    try:
        with ProcessPoolExecutor(max_workers=jobs, mp_context=mp_ctx) as ex:
            futures = [ex.submit(_scan_shard, str(root_path), all_files, shard)
                       for shard in shards]
            for fut in futures:
                f_findings, f_errors, f_ran = fut.result()
                findings.extend(f_findings)
                errors.extend(f_errors)
                if not ran:
                    ran = f_ran  # identical across workers (same builtin detector set)
    finally:
        _SHARED_INDEX = None
    return findings, errors, ran
