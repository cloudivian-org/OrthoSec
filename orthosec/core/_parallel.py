"""Process-parallel scanning.

The taint hot loop is pure-Python AST traversal — CPU-bound and GIL-bound, so
threads don't help; we shard across PROCESSES. Two parallel phases, both sharded:

  Phase A (build): workers parse their file shard and emit small picklable index
    records; the parent reduces them into a SlimIndex — the project-wide cross-module
    summaries/imports/tool-reachability, equivalent to a serial build_index for every
    query the detectors make (see project.assemble_slim). This is what removes the
    old serial ~4s "build the index in the parent" floor.
  Phase B (scan): workers run every detector over their shard, resolving cross-module
    context against the shared SlimIndex (passed in), and emit findings only for their
    shard. The union across disjoint shards is byte-for-byte the same finding set a
    serial scan produces, so the parallel scan is provably identical to serial.

Because the SlimIndex is picklable, both phases work the same under fork and spawn —
no per-worker index rebuild, no fork-inheritance tricks. Fail-open: any pool problem
raises and the caller runs serially.
"""
from __future__ import annotations

import os
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

# Below this many files the process startup cost outweighs the parallel win.
MIN_FILES_FOR_PARALLEL = 200


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
    return max(1, min(cores - 1, 8))


def _extract(root_str: str, paths: list):
    """Phase-A worker: parse a file shard → picklable index records."""
    from orthosec.analysis.project import extract_records
    return extract_records(Path(root_str), paths)


def _scan_shard(root_str: str, all_files: list, shard_files: list, slim):
    """Phase-B worker: run every builtin detector, emitting findings for this shard
    only, using the shared SlimIndex for Python cross-module context."""
    from orthosec.core.scanner import ScanContext
    from orthosec.detectors import load_builtin_detectors

    ctx = ScanContext(
        root=Path(root_str),
        files=[Path(f) for f in all_files],
        shard=[Path(f) for f in shard_files],
    )
    if slim is not None:
        ctx._project_index = slim  # skip the per-worker Python index rebuild

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
    all_files = [str(p) for p in files]
    py_files = [f for f in all_files if f.lower().endswith(".py")]

    findings, errors, ran = [], [], []
    with ProcessPoolExecutor(max_workers=jobs) as ex:
        # Phase A: build the Python cross-module SlimIndex in parallel.
        slim = None
        if py_files:
            from orthosec.analysis.project import assemble_slim
            pre_shards = [py_files[i::jobs] for i in range(jobs)]
            pre_shards = [s for s in pre_shards if s]
            records = []
            for fut in [ex.submit(_extract, str(root_path), s) for s in pre_shards]:
                records.extend(fut.result())
            slim = assemble_slim(records)

        # Phase B: scan shards, sharing the SlimIndex.
        shards = [all_files[i::jobs] for i in range(jobs)]
        shards = [s for s in shards if s]
        for fut in [ex.submit(_scan_shard, str(root_path), all_files, s, slim) for s in shards]:
            f_findings, f_errors, f_ran = fut.result()
            findings.extend(f_findings)
            errors.extend(f_errors)
            if not ran:
                ran = f_ran  # identical across workers (same builtin detector set)
    return findings, errors, ran
