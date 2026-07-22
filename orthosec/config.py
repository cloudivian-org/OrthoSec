"""Zero-dependency .env loader.

Keeps the core stdlib-only (no python-dotenv). Loads KEY=VALUE lines from a .env
file into os.environ without overwriting variables already set in the real
environment — so an exported ANTHROPIC_API_KEY always wins over the file.
"""
from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(path: str | os.PathLike | None = None) -> bool:
    """Load a .env file into os.environ. Returns True if a file was read.

    Search order when path is None: $ORTHOSEC_ENV, then ./.env.
    """
    candidates = []
    if path is not None:
        candidates.append(Path(path))
    else:
        if os.environ.get("ORTHOSEC_ENV"):
            candidates.append(Path(os.environ["ORTHOSEC_ENV"]))
        candidates.append(Path.cwd() / ".env")

    for env_path in candidates:
        if env_path.is_file():
            _parse_into_environ(env_path)
            return True
    return False


def _parse_into_environ(env_path: Path) -> None:
    for raw in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:  # real env wins over the file
            os.environ[key] = value
