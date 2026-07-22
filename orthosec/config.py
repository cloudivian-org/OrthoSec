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


# --- Project config: .orthosec.yml / .yaml / .json --------------------------------

_CONFIG_NAMES = (".orthosec.yml", ".orthosec.yaml", ".orthosec.json")
# The integration contract: a target AI product drops one of these at its root to
# declare how OrthoSec should scan it. Keys: profile, fail_on, exclude[], paths[].


def load_project_config(target: str | os.PathLike) -> dict:
    """Find and parse the .orthosec config nearest the scan target. Returns {} if none.

    Supports JSON and a small flat YAML subset (scalars + `-` lists) so the core
    stays stdlib-only — no PyYAML dependency.
    """
    base = Path(target)
    root = base if base.is_dir() else base.parent
    for name in _CONFIG_NAMES:
        candidate = root / name
        if candidate.is_file():
            text = candidate.read_text(encoding="utf-8", errors="replace")
            if candidate.suffix == ".json":
                import json
                try:
                    return json.loads(text) or {}
                except ValueError:
                    return {}
            return _parse_mini_yaml(text)
    return {}


def _parse_mini_yaml(text: str) -> dict:
    """Parse a flat YAML subset: `key: value` and `key:` + indented `- item` lists."""
    out: dict = {}
    current_list_key = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.lstrip().startswith("- ") and current_list_key is not None:
            out[current_list_key].append(_coerce(line.lstrip()[2:].strip()))
            continue
        if ":" in line and not line.startswith(" "):
            key, _, value = line.partition(":")
            key, value = key.strip(), value.strip()
            if value == "":
                out[key] = []
                current_list_key = key
            else:
                out[key] = _coerce(value)
                current_list_key = None
    return out


def _coerce(v: str):
    v = v.strip().strip('"').strip("'")
    low = v.lower()
    if low in ("true", "false"):
        return low == "true"
    if v.isdigit():
        return int(v)
    return v


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
