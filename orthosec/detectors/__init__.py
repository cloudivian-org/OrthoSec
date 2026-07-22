"""Detector plugin system.

A detector is a small, deterministic unit that inspects the scan context and
yields Findings. Community contributors add a file here, decorate with
@register, and it auto-loads — this is OrthoSec's OSS growth surface.
"""
from __future__ import annotations

import importlib
import pkgutil
from typing import Iterable, Protocol, runtime_checkable

from orthosec.core.finding import Finding

_REGISTRY: list[type["Detector"]] = []


@runtime_checkable
class Detector(Protocol):
    id: str
    name: str
    owasp_llm: str

    def scan(self, ctx) -> Iterable[Finding]:  # noqa: ANN001 - ctx is ScanContext
        ...


def register(cls: type) -> type:
    """Class decorator: add a detector to the registry."""
    _REGISTRY.append(cls)
    return cls


def load_builtin_detectors() -> list["Detector"]:
    """Import every module in this package so @register side-effects fire."""
    package = importlib.import_module(__name__)
    for mod in pkgutil.iter_modules(package.__path__):
        if mod.name.startswith("_"):
            continue
        importlib.import_module(f"{__name__}.{mod.name}")
    return [cls() for cls in _REGISTRY]


def all_detectors() -> list["Detector"]:
    return [cls() for cls in _REGISTRY]
