"""OrthoSec — The AI Security Architect.

Deterministic AI-risk detection with a grounded executive-context layer.
Core scan + report path is stdlib-only and runs with no external deps.
"""

__version__ = "0.2.0"

from orthosec.core.finding import Finding, Severity
from orthosec.core.scanner import Scanner, ScanContext, ScanResult

__all__ = ["Finding", "Severity", "Scanner", "ScanContext", "ScanResult", "__version__"]
