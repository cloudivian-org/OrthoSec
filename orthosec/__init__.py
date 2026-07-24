"""OrthoSec — The AI Security Architect.

Deterministic AI-risk detection with a grounded executive-context layer.
Core scan + report path is stdlib-only and runs with no external deps.
"""

__version__ = "0.7.6"

from orthosec.core.finding import Finding, Severity
from orthosec.core.scanner import Scanner, ScanContext, ScanResult
from orthosec.sdk import guard, scan_prompt, scan_output, GuardResult, PromptInjectionError

__all__ = [
    "Finding", "Severity", "Scanner", "ScanContext", "ScanResult",
    "guard", "scan_prompt", "scan_output", "GuardResult", "PromptInjectionError",
    "__version__",
]
