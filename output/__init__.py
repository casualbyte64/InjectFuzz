"""
Output package for the Generic Injection Testing Tool.

Responsible for:
- Persisting structured scan results
- Enforcing report-safe formats

No scanning or analysis logic belongs here.
"""

from .writer import OutputWriter

__all__ = [
    "OutputWriter",
    "OutputWriterError",
]
