"""
Core package for SignalFuzz.

This package exports the fundamental building blocks:
- PayloadEngine (Streaming & Mutation)
- RequestEngine (Safe HTTP Transport)
- BaselineEngine (Statistical Modeling)
- Analyzer (Differential Analysis)
- Classifier (Policy Enforcement)

It also exports critical Data Classes (DTOs) used for inter-module communication.
"""

# -----------------------------------------------------------------------------
# NOTICE THE DOT (.) BEFORE THE MODULE NAMES. THIS IS CRITICAL.
# -----------------------------------------------------------------------------

# 1. Payload Management (Phase 1)
from .payload_loader import PayloadEngine, Payload, MutationType

# 2. Request Handling (Phase 2)
from .request_engine import RequestEngine, ResponseData

# 3. Baseline Logic (Phase 3)
from .baseline import BaselineEngine, Baseline

# 4. Analysis Logic (Phase 4)
from .analyzer import Analyzer, AnalysisResult, Classification

# 5. Classification Policy (Phase 5)
from .classifier import Classifier, VulnerabilityLabel, SignalType

__all__ = [
    # Engines
    "PayloadEngine",
    "RequestEngine",
    "BaselineEngine",
    "Analyzer",
    "Classifier",
    
    # Data Structures (Crucial for Type Hinting in Main)
    "Payload",
    "MutationType",
    "ResponseData",
    "Baseline",
    "AnalysisResult",
    "Classification",
    "VulnerabilityLabel",
    "SignalType"
]