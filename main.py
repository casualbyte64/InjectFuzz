"""
Entry point for SignalFuzz.

This file exists ONLY to invoke the CLI orchestrator.
No logic, no configuration, no side effects.
"""

import sys
from cli import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)