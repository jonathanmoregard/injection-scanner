#!/usr/bin/env python3
"""pr-gate entry point. See README.md in this directory.

Runs with `python -I` in the action, which neither reads PYTHON* variables
nor puts this directory on sys.path, so both paths are added explicitly:
this directory (the `prgate` package) and its parent, the pinned checkout
of injection-scanner that provides `injection_scanner.unicode_sanitize`.
Both come from the same pinned commit as this file.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for p in (HERE, HERE.parent):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from prgate.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
