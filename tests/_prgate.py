"""Puts pr-gate/ on sys.path so tests can import the `prgate` package.

pr-gate/ is a GitHub composite action, not an installed package: the action
runs `python gate.py` from its own directory, which puts that directory on
sys.path the same way.
"""
import sys
from pathlib import Path

PR_GATE_DIR = Path(__file__).resolve().parent.parent / "pr-gate"
if str(PR_GATE_DIR) not in sys.path:
    sys.path.insert(0, str(PR_GATE_DIR))
