"""model-pins.json must name exactly the vendor models the scanner calls.

The manifest is read by the host's weekly model-retirement check
(nixos-config modules/nixos/security-batch/model-retirement.sh), which asks
each provider whether a pinned model is scheduled to shut down and records a
failure that reaches Claude sessions. It exists because gpt-4.1-nano shut down
on 2026-10-23 and the first sign was the nightly live eval failing the next
morning. A pin the manifest misses is a model nobody watches; an entry the
code no longer uses is a warning about nothing. So the comparison is equality,
including where each model is used.
"""
from __future__ import annotations

import json
from pathlib import Path

from injection_scanner import judge
from injection_scanner.honeypot_scenarios import ALL_SCENARIOS

MANIFEST = Path(__file__).resolve().parent.parent / "model-pins.json"


def _pins_in_code() -> dict[tuple[str, str], list[str]]:
    pins: dict[tuple[str, str], list[str]] = {}
    for j in judge._JUDGES:
        pins.setdefault((j["provider"], j["model"]), []).append(f"judge:{j['id']}")
    for s in ALL_SCENARIOS:
        pins.setdefault((s["provider"], s["model"]), []).append(f"honeypot:{s['name']}")
    return {k: sorted(v) for k, v in pins.items()}


def _pins_in_manifest() -> dict[tuple[str, str], list[str]]:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert data["schema"] == 1
    assert data["consumer"] == "injection-scanner"
    pins: dict[tuple[str, str], list[str]] = {}
    for m in data["models"]:
        key = (m["provider"], m["id"])
        assert key not in pins, f"duplicate manifest entry {key}"
        pins[key] = sorted(m["used_by"])
    return pins


def test_manifest_matches_code() -> None:
    assert _pins_in_manifest() == _pins_in_code()


def test_manifest_ids_are_url_safe() -> None:
    # The host check puts each id into a provider URL path; it re-validates,
    # but a bad id should fail here first rather than as a weekly tool error.
    import re

    for provider, model in _pins_in_manifest():
        assert provider in {"anthropic", "openai"}
        assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", model), model
