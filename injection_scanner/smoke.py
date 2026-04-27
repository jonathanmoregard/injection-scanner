"""Self-test for the layered intercept shim.

Exposes `run_smoke()` so consumers (research-agent MCP server boot,
claude-cl-sync cron tick, ad-hoc CLI) all exercise the same canary
set instead of hand-rolling drift-prone copies.

Each canary runs through BOTH public entry points so a regression
in either the in-memory path (`scan_text`) or the disk-read wrapper
(`scan` — adds path.read_text(encoding="utf-8", errors="replace"))
is caught at startup. claude-cl-sync uses scan(Path); research-agent
uses scan_text(str); without dual coverage, a wrapper-only bug
would slip past the consumer that doesn't exercise that entry point.

Two phases:

  1. Deterministic canaries — one per detector class (secret_shapes,
     unicode_sanitize). Each must be blocked AND the verdict.reason
     must mention the expected detector. Catches the "some other
     layer accidentally caught it" failure mode where a class
     regression hides because a sibling class still triggers.
     use_honeypot=False — no API cost, deterministic.

  2. Honeypot liveness — one benign payload with use_honeypot=True,
     run through scan(Path). Pays one round-trip per scenario. If
     L3 is degraded (SDK missing, key revoked, provider down),
     production scans fail-closed per intercept.py; this probe
     surfaces that BEFORE any real record is processed, AND it
     covers the disk-read wrapper at zero extra API cost.

Callers wrap the SmokeFailure exception however they want — exit
the process, refuse to bind a port, surface the reason to logs.
"""
from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from injection_scanner.intercept import Verdict, scan, scan_text


class SmokeFailure(Exception):
    """Raised when a self-test canary fails."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class _Canary:
    label: str
    payload: str
    expected_reason_substring: str


# Layout: each canary asserts both block AND that verdict.reason mentions
# the expected detector. A regression in regex.instruction_override that
# accidentally still gets caught by secret_shapes (because the payload
# contains an unrelated token) would otherwise silently pass — substring
# match catches that "wrong layer caught it" mode.
_DETERMINISTIC: tuple[_Canary, ...] = (
    # secret_shapes
    _Canary("github_token",    "leaked: ghp_" + "a" * 36, "github_token"),
    _Canary("anthropic_oauth", "key: sk-ant-oat01-" + "B" * 60, "anthropic"),
    # unicode_sanitize
    _Canary("bidi_density",    "safe‮malicious" * 200, "unicode_anomaly"),
)

_BENIGN_PROBE = "Benign smoke probe. Sources: 1. Routine self-test, no payload."


def _scan_via_path(payload: str, *, use_honeypot: bool) -> Verdict:
    """Write payload to a temp file and run scan(Path). Cleans up the
    temp file even if scan raises. Exists so the disk-read wrapper
    doesn't sit untested."""
    with tempfile.NamedTemporaryFile(
        "w", suffix=".smoke", delete=False, encoding="utf-8"
    ) as tf:
        tf.write(payload)
        tpath = Path(tf.name)
    try:
        return scan(tpath, use_honeypot=use_honeypot)
    finally:
        try:
            tpath.unlink()
        except FileNotFoundError:
            pass


def run_smoke(
    *,
    log_info: Callable[[str], None] | None = None,
    log_error: Callable[[str], None] | None = None,
) -> None:
    """Run the self-test. Raises SmokeFailure on any regression.

    log_info / log_error are injected so callers can route messages
    through their own logger (stdlib logging, FastMCP, journal, etc.)
    without this module taking a hard logger dep.
    """
    info = log_info or (lambda _msg: None)
    err = log_error or (lambda _msg: None)

    failures: list[str] = []

    # Phase 1: every canary, both entry points. scan_text covers
    # research-agent's hot path; scan(Path) covers claude-cl-sync's.
    for c in _DETERMINISTIC:
        for variant, runner in (
            ("scan_text", lambda p: scan_text(p, use_honeypot=False)),
            ("scan",      lambda p: _scan_via_path(p, use_honeypot=False)),
        ):
            v: Verdict = runner(c.payload)
            tag = f"{c.label}[{variant}]"
            if v.ok:
                failures.append(f"{tag}: payload passed (expected block)")
                continue
            if c.expected_reason_substring not in v.reason:
                failures.append(
                    f"{tag}: blocked but wrong layer "
                    f"({v.reason!r}, expected substr {c.expected_reason_substring!r})"
                )

    if failures:
        for f in failures:
            err(f"scanner self-test FAILED: {f}")
        raise SmokeFailure("; ".join(failures))

    # Phase 2: honeypot liveness via scan(Path) so we cover the disk-read
    # wrapper at no extra API cost. A benign payload must produce a
    # "pass" honeypot layer. Anything else (skipped, unavailable,
    # accidentally triggered) means infra rot or false-positive regression.
    v = _scan_via_path(_BENIGN_PROBE, use_honeypot=True)
    if not v.ok:
        msg = (
            f"honeypot probe returned ok=False ({v.reason}). "
            "Likely L3 degraded — check ANTHROPIC_API_KEY / network / SDK."
        )
        err(f"scanner self-test FAILED: {msg}")
        raise SmokeFailure(msg)
    hp = v.layers.get("honeypot", "")
    if hp != "pass":
        msg = (
            f"honeypot layer not 'pass' on benign probe (got {hp!r}). "
            "L3 likely degraded."
        )
        err(f"scanner self-test FAILED: {msg}")
        raise SmokeFailure(msg)

    info(
        f"scanner self-test OK ({len(_DETERMINISTIC)} canaries × "
        "2 entry points blocked; honeypot live via scan(Path))"
    )
