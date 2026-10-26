"""Self-test for the layered intercept shim.

Exposes `run_smoke()` so consumers (research-agent MCP server boot,
claude-cl-sync cron tick, ad-hoc CLI)
all exercise the same checks instead of hand-rolling drift-prone copies.

Each canary runs through BOTH public entry points so a regression
in either the in-memory path (`scan_text`) or the disk-read wrapper
(`scan` — adds path.read_text(encoding="utf-8", errors="replace"))
is caught at startup. claude-cl-sync uses scan(Path); research-agent
uses scan_text(str); without dual coverage, a wrapper-only bug
would slip past the consumer that doesn't exercise that entry point.

Two phases, neither of which makes a network call:

  1. Deterministic canaries — one per detector class (secret_shapes,
     unicode_sanitize). Each must be blocked AND the verdict.reason
     must mention the expected detector. Catches the "some other
     layer accidentally caught it" failure mode where a class
     regression hides because a sibling class still triggers.

  2. Readiness — could each remote layer be asked at all? L2 panel
     (`l2.ready`: credential, endpoint, limiter directory per vendor,
     against the panel floor), L3 honeypot and L4 judge (SDK importable,
     key resolvable). The first layer that is not ready raises, named by
     `diagnose.describe`.

Why no live probe (2026-10-24). It used to send one benign report through
the full stack, which spent vendor quota on every boot and recheck — enough,
measured 2026-09-06, to exhaust Lakera's monthly quota from spawns alone — and
needed a fleet-wide liveness cache that could hide a pane-local fault behind
a peer's pass. Its real value was refusing early on SETUP errors, which
readiness catches without a call. A vendor outage surfaces at the first real
scan instead: fail-closed, with the same agent-readable reason.

Callers wrap the SmokeFailure exception however they want — exit
the process, refuse to bind a port, surface the reason to logs.
"""
from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from injection_scanner import honeypot, judge, l2
from injection_scanner.diagnose import describe
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
# the expected detector. A regression in one detector that accidentally
# still gets caught by a sibling (because the payload contains an unrelated
# token) would otherwise silently pass — substring match catches that
# "wrong layer caught it" mode.
_DETERMINISTIC: tuple[_Canary, ...] = (
    # secret_shapes
    _Canary("github_token",    "leaked: ghp_" + "a" * 36, "github_token"),
    _Canary("anthropic_oauth", "key: sk-ant-oat01-" + "B" * 60, "anthropic"),
    # unicode_sanitize
    _Canary("bidi_density",    "safe‮malicious" * 200, "unicode_anomaly"),
)

def _scan_via_path(payload: str, *, use_honeypot: bool, use_l2: bool = True) -> Verdict:
    """Write payload to a temp file and run scan(Path). Cleans up the
    temp file even if scan raises. Exists so the disk-read wrapper
    doesn't sit untested."""
    with tempfile.NamedTemporaryFile(
        "w", suffix=".smoke", delete=False, encoding="utf-8"
    ) as tf:
        tf.write(payload)
        tpath = Path(tf.name)
    try:
        return scan(tpath, use_honeypot=use_honeypot, use_l2=use_l2)
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
    """Run the self-test. Raises SmokeFailure on any regression or any layer
    that is not ready. Makes no network call.

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
            ("scan_text", lambda p: scan_text(p, use_honeypot=False, use_l2=False)),
            ("scan",      lambda p: _scan_via_path(p, use_honeypot=False, use_l2=False)),
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

    # Phase 2: readiness, remote layers in pipeline order; the first not ready
    # is reported. Each answers `None` or a closed-vocabulary reason. No
    # vendor is called and no limiter token is spent.
    for layer_ready in (l2.ready, honeypot.ready, judge.ready):
        reason = layer_ready()
        if reason is not None:
            msg = f"readiness check failed ({reason}). Failed layer — {describe(reason)}."
            err(f"scanner self-test FAILED: {msg}")
            raise SmokeFailure(msg)

    info(
        f"scanner self-test OK ({len(_DETERMINISTIC)} canaries × "
        "2 entry points blocked; l2 panel, honeypot and judge ready)"
    )
