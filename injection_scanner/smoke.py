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

  2. Honeypot + Lakera liveness — one benign payload with
     use_honeypot=True AND use_lakera=True (both left ON), run through
     scan(Path). Pays one honeypot round-trip per scenario plus one
     Lakera Guard call. If L2 (Lakera) or L3 (honeypot) is degraded
     (SDK missing, key unset/revoked, provider down), production scans
     fail-closed per intercept.py; this probe surfaces that BEFORE any
     real record is processed, AND it covers the disk-read wrapper at
     minimal extra API cost. Because Lakera fails closed on a missing
     key, this phase REQUIRES a live LAKERA_API_KEY to pass.

Callers wrap the SmokeFailure exception however they want — exit
the process, refuse to bind a port, surface the reason to logs.
"""
from __future__ import annotations

import json
import math
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from injection_scanner import throttle
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

_BENIGN_PROBE = "Benign smoke probe. Sources: 1. Routine self-test, no payload."


# ---------- the fleet-wide liveness cache ----------
#
# Measured 2026-09-06: research-agent boot smokes alone ran ~632 per day — one
# per server spawn, plus one per degraded recheck — about 19,000 a month
# against Lakera's published Community quota of 10,000, before a single report
# is scanned. SPAWN FREQUENCY, not scan volume, is what exhausts the account,
# and one Claude Code session restore spawns six panes at once. The limiter in
# throttle.py bounds the RATE; it cannot reduce the demand. This does.
#
# So one PASSING Phase 2 probe is trusted fleet-wide for a TTL. It is a cache
# in front of a probe, NOT a gate: every failure mode below degrades to "run
# the probe exactly as before", never to "pass without probing". Phase 1 is
# never cached — it checks THIS process's own code, not the fleet's vendors.
#
# What a stale cached pass can hide: an outage that began within the TTL. Then
# the server boots "healthy" and the first real scan fails closed with the
# agent-readable infra reason. Fail-closed and visibility are both preserved;
# only the moment of discovery moves from spawn to first use.
#
# It caches a BOOLEAN ABOUT THE VENDORS, never a verdict about content. A
# verdict cache would be a second system with its own staleness and poisoning
# questions, and is deliberately out of scope.

ENV_LIVENESS_TTL_S = "INJECTION_SCANNER_SMOKE_LIVENESS_TTL_S"

# One hour: long enough that a six-pane session restore costs ONE Lakera call
# instead of six, short enough that an outage is rediscovered within the same
# working hour. `0` disables the cache; the clamp ceiling is a day. An INPUT,
# like every other limit in this package — never a fitted constant.
DEFAULT_LIVENESS_TTL_S = 3600.0
LIVENESS_TTL_RANGE = (0.0, 86400.0)

# Bumped only when the on-disk shape changes. Any other value is FOREIGN and is
# discarded exactly like a corrupt file: an older or newer scanner sharing the
# cache directory must never hand this one a liveness claim it would misread.
_LIVENESS_SCHEMA = 1

_LIVENESS_STATE_NAME = "smoke-liveness.json"
_LIVENESS_LOCK_NAME = "smoke-liveness.lock"


def _liveness_paths() -> tuple[Path, Path]:
    """State file and lock file, in the same cache directory the limiter and
    the self-updater already use — one place for an operator to look, and one
    place to clear."""
    d = throttle.cache_dir()
    return d / _LIVENESS_STATE_NAME, d / _LIVENESS_LOCK_NAME


def _liveness_ttl_s() -> float:
    """How long one passing probe is trusted. Malformed values fall back to
    the default and are then clamped, so a typo degrades to the documented
    hour rather than to a cache that never expires."""
    return throttle.env_float(
        ENV_LIVENESS_TTL_S, DEFAULT_LIVENESS_TTL_S, LIVENESS_TTL_RANGE
    )


def _liveness_lock_wait_s() -> float:
    """Bounded wait for the liveness lock.

    Deliberately the limiter's own `INJECTION_SCANNER_LAKERA_LOCK_WAIT_S`
    rather than a new knob: the flock discipline is shared, so the bound on it
    should be too, and an operator who widens one has widened both.
    """
    return throttle.LimiterConfig.from_env().lock_wait_s


def _cached_liveness_age(now: float) -> float | None:
    """Age in seconds of a still-fresh cached PASS, or `None` for a miss.

    Every unusable shape is a MISS, never an error and never a pass: missing,
    unreadable, truncated, non-JSON, wrong type, foreign schema, `ok` that is
    not literally `true`, an `at` that will not parse or is not finite, an `at`
    in the FUTURE (a clock step — trusting it could extend the TTL by an
    arbitrary amount), or an entry older than the TTL. A miss costs one probe,
    which is exactly what every boot cost before this cache existed.

    A cache directory this uid does not own is a miss too: `throttle.file_lock`
    refuses it, which lands in the `except` below. Somebody else's file must
    not be able to suppress the fleet's vendor probe.

    `json.loads` accepts bare `NaN`/`Infinity`, which is why the finiteness
    check is explicit rather than implied by `float()`.
    """
    ttl = _liveness_ttl_s()
    if ttl <= 0.0:
        return None
    state_path, lock_path = _liveness_paths()
    try:
        with throttle.file_lock(lock_path, _liveness_lock_wait_s()):
            obj = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — TOTAL by contract; any failure is a miss
        return None
    if not isinstance(obj, dict) or obj.get("schema") != _LIVENESS_SCHEMA:
        return None
    if obj.get("ok") is not True:
        return None
    try:
        at = float(obj["at"])
    except (KeyError, TypeError, ValueError):
        return None
    if not math.isfinite(at):
        return None
    age = now - at
    if age < 0.0 or age > ttl:
        return None
    return age


def _record_liveness_pass(now: float) -> None:
    """Record that the probe passed. Best effort, by design.

    An unwritable cache directory means the pass is simply not recorded — the
    next spawn probes again, which is what happens today. Failing the smoke
    because a CACHE could not be written would turn an optimisation into a new
    way to refuse to boot.

    The file carries a boolean and a timestamp and nothing else: no reason
    string, no layer map, no probe text. Invariant 4 ("the caught bytes never
    return") therefore holds trivially, and the payload is built by NAMING its
    three fields, so anything added upstream tomorrow stays invisible.
    """
    if _liveness_ttl_s() <= 0.0:
        return
    state_path, lock_path = _liveness_paths()
    try:
        with throttle.file_lock(lock_path, _liveness_lock_wait_s()):
            throttle.atomic_write_json(
                state_path,
                {"schema": _LIVENESS_SCHEMA, "ok": True, "at": now},
            )
    except Exception:  # noqa: BLE001 — see the docstring
        return


def _scan_via_path(payload: str, *, use_honeypot: bool, use_lakera: bool = True) -> Verdict:
    """Write payload to a temp file and run scan(Path). Cleans up the
    temp file even if scan raises. Exists so the disk-read wrapper
    doesn't sit untested."""
    with tempfile.NamedTemporaryFile(
        "w", suffix=".smoke", delete=False, encoding="utf-8"
    ) as tf:
        tf.write(payload)
        tpath = Path(tf.name)
    try:
        return scan(tpath, use_honeypot=use_honeypot, use_lakera=use_lakera)
    finally:
        try:
            tpath.unlink()
        except FileNotFoundError:
            pass


def run_smoke(
    *,
    log_info: Callable[[str], None] | None = None,
    log_error: Callable[[str], None] | None = None,
    clock: Callable[[], float] = time.time,
) -> None:
    """Run the self-test. Raises SmokeFailure on any regression.

    log_info / log_error are injected so callers can route messages
    through their own logger (stdlib logging, FastMCP, journal, etc.)
    without this module taking a hard logger dep.

    `clock` drives the liveness cache's TTL arithmetic and nothing else. It
    DEFAULTS, so every existing caller — research-agent's boot smoke
    (`run_smoke(log_info=…, log_error=…)`), the scheduled CI job, an ad-hoc
    CLI run — keeps working unchanged. Wall-clock rather than monotonic,
    deliberately: the cache is read by processes that did not exist when it
    was written.
    """
    info = log_info or (lambda _msg: None)
    err = log_error or (lambda _msg: None)

    failures: list[str] = []

    # Phase 1: every canary, both entry points. scan_text covers
    # research-agent's hot path; scan(Path) covers claude-cl-sync's.
    for c in _DETERMINISTIC:
        for variant, runner in (
            ("scan_text", lambda p: scan_text(p, use_honeypot=False, use_lakera=False)),
            ("scan",      lambda p: _scan_via_path(p, use_honeypot=False, use_lakera=False)),
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

    # Phase 2: honeypot + Lakera liveness via scan(Path) so we cover the
    # disk-read wrapper. A benign payload must produce a "pass" honeypot
    # layer AND a "pass" lakera layer. Anything else (skipped, unavailable,
    # accidentally triggered) means infra rot or a false-positive
    # regression. Because Lakera fails closed on a missing key, this phase
    # requires a live LAKERA_API_KEY.
    #
    # It is also the ONE call in here that spends vendor quota, which is why a
    # recent fleet-wide PASS is trusted instead of re-run: hit -> return,
    # miss -> probe exactly as before. See the liveness cache above.
    age = _cached_liveness_age(clock())
    if age is not None:
        info(f"liveness probe: cached pass, {int(age)}s old")
        info(
            f"scanner self-test OK ({len(_DETERMINISTIC)} canaries × "
            "2 entry points blocked; lakera + honeypot liveness from cache)"
        )
        return

    v = _scan_via_path(_BENIGN_PROBE, use_honeypot=True, use_lakera=True)
    if not v.ok:
        msg = (
            f"benign liveness probe returned ok=False ({v.reason}). "
            "Likely L2/L3 degraded — check LAKERA_API_KEY / ANTHROPIC_API_KEY "
            "/ OPENAI_API_KEY / network / SDK."
        )
        err(f"scanner self-test FAILED: {msg}")
        raise SmokeFailure(msg)
    lk = v.layers.get("lakera", "")
    if lk != "pass":
        msg = (
            f"lakera layer not 'pass' on benign probe (got {lk!r}). "
            "L2 likely degraded — check LAKERA_API_KEY / network."
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

    # Only here, with all three Phase 2 checks passed, is the result worth
    # sharing. A failure raised above and recorded nothing, so an outage can
    # never be cached — one bad boot must not silence the probe fleet-wide.
    _record_liveness_pass(clock())

    info(
        f"scanner self-test OK ({len(_DETERMINISTIC)} canaries × "
        "2 entry points blocked; lakera + honeypot live via scan(Path))"
    )
