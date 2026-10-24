"""
Layer 2: a panel of hosted prompt-injection classifiers, FAIL-CLOSED.

Every vendor in `VENDORS` classifies the same text, concurrently (wall time is
the slowest vendor's wait, not the sum). Each answer is a VERDICT
(`pass` or `<vendor>:prompt_attack`) or a SHORTFALL
(`<vendor>_unavailable:<condition>`).

Decision, with `floor` = `INJECTION_SCANNER_L2_MIN_VERDICTS` (default 2,
clamped to [1, number of vendors]):

  verdicts >= floor
      any prompt_attack -> FLAGGED      (reason: first flag, registry order)
      otherwise         -> PASS         (reason: `pass`)
  verdicts <  floor
      every shortfall is quota-class
                        -> DEGRADED_QUOTA (reason: first shortfall)
      otherwise         -> UNAVAILABLE  (reason: first non-quota shortfall)

Quota-class is exact membership in `<vendor>_unavailable:HTTPError:429` and
`<vendor>_unavailable:throttled` for that same vendor — no prefix matching,
no status parsing. The caller (`intercept.scan_text`) sends FLAGGED and
DEGRADED_QUOTA to strict L3/L4 arbitration and rejects UNAVAILABLE.

Invariant 3: an exception inside an adapter is that vendor's outage,
`<vendor>_unavailable:unhandled:<ExcType>`, never an escape. Closed
vocabulary: a result that is not a well-formed verdict and whose reason is not
in the vendor's own `<vendor>_unavailable:` namespace becomes
`<vendor>_unavailable:bad-result`, so no adapter bug can carry free text (or
another vendor's reason) across the scanner boundary.
"""
from __future__ import annotations

import enum
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Mapping

from injection_scanner import lakera, modelarmor
from injection_scanner.throttle import (
    CrossProcessLimiter,
    LimiterConfig,
    env_int,
    file_lock,
)
from injection_scanner.vendor_http import VendorResult

# Fixed registry order: reasons are chosen "first in registry order", so the
# order is part of the contract.
VENDORS: tuple[str, ...] = ("lakera", "model_armor")
_ADAPTERS = {"lakera": lakera, "model_armor": modelarmor}

ENV_MIN_VERDICTS = "INJECTION_SCANNER_L2_MIN_VERDICTS"
DEFAULT_MIN_VERDICTS = 2

Check = Callable[..., VendorResult]


class Outcome(enum.Enum):
    PASS = "pass"
    FLAGGED = "flagged"
    DEGRADED_QUOTA = "degraded-quota"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class PanelResult:
    outcome: Outcome
    reason: str
    results: dict[str, VendorResult]
    """Per-vendor results, in registry order."""
    verdicts: int
    floor: int

    @property
    def summary(self) -> str:
        """`<outcome> verdicts=<n>/<vendors> floor=<floor>`: fixed words and
        integers only, safe for `Verdict.layers`."""
        return (
            f"{self.outcome.value} verdicts={self.verdicts}/{len(self.results)} "
            f"floor={self.floor}"
        )


def outcome_of(summary: object) -> Outcome | None:
    """The Outcome named by a `PanelResult.summary`, or None.

    Exact match on the first word against the enum; anything else (a
    disabled panel, a malformed or foreign string) is None.
    """
    if not isinstance(summary, str):
        return None
    head = summary.split(" ", 1)[0]
    for outcome in Outcome:
        if outcome.value == head:
            return outcome
    return None


def _is_pass(r: object) -> bool:
    return (
        isinstance(r, VendorResult)
        and r.ok is True
        and r.flagged is False
        and r.reason == "pass"
    )


def _is_flag(vendor: str, r: object) -> bool:
    return (
        isinstance(r, VendorResult)
        and r.ok is False
        and r.flagged is True
        and r.reason == f"{vendor}:prompt_attack"
    )


def _is_quota(vendor: str, reason: str) -> bool:
    return reason in (
        f"{vendor}_unavailable:HTTPError:429",
        f"{vendor}_unavailable:throttled",
    )


def _run_one(
    vendor: str, check: Check, text: str, max_wait_s: float | None
) -> VendorResult:
    try:
        r = check(text, max_wait_s=max_wait_s)
    except Exception as e:  # noqa: BLE001 — Invariant 3: reduce to reject
        return VendorResult(
            ok=False, reason=f"{vendor}_unavailable:unhandled:{type(e).__name__}"
        )
    if _is_pass(r) or _is_flag(vendor, r):
        return r
    if (
        isinstance(r, VendorResult)
        and r.ok is False
        and r.flagged is False
        and isinstance(r.reason, str)
        and r.reason.startswith(f"{vendor}_unavailable:")
    ):
        return r
    return VendorResult(ok=False, reason=f"{vendor}_unavailable:bad-result")


def _floor(n_vendors: int) -> int:
    return env_int(ENV_MIN_VERDICTS, DEFAULT_MIN_VERDICTS, (1, n_vendors))


def _default_checks() -> dict[str, Check]:
    # Resolved per call so a replaced adapter `check` is the one that runs.
    return {name: _ADAPTERS[name].check for name in VENDORS}


def run(
    text: str,
    *,
    max_wait_s: float | None = None,
    checks: Mapping[str, Check] | None = None,
) -> PanelResult:
    """Classify `text` with every vendor at once and decide the panel outcome.

    `max_wait_s` is passed to each vendor unchanged; they wait concurrently.
    `checks` maps vendor name to adapter `check`, in registry order; `None`
    means the production registry.
    """
    if checks is None:
        checks = _default_checks()
    names = list(checks)
    with ThreadPoolExecutor(max_workers=len(names)) as pool:
        futures = {
            name: pool.submit(_run_one, name, checks[name], text, max_wait_s)
            for name in names
        }
        results = {name: futures[name].result() for name in names}

    floor = _floor(len(names))
    flags = [r.reason for name, r in results.items() if _is_flag(name, r)]
    verdicts = sum(
        1 for name, r in results.items() if _is_pass(r) or _is_flag(name, r)
    )
    shortfalls = [
        (name, r.reason)
        for name, r in results.items()
        if not (_is_pass(r) or _is_flag(name, r))
    ]

    if verdicts >= floor:
        if flags:
            outcome, reason = Outcome.FLAGGED, flags[0]
        else:
            outcome, reason = Outcome.PASS, "pass"
    else:
        hard = [reason for name, reason in shortfalls if not _is_quota(name, reason)]
        if hard:
            outcome, reason = Outcome.UNAVAILABLE, hard[0]
        else:
            outcome, reason = Outcome.DEGRADED_QUOTA, shortfalls[0][1]

    return PanelResult(
        outcome=outcome,
        reason=reason,
        results=results,
        verdicts=verdicts,
        floor=floor,
    )


# ---------- readiness: can each vendor be asked at all? ----------
#
# Deterministic and offline, for the boot smoke. No vendor call, no limiter
# token, no breaker read: whether a vendor is UP is the scan path's question,
# answered per scan, fail-closed and agent-readable. Readiness answers only
# what refusing at boot is worth refusing on — setup errors that would fail
# every scan.
#
# Adapter contract: a vendor module MAY define
#
#     def ready() -> str | None
#
# returning `None` when a call could be sent, else the closed
# `<vendor>_unavailable:<condition>` reason its `check` would return before
# sending (credential and endpoint/config resolution). It must not touch the
# network. The limiter directory is checked here, once for every vendor,
# because `vendor_http.paced_post` is shared. An adapter WITHOUT `ready` is
# `<vendor>_unavailable:not-implemented`: readiness that cannot be vouched for
# is not readiness.


def _limiter_ready(vendor: str) -> str | None:
    """The vendor's limiter state directory is usable: created or present,
    owned and mode-safe (`file_lock` refuses otherwise), lockable within the
    configured wait, writable, and its state file (if any) readable. Every
    failure is the `limiter-error` a scan would hit."""
    try:
        limiter = CrossProcessLimiter.from_env(vendor)
        with file_lock(limiter.lock_path, LimiterConfig.from_env(vendor).lock_wait_s):
            if not os.access(limiter.lock_path.parent, os.W_OK | os.X_OK):
                raise PermissionError("limiter directory not writable")
            if limiter.state_path.exists():
                limiter.state_path.read_bytes()
    except Exception:  # noqa: BLE001 — any limiter fault fails the scan closed
        return f"{vendor}_unavailable:limiter-error"
    return None


def _vendor_ready(vendor: str) -> str | None:
    adapter_ready = getattr(_ADAPTERS[vendor], "ready", None)
    if adapter_ready is None:
        return f"{vendor}_unavailable:not-implemented"
    try:
        reason = adapter_ready()
    except Exception as e:  # noqa: BLE001 — Invariant 3, as in `_run_one`
        return f"{vendor}_unavailable:unhandled:{type(e).__name__}"
    if reason is None:
        return _limiter_ready(vendor)
    if isinstance(reason, str) and reason.startswith(f"{vendor}_unavailable:"):
        return reason
    return f"{vendor}_unavailable:bad-result"


def ready() -> str | None:
    """`None` when at least `floor` vendors are ready, else the first
    not-ready vendor's reason in registry order.

    Mirrors `run`: below the floor every scan is UNAVAILABLE (no readiness
    condition is quota-class), at or above it scans can still reach a verdict.
    """
    reasons = [_vendor_ready(name) for name in VENDORS]
    not_ready = [r for r in reasons if r is not None]
    if len(VENDORS) - len(not_ready) >= _floor(len(VENDORS)):
        return None
    return not_ready[0]
