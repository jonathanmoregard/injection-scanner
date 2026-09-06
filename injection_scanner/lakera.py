"""
Layer 2: hosted Lakera Guard classifier — a FAIL-CLOSED gate.

Lakera Guard (https://api.lakera.ai) is a hosted prompt-injection / jailbreak
classifier. This layer sits between L1b (secret_shapes) and L3 (honeypot) and
is wired as a GATE, not an additive skip.

Design principle (from the maintainer): **all config issues must lead to loud
REJECTION — fail-CLOSED, exactly like the honeypot.** This is the OPPOSITE of
an earlier additive design where a missing key silently degraded to "pass".
Here, ANYTHING that prevents us from getting a clean classification — no key,
a botched `*_FILE` mount, a network error, an HTTP error, a malformed JSON
response — collapses to `ok=False` and the report is quarantined. Silent
degradation of a detection layer is the exact failure mode operators must hear
about, so an outage rejects real reports until the layer is back.

Key resolution goes through injection_scanner.keyloader with FILE > env >
keyring precedence (the FILE tier is the agenix pattern). A configured-but-
broken FILE path raises KeyConfigError, which we catch into a fail-closed
reject rather than crashing the scan.

Invariant (honeypot-manufacturing Invariant 4 — "the caught bytes never
return"): the `reason` and `categories` strings carry ONLY detector /
category labels, exception TYPE names, and a bounded HTTP status code —
never any fragment of the scanned input, and never a stringified exception
(some HTTP/JSON errors embed the request/response body, which is itself the
attacker-shaped bytes we sent). See `_transport_reason` for why the status
code is on the safe side of that line.

No new dependency: the POST is issued with stdlib urllib.request, isolated in
`_post` so tests can monkeypatch it and never touch the network.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from injection_scanner.http_status import bounded_status, status_suffix
from injection_scanner.keyloader import KeyConfigError, load_key
from injection_scanner.throttle import (
    CrossProcessLimiter,
    Decision,
    default_max_wait_s,
)

_DEFAULT_URL = "https://api.lakera.ai/v2/guard"
_DEFAULT_TIMEOUT_S = 10.0


@dataclass
class LakeraResult:
    ok: bool
    reason: str
    flagged: bool = False
    categories: list[str] = field(default_factory=list)


def _post(url: str, body: bytes, headers: dict, timeout: float) -> dict:
    """Isolated stdlib POST -> parsed JSON dict.

    Kept as a thin, monkeypatchable seam so the unit tests can inject
    responses (or raise) without any network access. Raises on network /
    HTTP / decode errors; the caller's blanket except turns those into a
    fail-closed reject.
    """
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    return json.loads(raw.decode("utf-8"))


def _transport_reason(e: BaseException) -> str:
    """Caller-visible reason for a failed POST: exception TYPE, plus the
    HTTP status when there is one.

    NEVER `str(e)`, and never anything else off the exception. An
    `HTTPError` stringifies as its reason phrase and can be `.read()` for
    the response body; both are server-supplied TEXT, and a provider error
    body can echo the request we sent — i.e. the attacker-shaped report
    bytes. Those stay out of `reason`, which is read outside the quarantine
    zone.

    The STATUS CODE is different in kind, not merely in degree. It is a
    bounded integer, range-checked by `http_status.bounded_status` before
    it is formatted, so at most three ASCII digits can reach the caller —
    strictly less expressive than the exception type name already in the
    string. Measured 2026-09-05: without it every failure read
    `lakera_unavailable:HTTPError`, so an expired key (401), throttling
    (429) and a Lakera-side outage (5xx) were indistinguishable and cost an
    operator a full session to tell apart.

    The `isinstance` gate is deliberate: only a real `HTTPError` has a
    `.code` that MEANS an HTTP status, so every other exception type keeps
    its previous reason byte for byte by construction rather than by
    coincidence of not having the attribute.
    """
    reason = f"lakera_unavailable:{type(e).__name__}"
    if isinstance(e, urllib.error.HTTPError):
        reason += status_suffix(e, "code")
    return reason


def _breaker_code(e: BaseException) -> int | None:
    """The HTTP status, as a bounded int, for BREAKER decisions only.

    Deliberately separate from `_transport_reason`'s use of `status_suffix`:
    that one decides what an operator reads, this one decides whether the
    whole fleet stops calling Lakera. `.code` is a plain attribute anyone can
    rebind and, on an SDK-style exception, can be a property that raises — so
    the read is guarded and the value is range-checked by `bounded_status`
    before it is compared. A value that is not a plausible status yields
    `None`, which leaves the breaker untouched.

    The `isinstance` gate means only a real `HTTPError` can trip the breaker:
    every other exception type is a transport or parse failure, which says
    nothing about our rate against the account.
    """
    if not isinstance(e, urllib.error.HTTPError):
        return None
    try:
        raw = getattr(e, "code", None)
    except Exception:  # noqa: BLE001 — a raising property is not an outage
        return None
    return bounded_status(raw)


def _retry_after(e: BaseException) -> str | None:
    """The raw `Retry-After` header, for the limiter and nothing else.

    This value is server-supplied TEXT. It is handed straight to
    `CrossProcessLimiter.record_throttled`, which parses it into a clamped
    number and discards the string; it is never bound to a local that
    reason-building code can reach, never logged, and never stored. See
    `throttle._parse_retry_after` for what the limiter will and will not
    accept from it.

    Total, like every other helper on the fail-closed path: `e.headers` can be
    absent or a property that raises, and a raise here would replace Lakera's
    own error with the type of the failure to read a header.
    """
    try:
        headers = getattr(e, "headers", None)
        if headers is None:
            return None
        value = headers.get("Retry-After")
    except Exception:  # noqa: BLE001 — see the docstring
        return None
    return value if isinstance(value, str) else None


def _lakera_key() -> str | None:
    return load_key(
        file_env="LAKERA_API_KEY_FILE",
        env_var="LAKERA_API_KEY",
        keyring_key="lakera-api-key",
    )


def check(text: str, *, max_wait_s: float | None = None) -> LakeraResult:
    """Classify `text` with Lakera Guard. FAIL-CLOSED at every step.

    Outcomes (all non-pass outcomes REJECT — the caller treats ok=False as
    quarantine):
      * key config broken (`*_FILE` set but mount botched)
                                 -> ok=False reason "lakera_unavailable:key-config-error"
      * no key configured at all -> ok=False reason "lakera_unavailable:no-key"
      * fleet budget exhausted / breaker open
                                 -> ok=False reason "lakera_unavailable:throttled"
      * the limiter itself is unusable (unwritable cache dir, lock wait
        exceeded, IO error)
                                 -> ok=False reason "lakera_unavailable:limiter-error"
      * any network/HTTP/JSON/timeout error
                                 -> ok=False reason "lakera_unavailable:<ExcType>",
                                    plus ":<status>" for an HTTPError with a
                                    plausible status code (e.g.
                                    "lakera_unavailable:HTTPError:429")
      * bad/unknown response shape
                                 -> ok=False reason "lakera_unavailable:bad-response"
      * prompt_attack detected   -> ok=False reason "lakera:prompt_attack"
      * flagged (fallback, no breakdown)
                                 -> ok=False reason "lakera:flagged"
      * clean (or only moderation/PII fired)
                                 -> ok=True  reason "pass"

    `max_wait_s` is how long this call may WAIT for its turn in the shared
    fleet budget. `None` means "use INJECTION_SCANNER_LAKERA_MAX_WAIT_S",
    which defaults to 0 — an interactive scan refuses immediately rather than
    parking a report behind the fleet. Batch callers (`eval`) pass a real
    budget so they queue instead of failing. Both refusals are fail-closed and
    carry a fixed literal from the closed reason vocabulary; neither costs a
    network round trip.
    """
    try:
        key = _lakera_key()
    except KeyConfigError:
        # A `*_FILE` path was configured but the mount is broken. Fail loud —
        # this is a botched deployment, not mere absence.
        return LakeraResult(ok=False, reason="lakera_unavailable:key-config-error")

    if not key:
        # Nothing configured. Under fail-closed semantics this now BLOCKS —
        # the Lakera gate is mandatory, so a missing key is a deployment
        # error the operator must hear about, not a quiet pass-through.
        return LakeraResult(ok=False, reason="lakera_unavailable:no-key")

    # Fleet-wide pacing. Everything above this line is a LOCAL decision about
    # a call that is not going to happen, so it must not spend a token: a pane
    # with a botched key mount would otherwise starve the panes that work.
    #
    # The limiter is built per call. `from_env` is a handful of environment
    # reads and one `Path`, and a module-level cache would go stale the moment
    # an operator or a test changed the budget — a cache with no invalidation
    # story is not worth the microseconds.
    #
    # CONSTRUCTION is inside the same guard as `acquire`, deliberately.
    # `acquire` is total by contract, but `from_env` reads the environment and
    # resolves the cache directory, and `intercept.scan_text` does NOT wrap
    # `lakera.check` — so an exception escaping here would abort the whole
    # scan instead of rejecting one report. Both halves therefore collapse to
    # the same fail-closed reason.
    try:
        limiter = CrossProcessLimiter.from_env()
        if max_wait_s is None:
            max_wait_s = default_max_wait_s()
        decision = limiter.acquire(max_wait_s)
    except Exception:  # noqa: BLE001 — see the comment above; fails CLOSED
        decision = Decision.ERROR
    if decision is Decision.THROTTLED:
        # The bucket is empty or the breaker is open, and waiting longer is
        # not allowed. Fail CLOSED, exactly like any other outage: this layer
        # could not classify the text, so the report is rejected.
        return LakeraResult(ok=False, reason="lakera_unavailable:throttled")
    if decision is Decision.ERROR:
        # The limiter itself is unusable. Also fail CLOSED — waving calls
        # through when the pacing mechanism breaks would re-enable precisely
        # the storm it was added to stop, and it is the failure mode nobody
        # would notice.
        return LakeraResult(ok=False, reason="lakera_unavailable:limiter-error")

    url = os.environ.get("LAKERA_GUARD_URL") or _DEFAULT_URL
    try:
        timeout = float(
            os.environ.get("INJECTION_SCANNER_LAKERA_TIMEOUT", _DEFAULT_TIMEOUT_S)
        )
    except (TypeError, ValueError):
        timeout = _DEFAULT_TIMEOUT_S

    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    # Lakera Guard v2, verified 2026: POST /v2/guard with the untrusted text as
    # the most-recent user message; `breakdown: true` asks for per-detector
    # detail so we can gate on the injection detector specifically rather than
    # the top-level `flagged` (which also fires on moderation/PII). An optional
    # LAKERA_PROJECT_ID points the request at a tuned project policy.
    payload: dict = {"messages": [{"role": "user", "content": text}], "breakdown": True}
    project_id = os.environ.get("LAKERA_PROJECT_ID")
    if project_id:
        payload["project_id"] = project_id
    body = json.dumps(payload).encode("utf-8")

    try:
        data = _post(url, body, headers, timeout)
    except Exception as e:  # noqa: BLE001 — any failure fails CLOSED
        # 429 and 503 are the two codes RFC 9110 pairs with `Retry-After`, and
        # both mean "stop calling": one because we are over our rate, one
        # because Lakera is down. Either way the whole fleet should hold off,
        # not just this process — which is what `record_throttled` arranges.
        # The header goes straight into the limiter and nowhere else.
        if _breaker_code(e) in (429, 503):
            limiter.record_throttled(_retry_after(e))
        # Exception TYPE (+ bounded HTTP status) only — never str(e). Some
        # HTTP/JSON errors embed the request/response body (the
        # attacker-shaped bytes we sent), so stringifying would flow input
        # back into the caller-visible reason. See `_transport_reason`.
        return LakeraResult(ok=False, reason=_transport_reason(e))

    # A parsed response means HTTP 200: whatever the verdict turns out to be,
    # the account is evidently not throttling us, so the breaker closes and
    # the consecutive-failure count resets. Recorded here rather than in each
    # parse branch — one call site, and a future branch cannot forget it.
    limiter.record_success()

    # Parse defensively: a malformed / unexpected response shape must not
    # fail-open. Any parse error collapses to a fail-closed reject with only
    # the exception type name in the reason.
    #
    # Lakera Guard v2, verified 2026: the response is a dict with a top-level
    # `flagged` bool and (because we requested it) a `breakdown` list. Each
    # breakdown entry carries `detector_type` (str) and `detected` (bool); all
    # other fields are optional. The prompt-injection / jailbreak detector's
    # `detector_type` is exactly "prompt_attack".
    try:
        if not isinstance(data, dict):
            # Not even a JSON object — cannot classify. Fail closed.
            return LakeraResult(ok=False, reason="lakera_unavailable:bad-response")

        breakdown = data.get("breakdown")
        if isinstance(breakdown, list):
            detected = [
                e for e in breakdown
                if isinstance(e, dict) and e.get("detected") is True
            ]
            categories = sorted({
                e["detector_type"]
                for e in detected
                if isinstance(e.get("detector_type"), str)
            })
            # Gate on the injection detector ONLY. We deliberately do NOT gate
            # on moderation (moderated_content/*) or PII detectors — those fire
            # on legitimate security-research prose and would over-reject.
            # Secret-exfil is covered by the deterministic secret_shapes layer.
            if any(e.get("detector_type") == "prompt_attack" for e in detected):
                return LakeraResult(
                    ok=False,
                    flagged=True,
                    categories=categories,
                    reason="lakera:prompt_attack",
                )
            return LakeraResult(ok=True, reason="pass")

        # Fallback: no usable breakdown (shouldn't happen since we request it),
        # but a top-level bool `flagged` is present -> gate conservatively.
        flagged = data.get("flagged")
        if isinstance(flagged, bool):
            if flagged:
                return LakeraResult(ok=False, flagged=True, reason="lakera:flagged")
            return LakeraResult(ok=True, reason="pass")

        # Neither a usable breakdown nor a bool flagged -> unknown shape.
        return LakeraResult(ok=False, reason="lakera_unavailable:bad-response")
    except Exception as e:  # noqa: BLE001 — defensive parse, fail CLOSED
        return LakeraResult(ok=False, reason=f"lakera_unavailable:{type(e).__name__}")
