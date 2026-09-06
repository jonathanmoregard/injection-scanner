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

Every call is PACED. `check` is the only function in the package that talks to
Lakera, and the whole fleet — a research-agent server per Claude Code pane, CI,
local eval runs — shares one account, which it collectively pushed into HTTP
429 for hours on 2026-09-05. So each call first spends a token from
`throttle.CrossProcessLimiter`: a token bucket plus a circuit breaker held in
one file under the cache directory, shared by every process on the machine. Key
resolution runs BEFORE the limiter, so a call that cannot happen (no key, a
botched `*_FILE` mount) spends nothing and cannot starve the panes that work.
Two reasons come out of it, both fail-closed like every other outage and both
fixed literals: `lakera_unavailable:throttled` when the budget is exhausted or
the breaker is open, and `lakera_unavailable:limiter-error` when the limiter
itself cannot keep state. A 429 or 503 from Lakera opens the breaker
fleet-wide; any HTTP 200 closes it.

No new dependency: the POST is issued with stdlib urllib.request, isolated in
`_post` so tests can monkeypatch it and never touch the network.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from injection_scanner.http_status import bounded_status, status_suffix
from injection_scanner.keyloader import KeyConfigError, load_key
from injection_scanner.throttle import (
    CrossProcessLimiter,
    Decision,
    default_max_wait_s,
    env_float,
)

_DEFAULT_URL = "https://api.lakera.ai/v2/guard"

# The per-request socket timeout, and the one knob in this module that is a
# LIMIT — so it gets the treatment every other limit in the package gets
# (`throttle.LimiterConfig`, `smoke.LIVENESS_TTL_RANGE`): an env INPUT, parsed
# by `env_float`, malformed-to-default and then clamped to a RANGE. Public
# names because the range is what the tests assert against and what an operator
# reads.
#
# Why a range and not a bare `float()`. Both ends fail SILENTLY, which is what
# makes them worth a clamp rather than a comment:
#
#   * a non-finite or absurd value (`inf`, `1e9` — 31 years) is a perfectly
#     good float, so no `except` fires, and `urlopen` then waits effectively
#     forever. The scan HANGS instead of failing closed, which is strictly
#     worse than a reject: fail-closed is the contract, and a parked scan
#     honours neither side of it.
#   * a NEGATIVE value makes `urlopen` raise on the spot, so every scan on the
#     box returns `lakera_unavailable:ValueError` — indistinguishable from a
#     real Lakera outage, and the reason names the exception rather than the
#     typo that caused it.
#
# The ceiling is generous (120 s) because a slow classifier is a legitimate
# configuration; the floor (1 s) is the smallest value that can complete a
# round trip, so anything under it would be a self-inflicted outage.
ENV_TIMEOUT_S = "INJECTION_SCANNER_LAKERA_TIMEOUT"
DEFAULT_TIMEOUT_S = 10.0
TIMEOUT_RANGE = (1.0, 120.0)


@dataclass
class LakeraResult:
    ok: bool
    reason: str
    flagged: bool = False
    categories: list[str] = field(default_factory=list)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect handler that refuses to redirect.

    Returning `None` from `redirect_request` makes `http_error_3xx` fall
    through the handler chain to `HTTPDefaultErrorHandler`, which raises
    `HTTPError` carrying the original status — so a 3xx arrives at
    `_transport_reason` exactly like a 500 does, and no second request is
    ever issued.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Built once, at import: the default opener FOLLOWS 3xx, and urllib strips only
# the `Content-*` headers when it builds the follow-up request — so
# `Authorization: Bearer <the shared Lakera key>` is re-sent to whatever host
# the `Location` names, cross-origin included. A redirecting endpoint (a
# captive portal, a hijacked DNS answer, a vendor URL that moved) would
# therefore hand the fleet's key to a third party, silently, while the scan
# returned an ordinary verdict.
#
# Suppressed rather than validated, because a `Location` check is a race: the
# host that answers the second request need not be the host that was checked.
# There is no legitimate redirect on this endpoint, so the whole behaviour goes
# away and a 3xx becomes what it already is for this caller — an outage. The
# `Location` value is neither read nor logged.
#
# `build_opener` replaces its default `HTTPRedirectHandler` with any SUBCLASS
# passed in, which is why `_NoRedirect` derives from it rather than standing
# alone. Everything else (proxy, cookie-less HTTP/HTTPS, the error processor)
# stays as `urlopen` had it.
_OPENER = urllib.request.build_opener(_NoRedirect())


def _post(url: str, body: bytes, headers: dict, timeout: float) -> dict:
    """Isolated stdlib POST -> parsed JSON dict.

    Kept as a thin, monkeypatchable seam so the unit tests can inject
    responses (or raise) without any network access. Raises on network /
    HTTP / decode errors; the caller's blanket except turns those into a
    fail-closed reject.

    Goes through `_OPENER`, not `urlopen`: see the comment on it for why a
    followed redirect is a key-exfiltration bug rather than a convenience.
    """
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with _OPENER.open(req, timeout=timeout) as resp:
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


def _is_https(url: str) -> bool:
    """True only for a URL whose scheme is exactly `https`.

    `LAKERA_GUARD_URL` is an operator input, and the next thing that happens to
    the URL is that `Bearer <the shared Lakera key>` is attached to it. Over
    `http://` that key crosses the wire in cleartext — and `urlopen` honours
    `http_proxy`/`all_proxy`, so a proxy variable in the environment is enough
    to route it through a host nobody chose deliberately. Every other scheme is
    worse in its own way (`file://` reads a local path and calls it a verdict).

    `urlsplit` lowercases the scheme, so `HTTPS://` is accepted — that is RFC
    3986's own rule, not a widening. Total: `urlsplit` raises `ValueError` on a
    malformed authority (an unbalanced IPv6 bracket), and a URL that cannot be
    parsed is not one that can be verified.
    """
    try:
        return urllib.parse.urlsplit(url).scheme == "https"
    except Exception:  # noqa: BLE001 — unparseable is not verifiable
        return False


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
      * `LAKERA_GUARD_URL` is not an https URL
                                 -> ok=False reason "lakera_unavailable:url-config-error"
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

    # The endpoint, resolved and checked BEFORE the key is attached to
    # anything and before a token is spent — the same rule key resolution
    # already follows, and for both of its reasons. A call that must not
    # happen must not cost the fleet a token; and a misconfigured endpoint is
    # a deployment error, so it is decided while the key is still nowhere near
    # a header.
    #
    # `http://` is the shape that matters: it puts `Bearer <the shared Lakera
    # key>` on the wire in cleartext, and `urlopen` honours `http_proxy` /
    # `all_proxy`, so a single environment variable is enough to route the
    # fleet's key through a host nobody chose. The reason is a fixed literal
    # from the closed vocabulary — the URL that caused it is NOT echoed, since
    # it is operator-authored text on a channel promised to be content-free.
    url = os.environ.get("LAKERA_GUARD_URL") or _DEFAULT_URL
    if not _is_https(url):
        return LakeraResult(ok=False, reason="lakera_unavailable:url-config-error")

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
    started_at = 0.0
    try:
        limiter = CrossProcessLimiter.from_env()
        if max_wait_s is None:
            max_wait_s = default_max_wait_s()
        decision = limiter.acquire(max_wait_s)
        # The moment this call is ISSUED, off the same wall clock the limiter
        # writes into its state file. Read HERE, not when the response lands:
        # a 200 may come back after peers have already shut the breaker, and
        # `record_success` discards a success older than the trip so that one
        # straggler cannot cancel the fleet's decision. Read after `acquire`
        # rather than before it because a waiting `acquire` can block for
        # minutes, and the call did not start until it returned.
        started_at = time.time()
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

    # Default-then-clamp, exactly like every limiter knob. See `TIMEOUT_RANGE`
    # for why a bare `float()` was not enough: the values that get through it
    # are the ones that hang the scan or disguise a typo as an outage.
    timeout = env_float(ENV_TIMEOUT_S, DEFAULT_TIMEOUT_S, TIMEOUT_RANGE)

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
        #
        # Outside the try/except above, deliberately: Task 1's recorders are
        # TOTAL by contract — they swallow their own errors, precisely so a
        # broken limiter cannot raise in the middle of a fail-closed result.
        # Pinned by tests/test_throttle.py::
        # test_an_unusable_state_directory_is_an_error_and_never_raises and
        # ::test_a_failed_write_leaves_the_previous_state_intact.
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
    # `started_at` is what lets the limiter tell this from a straggler whose
    # 200 predates a trip. Unguarded for the same reason as the recorder
    # above: total by contract, pinned by the same two tests.
    limiter.record_success(started_at)

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
