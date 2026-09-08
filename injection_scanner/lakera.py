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
    env_int,
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

# How many bytes of a response body this layer will read. The second LIMIT in
# this module, and it gets the same treatment as the first: an env INPUT,
# malformed-to-default, then clamped to a range.
#
# The timeout bounds how LONG a call may take; nothing bounded how MUCH it
# could return. A wedged proxy, a misrouted endpoint or a hostile server
# answering with gigabytes drives the process to the OOM killer, and process
# death is not a fail-closed reject: the report is neither delivered nor
# refused, the pane dies mid-scan, and no reason string is ever produced to say
# so. Every other failure in this module degrades to a reason; this one
# degraded to a corpse, which is why a cap belongs here and not only in the
# operator's kernel settings.
#
# 1 MiB is two orders of magnitude above any real Guard response (a breakdown
# with every detector is a few kilobytes), so it is headroom rather than a
# fitted value; the range exists because both ends fail badly. The floor (4 KiB)
# is the smallest cap that can still hold a legitimate breakdown, so anything
# under it would be a self-inflicted outage; the ceiling (64 MiB) keeps a typo
# from being spelled as "unbounded again".
ENV_MAX_RESPONSE_BYTES = "INJECTION_SCANNER_LAKERA_MAX_RESPONSE_BYTES"
DEFAULT_MAX_RESPONSE_BYTES = 1_048_576
MAX_RESPONSE_BYTES_RANGE = (4096, 67_108_864)


class ResponseTooLarge(Exception):
    """The response body exceeded `ENV_MAX_RESPONSE_BYTES`.

    A dedicated type, and deliberately not a `ValueError` or an `OSError`: the
    blanket handler in `check` renders it by TYPE NAME, so the outage reads
    `lakera_unavailable:ResponseTooLarge` and is distinguishable from a torn
    connection or a parse failure. Carries no message — nothing about the body
    it refused, its length included, crosses the scanner boundary.
    """


class DuplicateJSONKey(Exception):
    """A JSON object repeated a key.

    Carries no message because response keys are server-controlled content and
    this exception crosses the transport boundary before becoming the fixed
    `lakera_unavailable:bad-response` reason.
    """


class UnexpectedHTTPStatus(Exception):
    """The response status was not the exact HTTP 200 contract.

    Carries no message so provider-controlled response metadata cannot reach
    the caller-visible transport reason.
    """


def _max_response_bytes() -> int:
    return env_int(
        ENV_MAX_RESPONSE_BYTES, DEFAULT_MAX_RESPONSE_BYTES, MAX_RESPONSE_BYTES_RANGE
    )


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
# `build_opener` replaces defaults when an instance of their class is passed.
# `_NoRedirect` replaces redirect following, while `ProxyHandler({})` replaces
# environment-derived proxy routing with an explicitly empty mapping. CPython
# then omits that empty handler from `.handlers`, but its presence here still
# suppresses the default ambient-proxy handler.
def _build_opener():
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
    )


_OPENER = _build_opener()


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKey
        result[key] = value
    return result


def _post(url: str, body: bytes, headers: dict, timeout: float) -> dict:
    """Isolated stdlib POST -> parsed JSON dict.

    Kept as a thin, monkeypatchable seam so the unit tests can inject
    responses (or raise) without any network access. Raises on network /
    HTTP / decode errors, including any status other than exact HTTP 200; the
    caller's blanket except turns those into a fail-closed reject.

    Goes through `_OPENER`, not `urlopen`: see the comment on it for why a
    followed redirect is a key-exfiltration bug rather than a convenience.

    The read is CAPPED. `read(cap + 1)` is what makes the check possible
    without buffering the thing being refused: one byte over the limit is
    enough to know, and the rest is never pulled off the socket.
    """
    cap = _max_response_bytes()
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with _OPENER.open(req, timeout=timeout) as resp:
        try:
            status = resp.status
        except Exception:  # noqa: BLE001 — missing/hostile status fails closed
            raise UnexpectedHTTPStatus from None
        if type(status) is not int or status != 200:
            raise UnexpectedHTTPStatus
        raw = resp.read(cap + 1)
    if len(raw) > cap:
        raise ResponseTooLarge
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_object_without_duplicate_keys,
    )


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


def _is_trusted_endpoint(url: str) -> bool:
    """True only for the exact Lakera Guard HTTPS destination.

    `LAKERA_GUARD_URL` is an operator input, and the next thing that happens to
    the URL is that `Bearer <the shared Lakera key>` is attached to it. Scheme,
    host, port, credentials, path, query and fragment therefore form one
    allowlisted destination rather than independent best-effort checks.

    The raw spelling must be ASCII before case normalization, preventing
    Unicode case-folding confusables from becoming an allowlisted hostname.
    The round-trip check then rejects raw bytes that `urlsplit` silently
    strips, while normalizing only scheme casing because `urlunsplit` lowers
    it. It also distinguishes a bare trailing `?` or `#` from no
    query/fragment. Raw netloc matching rejects spellings such as an empty or
    zero-padded port even when `.port` normalizes them to `None` or `443`.
    Accessing `.port` can raise for malformed and out-of-range values, which
    makes the whole unverified endpoint invalid.
    """
    if not isinstance(url, str) or not url.isascii():
        return False
    try:
        parsed = urllib.parse.urlsplit(url)
        raw_scheme, separator, raw_after_scheme = url.partition(":")
        normalized_raw = f"{parsed.scheme}:{raw_after_scheme}"
        netloc = parsed.netloc.casefold()
        return (
            separator == ":"
            and raw_scheme.casefold() == parsed.scheme
            and normalized_raw == urllib.parse.urlunsplit(parsed)
            and parsed.scheme.lower() == "https"
            and netloc in ("api.lakera.ai", "api.lakera.ai:443")
            and parsed.hostname == "api.lakera.ai"
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and parsed.path == "/v2/guard"
            and not parsed.query
            and not parsed.fragment
            and "?" not in url
            and "#" not in url
        )
    except (TypeError, ValueError):
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
      * `LAKERA_GUARD_URL` is not the exact trusted Lakera endpoint
                                 -> ok=False reason "lakera_unavailable:url-config-error"
      * fleet budget exhausted / breaker open
                                 -> ok=False reason "lakera_unavailable:throttled"
      * the limiter itself is unusable (unwritable cache dir, lock wait
        exceeded, IO error)
                                 -> ok=False reason "lakera_unavailable:limiter-error"
      * any network/HTTP/JSON/timeout error, an over-cap response body
        included (`lakera_unavailable:ResponseTooLarge`)
                                 -> ok=False reason "lakera_unavailable:<ExcType>",
                                    plus ":<status>" for an HTTPError with a
                                    plausible status code (e.g.
                                    "lakera_unavailable:HTTPError:429")
      * bad/unknown response shape
                                 -> ok=False reason "lakera_unavailable:bad-response"
      * prompt_attack detected   -> ok=False reason "lakera:prompt_attack"
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
    # The full destination is pinned because any alternate host, userinfo,
    # port, path, query or fragment could redirect where the credential goes
    # or change what handles it. The reason is a fixed literal from the closed
    # vocabulary — the URL that caused it is NOT echoed.
    url = os.environ.get("LAKERA_GUARD_URL") or _DEFAULT_URL
    if not _is_trusted_endpoint(url):
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
    except DuplicateJSONKey:
        return LakeraResult(ok=False, reason="lakera_unavailable:bad-response")
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
    # fail-open. Every decoded shape failure converges on one fixed reason;
    # response content and exception details never cross the boundary.
    #
    # Lakera Guard v2, verified 2026: the response is a dict with a top-level
    # `flagged` bool and (because we requested it) a `breakdown` list. Each
    # breakdown entry carries `detector_type` (str) and `detected` (bool); all
    # other fields are optional. The prompt-injection / jailbreak detector's
    # `detector_type` is exactly "prompt_attack".
    try:
        if not isinstance(data, dict):
            return LakeraResult(ok=False, reason="lakera_unavailable:bad-response")

        flagged = data.get("flagged")
        breakdown = data.get("breakdown")
        if type(flagged) is not bool or not isinstance(breakdown, list):
            return LakeraResult(ok=False, reason="lakera_unavailable:bad-response")

        prompt_decisions = []
        for entry in breakdown:
            if not isinstance(entry, dict):
                return LakeraResult(ok=False, reason="lakera_unavailable:bad-response")
            detector_type = entry.get("detector_type")
            detected = entry.get("detected")
            if type(detector_type) is not str or type(detected) is not bool:
                return LakeraResult(ok=False, reason="lakera_unavailable:bad-response")
            if detector_type == "prompt_attack":
                prompt_decisions.append(detected)

        if len(prompt_decisions) != 1:
            return LakeraResult(ok=False, reason="lakera_unavailable:bad-response")

        prompt_detected = prompt_decisions[0]
        if prompt_detected:
            if flagged is not True:
                return LakeraResult(ok=False, reason="lakera_unavailable:bad-response")
            return LakeraResult(
                ok=False,
                flagged=True,
                categories=["prompt_attack"],
                reason="lakera:prompt_attack",
            )
        return LakeraResult(ok=True, reason="pass")
    except Exception:  # noqa: BLE001 — hostile decoded objects fail CLOSED
        return LakeraResult(ok=False, reason="lakera_unavailable:bad-response")
