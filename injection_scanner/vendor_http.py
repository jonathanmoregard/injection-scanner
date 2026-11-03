"""Hardened HTTP transport shared by every hosted L2 classifier adapter.

An adapter (`lakera`, `modelarmor`) owns its credential, its pinned endpoint,
its request payload and its strict response parse. Everything between "send
these bytes to that URL" and "here is the decoded JSON, or a fail-closed
reason" lives here, once:

  * no redirects and no ambient proxy (`_OPENER`), so a credential-bearing
    request goes to the pinned endpoint and nowhere else;
  * a capped read and an exact HTTP 200 contract (`_post`);
  * JSON decoding that rejects duplicate keys at every depth;
  * caller-visible reasons built from the exception TYPE name plus a bounded
    HTTP status only (`transport_reason`), never `str(e)`;
  * fleet-wide pacing per vendor (`paced_post`): one
    `throttle.CrossProcessLimiter` per vendor name, opened by that vendor's 429
    or 503 and closed by that vendor's decoded 200.

Every input is per vendor: `INJECTION_SCANNER_<VENDOR>_TIMEOUT`,
`INJECTION_SCANNER_<VENDOR>_MAX_RESPONSE_BYTES` and the limiter's
`INJECTION_SCANNER_<VENDOR>_*` knobs.

Invariant (honeypot-manufacturing Invariant 4, "the caught bytes never
return"): no reason built here carries any fragment of the request, the
response, a header or an exception message. Server-supplied text (a reason
phrase, an error body, `Retry-After`) is either discarded or handed to the
limiter, which parses it to a clamped number.

No new dependency: stdlib `urllib.request`. `_post` is the one network seam,
monkeypatchable so tests never open a socket.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

from injection_scanner.http_status import bounded_status, status_suffix
from injection_scanner.throttle import (
    BreakerCause,
    CrossProcessLimiter,
    Decision,
    default_max_wait_s,
    env_float,
    env_int,
    vendor_env,
)

# The per-request socket timeout: an input, clamped to a range because both
# ends fail silently. A non-finite or absurd value (`inf`, `1e9`) is a valid
# float, so the scan would HANG instead of failing closed; a negative one makes
# `urlopen` raise on the spot, so every scan reads as a vendor outage instead
# of the typo it is. 1 s is the smallest value that completes a round trip;
# 120 s is generous for a slow classifier.
ENV_TIMEOUT = "TIMEOUT"
DEFAULT_TIMEOUT_S = 10.0
TIMEOUT_RANGE = (1.0, 120.0)

# How many response bytes are read. The timeout bounds how LONG a call takes;
# this bounds how MUCH it can return. Without it a wedged proxy or hostile
# server answering with gigabytes drives the process to the OOM killer — a
# dead pane, not a fail-closed reject. 1 MiB is two orders of magnitude above
# any real classifier verdict; the floor (4 KiB) still holds one, the ceiling
# (64 MiB) keeps a typo from meaning "unbounded".
ENV_MAX_RESPONSE_BYTES = "MAX_RESPONSE_BYTES"
DEFAULT_MAX_RESPONSE_BYTES = 1_048_576
MAX_RESPONSE_BYTES_RANGE = (4096, 67_108_864)


@dataclass(frozen=True)
class VendorResult:
    """One vendor's answer for one text.

    `reason` is closed vocabulary: `pass`, `<vendor>:prompt_attack`, or
    `<vendor>_unavailable:<condition>`. `ok` is True only for `pass`;
    `flagged` is True only for `prompt_attack`.
    """

    ok: bool
    reason: str
    flagged: bool = False


@dataclass(frozen=True)
class Reply:
    """What `paced_post` produced: decoded JSON, or a fail-closed result.

    Exactly one is set. `data` is untrusted and must go through the
    adapter's strict response parse; `failure` is ready to return.
    """

    data: object = None
    failure: VendorResult | None = None


class ResponseTooLarge(Exception):
    """The response body exceeded the vendor's `MAX_RESPONSE_BYTES`.

    Its own type so the outage reads `<vendor>_unavailable:ResponseTooLarge`.
    Carries no message: nothing about the refused body, its length included,
    crosses the scanner boundary.
    """


class DuplicateJSONKey(Exception):
    """A JSON object repeated a key. Carries no message (keys are
    server-controlled); `paced_post` maps it to `bad-response`."""


class UnexpectedHTTPStatus(Exception):
    """The status was not exactly HTTP 200. Carries no message so provider
    response metadata cannot reach the reason."""


def timeout_s(vendor: str) -> float:
    return env_float(
        vendor_env(vendor, ENV_TIMEOUT), DEFAULT_TIMEOUT_S, TIMEOUT_RANGE
    )


def max_response_bytes(vendor: str) -> int:
    return env_int(
        vendor_env(vendor, ENV_MAX_RESPONSE_BYTES),
        DEFAULT_MAX_RESPONSE_BYTES,
        MAX_RESPONSE_BYTES_RANGE,
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect.

    Returning `None` makes `http_error_3xx` fall through to
    `HTTPDefaultErrorHandler`, which raises `HTTPError` with the original
    status: a 3xx arrives at `transport_reason` exactly like a 500, and no
    second request is issued.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# The default opener FOLLOWS 3xx and strips only `Content-*` headers, so the
# credential header would be re-sent to whatever host `Location` names. No
# endpoint used here has a legitimate redirect, so following is suppressed
# outright rather than validated (a `Location` check races the host that
# answers). `ProxyHandler({})` replaces environment-derived proxy routing with
# an explicitly empty mapping; CPython then omits the empty handler from
# `.handlers`, but passing it still suppresses the default ambient one.
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


def strict_json_loads(text: str) -> object:
    """`json.loads`, raising `DuplicateJSONKey` for a repeated key at any
    depth. Untrusted JSON (a response, a credential file) is read through
    this, so a second value cannot shadow the one a check looked at."""
    return json.loads(text, object_pairs_hook=_object_without_duplicate_keys)


def _post(
    url: str, body: bytes, headers: dict, *, timeout: float, max_bytes: int
) -> object:
    """POST `body` and return the decoded JSON.

    Raises on any network / HTTP / decode error and on any status other than
    exact HTTP 200. Goes through `_OPENER` (no redirects, no proxy). The read
    is capped: `read(max_bytes + 1)` detects an oversize body without pulling
    the rest off the socket.
    """
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with _OPENER.open(req, timeout=timeout) as resp:
        try:
            status = resp.status
        except Exception:  # noqa: BLE001 — missing/hostile status fails closed
            raise UnexpectedHTTPStatus from None
        if type(status) is not int or status != 200:
            raise UnexpectedHTTPStatus
        raw = resp.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ResponseTooLarge
    return strict_json_loads(raw.decode("utf-8"))


def send(vendor: str, url: str, body: bytes, headers: dict) -> object:
    """One UNPACED `_post` with `vendor`'s timeout and response cap.

    For an auxiliary request on the vendor's behalf (Model Armor's OAuth
    token exchange) that must take the same hardened path but is not a
    classification and spends no pacing token. Raises like `_post`; the
    caller builds its own closed reason.
    """
    return _post(
        url,
        body,
        headers,
        timeout=timeout_s(vendor),
        max_bytes=max_response_bytes(vendor),
    )


def transport_reason(vendor: str, e: BaseException) -> str:
    """`<vendor>_unavailable:<ExcType>`, plus `:<status>` for an HTTPError.

    Never `str(e)` or anything else off the exception: an HTTPError's reason
    phrase and body are server text, and a provider error body can echo the
    request — the attacker-shaped report. The status is a range-checked
    integer (`http_status.bounded_status`), at most three ASCII digits, and it
    is what tells an expired key (401) from throttling (429) from an outage
    (5xx). Only a real `HTTPError` gets a status, so every other exception
    type renders as its bare type name by construction.
    """
    reason = f"{vendor}_unavailable:{type(e).__name__}"
    if isinstance(e, urllib.error.HTTPError):
        reason += status_suffix(e, "code")
    return reason


def breaker_code(e: BaseException) -> int | None:
    """The HTTP status as a bounded int, for BREAKER decisions only.

    Separate from `transport_reason`: that decides what an operator reads,
    this decides whether the whole fleet stops calling a vendor. `.code` can
    be rebound or a raising property, so the read is guarded and
    range-checked; anything implausible is `None` and leaves the breaker
    alone. Only a real `HTTPError` can trip it — other exceptions say nothing
    about our rate against the account.
    """
    if not isinstance(e, urllib.error.HTTPError):
        return None
    try:
        raw = getattr(e, "code", None)
    except Exception:  # noqa: BLE001 — a raising property is not an outage
        return None
    return bounded_status(raw)


def retry_after(e: BaseException) -> str | None:
    """The raw `Retry-After` header, for the limiter and nothing else.

    Server-supplied TEXT: handed straight to `record_throttled`, which parses
    it to a clamped number and discards the string. Total: a missing or
    raising `headers` yields `None` rather than replacing the vendor's error
    with the failure to read a header.
    """
    try:
        headers = getattr(e, "headers", None)
        if headers is None:
            return None
        value = headers.get("Retry-After")
    except Exception:  # noqa: BLE001 — see the docstring
        return None
    return value if isinstance(value, str) else None


def _trip(limiter: CrossProcessLimiter, e: BaseException) -> None:
    """A 429 opens the breaker with cause QUOTA, a 503 with cause SERVICE —
    the two codes RFC 9110 pairs with `Retry-After`. Anything else leaves it."""
    code = breaker_code(e)
    if code == 429:
        limiter.record_throttled(retry_after(e), cause=BreakerCause.QUOTA)
    elif code == 503:
        limiter.record_throttled(retry_after(e), cause=BreakerCause.SERVICE)


def record_breaker(vendor: str, e: BaseException) -> None:
    """Trip `vendor`'s fleet breaker for an auxiliary request's failure (Model
    Armor's token exchange), exactly as `paced_post` does for its own. Total:
    a limiter that cannot be built records nothing, and the caller still
    fails closed on its own reason."""
    try:
        limiter = CrossProcessLimiter.from_env(vendor)
    except Exception:  # noqa: BLE001 — recording is best-effort by contract
        return
    _trip(limiter, e)


def unavailable(vendor: str, condition: str) -> VendorResult:
    return VendorResult(ok=False, reason=f"{vendor}_unavailable:{condition}")


def paced_post(
    vendor: str,
    url: str,
    body: bytes,
    headers: dict,
    *,
    max_wait_s: float | None,
    before_send: Callable[[], VendorResult | None] | None = None,
) -> Reply:
    """One paced POST for `vendor`. Never raises; fails CLOSED.

    Call only once the request is certain to be sent (credential and
    endpoint resolved): a call that cannot happen must not spend a token,
    or one pane's botched config would starve the panes that work.

    Order, and why:
      1. Build the vendor's limiter and `acquire` inside one guard. `from_env`
         reads the environment and resolves the cache directory; an escape
         here would abort the scan instead of rejecting one report.
         THROTTLED -> `throttled`, SERVICE_UNAVAILABLE ->
         `service-unavailable`, ERROR -> `limiter-error` (waving calls through
         a broken limiter would restore the storm it exists to stop).
      2. `started_at` is read after `acquire` returns (a waiting acquire can
         block for minutes) and before the POST: `record_success` discards a
         success issued before the breaker last tripped, so one straggler's
         200 cannot cancel the fleet's decision.
      3. A 429 opens the vendor's breaker with cause QUOTA, a 503 with cause
         SERVICE — the two codes RFC 9110 pairs with `Retry-After`.
      4. A decoded 200 records success whatever the verdict turns out to be:
         transport liveness and content acceptance are separate claims.

    The recorders are total by contract (they swallow their own errors), so
    they are called unguarded.

    `max_wait_s=None` means `INJECTION_SCANNER_<VENDOR>_MAX_WAIT_S`
    (default 0: refuse immediately).

    `before_send`, if given, runs once the limiter has admitted the call and
    before the POST; a `VendorResult` it returns is the reply and nothing is
    sent. It is where a per-call allowance (Model Armor's monthly budget) is
    charged, so a call the limiter refuses never spends it, and it may
    complete `headers` in place (Model Armor's bearer token, chosen after the
    limiter wait so it cannot expire while the call queues).
    """
    started_at = 0.0
    try:
        limiter = CrossProcessLimiter.from_env(vendor)
        if max_wait_s is None:
            max_wait_s = default_max_wait_s(vendor)
        decision = limiter.acquire(max_wait_s)
        started_at = time.time()
    except Exception:  # noqa: BLE001 — see step 1; fails CLOSED
        decision = Decision.ERROR
    if decision is Decision.THROTTLED:
        return Reply(failure=unavailable(vendor, "throttled"))
    if decision is Decision.SERVICE_UNAVAILABLE:
        return Reply(failure=unavailable(vendor, "service-unavailable"))
    if decision is not Decision.ALLOWED:
        return Reply(failure=unavailable(vendor, "limiter-error"))
    if before_send is not None:
        refusal = before_send()
        if refusal is not None:
            return Reply(failure=refusal)

    try:
        data = send(vendor, url, body, headers)
    except DuplicateJSONKey:
        return Reply(failure=unavailable(vendor, "bad-response"))
    except Exception as e:  # noqa: BLE001 — any failure fails CLOSED
        _trip(limiter, e)
        return Reply(
            failure=VendorResult(ok=False, reason=transport_reason(vendor, e))
        )

    limiter.record_success(started_at)
    return Reply(data=data)
