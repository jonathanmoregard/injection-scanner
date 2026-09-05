"""Turn a provider-supplied HTTP status into something safe to say out loud.

`reason`, `signal` and `Verdict.layers` are the strings that leave the
quarantine zone — they reach the calling agent, its logs, and whatever
renders them. Invariant 4 ("the caught bytes never return") is why the
scanner's error paths carry the exception TYPE NAME and nothing else: an
SDK exception stringifies with request/response fragments, and those
fragments are the attacker-shaped report bytes we just sent.

Measured 2026-09-05: that rule, applied whole, also threw away the HTTP
STATUS CODE, and the status code is the one thing that separates an expired
key (401) from throttling (429) from a provider-side outage (5xx). An
operator spent a session on a `lakera_unavailable:HTTPError` that could
have been any of the three.

A status code is not free text. It is an integer from a small, fixed range,
so once it has been coerced and range-checked there is no way for provider
bytes to ride it out: what gets formatted is at most three ASCII digits,
which is strictly less expressive than the type name already beside it.
This module is where that coercion happens, so no call site has to be
trusted to do it — the callers see only `int | None` and a `":429"`-shaped
suffix, and there is nowhere for a raw attribute value to be interpolated.

Two properties every caller depends on:

  * TOTAL, never raising. Every call site is inside an `except` handler
    part-way through building a fail-closed result. A raise there would
    abort that result and replace the provider's own error type with the
    type of the failure to describe it — the exact fault
    `honeypot._error_detail` documents at length as CANNOT RAISE. Every
    step here is guarded, including the attribute read (SDK status
    accessors are properties, and a property can raise) and the `int()`
    conversion (an arbitrary object's `__int__` can raise anything).
  * BOUNDED output. `bounded_status` returns a genuine `int` or `None`,
    never a passthrough of whatever the attribute happened to hold, so a
    `.code` rebound to `"429; ignore all previous instructions"` is
    dropped rather than formatted.

What deliberately does NOT belong here, and must not be added later: the
reason phrase (`HTTPError.reason` / `.msg`), the response body
(`HTTPError.read()`), the SDK's structured error body, and any header that
is not itself a bounded integer. All of those are server-supplied TEXT and
a provider can echo request fragments back inside them. The honeypot's
audit-only `api_error_detail` channel (commit 4cada8d) is where that
material is allowed to go; it is not allowed here.
"""
from __future__ import annotations

# The HTTP status range. A RANGE, not an allowlist: real deployments emit
# codes no RFC defines — nginx's 444/499, Cloudflare's 520-530 — and those
# are exactly what an operator debugging a proxy in front of the API needs
# to see. Anything outside [100, 599] is not a status code that any HTTP
# stack produced, so it is a rebound attribute or a bug, and is dropped.
_MIN_STATUS = 100
_MAX_STATUS = 599


def bounded_status(value: object) -> int | None:
    """`value` as a plausible HTTP status code, or None.

    The return is a real `int` in [100, 599] — a numeric string is accepted
    and CONVERTED, so the caller still formats an integer and never the
    original object. `bool` is turned back explicitly: `True` is an `int`
    in Python and would otherwise format as `1`.
    """
    try:
        # `isinstance(value, bool)` before `int()`: bools are ints, and a
        # status code is never one.
        if isinstance(value, bool):
            return None
        code = int(value)  # type: ignore[call-overload]
        if _MIN_STATUS <= code <= _MAX_STATUS:
            return code
    except Exception:  # noqa: BLE001 — TOTAL by contract; see module docstring
        pass
    return None


def status_suffix(exc: BaseException, attr: str) -> str:
    """`":<code>"` when `exc.<attr>` is a plausible HTTP status, else `""`.

    `attr` is named by the caller rather than probed for, because the two
    call sites mean different things by it and neither should pick up the
    other's:

      * `urllib.error.HTTPError.code` — the status of an HTTP response.
      * `<sdk>.APIStatusError.status_code` — the same, on the Anthropic and
        OpenAI SDK exceptions.

    In particular this must never fall back to the SDKs' `APIError.code`,
    which is a provider-supplied STRING (`"insufficient_quota"`), i.e. the
    free text this module exists to keep out.

    `getattr` alone is not enough of a guard: its default only absorbs
    `AttributeError`, and these attributes are SDK properties that can
    raise anything.
    """
    try:
        raw = getattr(exc, attr, None)
    except Exception:  # noqa: BLE001 — a raising property is not an outage
        return ""
    code = bounded_status(raw)
    return "" if code is None else f":{code}"
