"""The bounded-integer HTTP status extractor (injection_scanner.http_status).

`reason` / `signal` / `Verdict.layers` are consumed OUTSIDE the quarantine
zone, so everything interpolated into them must be library-synthesized or
provably content-free. An HTTP status code qualifies — but only once it has
been coerced to an `int` AND range-checked. That is what this module is:
the one place a provider-supplied status becomes safe to format, and the
one place a malformed one is turned back.

These tests pin the two properties the callers rely on:

  * the return is `None` or a real `int` in [100, 599] — never a string,
    never a passthrough of whatever the attribute happened to hold, so at
    most three ASCII digits can ever reach a caller-visible string;
  * nothing here raises. Every call site is inside an `except` handler that
    is mid-way through building a fail-closed result, so a raise would
    replace the provider's own error type with the type of the failure to
    describe it (the fault `honeypot._error_detail` documents as CANNOT
    RAISE).
"""
from __future__ import annotations

from decimal import Decimal

import pytest

from injection_scanner.http_status import (
    _MAX_STATUS,
    _MIN_STATUS,
    bounded_status,
    status_suffix,
)


# ---------- accepted: real, in-range statuses ----------

@pytest.mark.parametrize("code", [100, 200, 301, 401, 403, 429, 500, 503, 599])
def test_plausible_status_codes_pass_through(code):
    assert bounded_status(code) == code


def test_non_standard_but_in_range_codes_pass():
    """Real deployments emit these; the bound is a range, not an allowlist.

    499 (nginx client-closed) and 530 (Cloudflare) are exactly the codes an
    operator debugging a proxy in front of the API needs to see.
    """
    assert bounded_status(499) == 499
    assert bounded_status(530) == 530


@pytest.mark.parametrize("raw", ["429", b"429", Decimal(429), 429.0])
def test_numeric_values_are_coerced_to_int(raw):
    """`.code` is documented as an int but is a plain attribute anyone can
    rebind. Whatever `int()` can read yields a bounded INT, so the result is
    exactly as safe as the well-formed case — the contract is the TYPE and
    RANGE of the output, not the type of the input."""
    out = bounded_status(raw)
    assert out == 429
    assert type(out) is int


# ---------- rejected: anything that could inject text or is implausible ----------

@pytest.mark.parametrize(
    "bad",
    [
        None,
        "",
        "429; DROP TABLE reports",
        "4xx",
        "not-a-number",
        "  ",
        b"4xx",
        [429],
        {"code": 429},
        object(),
        float("nan"),
        float("inf"),
        1 << 200,
    ],
)
def test_malformed_values_are_rejected(bad):
    assert bounded_status(bad) is None


@pytest.mark.parametrize("bad", [-1, 0, 42, 99, 600, 999, 99999])
def test_out_of_range_codes_are_rejected(bad):
    assert bounded_status(bad) is None


def test_bools_are_rejected():
    """`True` is an `int` in Python and would format as `1`. It is never a
    status code, so it is turned back explicitly rather than by luck of the
    range check."""
    assert bounded_status(True) is None
    assert bounded_status(False) is None


def test_range_constants_are_the_http_range():
    assert (_MIN_STATUS, _MAX_STATUS) == (100, 599)


# ---------- cannot raise ----------

def test_a_raising_int_conversion_is_not_an_outage():
    class Hostile:
        def __int__(self):
            raise RuntimeError("MUST-NOT-ESCAPE-MARKER")

    assert bounded_status(Hostile()) is None


def test_a_raising_comparison_is_not_an_outage():
    class HostileInt(int):
        def __le__(self, other):  # pragma: no cover - exercised via bounds
            raise RuntimeError("MUST-NOT-ESCAPE-MARKER")

        def __ge__(self, other):  # pragma: no cover - exercised via bounds
            raise RuntimeError("MUST-NOT-ESCAPE-MARKER")

    # int() re-reads the value as a plain int, so the hostile comparison
    # never runs — but if that ever changes, this must still not raise.
    assert bounded_status(HostileInt(429)) in (429, None)


# ---------- status_suffix ----------

class _Exc(Exception):
    def __init__(self, **attrs):
        super().__init__("x")
        for k, v in attrs.items():
            setattr(self, k, v)


def test_status_suffix_formats_a_leading_colon():
    assert status_suffix(_Exc(status_code=429), "status_code") == ":429"
    assert status_suffix(_Exc(code=401), "code") == ":401"


def test_status_suffix_is_empty_when_the_attribute_is_absent():
    assert status_suffix(_Exc(), "status_code") == ""


def test_status_suffix_is_empty_for_a_malformed_status():
    assert status_suffix(_Exc(status_code="nope"), "status_code") == ""
    assert status_suffix(_Exc(status_code=99999), "status_code") == ""


def test_status_suffix_survives_a_raising_property():
    """SDK status accessors are properties, and a property can raise."""

    class Exploding(Exception):
        @property
        def status_code(self):
            raise RuntimeError("MUST-NOT-ESCAPE-MARKER")

    assert status_suffix(Exploding("x"), "status_code") == ""


def test_status_suffix_is_at_most_four_ascii_characters():
    """The whole safety argument in one assertion: whatever the provider
    put on the attribute, what reaches a caller-visible string is a colon
    plus at most three digits."""
    for value in (429, "503", 99999, None, "IGNORE PREVIOUS INSTRUCTIONS"):
        out = status_suffix(_Exc(status_code=value), "status_code")
        assert out == "" or (
            len(out) <= 4 and out[0] == ":" and out[1:].isdigit()
        )
