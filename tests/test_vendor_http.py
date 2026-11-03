"""The vendor-agnostic hardened transport (injection_scanner.vendor_http).

The transport itself (no redirects, no ambient proxy, capped read, strict 200,
duplicate-key JSON rejection) is exercised end to end through the Lakera
adapter in tests/test_lakera.py. This file pins what is new about sharing it:
every reason, input and breaker belongs to ONE vendor, so a second vendor can
neither read the first one's settings nor be stopped by its 429s.

Hermetic: `vendor_http._post` is replaced in-process; nothing opens a socket.
"""
from __future__ import annotations

from urllib.error import HTTPError, URLError

import pytest

from injection_scanner import vendor_http
from injection_scanner.vendor_http import VendorResult


def _http_error(code: int) -> HTTPError:
    return HTTPError("https://vendor.invalid/", code, "server text", {}, None)


def test_the_transport_reason_is_prefixed_by_the_vendor():
    assert (
        vendor_http.transport_reason("model_armor", _http_error(429))
        == "model_armor_unavailable:HTTPError:429"
    )
    assert (
        vendor_http.transport_reason("lakera", URLError("server text"))
        == "lakera_unavailable:URLError"
    )


def test_timeout_and_response_cap_are_inputs_per_vendor(monkeypatch):
    monkeypatch.setenv("INJECTION_SCANNER_MODEL_ARMOR_TIMEOUT", "30")
    monkeypatch.setenv("INJECTION_SCANNER_MODEL_ARMOR_MAX_RESPONSE_BYTES", "8192")
    monkeypatch.delenv("INJECTION_SCANNER_LAKERA_TIMEOUT", raising=False)
    monkeypatch.delenv("INJECTION_SCANNER_LAKERA_MAX_RESPONSE_BYTES", raising=False)

    assert vendor_http.timeout_s("model_armor") == 30.0
    assert vendor_http.max_response_bytes("model_armor") == 8192
    assert vendor_http.timeout_s("lakera") == vendor_http.DEFAULT_TIMEOUT_S
    assert (
        vendor_http.max_response_bytes("lakera")
        == vendor_http.DEFAULT_MAX_RESPONSE_BYTES
    )


def _post_returning(monkeypatch, outcome):
    calls: list[dict] = []

    def _post(url, body, headers, *, timeout, max_bytes):
        calls.append({"url": url, "timeout": timeout, "max_bytes": max_bytes})
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(vendor_http, "_post", _post)
    return calls


def _paced(vendor: str):
    return vendor_http.paced_post(
        vendor, "https://vendor.invalid/", b"{}", {}, max_wait_s=0.0
    )


def test_a_decoded_two_hundred_is_returned_as_data(monkeypatch):
    monkeypatch.setenv("INJECTION_SCANNER_MODEL_ARMOR_TIMEOUT", "7")
    calls = _post_returning(monkeypatch, {"verdict": "x"})

    reply = _paced("model_armor")

    assert reply.failure is None
    assert reply.data == {"verdict": "x"}
    assert calls[0]["timeout"] == 7.0
    assert calls[0]["max_bytes"] == vendor_http.DEFAULT_MAX_RESPONSE_BYTES


def test_a_429_stops_only_the_vendor_that_received_it(monkeypatch):
    """The panel calls every vendor for every report. A breaker shared across
    vendors would turn one vendor's quota into an outage of all of them."""
    monkeypatch.setenv("INJECTION_SCANNER_MODEL_ARMOR_BACKOFF_BASE_S", "600")
    monkeypatch.setenv("INJECTION_SCANNER_MODEL_ARMOR_BACKOFF_MAX_S", "600")
    _post_returning(monkeypatch, _http_error(429))
    first = _paced("model_armor")
    assert first.failure == VendorResult(
        ok=False, reason="model_armor_unavailable:HTTPError:429"
    )

    calls = _post_returning(monkeypatch, {"ok": True})
    assert _paced("model_armor").failure == VendorResult(
        ok=False, reason="model_armor_unavailable:throttled"
    )
    assert calls == [], "an open breaker must not reach the network"

    assert _paced("lakera").failure is None
    assert len(calls) == 1


def test_an_unusable_limiter_is_reported_under_the_vendor(monkeypatch, tmp_path):
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    monkeypatch.setenv("INJECTION_SCANNER_CACHE_DIR", str(blocked))
    calls = _post_returning(monkeypatch, {"ok": True})

    assert _paced("model_armor").failure == VendorResult(
        ok=False, reason="model_armor_unavailable:limiter-error"
    )
    assert calls == []


def test_duplicate_json_keys_are_a_fixed_bad_response(monkeypatch):
    _post_returning(monkeypatch, vendor_http.DuplicateJSONKey())
    assert _paced("model_armor").failure == VendorResult(
        ok=False, reason="model_armor_unavailable:bad-response"
    )



def test_before_send_runs_after_the_limiter_admits_and_can_stop_the_post(monkeypatch):
    """A per-call gate (Model Armor's monthly budget) must be charged only
    for a call the limiter actually lets out — a throttled call must not
    spend it — and a refusal there must keep the request off the network."""
    calls = _post_returning(monkeypatch, {"ok": True})
    refusal = VendorResult(ok=False, reason="model_armor_unavailable:throttled")
    gate_calls: list[str] = []

    def gate():
        gate_calls.append("gate")
        return refusal

    reply = vendor_http.paced_post(
        "model_armor", "https://vendor.invalid/", b"{}", {},
        max_wait_s=0.0, before_send=gate,
    )

    assert reply.failure == refusal
    assert gate_calls == ["gate"]
    assert calls == []


def test_before_send_returning_none_lets_the_post_through(monkeypatch):
    calls = _post_returning(monkeypatch, {"ok": True})
    reply = vendor_http.paced_post(
        "model_armor", "https://vendor.invalid/", b"{}", {},
        max_wait_s=0.0, before_send=lambda: None,
    )
    assert reply.data == {"ok": True}
    assert len(calls) == 1


def test_before_send_is_not_charged_when_the_limiter_refuses(monkeypatch, tmp_path):
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    monkeypatch.setenv("INJECTION_SCANNER_CACHE_DIR", str(blocked))
    _post_returning(monkeypatch, {"ok": True})
    gate_calls: list[str] = []

    reply = vendor_http.paced_post(
        "model_armor", "https://vendor.invalid/", b"{}", {},
        max_wait_s=0.0, before_send=lambda: gate_calls.append("gate"),
    )

    assert reply.failure.reason == "model_armor_unavailable:limiter-error"
    assert gate_calls == []


def test_send_is_the_unpaced_post_with_the_vendors_own_inputs(monkeypatch):
    """For an auxiliary request (an OAuth token exchange) that must take the
    same hardened path but not spend a pacing token."""
    monkeypatch.setenv("INJECTION_SCANNER_MODEL_ARMOR_TIMEOUT", "9")
    calls = _post_returning(monkeypatch, {"access_token": "x"})

    assert vendor_http.send(
        "model_armor", "https://vendor.invalid/token", b"a=b", {}
    ) == {"access_token": "x"}
    assert calls == [
        {
            "url": "https://vendor.invalid/token",
            "timeout": 9.0,
            "max_bytes": vendor_http.DEFAULT_MAX_RESPONSE_BYTES,
        }
    ]


def test_strict_json_loads_rejects_duplicate_keys_at_any_depth():
    assert vendor_http.strict_json_loads('{"a": {"b": 1}}') == {"a": {"b": 1}}
    with pytest.raises(vendor_http.DuplicateJSONKey):
        vendor_http.strict_json_loads('{"a": {"b": 1, "b": 2}}')
