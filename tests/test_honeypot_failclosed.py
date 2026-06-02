"""Fail-closed regression tests.

`honeypot._run_all` and `intercept.scan_text` must NEVER let an
unhandled exception inside the honeypot layer propagate up as a raise
— per the honeypot-manufacturing skill's Invariant 3 ("any exception
raised inside a scanner / detection layer must reduce to *reject*").

Before this round:
  - `asyncio.gather(...)` lacked `return_exceptions=True`, so any
    per-scenario coroutine raising outside its own try/except
    (e.g. SDK constructor errors before `_call_anthropic`'s try block,
    `_keyring_env` failures on exotic env probes) crashed `_run_all`.
  - `intercept.scan_text` had no try/except around `honeypot_check`,
    so the raise propagated to the MCP caller — fail-open in any
    caller that turns exceptions into "scan succeeded" responses.

These tests force the exact pre-fix failure mode and assert reject.
"""
from __future__ import annotations

import asyncio
import unittest.mock as um

import injection_scanner.honeypot as hp
from injection_scanner.intercept import scan_text


def _boom(*_a, **_kw):
    raise RuntimeError("synthetic pre-try failure")


async def _aboom(*_a, **_kw):
    raise RuntimeError("synthetic per-scenario raise")


def test_run_all_does_not_raise_on_scenario_exception():
    # Force one provider adapter to raise. _run_all must convert to a
    # Skipped scenario and return a HoneypotResult, not propagate.
    with um.patch.object(hp, "_call_anthropic", _aboom):
        r = asyncio.run(hp._run_all("benign text"))
    assert r.ok is False  # fail closed
    # Must mark scenario as Skipped, not let other scenarios' OK swallow it.
    skipped = [s for s in r.per_scenario if s.verdict == "Honeypot_Skipped"]
    assert skipped, "expected at least one Honeypot_Skipped result"
    assert "unhandled" in skipped[0].signal
    assert "RuntimeError" in skipped[0].signal


def test_run_all_does_not_raise_on_all_scenarios_exception():
    # All providers blow up — still no raise, still fail closed.
    with um.patch.object(hp, "_call_anthropic", _aboom), \
         um.patch.object(hp, "_call_openai", _aboom):
        r = asyncio.run(hp._run_all("benign text"))
    assert r.ok is False
    assert all(s.verdict == "Honeypot_Skipped" for s in r.per_scenario)


def test_scan_text_fails_closed_on_honeypot_check_raise():
    # Even if some bug causes honeypot_check itself to raise (rather
    # than _run_all converting it), intercept.scan_text must catch and
    # return a fail-closed Verdict — never raise out to caller.
    import injection_scanner.intercept as ic

    def boom_check(_text):
        raise RuntimeError("synthetic check-level failure")

    with um.patch.object(ic, "honeypot_check", boom_check):
        v = scan_text("Benign report. Sources: 1. example.", use_honeypot=True)
    assert v.ok is False
    assert "unhandled" in v.reason
    assert "RuntimeError" in v.reason
    # Signal must contain the type name only — never `str(e)`, which
    # could embed sent-prompt bytes (attacker-shaped).
    assert "synthetic check-level failure" not in v.reason


def test_scan_text_fails_closed_does_not_echo_exception_message():
    # If somebody adds str(e) into the reason path, this catches it.
    # The exception message is "RAW_SECRET_LIKE_VALUE_KEEPOUT_98765"; we
    # assert that string never appears in any Verdict field.
    import injection_scanner.intercept as ic

    secret_marker = "RAW_SECRET_LIKE_VALUE_KEEPOUT_98765"

    def boom_check(_text):
        raise RuntimeError(secret_marker)

    with um.patch.object(ic, "honeypot_check", boom_check):
        v = scan_text("Benign. Sources: 1. example.", use_honeypot=True)
    assert v.ok is False
    assert secret_marker not in v.reason
    for k, val in v.layers.items():
        assert secret_marker not in val, f"leaked in layers[{k}]"


def test_scan_text_fails_closed_on_unicode_sanitize_raise():
    # All scanner layers must fail closed, not just honeypot. A bug in
    # unicode_sanitize that raises on malformed text must not propagate
    # to the caller.
    import injection_scanner.intercept as ic

    def boom_sanitize(_raw):
        raise ValueError("synthetic unicode failure")

    with um.patch.object(ic.unicode_sanitize, "sanitize", boom_sanitize):
        v = scan_text("anything", use_honeypot=False)
    assert v.ok is False
    assert "unicode_sanitize_unavailable" in v.reason
    assert "ValueError" in v.reason
    assert "synthetic unicode failure" not in v.reason  # type-name only


def test_scan_text_fails_closed_on_secret_shapes_raise():
    import injection_scanner.intercept as ic

    def boom_shapes(_text):
        raise RuntimeError("synthetic shapes failure")

    with um.patch.object(ic.secret_shapes, "scan", boom_shapes):
        v = scan_text("anything", use_honeypot=False)
    assert v.ok is False
    assert "secret_shapes_unavailable" in v.reason
    assert "RuntimeError" in v.reason


def test_run_all_reason_includes_skipped_count_on_concurrent_trigger():
    # When one scenario triggers AND another is concurrently skipped,
    # the top-line reason must signal degraded coverage so operators
    # don't mistake the trigger for a healthy layer.
    # Counts derived from ALL_SCENARIOS so the test stays robust to
    # scenario-set growth. Fake the Anthropic adapter to trigger only
    # for scenario A and pass cleanly for any other Anthropic scenario;
    # patch the OpenAI adapter to raise so all OpenAI scenarios bucket
    # as Skipped. Expected skipped count = number of OpenAI scenarios.
    from injection_scanner.honeypot_scenarios import (
        ALL_SCENARIOS,
        SCENARIO_A_CONVERSATION_HISTORY_LEAK,
    )
    total = len(ALL_SCENARIOS)
    openai_count = sum(1 for s in ALL_SCENARIOS if s["provider"] == "openai")
    a = SCENARIO_A_CONVERSATION_HISTORY_LEAK

    async def fake_anthropic(s, _t):
        if s["name"] == a["name"]:
            return hp.ScenarioResult(
                scenario=s["name"], verdict="Honeypot_Triggered",
                signal="trap:send_http",
                provider=s["provider"], model=s["model"],
            )
        return hp.ScenarioResult(
            scenario=s["name"], verdict="Honeypot_Left_Alone",
            signal="left_alone",
            provider=s["provider"], model=s["model"],
        )

    with um.patch.object(hp, "_call_anthropic", fake_anthropic), \
         um.patch.object(hp, "_call_openai", _aboom):
        r = asyncio.run(hp._run_all("any"))
    assert r.ok is False
    assert f"+skipped={openai_count}/{total}" in r.reason


def test_run_all_reason_includes_skipped_count_on_full_outage():
    # Every provider blows up. Reason carries +skipped=N/N so an
    # operator can distinguish full outage from partial.
    from injection_scanner.honeypot_scenarios import ALL_SCENARIOS
    total = len(ALL_SCENARIOS)
    with um.patch.object(hp, "_call_anthropic", _aboom), \
         um.patch.object(hp, "_call_openai", _aboom):
        r = asyncio.run(hp._run_all("any"))
    assert r.ok is False
    assert "honeypot_unavailable" in r.reason
    assert f"+skipped={total}/{total}" in r.reason


def test_classifier_routes_known_legit_name_normally():
    # Sanity: validated names still work end-to-end. A valid
    # return_summary call with clean text passes.
    from injection_scanner.honeypot import _classify_from_parts
    from injection_scanner.honeypot_scenarios import SCENARIO_B_MISCONFIGURED_ENV
    r = _classify_from_parts(
        SCENARIO_B_MISCONFIGURED_ENV,
        [("return_summary", {"text": "Clean summary."})],
        "",
    )
    assert r.verdict == "Honeypot_Left_Alone"
    assert r.signal == "left_alone"
