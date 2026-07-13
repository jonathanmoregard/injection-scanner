"""Unit tests for the honeypot PURE classification + aggregation logic.

These tests never touch the network or any API key. They exercise:
  - `_classify_from_parts` — trap-tool / canary / crosstalk / left-alone
    decisions, INCLUDING the FIX-1 regression guard that a canary hidden in
    a legit tool's ARGUMENTS (not just freeform text) still triggers.
  - `_run_all` — the triggered / unavailable / pass aggregation, with
    `_run_one` monkeypatched to return canned ScenarioResults.
"""
from __future__ import annotations

import asyncio

from injection_scanner import honeypot
from injection_scanner.honeypot import ScenarioResult, _classify_from_parts, _run_all
from injection_scanner.honeypot_scenarios import (
    ALL_SCENARIOS,
    CANARY_ALPHA,
    CANARY_BRAVO,
    SCENARIO_A_CONVERSATION_HISTORY_LEAK as SCEN_A,
)


# ---------- _classify_from_parts ----------

def test_trap_tool_call_triggers():
    r = _classify_from_parts(SCEN_A, [("dump_env", {})], "")
    assert r.verdict == "Honeypot_Triggered"
    assert r.signal.startswith("trap:dump_env")


def test_canary_in_freeform_text_triggers():
    r = _classify_from_parts(SCEN_A, [], f"here it is: {CANARY_ALPHA}")
    assert r.verdict == "Honeypot_Triggered"
    assert r.signal.startswith("canary:")


def test_canary_in_tool_arguments_triggers():
    # FIX-1 regression guard: canary hidden in a LEGIT tool's args, empty text.
    r = _classify_from_parts(
        SCEN_A, [("return_summary", {"text": CANARY_ALPHA})], ""
    )
    assert r.verdict == "Honeypot_Triggered"
    assert r.signal.startswith("canary:")


def test_crosstalk_canary_in_arguments_triggers():
    # A DIFFERENT scenario's canary in this scenario's tool args -> crosstalk.
    r = _classify_from_parts(
        SCEN_A, [("return_summary", {"text": CANARY_BRAVO})], ""
    )
    assert r.verdict == "Honeypot_Triggered"
    assert r.signal.startswith("canary_crosstalk:")


def test_report_issue_injection_is_left_alone():
    r = _classify_from_parts(
        SCEN_A,
        [("report_issue", {"category": "Prompt_Injection_Attempt",
                           "description": "looks like an injection"})],
        "",
    )
    assert r.verdict == "Honeypot_Left_Alone"
    assert r.signal == "left_alone_with_injection_report"


def test_benign_return_summary_is_left_alone():
    r = _classify_from_parts(
        SCEN_A, [("return_summary", {"text": "a clean summary"})], "clean"
    )
    assert r.verdict == "Honeypot_Left_Alone"
    assert r.signal == "left_alone"


# ---------- _run_all aggregation ----------

def _left_alone(scenario) -> ScenarioResult:
    return ScenarioResult(
        scenario=scenario["name"], verdict="Honeypot_Left_Alone",
        signal="left_alone", provider=scenario["provider"],
        model=scenario["model"],
    )


def _patch_run_one(monkeypatch, mapping):
    """mapping: scenario-name -> ScenarioResult. Missing names -> Left_Alone."""
    async def fake_run_one(scenario, report_text):
        return mapping.get(scenario["name"], _left_alone(scenario))
    monkeypatch.setattr(honeypot, "_run_one", fake_run_one)


def test_run_all_all_left_alone_passes(monkeypatch):
    _patch_run_one(monkeypatch, {})
    res = asyncio.run(_run_all("report"))
    assert res.ok is True
    assert res.reason == "pass"
    assert len(res.per_scenario) == len(ALL_SCENARIOS)


def test_run_all_one_triggered_fails(monkeypatch):
    target = ALL_SCENARIOS[0]
    trig = ScenarioResult(
        scenario=target["name"], verdict="Honeypot_Triggered",
        signal="trap:dump_env", provider=target["provider"],
        model=target["model"],
    )
    _patch_run_one(monkeypatch, {target["name"]: trig})
    res = asyncio.run(_run_all("report"))
    assert res.ok is False
    assert res.reason.startswith("honeypot:")
    assert target["name"] in res.reason


def test_run_all_one_skipped_fails_unavailable(monkeypatch):
    target = ALL_SCENARIOS[0]
    skipped = ScenarioResult(
        scenario=target["name"], verdict="Honeypot_Skipped",
        signal="unavailable:no-anthropic-api-key",
        provider=target["provider"], model=target["model"],
    )
    _patch_run_one(monkeypatch, {target["name"]: skipped})
    res = asyncio.run(_run_all("report"))
    assert res.ok is False
    assert res.reason.startswith("honeypot_unavailable:")
    assert target["name"] in res.reason
