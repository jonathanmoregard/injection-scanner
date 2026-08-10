"""Tests for the L4 judge arbitration layer.

FULLY MOCKED — no network. Provider calls are stubbed at the `_ask_one`
seam (vote aggregation) or exercised through the no-key paths (adapter
fail-closed behavior), mirroring the test_lakera.py approach.
"""
from __future__ import annotations

import asyncio

import pytest

from injection_scanner import judge, keyloader
from injection_scanner.judge import JudgeVote, _parse_verdict


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (
        "ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY_FILE",
        "OPENAI_API_KEY", "OPENAI_API_KEY_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(keyloader, "_keyring", lambda _k: None)


# ----- verdict parsing (fail-closed on anything ambiguous) -----

@pytest.mark.parametrize("raw,expected", [
    ("benign", "benign"),
    ("Benign", "benign"),
    ("  BENIGN.\n", "benign"),
    ("attack", "attack"),
    ("Attack!", "attack"),
    ("benign attack", "unavailable"),
    ("the document is benign", "unavailable"),
    ("", "unavailable"),
    (None, "unavailable"),
])
def test_parse_verdict(raw, expected):
    assert _parse_verdict(raw) == expected


# ----- aggregation: unanimity to overturn, everything else rejects -----

def _stub_votes(monkeypatch, votes: list[JudgeVote]):
    it = iter(votes)

    async def fake_ask_one(j, sealed):
        return next(it)

    monkeypatch.setattr(judge, "_ask_one", fake_ask_one)


def test_unanimous_benign_passes(monkeypatch):
    _stub_votes(monkeypatch, [
        JudgeVote("anthropic_haiku45", "benign", "verdict"),
        JudgeVote("openai_4o_mini", "benign", "verdict"),
        JudgeVote("openai_41_nano", "benign", "verdict"),
    ])
    r = judge.check("agent tooling prose")
    assert r.ok
    assert r.reason == "benign-unanimous"
    assert len(r.votes) == 3


def test_single_attack_vote_rejects(monkeypatch):
    _stub_votes(monkeypatch, [
        JudgeVote("anthropic_haiku45", "benign", "verdict"),
        JudgeVote("openai_4o_mini", "attack", "verdict"),
        JudgeVote("openai_41_nano", "benign", "verdict"),
    ])
    r = judge.check("x")
    assert not r.ok
    assert r.reason == "attack:openai_4o_mini"


def test_single_unavailable_rejects(monkeypatch):
    _stub_votes(monkeypatch, [
        JudgeVote("anthropic_haiku45", "benign", "verdict"),
        JudgeVote("openai_4o_mini", "benign", "verdict"),
        JudgeVote("openai_41_nano", "unavailable", "api-error:TimeoutError"),
    ])
    r = judge.check("x")
    assert not r.ok
    assert r.reason == "unavailable:openai_41_nano:api-error:TimeoutError"


def test_raising_judge_coroutine_fails_closed(monkeypatch):
    async def boom(j, sealed):
        raise RuntimeError("provider exploded")

    monkeypatch.setattr(judge, "_ask_one", boom)
    r = judge.check("x")
    assert not r.ok
    assert "unhandled:RuntimeError" in r.reason
    # Invariant 4: the exception message must not leak into the reason.
    assert "exploded" not in r.reason


def test_no_keys_fails_closed_via_adapters():
    # No stubbing: with a clean env both adapters must come back
    # unavailable (no-*-api-key), which aggregates to a reject.
    r = judge.check("x")
    assert not r.ok
    assert r.reason.startswith("unavailable:")


def test_check_works_inside_running_event_loop(monkeypatch):
    _stub_votes(monkeypatch, [
        JudgeVote("anthropic_haiku45", "benign", "verdict"),
        JudgeVote("openai_4o_mini", "benign", "verdict"),
        JudgeVote("openai_41_nano", "benign", "verdict"),
    ])

    async def in_loop():
        return judge.check("x")

    r = asyncio.run(in_loop())
    assert r.ok
