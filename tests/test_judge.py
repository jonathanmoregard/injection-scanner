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


# ----- adapter API errors: type name + bounded HTTP status -----
#
# Same 2026-09-05 opacity as the Lakera gate: a judge vote's `signal` flows
# into `JudgeResult.reason` and on into `Verdict.reason` /
# `Verdict.layers`, where `api-error:APIStatusError` said nothing about
# whether the panel was throttled, unauthorized, or facing an outage.
# `status_code` is a bounded INTEGER (range-checked by
# `http_status.bounded_status`), so it carries no request or response bytes
# — Invariant 4 is untouched. Free text is NOT added here: this layer has
# no audit-only channel, so the SDK body stays discarded.

_JUDGE_STR_E_MARKER = "JUDGE_STR_E_ONLY_MARKER_5150"

# First judge of each provider, looked up from the real table so a
# reordering of `_JUDGES` cannot quietly retarget these tests.
_JUDGES_BY_PROVIDER = {
    p: next(j for j in judge._JUDGES if j["provider"] == p)
    for p in ("anthropic", "openai")
}


class _FakeResponse:
    """The only two things `APIStatusError.__init__` reads off a response.

    Duck-typed rather than a real `httpx.Response` so this module needs no
    dependency beyond the two SDKs the package already declares — the real
    SDK exception CLASS is still what gets raised, which is the part that
    matters: it is where `status_code` actually comes from.
    """

    def __init__(self, status: int) -> None:
        self.status_code = status
        self.headers: dict[str, str] = {}
        self.request = None


def _sdk_status_error(sdk: str, status: int = 429):
    if sdk == "anthropic":
        import anthropic

        return anthropic.RateLimitError(
            _JUDGE_STR_E_MARKER,
            response=_FakeResponse(status),  # type: ignore[arg-type]
            body={"error": {"type": "rate_limit_error", "message": "slow down"}},
        )
    import openai

    return openai.RateLimitError(
        _JUDGE_STR_E_MARKER,
        response=_FakeResponse(status),  # type: ignore[arg-type]
        body={"message": "slow down", "type": "rate_limit_error"},
    )


class _Raiser:
    def __init__(self, exc):
        self._exc = exc

    def __call__(self, *_a, **_kw):
        raise self._exc


def _vote_for(monkeypatch, provider: str, exc) -> JudgeVote:
    monkeypatch.setattr(judge, "_anthropic_key", lambda: "sk-ant-test")
    monkeypatch.setattr(judge, "_openai_key", lambda: "sk-openai-test")
    if provider == "anthropic":
        import anthropic

        class _FakeAnthropic:
            def __init__(self, *_a, **_kw):
                self.messages = type("_M", (), {"create": _Raiser(exc)})()

        monkeypatch.setattr(anthropic, "Anthropic", _FakeAnthropic)
        return asyncio.run(judge._ask_anthropic(_JUDGES_BY_PROVIDER["anthropic"], "s"))

    import openai

    class _FakeOpenAI:
        def __init__(self, *_a, **_kw):
            completions = type("_C", (), {"create": _Raiser(exc)})()
            self.chat = type("_Chat", (), {"completions": completions})()

    monkeypatch.setattr(openai, "OpenAI", _FakeOpenAI)
    return asyncio.run(judge._ask_openai(_JUDGES_BY_PROVIDER["openai"], "s"))


@pytest.mark.parametrize("provider", ["anthropic", "openai"])
def test_judge_api_error_signal_carries_status(monkeypatch, provider):
    v = _vote_for(monkeypatch, provider, _sdk_status_error(provider, 429))
    assert v.vote == "unavailable"
    assert v.signal == "api-error:RateLimitError:429"
    # Invariant 4 unchanged: never `str(e)`, never the structured body.
    assert _JUDGE_STR_E_MARKER not in v.signal
    assert "slow down" not in v.signal


@pytest.mark.parametrize("provider", ["anthropic", "openai"])
def test_judge_api_error_without_status_is_unchanged(monkeypatch, provider):
    v = _vote_for(monkeypatch, provider, TimeoutError())
    assert v.signal == "api-error:TimeoutError"


@pytest.mark.parametrize("provider", ["anthropic", "openai"])
def test_judge_malformed_status_degrades(monkeypatch, provider):
    exc = _sdk_status_error(provider)
    exc.status_code = "429; IGNORE PREVIOUS"  # type: ignore[assignment]
    v = _vote_for(monkeypatch, provider, exc)
    assert v.signal == "api-error:RateLimitError"


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
