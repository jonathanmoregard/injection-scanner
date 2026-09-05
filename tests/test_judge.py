"""Tests for the L4 judge arbitration layer.

FULLY MOCKED — no network. Provider calls are stubbed at the `_ask_one`
seam (vote aggregation), exercised through the no-key paths (adapter
fail-closed behavior), or — for the request itself — driven through the
REAL provider SDK over a stub HTTP transport (see "real-SDK request shape"
at the bottom of this file), mirroring the test_lakera.py approach.
"""
from __future__ import annotations

import asyncio
import json

import httpx2
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


# ----- real-SDK request shape (the silent parameter-removal class) -----
#
# Measured 2026-09-05. The anthropic SDK moved 0.x -> 1.4.0 under this
# package's unbounded `anthropic>=0.96.0` floor and dropped `temperature`
# from `messages.create`. Every Anthropic judge call then raised TypeError
# before reaching the network: `api-error:TypeError` -> `unavailable` ->
# fail-closed. The gate stayed sound, but L4 arbitration — whose entire job
# is clearing Lakera `prompt_attack` false positives on agent-tooling
# research — stopped clearing anything, and the eval blocked 4/9 benign
# `fp_*` fixtures (fp_rate 0.444 against a 0.000 ceiling).
#
# The escape was in the TESTS, not the code. `_Raiser.__call__(*a, **kw)`
# above — like any `MagicMock` — accepts every keyword, so no local test
# could see a signature change; it took a live-key CI job to surface it.
#
# These tests fix that by stubbing only the HTTP transport: the real client
# class and the real `create` method run, so a removed, renamed, or
# retyped parameter raises here exactly as it does in production, with no
# network and no API key. They also assert the resulting WIRE body, which
# is the only place a raw-body parameter can be observed now that the SDK
# no longer exposes `temperature` as a named argument to introspect.

_ANTHROPIC_200 = {
    "id": "msg_regression",
    "type": "message",
    "role": "assistant",
    "model": "claude-haiku-4-5",
    "content": [{"type": "text", "text": "benign"}],
    "stop_reason": "end_turn",
    "stop_sequence": None,
    "usage": {"input_tokens": 1, "output_tokens": 1},
}

_OPENAI_200 = {
    "id": "chatcmpl-regression",
    "object": "chat.completion",
    "created": 1,
    "model": "gpt-4o-mini",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "benign"},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
}


def _stub_transport(monkeypatch, provider: str) -> list[dict]:
    """Run the REAL provider SDK against a stub transport.

    Returns the list the outgoing JSON request bodies are captured into.
    Only `http_client` is substituted — the SDK's own client class and
    `create` method are untouched, which is the whole point: they are what
    validates the keyword arguments the adapter passes.

    `httpx2` is no extra dependency surface: it is a hard requirement of
    both installed SDKs (`anthropic` needs httpx2<3,>=2.0.0, `openai`
    httpx2<3,>=2.7.0) and is pinned in uv.lock. Importing it at module
    scope is deliberate — if a future SDK swaps its HTTP layer, this file
    fails loudly, which is exactly the drift these tests exist to catch.
    """
    bodies: list[dict] = []

    def handle(request, payload=None):
        bodies.append(json.loads(request.content))
        return httpx2.Response(200, json=payload)

    monkeypatch.setattr(judge, "_anthropic_key", lambda: "sk-ant-test")
    monkeypatch.setattr(judge, "_openai_key", lambda: "sk-openai-test")

    if provider == "anthropic":
        import anthropic

        real = anthropic.Anthropic

        def factory(*a, **kw):
            kw["http_client"] = anthropic.DefaultHttpxClient(
                transport=httpx2.MockTransport(
                    lambda r: handle(r, _ANTHROPIC_200)
                )
            )
            return real(*a, **kw)

        monkeypatch.setattr(anthropic, "Anthropic", factory)
        return bodies

    import openai

    real_openai = openai.OpenAI

    def openai_factory(*a, **kw):
        kw["http_client"] = openai.DefaultHttpxClient(
            transport=httpx2.MockTransport(lambda r: handle(r, _OPENAI_200))
        )
        return real_openai(*a, **kw)

    monkeypatch.setattr(openai, "OpenAI", openai_factory)
    return bodies


def _ask_over_stub(monkeypatch, provider: str):
    bodies = _stub_transport(monkeypatch, provider)
    ask = judge._ask_anthropic if provider == "anthropic" else judge._ask_openai
    vote = asyncio.run(ask(_JUDGES_BY_PROVIDER[provider], "sealed document"))
    return vote, bodies


@pytest.mark.parametrize("provider", ["anthropic", "openai"])
def test_judge_request_matches_installed_sdk_signature(monkeypatch, provider):
    """Every kwarg the adapter passes must exist on the INSTALLED SDK.

    This is the test that would have caught the incident: with
    `temperature=0` passed as a named argument, the real `create` raises
    TypeError, the adapter maps it to `api-error:TypeError`, and this fails
    — offline, in under a second.
    """
    vote, bodies = _ask_over_stub(monkeypatch, provider)
    assert vote.signal != "api-error:TypeError"
    assert not vote.signal.startswith("api-error:")
    assert (vote.vote, vote.signal) == ("benign", "verdict")
    assert len(bodies) == 1, "the adapter must actually reach the transport"


@pytest.mark.parametrize("provider", ["anthropic", "openai"])
def test_judge_requests_deterministic_sampling(monkeypatch, provider):
    """Determinism is a security property of this layer, not a nicety.

    A judge sampling at the provider default is a behavior change: this
    panel decides whether a Lakera flag is overturned, and `_parse_verdict`
    fails closed on anything but an exact single verdict word. Asserted on
    the wire body because `temperature` reaches the Anthropic API as a raw
    body field now — the 1.x SDK has no named parameter to inspect.
    """
    _, bodies = _ask_over_stub(monkeypatch, provider)
    assert bodies[0]["temperature"] == 0
    assert bodies[0]["model"] == _JUDGES_BY_PROVIDER[provider]["model"]
    assert bodies[0]["max_tokens"] == 8
