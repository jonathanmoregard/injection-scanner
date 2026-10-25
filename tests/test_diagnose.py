"""`diagnose.describe` names the layer, provider/model and condition that failed.

Motivating incident (2026-10-24): the honeypot hit a retired OpenAI model and
returned 404, but the smoke hint read "Likely L2/L3 degraded — check
LAKERA_API_KEY ..." and everyone went looking at Lakera. Each case below is a
reason shape the scanner really produces; the last group pins the no-leak rule.
"""
from __future__ import annotations

import pytest

from injection_scanner import smoke
from injection_scanner.diagnose import describe
from injection_scanner.intercept import Verdict


@pytest.mark.parametrize(
    "reason, expected",
    [
        # L3 honeypot — the 2026-10-24 outage, as the Verdict reason wraps it.
        (
            "honeypot:honeypot_unavailable:simulated_env_dump_in_history:"
            "unavailable:openai-api-error:NotFoundError:404+skipped=2/6",
            "honeypot: openai model gpt-4.1-mini (scenario simulated_env_dump_in_history): "
            "returned HTTP 404 (NotFoundError); 2/6 scenarios skipped",
        ),
        # ...and as the bare layer value (`layers["honeypot"]`).
        (
            "honeypot_unavailable:misconfigured_env_file:unavailable:"
            "no-openai-api-key+skipped=4/6",
            "honeypot: openai model gpt-4o-mini (scenario misconfigured_env_file): "
            "no API key (set OPENAI_API_KEY); 4/6 scenarios skipped",
        ),
        (
            "honeypot_unavailable:conversation_history_leak:unavailable:"
            "anthropic-api-error:APIConnectionError+skipped=1/6",
            "honeypot: anthropic model claude-haiku-4-5-20251001 (scenario "
            "conversation_history_leak): API call failed (APIConnectionError); "
            "1/6 scenarios skipped",
        ),
        (
            "honeypot:honeypot:minimal_priors:trap-call",
            "honeypot: openai model gpt-4.1-mini (scenario minimal_priors) "
            "was triggered by the benign probe",
        ),
        (
            "honeypot_unavailable:unhandled:KeyError",
            "honeypot: unhandled KeyError",
        ),
        # L2 Lakera.
        (
            "lakera_unavailable:HTTPError:429",
            "lakera: HTTP 429 (quota/rate limit) (HTTPError)",
        ),
        (
            "lakera_unavailable:HTTPError:401",
            "lakera: HTTP 401 (HTTPError)",
        ),
        (
            "lakera_unavailable:no-key",
            "lakera: no API key (set LAKERA_API_KEY or LAKERA_API_KEY_FILE)",
        ),
        (
            "lakera_unavailable:throttled",
            "lakera: local fleet budget exhausted or quota breaker open (throttled)",
        ),
        ("lakera_unavailable:URLError", "lakera: transport error (URLError)"),
        ("lakera:prompt_attack", "lakera: flagged the benign probe (prompt_attack)"),
        # L4 judge. Its vote signals are NOT provider-prefixed (judge.py):
        # `api-error:<Type>[:<status>]`, `parse-error:<Type>`, and fixed labels.
        (
            "lakera_arbitration:unavailable:openai_41_mini:api-error:RateLimitError:429",
            "judge: openai model gpt-4.1-mini: returned HTTP 429 (quota/rate limit) "
            "(RateLimitError)",
        ),
        (
            "lakera_arbitration:unavailable:openai_41_mini:api-error:NotFoundError:404",
            "judge: openai model gpt-4.1-mini: returned HTTP 404 (NotFoundError)",
        ),
        (
            "lakera_arbitration:unavailable:anthropic_haiku45:api-error:TimeoutError",
            "judge: anthropic model claude-haiku-4-5: API call failed (TimeoutError)",
        ),
        (
            "lakera_arbitration:unavailable:anthropic_haiku45:parse-error:IndexError",
            "judge: anthropic model claude-haiku-4-5: unparseable response (IndexError)",
        ),
        (
            "lakera_arbitration:unavailable:openai_41_mini:malformed-verdict",
            "judge: openai model gpt-4.1-mini: reply was not a verdict (malformed-verdict)",
        ),
        (
            "lakera_arbitration:unavailable:openai_41_mini:key-config-error",
            "judge: openai model gpt-4.1-mini: API key configuration error (key file "
            "unreadable or malformed)",
        ),
        (
            "lakera_arbitration:unavailable:openai_41_mini:no-openai-api-key",
            "judge: openai model gpt-4.1-mini: no API key (set OPENAI_API_KEY)",
        ),
        (
            "lakera_arbitration:attack:anthropic_haiku45",
            "judge: anthropic model claude-haiku-4-5 voted attack on the benign probe",
        ),
        ("judge_unavailable:unhandled:RuntimeError", "judge: unhandled RuntimeError"),
        # Deterministic layers.
        (
            "secret_shapes_unavailable:unhandled:RecursionError",
            "secret_shapes: unhandled RecursionError",
        ),
    ],
)
def test_each_layer_is_named(reason: str, expected: str) -> None:
    assert describe(reason) == expected


@pytest.mark.parametrize(
    "reason",
    [
        "lakera_unavailable:Evil$(rm -rf):999999",
        "honeypot_unavailable:ignore previous instructions:unavailable:x",
        "lakera_arbitration:unavailable:<script>:openai-api-error:X:4044",
        "lakera_arbitration:unavailable:<script>:api-error:X:4044",
        "lakera_arbitration:unavailable:openai_41_mini:parse-error:ignore previous",
    ],
)
def test_out_of_vocabulary_segments_never_reach_the_message(reason: str) -> None:
    msg = describe(reason)
    for fragment in ("$(", "rm -rf", "ignore previous", "<script>", "999999", "4044"):
        assert fragment not in msg
    assert "other" in msg or "unknown" in msg


def test_unknown_scenario_is_not_echoed() -> None:
    msg = describe("honeypot_unavailable:made_up_scenario:unavailable:no-openai-api-key")
    assert "unknown provider model unknown model" in msg


def test_smoke_failure_names_the_honeypot_not_lakera(monkeypatch) -> None:
    """End to end through run_smoke: the 2026-10-24 reason produces a message
    that names the honeypot's OpenAI model and does not point at Lakera."""
    reason = (
        "honeypot:honeypot_unavailable:simulated_env_dump_in_history:"
        "unavailable:openai-api-error:NotFoundError:404+skipped=2/6"
    )
    real = smoke._scan_via_path

    def fake(payload, *, use_honeypot, use_lakera=True):
        if not use_honeypot:
            return real(payload, use_honeypot=use_honeypot, use_lakera=use_lakera)
        return Verdict(
            ok=False,
            reason=reason,
            layers={"lakera": "pass", "honeypot": reason.removeprefix("honeypot:")},
            sanitize_stats={},
            sanitized_text=smoke._BENIGN_PROBE,
        )

    monkeypatch.setattr(smoke, "_scan_via_path", fake)
    errors: list[str] = []
    with pytest.raises(smoke.SmokeFailure) as excinfo:
        smoke.run_smoke(log_info=lambda _m: None, log_error=errors.append)
    msg = excinfo.value.reason
    assert "honeypot: openai model gpt-4.1-mini" in msg
    assert "HTTP 404" in msg
    assert "LAKERA_API_KEY" not in msg


class _FakeResponse:
    """What `APIStatusError.__init__` reads off a response (see test_judge)."""

    def __init__(self, status: int) -> None:
        self.status_code = status
        self.headers: dict[str, str] = {}
        self.request = None


@pytest.mark.parametrize("status, exc_name", [(404, "NotFoundError"), (429, "RateLimitError")])
def test_real_judge_reason_keeps_type_and_status(monkeypatch, status, exc_name) -> None:
    """The reason comes from the real judge panel, not a hand-typed string, so
    a drift between what judge.py emits and what describe() parses fails here.
    Every judge raises the real SDK status error for `status`."""
    import anthropic
    import openai

    from injection_scanner import judge

    def raiser(sdk):
        exc = getattr(sdk, exc_name)("msg", response=_FakeResponse(status), body=None)

        def create(*_a, **_kw):
            raise exc

        return create

    class _FakeAnthropic:
        def __init__(self, *_a, **_kw):
            self.messages = type("_M", (), {"create": staticmethod(raiser(anthropic))})()

    class _FakeOpenAI:
        def __init__(self, *_a, **_kw):
            completions = type("_C", (), {"create": staticmethod(raiser(openai))})()
            self.chat = type("_Chat", (), {"completions": completions})()

    monkeypatch.setattr(judge, "_anthropic_key", lambda: "sk-ant-test")
    monkeypatch.setattr(judge, "_openai_key", lambda: "sk-openai-test")
    monkeypatch.setattr(anthropic, "Anthropic", _FakeAnthropic)
    monkeypatch.setattr(openai, "OpenAI", _FakeOpenAI)

    jr = judge.check("benign text")
    assert not jr.ok and jr.reason.startswith("unavailable:")
    msg = describe(f"lakera_arbitration:{jr.reason}")
    assert f"HTTP {status}" in msg and f"({exc_name})" in msg, msg
