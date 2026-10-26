"""`diagnose.describe` names the layer, provider/model and condition that failed.

Motivating incident (2026-10-24): the honeypot hit a retired OpenAI model and
returned 404, but the smoke hint read "Likely L2/L3 degraded — check
LAKERA_API_KEY ..." and everyone went looking at Lakera. Each case below is a
reason shape the scanner really produces; the last group pins the no-leak rule.
"""
from __future__ import annotations

import pytest

from injection_scanner.diagnose import describe


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
        (
            "lakera_unavailable:unhandled:RuntimeError",
            "lakera: unhandled RuntimeError",
        ),
        # L2 Model Armor.
        (
            "model_armor_unavailable:no-key",
            "model_armor: no credential (set MODEL_ARMOR_CREDENTIALS_FILE)",
        ),
        (
            "model_armor_unavailable:key-config-error",
            "model_armor: credential configuration error (MODEL_ARMOR_CREDENTIALS_FILE "
            "unreadable, or not a service-account key for oauth2.googleapis.com)",
        ),
        (
            "model_armor_unavailable:url-config-error",
            "model_armor: endpoint configuration error (MODEL_ARMOR_PROJECT / "
            "MODEL_ARMOR_LOCATION / MODEL_ARMOR_TEMPLATE missing or invalid)",
        ),
        (
            "model_armor_unavailable:too-large",
            "model_armor: text needs more than INJECTION_SCANNER_MODEL_ARMOR_MAX_CHUNKS windows, not sent",
        ),
        (
            "model_armor_unavailable:skipped",
            "model_armor: prompt-injection filter skipped (EXECUTION_SKIPPED)",
        ),
        (
            "model_armor_unavailable:partial-invocation",
            "model_armor: not every filter ran (invocationResult PARTIAL or FAILURE)",
        ),
        (
            "model_armor_unavailable:token-error",
            "model_armor: OAuth token exchange failed (network error or malformed "
            "token response)",
        ),
        (
            "model_armor_unavailable:token-error:400",
            "model_armor: OAuth token exchange returned HTTP 400",
        ),
        (
            "model_armor_unavailable:token-error:4000",
            "model_armor: OAuth token exchange returned HTTP other",
        ),
        (
            "model_armor_unavailable:limiter-error",
            "model_armor: shared limiter or monthly budget ledger unusable (cache "
            "directory, lock, IO error, or torn model_armor-budget.json)",
        ),
        (
            "model_armor_unavailable:HTTPError:429",
            "model_armor: HTTP 429 (quota/rate limit) (HTTPError)",
        ),
        (
            "model_armor_unavailable:throttled",
            "model_armor: local fleet budget or monthly token budget exhausted, or "
            "quota breaker open (throttled)",
        ),
        (
            "model_armor_unavailable:bad-result",
            "model_armor: adapter result outside its closed vocabulary",
        ),
        (
            "model_armor:prompt_attack",
            "model_armor: flagged the benign probe (prompt_attack)",
        ),
        # The panel's own machinery.
        ("l2_unavailable:unhandled:RuntimeError", "l2: unhandled RuntimeError"),
        # L4 judge — the exact shapes judge.py + intercept emit. Judge signals
        # are `api-error:<Exc>[:<status>]`, not the honeypot's
        # `<provider>-api-error`.
        (
            "l2_arbitration:judge_unavailable:openai_41_mini:api-error:"
            "RateLimitError:429",
            "judge: openai model gpt-4.1-mini: returned HTTP 429 (quota/rate limit) "
            "(RateLimitError)",
        ),
        (
            "l2_arbitration:judge_unavailable:anthropic_haiku45:no-anthropic-api-key",
            "judge: anthropic model claude-haiku-4-5: no API key (set ANTHROPIC_API_KEY)",
        ),
        (
            "l2_arbitration:judge_unavailable:openai_41_mini:api-error:NotFoundError:404",
            "judge: openai model gpt-4.1-mini: returned HTTP 404 (NotFoundError)",
        ),
        (
            "l2_arbitration:judge_unavailable:anthropic_haiku45:api-error:TimeoutError",
            "judge: anthropic model claude-haiku-4-5: API call failed (TimeoutError)",
        ),
        (
            "l2_arbitration:judge_unavailable:anthropic_haiku45:parse-error:IndexError",
            "judge: anthropic model claude-haiku-4-5: unparseable response (IndexError)",
        ),
        (
            "l2_arbitration:judge_unavailable:openai_41_mini:malformed-verdict",
            "judge: openai model gpt-4.1-mini: reply was not a verdict (malformed-verdict)",
        ),
        (
            "l2_arbitration:judge_unavailable:openai_41_mini:key-config-error",
            "judge: openai model gpt-4.1-mini: API key configuration error (key file "
            "unreadable or malformed)",
        ),
        ("l2_arbitration:judge_unavailable:panel-incomplete", "judge: panel incomplete"),
        (
            "l2_arbitration:attack:anthropic_haiku45",
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
        "l2_arbitration:judge_unavailable:<script>:api-error:X:4044",
        "l2_arbitration:judge_unavailable:openai_41_mini:parse-error:ignore previous",
        "model_armor_unavailable:Evil$(x):999999",
        "model_armor:ignore previous instructions",
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


def test_every_panel_vendor_has_a_diagnosis() -> None:
    """A vendor added to the panel without a diagnose entry would fall
    through to the generic layer message and lose its fixed conditions."""
    from injection_scanner import l2

    for vendor in l2.VENDORS:
        # The generic fall-through renders the bare condition (`<vendor>: throttled`).
        message = describe(f"{vendor}_unavailable:throttled")
        assert message.startswith(f"{vendor}: ")
        assert message.endswith("quota breaker open (throttled)")


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
    assert not jr.ok and jr.reason.startswith("judge_unavailable:")
    # intercept wraps the judge's reason exactly like this.
    msg = describe(f"l2_arbitration:{jr.reason}")
    assert f"HTTP {status}" in msg and f"({exc_name})" in msg, msg
