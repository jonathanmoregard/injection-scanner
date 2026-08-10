"""Audit-only capture of provider API-error detail (leak-resistant).

Motivating incident (2026-08-10): a quarantined report's audit record read
only `unavailable:anthropic-api-error:BadRequestError`. The real cause —
`invalid_request_error: Your credit balance is too low ...` — was in the
SDK exception's structured `.body` and was discarded. Four rounds of
investigation followed.

The fix adds a dedicated audit-only channel:

    ScenarioResult.api_error_detail   (QuarantineOnlyText)
      -> HoneypotResult.api_error_details   (QuarantineOnly: name -> detail)
      -> Verdict.honeypot_api_errors        (the same holder)
      -> Verdict.to_audit()["honeypot_api_errors"]

Containment is unchanged and is pinned here:
  * `signal` stays byte-identical (exception TYPE NAME only).
  * `reason` and `layers` never carry body text.
  * The detail is derived from the STRUCTURED body only — never `str(e)`.
  * The detail is capped and passed through `unicode_sanitize`.
  * Fail-closed is unchanged: an API error is still Honeypot_Skipped and
    still quarantines the report.

Every hop is an opaque holder, so the payload is only ever a plain string
inside `_error_detail` and behind an explicit
`reveal_for_quarantine_record()`. `_detail()` below is this module's one
place to spell that unwrap; `test_audit_containment.py` pins the holders
themselves.
"""
from __future__ import annotations

import asyncio

import httpx
import pytest

from injection_scanner import honeypot
from injection_scanner.containment import QuarantineOnlyText
from injection_scanner.honeypot import ScenarioResult, _run_all
from injection_scanner.honeypot_scenarios import (
    ALL_SCENARIOS,
    SCENARIO_A_CONVERSATION_HISTORY_LEAK as SCEN_A,
)

# A scenario that runs on the OpenAI provider, so the OpenAI adapter test
# stays valid if the scenario table is reordered.
SCEN_OPENAI = next(s for s in ALL_SCENARIOS if s["provider"] == "openai")

# Present ONLY in `str(e)` (the SDK's `message` argument), never in the
# structured body. If this ever shows up in the captured detail, someone
# reintroduced `str(e)`.
STR_E_MARKER = "STR_E_ONLY_MARKER_91827364"

ANTHROPIC_MESSAGE = (
    "Your credit balance is too low to access the Anthropic API. "
    "Please go to Plans & Billing to upgrade or purchase credits."
)
ANTHROPIC_REQUEST_ID = "req_011CTestBalance"

OPENAI_MESSAGE = (
    "You exceeded your current quota, please check your plan and "
    "billing details."
)
OPENAI_REQUEST_ID = "req_openaiTestQuota"


# ---------- SDK exception builders (real exception classes) ----------

def _anthropic_bad_request(message: str = ANTHROPIC_MESSAGE):
    import anthropic

    request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    response = httpx.Response(
        400, request=request, headers={"request-id": ANTHROPIC_REQUEST_ID}
    )
    body = {
        "type": "error",
        "error": {"type": "invalid_request_error", "message": message},
        "request_id": ANTHROPIC_REQUEST_ID,
    }
    return anthropic.BadRequestError(STR_E_MARKER, response=response, body=body)


def _openai_bad_request(message: str = OPENAI_MESSAGE):
    import openai

    request = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    response = httpx.Response(
        400, request=request, headers={"x-request-id": OPENAI_REQUEST_ID}
    )
    # NOTE: the OpenAI SDK unwraps the JSON envelope before constructing the
    # exception — `BadRequestError.body` is the INNER error object, not
    # `{"error": {...}}`. Verified against openai 2.32.0
    # `_client.OpenAI._make_status_error`.
    body = {
        "message": message,
        "type": "insufficient_quota",
        "param": None,
        "code": "insufficient_quota",
    }
    return openai.BadRequestError(STR_E_MARKER, response=response, body=body)


# ---------- fake clients ----------

class _Raiser:
    def __init__(self, exc):
        self._exc = exc

    def __call__(self, *_a, **_kw):
        raise self._exc


class _FakeAnthropic:
    exc = None

    def __init__(self, *_a, **_kw):
        self.messages = type("_M", (), {"create": _Raiser(type(self).exc)})()


class _FakeOpenAI:
    exc = None

    def __init__(self, *_a, **_kw):
        completions = type("_C", (), {"create": _Raiser(type(self).exc)})()
        self.chat = type("_Chat", (), {"completions": completions})()


@pytest.fixture(autouse=True)
def _no_retry_sleep(monkeypatch):
    monkeypatch.setattr(honeypot, "_MAX_RETRIES", 0)
    monkeypatch.setattr(honeypot, "_RETRY_BASE_S", 0.0)


def _patch_anthropic(monkeypatch, exc):
    import anthropic

    monkeypatch.setattr(honeypot, "_anthropic_key", lambda: "sk-ant-test")
    monkeypatch.setattr(_FakeAnthropic, "exc", exc)
    monkeypatch.setattr(anthropic, "Anthropic", _FakeAnthropic)


def _patch_openai(monkeypatch, exc):
    import openai

    monkeypatch.setattr(honeypot, "_openai_key", lambda: "sk-openai-test")
    monkeypatch.setattr(_FakeOpenAI, "exc", exc)
    monkeypatch.setattr(openai, "OpenAI", _FakeOpenAI)


def _call_anthropic(monkeypatch, exc) -> ScenarioResult:
    _patch_anthropic(monkeypatch, exc)
    return asyncio.run(honeypot._call_anthropic(SCEN_A, "report body", [], set()))


def _call_openai(monkeypatch, exc) -> ScenarioResult:
    _patch_openai(monkeypatch, exc)
    return asyncio.run(honeypot._call_openai(SCEN_OPENAI, "report body", [], set()))


def _detail(r: ScenarioResult) -> str:
    """Unwrap the audit-only holder for assertions.

    A test IS the quarantine-side reader, so the unwrap is legitimate here.
    Kept to one helper so the reveal does not get sprinkled around.
    """
    assert isinstance(r.api_error_detail, QuarantineOnlyText)
    return r.api_error_detail.reveal_for_quarantine_record()


# ---------- (a) signal string byte-identical ----------

def test_anthropic_api_error_signal_unchanged(monkeypatch):
    r = _call_anthropic(monkeypatch, _anthropic_bad_request())
    assert r.verdict == "Honeypot_Skipped"
    assert r.signal == "unavailable:anthropic-api-error:BadRequestError"


def test_openai_api_error_signal_unchanged(monkeypatch):
    r = _call_openai(monkeypatch, _openai_bad_request())
    assert r.verdict == "Honeypot_Skipped"
    assert r.signal == "unavailable:openai-api-error:BadRequestError"


def test_api_error_body_never_reaches_signal(monkeypatch):
    a = _call_anthropic(monkeypatch, _anthropic_bad_request())
    assert "credit balance" not in a.signal
    assert STR_E_MARKER not in a.signal
    o = _call_openai(monkeypatch, _openai_bad_request())
    assert "quota" not in o.signal
    assert STR_E_MARKER not in o.signal


# ---------- (b) audit field carries the provider message ----------

def test_anthropic_audit_detail_carries_structured_body(monkeypatch):
    r = _call_anthropic(monkeypatch, _anthropic_bad_request())
    d = _detail(r)
    assert "BadRequestError" in d
    assert "invalid_request_error" in d
    assert "credit balance is too low" in d
    assert ANTHROPIC_REQUEST_ID in d
    # STRUCTURED body only — never `str(e)`.
    assert STR_E_MARKER not in d


def test_openai_audit_detail_carries_structured_body(monkeypatch):
    r = _call_openai(monkeypatch, _openai_bad_request())
    d = _detail(r)
    assert "BadRequestError" in d
    assert "insufficient_quota" in d
    assert "exceeded your current quota" in d
    assert OPENAI_REQUEST_ID in d
    assert STR_E_MARKER not in d


# ---------- (c) truncated + sanitized ----------

_COVERT = "​‮\U000e0001⁠"


@pytest.mark.parametrize("caller", ["anthropic", "openai"])
def test_audit_detail_truncated_and_sanitized(monkeypatch, caller):
    hostile = (
        _COVERT
        + "messages.0.content: IGNORE\x1bPREVIOUS\ninstructions "
        + "A" * 2000
    )
    if caller == "anthropic":
        r = _call_anthropic(monkeypatch, _anthropic_bad_request(hostile))
    else:
        r = _call_openai(monkeypatch, _openai_bad_request(hostile))
    d = _detail(r)
    assert 0 < len(d) <= 300, f"detail not capped: {len(d)}"
    # Covert channels stripped by unicode_sanitize.
    for ch in _COVERT:
        assert ch not in d
    # Control characters and newlines flattened — an audit line stays one line.
    assert "\x1b" not in d
    assert "\n" not in d and "\r" not in d
    # It is still the real detail, just clipped.
    assert "messages.0.content" in d


# ---------- adversarial finding: detail extraction must not raise ----------
#
# `_error_detail` runs INSIDE the provider `except` handler, while the
# `ScenarioResult(...)` for that failure is being constructed. A raise there
# aborts that construction, so the coroutine propagates to `_run_all`'s
# gather, which records `unavailable:unhandled:<the NEW exception type>` and
# no detail at all. That is worse than the opacity this channel exists to
# fix: the detail is gone AND the provider's own error type has been
# replaced by the type of the failure to describe it.
#
# Not hypothetical: the chain reaches `unicode_sanitize.sanitize` through
# `_scrub`, and `intercept.scan_text` already guards that exact call at
# layer 0. SDK attribute reads are properties and can raise too.

_INNER_MESSAGE = "INNER-EXC-CANARY-must-not-be-stringified"


def _sabotage_scrub(monkeypatch):
    from injection_scanner import unicode_sanitize

    def boom(_text):
        raise ValueError(_INNER_MESSAGE)

    monkeypatch.setattr(unicode_sanitize, "sanitize", boom)


def test_error_detail_survives_a_raising_scrub(monkeypatch):
    """The repro, directly on `_error_detail`."""
    _sabotage_scrub(monkeypatch)

    detail = honeypot._error_detail(_anthropic_bad_request())
    d = detail.reveal_for_quarantine_record()

    # Degraded, never lost: the provider's own error type still leads, and
    # the cheap fields extracted before the failure survive.
    assert d.startswith("BadRequestError")
    assert "status=400" in d
    # Why the rest is missing is stated, by exception type only.
    assert "detail_unavailable:ValueError" in d
    # Never `str(inner_exc)` — an exception raised while handling provider
    # bytes can carry those bytes in its own message.
    assert _INNER_MESSAGE not in d
    # And no unscrubbed provider text rode the fallback out.
    assert "credit balance" not in d


@pytest.mark.parametrize("caller", ["anthropic", "openai"])
def test_a_raising_scrub_does_not_cost_the_provider_error_type(monkeypatch, caller):
    """The consequence the guard exists to prevent, pinned end to end.

    Unguarded, the adapter's `except` handler never finished building its
    result, so the signal became `unavailable:unhandled:ValueError`.
    """
    if caller == "anthropic":
        _patch_anthropic(monkeypatch, _anthropic_bad_request())
        _sabotage_scrub(monkeypatch)
        r = asyncio.run(honeypot._call_anthropic(SCEN_A, "report body", [], set()))
        expected = "unavailable:anthropic-api-error:BadRequestError"
    else:
        _patch_openai(monkeypatch, _openai_bad_request())
        _sabotage_scrub(monkeypatch)
        r = asyncio.run(honeypot._call_openai(SCEN_OPENAI, "report body", [], set()))
        expected = "unavailable:openai-api-error:BadRequestError"

    assert r.signal == expected
    assert "unhandled" not in r.signal
    # Fail-closed is unchanged: a provider error is still degraded coverage.
    assert r.verdict == "Honeypot_Skipped"
    assert "detail_unavailable:ValueError" in _detail(r)


def test_error_detail_survives_exploding_sdk_properties():
    """`status_code` / `body` / `request_id` are SDK properties, not fields."""

    class Exploding(Exception):
        @property
        def status_code(self):
            raise RuntimeError(_INNER_MESSAGE)

        @property
        def body(self):  # pragma: no cover - status_code raises first
            raise RuntimeError(_INNER_MESSAGE)

    d = honeypot._error_detail(Exploding("x")).reveal_for_quarantine_record()
    assert d.startswith("Exploding")
    assert "detail_unavailable:RuntimeError" in d
    assert _INNER_MESSAGE not in d


def test_error_detail_still_returns_a_holder_when_it_degrades(monkeypatch):
    """The degraded path must not drop the containment either."""
    _sabotage_scrub(monkeypatch)
    assert isinstance(honeypot._error_detail(_anthropic_bad_request()),
                      QuarantineOnlyText)


# ---------- cross-vendor finding: the cap must follow the scrub ----------
#
# The cap used to be applied to the RAW message, before scrubbing. Every
# character the scrubber later deletes therefore cost budget, so an echoed
# prefix of invisible characters — free to send, and derived from the
# attacker's own report text — could burn the entire allowance and truncate
# the real provider diagnostic away. The report bytes silenced the
# diagnostic without ever appearing in it.

# One representative of each class `_scrub` removes: zero-width space, tag
# block, variation-selector supplement, bidi override, word joiner, and a
# C0 control.
_STRIPPED_CLASSES = "​\U000e0041\U000e0100‮⁠\x01"


@pytest.mark.parametrize("caller", ["anthropic", "openai"])
def test_stripped_prefix_cannot_burn_the_content_budget(monkeypatch, caller):
    """The repro, at four times the old pre-scrub slice."""
    from injection_scanner.honeypot import _API_ERROR_DETAIL_MAX

    real = "Your credit balance is too low to access the Anthropic API."
    burner = _STRIPPED_CLASSES * (_API_ERROR_DETAIL_MAX * 4)
    assert len(burner) > _API_ERROR_DETAIL_MAX * 4  # the old budget, exhausted

    if caller == "anthropic":
        r = _call_anthropic(monkeypatch, _anthropic_bad_request(burner + real))
    else:
        r = _call_openai(monkeypatch, _openai_bad_request(burner + real))
    d = _detail(r)

    assert "credit balance is too low" in d, (
        "an invisible prefix truncated the real diagnostic away"
    )
    assert len(d) <= _API_ERROR_DETAIL_MAX
    for ch in _STRIPPED_CLASSES:
        assert ch not in d


def test_scrub_leaves_no_whitespace_residue_from_stripped_characters():
    """The subtler half of the same bug, pinned directly on `_scrub`.

    Deleting covert characters from between whitespace, or folding NBSP to
    U+0020, both manufacture blanks. If the whitespace collapse has already
    run by then, those blanks survive and an all-covert prefix still eats
    the content budget — just as spaces instead of invisibles.
    """
    from injection_scanner.honeypot import _scrub

    out = _scrub("before" + _STRIPPED_CLASSES * 100 + "after")
    assert out == "before after"
    assert "  " not in out
    # NBSP folds to U+0020 under NFKC; that has to be collapsed too.
    assert _scrub("a   b") == "a b"
    # A run with nothing but strippable content leaves nothing behind.
    assert _scrub(_STRIPPED_CLASSES * 50) == ""


def test_scrub_input_stays_bounded_for_an_oversized_body(monkeypatch):
    """The pre-slice is a DoS bound, so it must still bound.

    Reordering must not have turned "scrub then cap" into "normalize an
    arbitrarily large provider body".
    """
    from injection_scanner.honeypot import _API_ERROR_DETAIL_MAX, _SCRUB_INPUT_MAX

    assert _SCRUB_INPUT_MAX > _API_ERROR_DETAIL_MAX  # bound, not budget

    past_the_bound = "PAST-THE-DOS-BOUND-MARKER-4d1e"
    huge = "​" * (_SCRUB_INPUT_MAX * 4) + past_the_bound
    r = _call_anthropic(monkeypatch, _anthropic_bad_request(huge))
    d = _detail(r)

    assert past_the_bound not in d
    assert len(d) <= _API_ERROR_DETAIL_MAX
    # Degrades to the cheap high-value fields, exactly like a body-less error.
    assert d.startswith("BadRequestError")
    assert ANTHROPIC_REQUEST_ID in d


def test_cap_cannot_split_a_multibyte_sequence(monkeypatch):
    """Slicing is by code point, so the UTF-8 encoding stays well-formed."""
    from injection_scanner.honeypot import _API_ERROR_DETAIL_MAX

    # Astral (4-byte) and BMP 3-byte characters, so the cap lands mid-run
    # whichever offset it falls at.
    hostile = ("𝔘𝔫𝔦𝔠𝔬𝔡𝔢 ⚠ 日本語 " * 200)
    r = _call_anthropic(monkeypatch, _anthropic_bad_request(hostile))
    d = _detail(r)

    assert len(d) == _API_ERROR_DETAIL_MAX  # truncation actually happened
    assert d.endswith("...")
    # Well-formed both ways, and no replacement character was manufactured.
    assert d.encode("utf-8").decode("utf-8") == d
    assert "�" not in d
    # And it survives the audit writer's encoder unchanged.
    import json
    assert json.loads(json.dumps({"d": d}))["d"] == d


def test_no_line_break_survives_into_the_jsonl_audit_row(monkeypatch):
    """A raw newline would split one audit record into two JSONL rows."""
    import json

    breaks = "\n\r\r\n\v\f\x1c\x1d\x1e\x85  "
    hostile = f"line one{breaks}line two: quota exceeded"
    r = _call_anthropic(monkeypatch, _anthropic_bad_request(hostile))
    d = _detail(r)

    for ch in breaks:
        assert ch not in d, f"line break {ch!r} survived the scrub"
    assert "line one line two" in d  # flattened, not deleted
    # The writer emits one `json.dumps(...) + "\n"` per record.
    row = json.dumps({"honeypot_api_errors": {"A": d}}, default=str)
    assert "\n" not in row


# ---------- graceful degradation: no structured body ----------

def test_no_structured_body_degrades_to_type_name(monkeypatch):
    marker = "RAW_EXCEPTION_TEXT_KEEPOUT_5150"
    r = _call_anthropic(monkeypatch, RuntimeError(marker))
    assert r.signal == "unavailable:anthropic-api-error:RuntimeError"
    assert _detail(r) == "RuntimeError"
    assert marker not in _detail(r)


def test_connection_error_without_body_degrades(monkeypatch):
    import anthropic

    request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    exc = anthropic.APIConnectionError(request=request)
    r = _call_anthropic(monkeypatch, exc)
    assert r.signal == "unavailable:anthropic-api-error:APIConnectionError"
    assert _detail(r) == "APIConnectionError"


# ---------- aggregation onto HoneypotResult ----------

def test_run_all_aggregates_api_error_details(monkeypatch):
    target = ALL_SCENARIOS[0]

    async def fake_run_one(scenario, _report):
        if scenario["name"] == target["name"]:
            return ScenarioResult(
                scenario=scenario["name"], verdict="Honeypot_Skipped",
                signal="unavailable:anthropic-api-error:BadRequestError",
                provider=scenario["provider"], model=scenario["model"],
                api_error_detail=QuarantineOnlyText(
                    "BadRequestError type=invalid_request_error "
                    "message=credit balance is too low"
                ),
            )
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Left_Alone",
            signal="left_alone",
            provider=scenario["provider"], model=scenario["model"],
        )

    monkeypatch.setattr(honeypot, "_run_one", fake_run_one)
    res = asyncio.run(_run_all("report"))
    assert res.ok is False  # fail-closed unchanged
    # The aggregate is a holder, not a bare dict — unwrap once, deliberately.
    details = res.api_error_details.reveal_for_quarantine_record()
    assert details[target["name"]].startswith("BadRequestError")
    # Only scenarios that actually errored appear.
    assert list(details) == [target["name"]]
    # Containment: the aggregated reason still carries the type name only.
    assert "credit balance" not in res.reason
    # ...and the holder itself renders nothing, even for the errored scenario.
    assert "credit balance" not in repr(res)
    assert "credit balance" not in repr(res.api_error_details)


# ---------- (d) + (e) end-to-end through intercept / to_audit ----------

def test_scan_text_audit_has_detail_reason_and_layers_do_not(monkeypatch):
    from injection_scanner import intercept

    _patch_anthropic(monkeypatch, _anthropic_bad_request())
    _patch_openai(monkeypatch, _openai_bad_request())

    v = intercept.scan_text(
        "Benign report. Sources: 1. example.",
        use_honeypot=True,
        use_lakera=False,
    )

    # (e) fail-closed reject still happens.
    assert v.ok is False
    assert v.reason.startswith("honeypot:honeypot_unavailable:")

    # (b) the audit record carries the real provider detail.
    audit = v.to_audit()
    details = audit["honeypot_api_errors"]
    assert details, "audit record carries no api-error detail"
    joined = " ".join(details.values())
    assert "credit balance is too low" in joined
    assert "exceeded your current quota" in joined
    assert ANTHROPIC_REQUEST_ID in joined
    assert OPENAI_REQUEST_ID in joined
    # Every scenario errored, so every scenario has a detail.
    assert len(details) == len(ALL_SCENARIOS)

    # (d) reason and layers carry NO body text.
    forbidden = [
        "credit balance",
        "Plans & Billing",
        "exceeded your current quota",
        "invalid_request_error",
        "insufficient_quota",
        ANTHROPIC_REQUEST_ID,
        OPENAI_REQUEST_ID,
        STR_E_MARKER,
    ]
    for needle in forbidden:
        assert needle not in v.reason, f"leaked into reason: {needle}"
        for k, val in v.layers.items():
            assert needle not in val, f"leaked into layers[{k}]: {needle}"
    assert audit["reason"] == v.reason


def test_clean_scan_has_empty_api_error_audit_field(monkeypatch):
    from injection_scanner import intercept
    from injection_scanner.honeypot import HoneypotResult

    monkeypatch.setattr(
        intercept, "honeypot_check", lambda _t: HoneypotResult(ok=True, reason="pass")
    )
    v = intercept.scan_text("Benign.", use_honeypot=True, use_lakera=False)
    assert v.ok is True
    assert v.to_audit()["honeypot_api_errors"] == {}
