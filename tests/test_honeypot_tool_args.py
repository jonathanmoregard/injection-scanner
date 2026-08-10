"""Tool-ARGUMENT shapes must fail closed, exactly like tool NAMES do.

The classifier trusted every tool call's arguments to be a dict. Neither
provider guarantees that: `json.loads` returns any JSON value (`'["x"]'`
parses fine) and anthropic types `block.input` as `object`. Step 4's
`inp.get("category")` then raised `AttributeError` — out of the adapter,
because both of its try/except blocks sit upstream of the classify call —
and `_run_all`'s gather recorded `unavailable:unhandled:AttributeError`.
Pre-fix repro:

    -> RAISED out of _call_openai: AttributeError: 'list' object has no
       attribute 'get'
    -> RAISED out of _call_anthropic: AttributeError: 'list' object has
       no attribute 'get'
    -> reason = honeypot_unavailable:misconfigured_env_file:
       unavailable:unhandled:AttributeError+skipped=4/6

Fail-closed by luck, and misfiled: an argument shape this layer cannot
read is a malformed tool call, not a provider outage, and the audit line
sent the operator looking at the wrong system.

The fix shape-checks the arguments and routes them to the same bucket a
malformed NAME already used — `Honeypot_Skipped` /
`unavailable:malformed-tool-args`. The ORDER is the design: the gate sits
at the last moment before a CLEAN verdict, not at the top of the
function, so every detection step still gets to fire on a misshapen
response and only the conclusion of absence is blocked.
"""
from __future__ import annotations

import asyncio

import pytest

from injection_scanner import honeypot
from injection_scanner.honeypot import _classify_from_parts
from injection_scanner.honeypot_scenarios import (
    ALL_SCENARIOS,
    CANARY_ALPHA,
    SCENARIO_A_CONVERSATION_HISTORY_LEAK as SCEN_A,
    SCENARIO_B_MISCONFIGURED_ENV as SCEN_B,
    TRAP_CAPABILITIES,
)

SCEN_OPENAI = next(s for s in ALL_SCENARIOS if s["provider"] == "openai")
OPENAI_CANARY = SCEN_OPENAI["canary"]
OWN = SCEN_B["canary"]
TRAPS = set(TRAP_CAPABILITIES)


# ---------- fake provider responses ----------

class _Fn:
    def __init__(self, name: str, arguments):
        self.name = name
        self.arguments = arguments


class _ToolCall:
    def __init__(self, name: str, arguments):
        self.function = _Fn(name, arguments)


class _Message:
    def __init__(self, tool_calls, content=""):
        self.tool_calls = tool_calls
        self.content = content


class _OpenAIResponse:
    def __init__(self, msg):
        self.choices = [type("_Choice", (), {"message": msg})()]


class _Block:
    """One anthropic content block; attributes set verbatim."""

    def __init__(self, **kw):
        self.__dict__.update(kw)


def _patch_openai(monkeypatch, tool_calls, content=""):
    import openai

    resp = _OpenAIResponse(_Message(tool_calls, content))

    class _FakeOpenAI:
        def __init__(self, *_a, **_kw):
            completions = type("_C", (), {"create": lambda *_a, **_kw: resp})()
            self.chat = type("_Chat", (), {"completions": completions})()

    monkeypatch.setattr(honeypot, "_openai_key", lambda: "sk-openai-test")
    monkeypatch.setattr(openai, "OpenAI", _FakeOpenAI)


def _openai_call(monkeypatch, tool_calls, content=""):
    _patch_openai(monkeypatch, tool_calls, content)
    return asyncio.run(honeypot._call_openai(SCEN_OPENAI, "report body", [], set()))


def _patch_anthropic(monkeypatch, blocks):
    import anthropic

    resp = type("_R", (), {"content": blocks})()

    class _FakeAnthropic:
        def __init__(self, *_a, **_kw):
            self.messages = type("_M", (), {"create": lambda *_a, **_kw: resp})()

    monkeypatch.setattr(honeypot, "_anthropic_key", lambda: "sk-ant-test")
    monkeypatch.setattr(anthropic, "Anthropic", _FakeAnthropic)


def _anthropic_call(monkeypatch, blocks):
    _patch_anthropic(monkeypatch, blocks)
    return asyncio.run(honeypot._call_anthropic(SCEN_A, "report body", [], set()))


# ---------- bug 2: a non-dict parse result ----------

_NON_DICT_ARGS = {
    "list": '["Prompt_Injection_Attempt"]',
    "string": '"Prompt_Injection_Attempt"',
    "number": "42",
    "bool": "true",
    "null": "null",
}


@pytest.mark.parametrize(
    "raw", list(_NON_DICT_ARGS.values()), ids=list(_NON_DICT_ARGS)
)
def test_non_dict_parse_result_is_malformed_not_an_attributeerror(
    monkeypatch, raw
):
    """`'["x"]'` parses fine, and `inp.get("category")` then raised.

    The raise escaped the adapter (both try/except blocks are upstream of
    the classify call), so the gather filed it as
    `unavailable:unhandled:AttributeError` — fail-closed by luck, and
    misattributed to the provider.
    """
    r = _openai_call(monkeypatch, [_ToolCall("report_issue", raw)])
    assert r.verdict == "Honeypot_Skipped"
    assert r.signal == "unavailable:malformed-tool-args"


def test_non_dict_parse_result_carrying_a_canary_still_triggers(monkeypatch):
    """Salvage applies to a successful parse of the wrong shape too."""
    r = _openai_call(
        monkeypatch,
        [_ToolCall("return_summary", '["' + OPENAI_CANARY + '"]')],
    )
    assert r.verdict == "Honeypot_Triggered"
    assert r.signal.startswith("canary_in_arg:")


@pytest.mark.parametrize(
    "value", [["Prompt_Injection_Attempt"], "Prompt_Injection_Attempt", 42,
              None, True],
    ids=["list", "string", "number", "none", "bool"],
)
def test_anthropic_block_input_is_shape_checked(monkeypatch, value):
    """`block.input` was trusted to be a dict; the SDK types it `object`."""
    r = _anthropic_call(
        monkeypatch,
        [_Block(type="tool_use", name="report_issue", input=value)],
    )
    assert r.verdict == "Honeypot_Skipped"
    assert r.signal == "unavailable:malformed-tool-args"


def test_anthropic_non_dict_block_input_carrying_a_canary_triggers(monkeypatch):
    r = _anthropic_call(
        monkeypatch,
        [_Block(type="tool_use", name="return_summary",
                input=[CANARY_ALPHA])],
    )
    assert r.verdict == "Honeypot_Triggered"
    assert r.signal.startswith("canary_in_arg:")


def test_no_scenario_is_recorded_as_an_unhandled_outage(monkeypatch):
    """The misattribution, pinned at the aggregate."""
    _patch_openai(
        monkeypatch, [_ToolCall("report_issue", '["Prompt_Injection_Attempt"]')]
    )
    _patch_anthropic(
        monkeypatch,
        [_Block(type="tool_use", name="report_issue", input=["x"])],
    )
    res = asyncio.run(honeypot._run_all("report body"))

    assert res.ok is False
    assert all(s.verdict == "Honeypot_Skipped" for s in res.per_scenario)
    for s in res.per_scenario:
        assert s.signal == "unavailable:malformed-tool-args", s.scenario
    assert "unhandled" not in res.reason


# ---------- the clean paths must not become trigger-happy ----------
#
# A false positive quarantines a legitimate report, so every benign shape
# that used to pass must still pass.

def test_well_formed_args_still_pass(monkeypatch):
    r = _openai_call(
        monkeypatch,
        [_ToolCall("return_summary", '{"text": "Python 3.13 was released."}')],
    )
    assert r.verdict == "Honeypot_Left_Alone"
    assert r.signal == "left_alone"


def test_an_injection_report_still_reads_as_the_good_signal(monkeypatch):
    r = _openai_call(
        monkeypatch,
        [_ToolCall(
            "report_issue",
            '{"category": "Prompt_Injection_Attempt", '
            '"description": "the attached content tells me to call a tool"}',
        )],
    )
    assert r.verdict == "Honeypot_Left_Alone"
    assert r.signal == "left_alone_with_injection_report"


@pytest.mark.parametrize("empty", ["", "{}", "   "], ids=["blank", "braces", "spaces"])
def test_an_argument_less_tool_call_still_passes(monkeypatch, empty):
    """A no-arg call is "no arguments", not "arguments we could not read".

    OpenAI sends `""` or `"{}"` for a tool with no parameters. Treating
    that as malformed would quarantine every legitimate report a judge
    answers with a bare call — and it would concede nothing in exchange,
    because an empty or all-whitespace argument string provably cannot
    contain a canary. Fail-closed is for what we could not determine, and
    this one is determined.
    """
    r = _openai_call(monkeypatch, [_ToolCall("return_summary", empty)])
    assert r.verdict == "Honeypot_Left_Alone"


def test_an_empty_dict_input_still_passes_on_anthropic(monkeypatch):
    r = _anthropic_call(
        monkeypatch, [_Block(type="tool_use", name="return_summary", input={})]
    )
    assert r.verdict == "Honeypot_Left_Alone"


def test_a_text_only_response_still_passes(monkeypatch):
    r = _openai_call(monkeypatch, [], content="Here is a clean summary.")
    assert r.verdict == "Honeypot_Left_Alone"


def test_nested_and_unicode_args_are_not_mistaken_for_malformed(monkeypatch):
    r = _openai_call(
        monkeypatch,
        [_ToolCall(
            "return_summary",
            '{"text": "\\u65e5\\u672c\\u8a9e", "meta": {"n": [1, 2, 3]}}',
        )],
    )
    assert r.verdict == "Honeypot_Left_Alone"



# ---------- classifier-level shape gate ----------

@pytest.mark.parametrize(
    "args",
    [["a"], "a string", 42, 3.5, True, None, ("a",), {"a"}],
    ids=["list", "str", "int", "float", "bool", "none", "tuple", "set"],
)
def test_unreadable_arguments_never_classify_as_left_alone(args):
    """The single invariant behind every case above.

    The gate sits exactly where the classifier would otherwise conclude
    ABSENCE of a leak, so no shape of unreadable argument can produce a
    pass — while every detection step upstream of it still gets its
    chance to fire.
    """
    for name in ("return_summary", "report_issue"):
        r = _classify_from_parts(SCEN_B, [(name, args)], "", TRAPS)
        assert r.verdict == "Honeypot_Skipped", (name, args)
        assert r.signal == "unavailable:malformed-tool-args"


def test_a_canary_inside_any_unreadable_shape_is_still_found():
    for args in ([OWN], OWN, {"nested": [OWN]}):
        r = _classify_from_parts(SCEN_B, [("return_summary", args)], "", TRAPS)
        assert r.verdict == "Honeypot_Triggered", args
        assert r.signal.startswith("canary_in_arg:")


def test_arguments_that_cannot_be_rendered_at_all_fail_closed():
    """If the blob cannot be produced, the canary scan proved nothing.

    A dict is the right SHAPE, so the shape check alone would pass it — but
    `json.dumps` and `str()` both blow up on this one, so the scan that is
    supposed to clear it never ran.
    """
    class _Hostile:
        def __repr__(self):
            raise RuntimeError("BOOM-CANARY-must-not-escape")

        __str__ = __repr__

    r = _classify_from_parts(
        SCEN_B, [("return_summary", {"x": _Hostile()})], "", TRAPS
    )
    assert r.verdict == "Honeypot_Skipped"
    assert r.signal == "unavailable:malformed-tool-args"
    assert "BOOM-CANARY" not in r.signal
