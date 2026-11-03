"""Tests for the layered intercept shim."""
from __future__ import annotations

import base64
import tempfile
from pathlib import Path

import pytest

from injection_scanner import secret_shapes, unicode_sanitize
from injection_scanner.intercept import scan


# ----- unicode_sanitize -----

def test_strips_tag_block():
    # U+E0045 = ASCII smuggler 'E'
    dirty = "Hello\U000E0045World"
    r = unicode_sanitize.sanitize(dirty)
    assert r.tag_hits == 1
    assert "\U000E0045" not in r.text


def test_strips_bidi_override():
    dirty = "safe\u202Emalicious"
    r = unicode_sanitize.sanitize(dirty)
    assert r.bidi_hits == 1
    assert "\u202E" not in r.text


def test_strips_zero_width():
    dirty = "a\u200Bb\u200Cc\u200Dd\uFEFFe"
    r = unicode_sanitize.sanitize(dirty)
    assert r.zw_hits == 4
    assert r.text == "abcde"


def test_nfkc_normalizes():
    # Fullwidth 'A' -> 'A'
    dirty = "\uFF21BC"
    r = unicode_sanitize.sanitize(dirty)
    assert r.text == "ABC"
    assert r.nfkc_changed


def test_benign_prose_untouched():
    text = (
        "# Python 3.13 Release\n\n"
        "Python 3.13 was released in October 2024 with improved REPL."
    )
    r = unicode_sanitize.sanitize(text)
    assert r.stripped == 0
    assert r.text == text


# ----- L0 invisibles expansion (Item A) -----

def test_strips_variation_selector_supplement():
    # U+E0100 — Butler/Goodside byte-smuggling channel. Counted as tag_hits.
    dirty = "hello\U000E0100world"
    r = unicode_sanitize.sanitize(dirty)
    assert r.tag_hits == 1
    assert r.stripped == 1
    assert "\U000E0100" not in r.text
    assert r.text == "helloworld"


def test_strips_word_joiner_and_fmt_covert():
    # U+2060 WORD JOINER + U+2061 (invisible math) are covert format chars.
    dirty = "a⁠b⁡c"
    r = unicode_sanitize.sanitize(dirty)
    assert r.fmt_hits == 2
    assert r.stripped == 2
    assert r.text == "abc"


def test_preserves_emoji_variation_selector():
    # U+FE0F is part of the "warning" emoji ⚠️ and MUST survive intact and
    # NOT be counted — stripping it would corrupt legitimate benign content.
    text = "warning ⚠️ ahead"
    r = unicode_sanitize.sanitize(text)
    assert "️" in r.text
    assert r.text == text
    assert r.stripped == 0
    assert r.fmt_hits == 0


def test_preserves_arabic_with_lrm():
    # U+200E LRM is legitimate in RTL text; the snippet must survive untouched.
    text = "قال ‎(hello)‎ مرحبا"
    r = unicode_sanitize.sanitize(text)
    assert "‎" in r.text
    assert r.text == text
    assert r.stripped == 0


# ----- anomaly-density absolute floor (Item B) -----

def test_short_doc_single_zw_stripped_but_not_anomalous():
    # A 200-char doc with a single stray zero-width: stripped, but below the
    # ANOMALY_MIN_STRIPPED floor so NOT escalated to quarantine.
    text = "x" * 199 + "​"
    r = unicode_sanitize.sanitize(text)
    assert r.stripped == 1
    assert "​" not in r.text
    assert unicode_sanitize.is_anomalous(r, len(text)) is False


def test_bidi_density_smoke_still_anomalous():
    # Many strips (well above both floor and density) still flags anomalous.
    text = "benign ‮malicious" * 100
    r = unicode_sanitize.sanitize(text)
    assert r.stripped >= unicode_sanitize.ANOMALY_MIN_STRIPPED
    assert unicode_sanitize.is_anomalous(r, len(text)) is True


# ----- secret_shapes -----

def test_finds_anthropic_key():
    text = "My key is sk-ant-api01-" + "A" * 95
    hits = secret_shapes.scan(text)
    assert any(h.name == "anthropic_api_key" for h in hits)


def test_finds_anthropic_oauth():
    text = "oauth: sk-ant-oat01-" + "B" * 60
    hits = secret_shapes.scan(text)
    assert any(h.name == "anthropic_oauth_token" for h in hits)


def test_finds_github_token():
    text = "token = ghp_" + "A" * 36
    hits = secret_shapes.scan(text)
    assert any(h.name == "github_token" for h in hits)


def test_finds_env_assignment():
    text = "EXA_API_KEY=abc123def456ghi789jkl\n"
    hits = secret_shapes.scan(text)
    assert any(h.name == "env_assignment_secret" for h in hits)


def test_benign_research_text_no_hits():
    text = (
        "The sk-ant-api prefix is documented in Anthropic's key format."
        "  Tokens begin with gh[psoure]_ for GitHub."
    )
    # discussing prefixes without a real token should NOT fire
    hits = secret_shapes.scan(text)
    assert not hits


# ----- intercept integration -----

def test_orchestrator_passes_clean_report():
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write(
            "# Python 3.13\n\n*Sources: 1*\n\n## Summary\nReleased October 2024.\n"
        )
        path = Path(f.name)
    v = scan(path, use_honeypot=False, use_l2=False)
    assert v.ok, f"expected pass, got {v.reason}"
    assert v.layers["secret_shapes"] == "pass"


def test_orchestrator_blocks_secret():
    # Pin the structured reason shape: `secret_shape:<rule_name>` only —
    # NO snippet bytes. Previously the reason carried up to 40 chars of
    # the matched secret, which violated Invariant 4 (caught bytes never
    # return to caller context).
    secret_bytes = "sk-ant-oat01-" + "X" * 60
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write("# Report\n\nLeaked key: " + secret_bytes + "\n")
        path = Path(f.name)
    v = scan(path, use_honeypot=False, use_l2=False)
    assert not v.ok
    assert v.reason == "secret_shape:anthropic_oauth_token"
    # No part of the secret bytes appears in reason or layers.
    assert secret_bytes not in v.reason
    for k, val in v.layers.items():
        assert secret_bytes not in val, f"leaked in layers[{k}]"
    # First 13 chars are the rule prefix and could appear in `name`;
    # require the *unique tail* (the X*60 attacker-controlled bytes)
    # never to leak.
    assert "X" * 60 not in v.reason
    for k, val in v.layers.items():
        assert "X" * 60 not in val, f"leaked in layers[{k}]"


def test_orchestrator_blocks_unicode_covert():
    # Above 0.1% density threshold.
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write("benign \u202Emalicious" * 100)
        path = Path(f.name)
    v = scan(path, use_honeypot=False, use_l2=False)
    assert not v.ok
    assert "unicode_anomaly" in v.reason


def test_orchestrator_strips_but_passes_single_zw():
    # Single zero-width in a long doc is below threshold; gets stripped,
    # doesn't fail.
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write("clean text " * 500 + "\u200Bcontaminated")
        path = Path(f.name)
    v = scan(path, use_honeypot=False, use_l2=False)
    assert v.ok
    assert "\u200B" not in v.sanitized_text


# ----- L2 panel -> L3/L4 wiring -----
#
# Both vendors are stubbed at their adapter `check`, so the real panel
# (`l2.run`, default floor 2) decides and `scan_text` routes its outcome:
# FLAGGED and DEGRADED_QUOTA go to strict honeypot + unanimous judge
# arbitration, UNAVAILABLE rejects, and with the honeypot off nothing is
# arbitrated.

def _vendor(reason: str):
    from injection_scanner.vendor_http import VendorResult

    if reason == "pass":
        result = VendorResult(ok=True, reason="pass")
    elif reason.endswith(":prompt_attack"):
        result = VendorResult(ok=False, flagged=True, reason=reason)
    else:
        result = VendorResult(ok=False, reason=reason)
    return lambda _text, **_kw: result


def _panel(monkeypatch, lakera_reason: str, armor_reason: str) -> None:
    from injection_scanner import lakera, modelarmor

    monkeypatch.setattr(lakera, "check", _vendor(lakera_reason))
    monkeypatch.setattr(modelarmor, "check", _vendor(armor_reason))


def _hp_clean(_text):
    from injection_scanner.honeypot import HoneypotResult
    return HoneypotResult(ok=True, reason="pass")


def _judge_benign(_text):
    from injection_scanner.judge import JudgeResult, JudgeVote
    return JudgeResult(
        ok=True,
        reason="benign-unanimous",
        votes=[JudgeVote("anthropic_haiku45", "benign", "verdict")],
    )


def _must_not_run(what: str):
    def _fail(*_a, **_kw):
        pytest.fail(f"{what} must not run")
    return _fail


@pytest.mark.parametrize(
    "lakera_reason,armor_reason",
    [
        ("lakera_unavailable:HTTPError:429", "pass"),
        ("lakera_unavailable:throttled", "pass"),
        ("pass", "model_armor_unavailable:HTTPError:429"),
        ("pass", "model_armor_unavailable:throttled"),
        ("lakera:prompt_attack", "model_armor_unavailable:throttled"),
    ],
)
def test_quota_degradation_uses_strict_benign_arbitration(
    monkeypatch, lakera_reason, armor_reason
):
    from injection_scanner import intercept, judge

    _panel(monkeypatch, lakera_reason, armor_reason)
    monkeypatch.setattr(intercept, "honeypot_check", _hp_clean)
    monkeypatch.setattr(judge, "check", _judge_benign)

    verdict = intercept.scan_text("clean prose")

    assert verdict.ok is True
    assert verdict.layers["lakera"] == lakera_reason
    assert verdict.layers["model_armor"] == armor_reason
    assert verdict.layers["l2"] == "degraded-quota verdicts=1/2 floor=2"
    assert verdict.layers["honeypot"] == "pass"
    assert verdict.layers["judge"] == "benign-unanimous"


@pytest.mark.parametrize(
    "lakera_reason,armor_reason,expected",
    [
        ("lakera_unavailable:service-unavailable", "pass",
         "lakera_unavailable:service-unavailable"),
        ("lakera_unavailable:HTTPError:503", "pass", "lakera_unavailable:HTTPError:503"),
        ("lakera_unavailable:HTTPError:429-extra", "pass",
         "lakera_unavailable:HTTPError:429-extra"),
        ("lakera_unavailable:no-key", "pass", "lakera_unavailable:no-key"),
        ("pass", "model_armor_unavailable:no-key", "model_armor_unavailable:no-key"),
        ("lakera_unavailable:throttled", "model_armor_unavailable:limiter-error",
         "model_armor_unavailable:limiter-error"),
        ("lakera:prompt_attack", "model_armor_unavailable:skipped",
         "model_armor_unavailable:skipped"),
    ],
)
def test_a_non_quota_shortfall_rejects_before_any_arbitration(
    monkeypatch, lakera_reason, armor_reason, expected
):
    from injection_scanner import intercept, judge

    _panel(monkeypatch, lakera_reason, armor_reason)
    monkeypatch.setattr(intercept, "honeypot_check", _must_not_run("honeypot"))
    monkeypatch.setattr(judge, "check", _must_not_run("judge"))

    verdict = intercept.scan_text("x")

    assert verdict.ok is False
    assert verdict.reason == expected
    assert verdict.layers["l2"].startswith("unavailable verdicts=")


def test_quota_degradation_without_honeypot_stays_fail_closed(monkeypatch):
    from injection_scanner import intercept

    _panel(monkeypatch, "pass", "model_armor_unavailable:HTTPError:429")
    verdict = intercept.scan_text("x", use_honeypot=False)
    assert verdict.ok is False
    assert verdict.reason == "model_armor_unavailable:HTTPError:429"


def test_quota_degradation_with_honeypot_trigger_rejects_without_judge(
    monkeypatch,
):
    from injection_scanner import intercept, judge
    from injection_scanner.honeypot import HoneypotResult

    _panel(monkeypatch, "lakera_unavailable:throttled", "pass")
    monkeypatch.setattr(
        intercept,
        "honeypot_check",
        lambda _t: HoneypotResult(ok=False, reason="scenario:triggered"),
    )
    monkeypatch.setattr(judge, "check", _must_not_run("judge"))

    verdict = intercept.scan_text("x")

    assert verdict.ok is False
    assert verdict.reason == "honeypot:scenario:triggered"


def test_l2_outcome_reads_the_panel_summary_of_a_verdict(monkeypatch):
    from injection_scanner import intercept
    from injection_scanner.l2 import Outcome

    _panel(monkeypatch, "pass", "pass")
    assert intercept.l2_outcome(
        intercept.scan_text("x", use_honeypot=False)
    ) is Outcome.PASS

    _panel(monkeypatch, "pass", "model_armor_unavailable:throttled")
    assert intercept.l2_outcome(
        intercept.scan_text("x", use_honeypot=False)
    ) is Outcome.DEGRADED_QUOTA

    assert intercept.l2_outcome(
        intercept.scan_text("x", use_honeypot=False, use_l2=False)
    ) is None


@pytest.mark.parametrize(
    "lakera_reason,armor_reason",
    [
        ("lakera:prompt_attack", "pass"),
        ("pass", "model_armor:prompt_attack"),
    ],
)
def test_a_flag_honeypot_clean_judge_benign_delivers(
    monkeypatch, lakera_reason, armor_reason
):
    from injection_scanner import intercept, judge

    _panel(monkeypatch, lakera_reason, armor_reason)
    monkeypatch.setattr(intercept, "honeypot_check", _hp_clean)
    monkeypatch.setattr(judge, "check", _judge_benign)

    v = intercept.scan_text("prose about agent tooling", use_honeypot=True, use_l2=True)

    assert v.ok
    assert v.layers["lakera"] == lakera_reason
    assert v.layers["model_armor"] == armor_reason
    assert v.layers["l2"] == "flagged verdicts=2/2 floor=2"
    assert v.layers["judge"] == "benign-unanimous"


def test_a_flag_with_a_judge_attack_vote_rejects(monkeypatch):
    from injection_scanner import intercept, judge
    from injection_scanner.judge import JudgeResult

    _panel(monkeypatch, "pass", "model_armor:prompt_attack")
    monkeypatch.setattr(intercept, "honeypot_check", _hp_clean)
    monkeypatch.setattr(judge, "check", lambda _t: JudgeResult(
        ok=False, reason="attack:openai_4o_mini"))
    v = intercept.scan_text("x", use_honeypot=True, use_l2=True)
    assert not v.ok
    assert v.reason == "l2_arbitration:attack:openai_4o_mini"


def test_a_judge_outage_is_an_unavailable_reason_under_l2_arbitration(monkeypatch):
    """A judge that could not answer is an OUTAGE: the verdict reason is
    `l2_arbitration:judge_unavailable:<judge>:<signal>`, the
    `<wrapper>:<layer>_unavailable:*` shape consumers classify as infra.
    Driven through the real vote aggregation in judge._run_all."""
    from injection_scanner import intercept, judge
    from injection_scanner.judge import JudgeVote

    async def one(j, _sealed):
        if j["id"] == "openai_41_mini":
            return JudgeVote(j["id"], "unavailable", "api-error:RateLimitError:429")
        return JudgeVote(j["id"], "benign", "verdict")

    _panel(monkeypatch, "lakera:prompt_attack", "pass")
    monkeypatch.setattr(intercept, "honeypot_check", _hp_clean)
    monkeypatch.setattr(judge, "_ask_one", one)
    v = intercept.scan_text("x", use_honeypot=True, use_l2=True)
    assert not v.ok
    assert v.reason == (
        "l2_arbitration:judge_unavailable:openai_41_mini:api-error:RateLimitError:429"
    )


def test_judge_ok_with_non_unanimous_reason_still_rejects(monkeypatch):
    from injection_scanner import intercept, judge
    from injection_scanner.judge import JudgeResult

    _panel(monkeypatch, "lakera:prompt_attack", "pass")
    monkeypatch.setattr(intercept, "honeypot_check", _hp_clean)
    monkeypatch.setattr(
        judge,
        "check",
        lambda _t: JudgeResult(ok=True, reason="unexpected-pass-shape"),
    )

    verdict = intercept.scan_text("x")

    assert verdict.ok is False
    assert verdict.reason == "l2_arbitration:unexpected-pass-shape"


def test_a_flag_with_a_triggered_honeypot_rejects_without_judge(monkeypatch):
    from injection_scanner import intercept, judge
    from injection_scanner.honeypot import HoneypotResult

    _panel(monkeypatch, "lakera:prompt_attack", "pass")
    monkeypatch.setattr(intercept, "honeypot_check", lambda _t: HoneypotResult(
        ok=False, reason="honeypot:scn:trap:x"))
    monkeypatch.setattr(judge, "check", _must_not_run("judge"))
    v = intercept.scan_text("x", use_honeypot=True, use_l2=True)
    assert not v.ok
    assert v.reason.startswith("honeypot:")


def test_a_flag_without_honeypot_hard_rejects(monkeypatch):
    from injection_scanner import intercept

    _panel(monkeypatch, "pass", "model_armor:prompt_attack")
    v = intercept.scan_text("x", use_honeypot=False, use_l2=True)
    assert not v.ok
    assert v.reason == "model_armor:prompt_attack"


def test_a_clean_panel_never_calls_judge(monkeypatch):
    from injection_scanner import intercept, judge

    _panel(monkeypatch, "pass", "pass")
    monkeypatch.setattr(intercept, "honeypot_check", _hp_clean)
    monkeypatch.setattr(judge, "check", _must_not_run("judge"))
    v = intercept.scan_text("clean text", use_honeypot=True, use_l2=True)
    assert v.ok
    assert v.reason == "pass"
    assert v.layers["l2"] == "pass verdicts=2/2 floor=2"


def test_judge_crash_fails_closed(monkeypatch):
    from injection_scanner import intercept, judge

    _panel(monkeypatch, "lakera:prompt_attack", "pass")
    monkeypatch.setattr(intercept, "honeypot_check", _hp_clean)
    monkeypatch.setattr(judge, "check", lambda _t: (_ for _ in ()).throw(
        RuntimeError("judge infra down")))
    v = intercept.scan_text("x", use_honeypot=True, use_l2=True)
    assert not v.ok
    assert v.reason == "judge_unavailable:unhandled:RuntimeError"
    assert "infra down" not in v.reason


def test_a_disabled_panel_calls_no_vendor(monkeypatch):
    from injection_scanner import intercept, lakera, modelarmor

    monkeypatch.setattr(lakera, "check", _must_not_run("lakera"))
    monkeypatch.setattr(modelarmor, "check", _must_not_run("model_armor"))
    v = intercept.scan_text("clean text", use_honeypot=False, use_l2=False)
    assert v.ok
    assert v.layers["l2"] == "disabled (test-only)"
    assert "lakera" not in v.layers and "model_armor" not in v.layers


def test_a_crash_in_the_panel_itself_fails_closed(monkeypatch):
    """Invariant 3 for the panel's own machinery (thread pool, floor
    parsing): the type name only, never the message."""
    from injection_scanner import intercept, l2

    def _boom(*_a, **_kw):
        raise RuntimeError("SECRET_MESSAGE_MARKER")

    monkeypatch.setattr(l2, "run", _boom)
    v = intercept.scan_text("clean text", use_honeypot=False)
    assert v.ok is False
    assert v.reason == "l2_unavailable:unhandled:RuntimeError"
    assert v.layers["l2"] == "unhandled:RuntimeError"
    assert "SECRET_MESSAGE_MARKER" not in repr(v)


# ----- the batch wait budget reaches every L2 vendor (2026-09-05) -----
#
# `eval` is always a batch caller: it would rather queue behind the fleet's
# budget than be refused. That preference is the caller's, so it travels as a
# keyword from the caller to each adapter `check` and nothing in between
# interprets it.

# The spy's default is a SENTINEL, not None: `None` is a value intercept is
# required to forward, so a default of None would make "keyword omitted" and
# "keyword passed as None" record identically.
_UNSET = object()


def _wait_spies(monkeypatch):
    """Install recording stand-ins for both adapters; return what they saw."""
    from injection_scanner import lakera, modelarmor
    from injection_scanner.vendor_http import VendorResult

    seen: dict[str, list[object]] = {"lakera": [], "model_armor": []}

    def _spy(name):
        def check(text, *, max_wait_s=_UNSET):
            seen[name].append(max_wait_s)
            return VendorResult(ok=True, reason="pass")
        return check

    monkeypatch.setattr(lakera, "check", _spy("lakera"))
    monkeypatch.setattr(modelarmor, "check", _spy("model_armor"))
    return seen


def test_l2_max_wait_s_reaches_every_vendor(monkeypatch):
    from injection_scanner import intercept

    seen = _wait_spies(monkeypatch)

    v = intercept.scan_text(
        "clean prose", use_honeypot=False, use_l2=True, l2_max_wait_s=900.0
    )
    assert v.ok
    assert seen == {"lakera": [900.0], "model_armor": [900.0]}

    # Absent means absent: each adapter resolves its own default from the
    # environment, so intercept must not substitute a number of its own.
    intercept.scan_text("clean prose", use_honeypot=False, use_l2=True)
    assert seen == {"lakera": [900.0, None], "model_armor": [900.0, None]}


def test_scan_forwards_l2_max_wait_s_from_the_disk_entry_point(monkeypatch, tmp_path):
    from injection_scanner import intercept

    seen = _wait_spies(monkeypatch)
    report = tmp_path / "report.md"
    report.write_text("# Report\n\nClean prose.\n", encoding="utf-8")

    v = intercept.scan(
        report, use_honeypot=False, use_l2=True, l2_max_wait_s=120.0
    )
    assert v.ok
    assert seen == {"lakera": [120.0], "model_armor": [120.0]}


# ----- L1a-decode fails closed like every other layer (2026-09-06) -----
#
# Every other layer in `scan_text` sits inside a blanket try/except per
# honeypot-manufacturing Invariant 3: an exception inside a layer reduces to
# REJECT, it does not propagate. The L1a-decode block was the one that did not,
# so a raise in `decode.find_encoded_blobs` or in the `secret_shapes.scan` over
# a decoded blob escaped `scan_text` entirely — aborting the scan instead of
# rejecting the report, and breaking `run_smoke`'s contract of raising only
# `SmokeFailure`.
#
# `decode` is already a layer name research-agent's closed vocabulary knows and
# `_unavailable` is the infra head suffix, so `eval._is_infra_reason` and the
# downstream diagnosis classify this exactly as they classify every other
# outage — no new vocabulary crosses the boundary.


def _raise(exc):
    def _boom(*_a, **_k):
        raise exc
    return _boom


def test_a_decode_crash_fails_closed_and_does_not_escape(monkeypatch):
    from injection_scanner import decode, intercept
    monkeypatch.setattr(
        decode, "find_encoded_blobs", _raise(RuntimeError("secret sauce"))
    )
    v = intercept.scan_text("clean text", use_honeypot=False, use_l2=False)
    assert v.ok is False
    assert v.reason == "decode_unavailable:unhandled:RuntimeError"
    assert v.layers["decode"] == "unhandled:RuntimeError"


def test_a_crash_scanning_a_decoded_blob_also_fails_closed(monkeypatch):
    """The second arm of the same block: `secret_shapes.scan(blob.decoded)`.

    Driven with a real base64 blob so `find_encoded_blobs` genuinely produces
    one — a test that stubbed the blobs too would pass even if the loop were
    left outside the guard.
    """
    from injection_scanner import intercept, secret_shapes as ss
    monkeypatch.setattr(ss, "scan", _raise(ValueError("secret sauce")))
    blob = base64.b64encode(b"x" * 90).decode("ascii")
    v = intercept.scan_text(
        f"report body\n\n{blob}\n", use_honeypot=False, use_l2=False
    )
    assert v.ok is False
    assert v.reason == "decode_unavailable:unhandled:ValueError"


def test_the_decode_outage_reason_carries_no_exception_text(monkeypatch):
    """Invariant 4: the type name only, never `str(e)`. An exception raised
    over decoded bytes is the one most likely to embed them."""
    from injection_scanner import decode, intercept
    monkeypatch.setattr(
        decode, "find_encoded_blobs", _raise(RuntimeError("secret sauce"))
    )
    v = intercept.scan_text("clean text", use_honeypot=False, use_l2=False)
    rendered = repr(v) + "|".join([v.reason, *v.layers.values()])
    assert "secret sauce" not in rendered
    assert "secret sauce" not in repr(v.to_audit())


def test_an_ordinary_decode_run_is_unchanged():
    """Control: the guard changes neither the pass path nor the detection.

    `encoded_secret` must still fire — a guard that swallowed the loop would
    turn this into a silent pass, which is the fail-OPEN direction.
    """
    # "Hello, world." is short enough that even the rot13 candidate rule —
    # which speculatively rot13s ordinary prose — finds nothing to try.
    clean = intercept_scan_text("Hello, world.")
    assert clean.ok is True
    assert clean.layers["decode"] == "blobs=0 encodings="

    prose = intercept_scan_text("A short note about the weather today.")
    assert prose.ok is True
    assert prose.layers["decode"] == "blobs=1 encodings=rot13"

    leak = base64.b64encode(
        b"AWS key AKIAIOSFODNN7EXAMPLE for the record"
    ).decode("ascii")
    v = intercept_scan_text(f"see attachment\n\n{leak}\n")
    assert v.ok is False
    assert v.reason.startswith("encoded_secret:base64:")
    assert v.layers["decode"].startswith("blobs=")


def intercept_scan_text(text: str):
    from injection_scanner import intercept
    return intercept.scan_text(text, use_honeypot=False, use_l2=False)
