"""Tests for the layered intercept shim."""
from __future__ import annotations

import tempfile
from pathlib import Path

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
    v = scan(path, use_honeypot=False, use_lakera=False)
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
    v = scan(path, use_honeypot=False, use_lakera=False)
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
    v = scan(path, use_honeypot=False, use_lakera=False)
    assert not v.ok
    assert "unicode_anomaly" in v.reason


def test_orchestrator_strips_but_passes_single_zw():
    # Single zero-width in a long doc is below threshold; gets stripped,
    # doesn't fail.
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write("clean text " * 500 + "\u200Bcontaminated")
        path = Path(f.name)
    v = scan(path, use_honeypot=False, use_lakera=False)
    assert v.ok
    assert "\u200B" not in v.sanitized_text


# ----- L4 arbitration wiring (lakera flag + honeypot clean -> judge) -----

def _flagged(_text, **_kw):
    from injection_scanner.lakera import LakeraResult
    return LakeraResult(ok=False, flagged=True, reason="lakera:prompt_attack")


def _hp_clean(_text):
    from injection_scanner.honeypot import HoneypotResult
    return HoneypotResult(ok=True, reason="pass")


def test_lakera_flag_honeypot_clean_judge_benign_delivers(monkeypatch):
    from injection_scanner import intercept, judge, lakera
    from injection_scanner.judge import JudgeResult, JudgeVote
    monkeypatch.setattr(lakera, "check", _flagged)
    monkeypatch.setattr(intercept, "honeypot_check", _hp_clean)
    monkeypatch.setattr(judge, "check", lambda _t: JudgeResult(
        ok=True, reason="benign-unanimous",
        votes=[JudgeVote("anthropic_haiku45", "benign", "verdict")],
    ))
    v = intercept.scan_text("prose about agent tooling", use_honeypot=True, use_lakera=True)
    assert v.ok
    assert v.layers["lakera"] == "lakera:prompt_attack"
    assert v.layers["judge"] == "benign-unanimous"


def test_lakera_flag_judge_attack_rejects(monkeypatch):
    from injection_scanner import intercept, judge, lakera
    from injection_scanner.judge import JudgeResult
    monkeypatch.setattr(lakera, "check", _flagged)
    monkeypatch.setattr(intercept, "honeypot_check", _hp_clean)
    monkeypatch.setattr(judge, "check", lambda _t: JudgeResult(
        ok=False, reason="attack:openai_4o_mini"))
    v = intercept.scan_text("x", use_honeypot=True, use_lakera=True)
    assert not v.ok
    assert v.reason == "lakera_arbitration:attack:openai_4o_mini"


def test_lakera_flag_honeypot_triggered_rejects_without_judge(monkeypatch):
    from injection_scanner import intercept, judge, lakera
    from injection_scanner.honeypot import HoneypotResult
    monkeypatch.setattr(lakera, "check", _flagged)
    monkeypatch.setattr(intercept, "honeypot_check", lambda _t: HoneypotResult(
        ok=False, reason="honeypot:scn:trap:x"))
    monkeypatch.setattr(judge, "check", lambda _t: (_ for _ in ()).throw(
        AssertionError("judge must not run when honeypot triggers")))
    v = intercept.scan_text("x", use_honeypot=True, use_lakera=True)
    assert not v.ok
    assert v.reason.startswith("honeypot:")


def test_lakera_outage_hard_rejects_without_judge(monkeypatch):
    from injection_scanner import intercept, judge, lakera
    from injection_scanner.lakera import LakeraResult
    monkeypatch.setattr(lakera, "check", lambda _t, **_kw: LakeraResult(
        ok=False, reason="lakera_unavailable:no-key"))
    monkeypatch.setattr(judge, "check", lambda _t: (_ for _ in ()).throw(
        AssertionError("judge must not run on lakera outage")))
    v = intercept.scan_text("x", use_honeypot=True, use_lakera=True)
    assert not v.ok
    assert v.reason == "lakera_unavailable:no-key"


def test_lakera_flag_without_honeypot_hard_rejects(monkeypatch):
    from injection_scanner import intercept, lakera
    monkeypatch.setattr(lakera, "check", _flagged)
    v = intercept.scan_text("x", use_honeypot=False, use_lakera=True)
    assert not v.ok
    assert v.reason == "lakera:prompt_attack"


def test_lakera_clean_never_calls_judge(monkeypatch):
    from injection_scanner import intercept, judge, lakera
    from injection_scanner.lakera import LakeraResult
    monkeypatch.setattr(
        lakera, "check", lambda _t, **_kw: LakeraResult(ok=True, reason="pass")
    )
    monkeypatch.setattr(intercept, "honeypot_check", _hp_clean)
    monkeypatch.setattr(judge, "check", lambda _t: (_ for _ in ()).throw(
        AssertionError("judge must not run when lakera passes")))
    v = intercept.scan_text("clean text", use_honeypot=True, use_lakera=True)
    assert v.ok
    assert v.reason == "pass"


def test_judge_crash_fails_closed(monkeypatch):
    from injection_scanner import intercept, judge, lakera
    monkeypatch.setattr(lakera, "check", _flagged)
    monkeypatch.setattr(intercept, "honeypot_check", _hp_clean)
    monkeypatch.setattr(judge, "check", lambda _t: (_ for _ in ()).throw(
        RuntimeError("judge infra down")))
    v = intercept.scan_text("x", use_honeypot=True, use_lakera=True)
    assert not v.ok
    assert v.reason == "judge_unavailable:unhandled:RuntimeError"
    assert "infra down" not in v.reason


# ----- the batch wait budget reaches L2 (2026-09-05) -----
#
# `eval` is always a batch caller: it would rather queue behind the fleet's
# budget than be refused. That preference is the caller's, so it travels as a
# keyword from the caller to `lakera.check` and nothing in between interprets
# it.

def test_lakera_max_wait_s_reaches_the_lakera_layer(monkeypatch):
    from injection_scanner import intercept, lakera
    from injection_scanner.lakera import LakeraResult

    seen: list[float | None] = []

    def _spy(text, *, max_wait_s=None):
        seen.append(max_wait_s)
        return LakeraResult(ok=True, reason="pass")

    monkeypatch.setattr(lakera, "check", _spy)

    v = intercept.scan_text(
        "clean prose", use_honeypot=False, use_lakera=True, lakera_max_wait_s=900.0
    )
    assert v.ok
    assert seen == [900.0]

    # Absent means absent: `lakera.check` resolves the default from the
    # environment, so intercept must not substitute a number of its own.
    intercept.scan_text("clean prose", use_honeypot=False, use_lakera=True)
    assert seen == [900.0, None]


def test_scan_forwards_lakera_max_wait_s_from_the_disk_entry_point(monkeypatch, tmp_path):
    from injection_scanner import intercept, lakera
    from injection_scanner.lakera import LakeraResult

    seen: list[float | None] = []

    def _spy(text, *, max_wait_s=None):
        seen.append(max_wait_s)
        return LakeraResult(ok=True, reason="pass")

    monkeypatch.setattr(lakera, "check", _spy)
    report = tmp_path / "report.md"
    report.write_text("# Report\n\nClean prose.\n", encoding="utf-8")

    v = intercept.scan(
        report, use_honeypot=False, use_lakera=True, lakera_max_wait_s=120.0
    )
    assert v.ok
    assert seen == [120.0]
