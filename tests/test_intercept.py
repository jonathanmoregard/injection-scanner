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
