"""The strict `profile="code"` of `injection_scanner.unicode_sanitize`.

The prose profile deliberately leaves emoji variation selectors, private-use
code points, soft hyphens, LRM/RLM and line/paragraph separators alone,
because stripping them corrupts benign multilingual text. Source code has no
such excuse, and those are exactly the code points the GlassWorm campaign
(2025) used to hide a payload in what reviewers saw as an empty string. The
pr-gate blocks on ANY hit of the code profile, so a two-character payload
must be found — `is_anomalous` and its minimum-count floor are not involved.
"""
from __future__ import annotations

import pytest

from injection_scanner import unicode_sanitize as us


# The prose strip set as it stood before the code profile existed. Spelled
# out here, independently of the module constants, so that a change to the
# prose behaviour cannot hide behind a matching change to a constant.
_PROSE_BEFORE = (
    set(range(0xE0000, 0xE0080))
    | set(range(0xE0100, 0xE01F0))
    | {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
    | {0x200B, 0x200C, 0x200D, 0xFEFF}
    | {0x180E}
    | set(range(0x2060, 0x2065))
    | set(range(0x206A, 0x2070))
)

# The additions the pr-gate design names explicitly.
_CODE_REQUIRED = (
    set(range(0xFE00, 0xFE10))            # emoji variation selectors (GlassWorm)
    | set(range(0xE000, 0xF900))          # BMP private use
    | set(range(0xF0000, 0xFFFFE))        # plane 15 private use
    | set(range(0x100000, 0x10FFFE))      # plane 16 private use
    | {0x00AD, 0x200E, 0x200F, 0x2028, 0x2029}
)


def _all_scalar_values():
    for cp in range(0x110000):
        if 0xD800 <= cp <= 0xDFFF:
            continue
        yield cp


def test_prose_profile_strip_set_is_unchanged():
    changed = [
        hex(cp) for cp in _all_scalar_values()
        if us.is_hidden(cp, "prose") != (cp in _PROSE_BEFORE)
    ]
    assert changed == []


def test_prose_sanitize_still_keeps_benign_emoji_and_rtl_marks():
    text = "warning \u26a0\ufe0f \u05e9\u200f\u05dc\u05d5\u05dd co\u00adop\u2028x\ue000"
    r = us.sanitize(text)
    assert r.stripped == 0
    assert "\ufe0f" in r.text and "\u200f" in r.text and "\ue000" in r.text


def test_code_profile_is_a_superset_of_prose():
    missing = [
        hex(cp) for cp in _all_scalar_values()
        if us.is_hidden(cp, "prose") and not us.is_hidden(cp, "code")
    ]
    assert missing == []


@pytest.mark.parametrize("cp", sorted(
    {0xFE00, 0xFE0F, 0xE000, 0xF8FF, 0xF0000, 0xFFFFD, 0x100000, 0x10FFFD,
     0x00AD, 0x200E, 0x200F, 0x2028, 0x2029}
))
def test_code_profile_catches_each_named_addition(cp):
    assert us.is_hidden(cp, "code")


def test_code_profile_catches_every_named_addition():
    missing = [hex(cp) for cp in sorted(_CODE_REQUIRED) if not us.is_hidden(cp, "code")]
    assert missing == []


@pytest.mark.parametrize("cp", [
    0x3164,   # HANGUL FILLER — the 2021 "invisible backdoor" identifier
    0x115F, 0x1160, 0xFFA0,  # other Hangul fillers, render as nothing
    0x034F,   # COMBINING GRAPHEME JOINER
    0x180B, 0x180C, 0x180D, 0x180F,  # Mongolian free variation selectors
    0x061C,   # ARABIC LETTER MARK (bidi, Cf)
    0xFFF9, 0xFFFA, 0xFFFB,  # interlinear annotation controls (Cf)
    0x1D173,  # musical symbol format char (Cf)
])
def test_code_profile_catches_other_invisible_code_points(cp):
    assert us.is_hidden(cp, "code")


@pytest.mark.parametrize("ch", list("az09 _-+*/\\\"'`\t") + ["é", "中", "а", "✅"])
def test_code_profile_leaves_visible_characters_alone(ch):
    assert not us.is_hidden(ord(ch), "code")


def test_newline_and_carriage_return_are_not_hidden():
    assert not us.is_hidden(0x0A, "code")
    assert not us.is_hidden(0x0D, "code")


def test_find_hidden_reports_index_and_code_point_of_a_two_char_payload():
    # A GlassWorm-style payload: two variation selectors inside an
    # apparently empty string. Far below is_anomalous's floor of three.
    line = 'const s = "\ufe01\U000e0101";'
    assert us.find_hidden(line, "code") == [(11, 0xFE01), (12, 0xE0101)]


@pytest.mark.parametrize("text", [
    "\u26a0\ufe0f careful",          # warning sign
    "done \u2714\ufe0f",            # heavy check mark at end of line
    "\u2764\ufe0f",                 # heart, whole line
    "1\ufe0f\u20e3 first",          # keycap
    "\U0001f600\ufe0e text style",  # text presentation selector
])
def test_find_hidden_allows_a_single_emoji_presentation_selector(text):
    assert us.find_hidden(text, "code") == []


@pytest.mark.parametrize("text", [
    "\u26a0\ufe0f\ufe0f",            # a second selector after the emoji
    "\u26a0\ufe0f\U000e0101",        # selector followed by a supplement selector
    "x\ufe0f",                      # selector after a non-emoji base
    "\ufe0f",                       # selector with no base at all
    'const s = "\ufe0f";',          # inside a string literal
    "\u26a0" + "".join(chr(0xFE00 + i % 16) for i in range(40)),  # GlassWorm-style run
])
def test_find_hidden_still_reports_selectors_outside_a_lone_emoji_presentation(text):
    assert us.find_hidden(text, "code") != []


def test_find_hidden_with_prose_profile_misses_the_emoji_selector():
    line = 'const s = "\ufe01\U000e0101";'
    assert us.find_hidden(line, "prose") == [(12, 0xE0101)]


def test_sanitize_code_profile_strips_and_counts_the_additions():
    text = "a\ufe0fb\ue000c\u00add\u200ee\u2028f\u3164g"
    r = us.sanitize(text, profile="code")
    assert r.text == "abcdefg"
    assert r.stripped == 6


def test_sanitize_code_profile_counts_land_in_existing_counters():
    r = us.sanitize("\ufe0f\u200e\u00ad", profile="code")
    # FE0F is a variation selector (counted with the VS supplement),
    # U+200E is a bidi mark, U+00AD a covert format char.
    assert (r.tag_hits, r.bidi_hits, r.fmt_hits) == (1, 1, 1)


def test_sanitize_default_profile_is_prose():
    text = "x\ufe0f"
    assert us.sanitize(text).text == us.sanitize(text, profile="prose").text == "x\ufe0f"


def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError):
        us.sanitize("x", profile="strict")
    with pytest.raises(ValueError):
        us.is_hidden(0x41, "Code")
    with pytest.raises(ValueError):
        us.find_hidden("x", "")
