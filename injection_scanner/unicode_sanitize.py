"""
Layer 0: Unicode normalization + covert-channel stripping.

Based on the convergent recommendation from Boucher et al. ("Bad Characters",
IEEE S&P 2022), Unicode Technical Standard #39 (confusables), Trojan Source
(Boucher & Anderson 2021), and Rehberger's ASCII-smuggler catalogue.

The variation-selector channel (Variation Selectors Supplement,
U+E0100..U+E01EF) is a byte-smuggling vector popularized by Paul Butler's
"Smuggling arbitrary data through an emoji" (2024) and demonstrated by
Riley Goodside for hidden LLM instructions: a payload is encoded as a run
of variation selectors with no visible glyph. These have no benign text
use and are stripped here. Note the emoji variation selectors U+FE00..U+FE0F
(e.g. U+FE0F in "warning" and "heart" emoji) are deliberately NOT stripped —
they have common benign use and removing them corrupts legitimate emoji.

Goals:
  - Remove invisible channels that can carry hidden instructions or exfil
    payloads: tag block (U+E0000..U+E007F), variation-selector supplement
    (U+E0100..U+E01EF), zero-width marks, bidi overrides, and a small set of
    deprecated/covert format characters (word joiner, invisible math
    operators, Mongolian vowel separator, deprecated format controls).
  - NFKC-normalize so homoglyph lookalikes collapse before other scanners run.
  - Flag anomalies (density of suspicious code points) — caller can escalate
    to quarantine if density is above a threshold, even though the text has
    been stripped.

This is NOT a verdict layer on its own; it cleans input and emits a stats
dict the orchestrator can use.

Profiles:
  - "prose" (default): the set above. Tuned for research reports, where
    emoji selectors, RTL marks, soft hyphens and private-use glyphs occur
    in benign text.
  - "code": strict, for source diffs (used by the pr-gate). Adds everything
    the prose profile spares for benign-text reasons: emoji variation
    selectors U+FE00..U+FE0F (the GlassWorm vector), all private-use code
    points (BMP and planes 15/16), U+00AD, U+200E/U+200F, U+2028/U+2029,
    every other format character (category Cf), and the code points that
    render as nothing (Hangul fillers, combining grapheme joiner, Mongolian
    free variation selectors). Source code has no legitimate need for any
    of them that an escape sequence cannot serve.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass

# Unicode ranges / points to strip entirely. Anything in these groups is
# overwhelmingly abusive (near-zero benign prevalence in research reports).
TAG_BLOCK = (0xE0000, 0xE007F)            # Rehberger ASCII smuggler
VARIATION_SELECTORS_SUPPLEMENT = (0xE0100, 0xE01EF)  # Butler/Goodside smuggler
BIDI_OVERRIDES = (
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2066, 0x2067, 0x2068, 0x2069,
)                                         # Trojan Source
ZERO_WIDTH = (0x200B, 0x200C, 0x200D, 0xFEFF)   # Bad Characters

# Discrete covert/deprecated format code points with near-zero benign
# prevalence. Stripped and counted as `fmt_hits`. Deliberately EXCLUDES
# U+FE00..U+FE0F (emoji variation selectors — U+FE0F appears in "warning"/
# "heart" emoji), U+200E/U+200F (LRM/RLM, legitimate in Arabic/Hebrew RTL
# text), and U+00AD (SOFT HYPHEN, legitimate hyphenation) — stripping any of
# those would cause false positives on benign multilingual/emoji content.
FMT_COVERT = frozenset(
    {0x180E}                              # MONGOLIAN VOWEL SEPARATOR (deprecated)
    | set(range(0x2060, 0x2065))          # WORD JOINER + invisible math operators
    | set(range(0x206A, 0x2070))          # deprecated format chars U+206A..U+206F
)

# Whitespace-in-weird-places: NBSP + line/paragraph separators often used
# to desynchronize tokenizers but not always malicious. We strip only the
# zero-width variants; NBSP is left alone.

# Code-profile additions, beyond everything the prose profile strips.
# Emoji variation selectors U+FE00..U+FE0F are the GlassWorm (2025) vector:
# a run of them inside a string literal decodes to a payload while the
# reviewer sees an empty string.
EMOJI_VARIATION_SELECTORS = (0xFE00, 0xFE0F)
PRIVATE_USE = ((0xE000, 0xF8FF), (0xF0000, 0xFFFFD), (0x100000, 0x10FFFD))
CODE_BIDI_MARKS = frozenset({0x200E, 0x200F, 0x061C})  # LRM, RLM, ALM
# Code points that are not category Cf but still render as nothing.
CODE_INVISIBLE = frozenset(
    {0x00AD, 0x2028, 0x2029, 0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0}
    | set(range(0x180B, 0x1810))          # Mongolian free variation selectors
)

PROFILES = ("prose", "code")

# Confusable slashes that NFKC does NOT fold to ASCII `/`. Without
# explicit translation, a tag like `<∕system-reminder>` (U+2215 DIVISION
# SLASH) passes every regex that expects ASCII `/` — defeating the
# wrap_escape defense. NFKC normalizes U+FF0F FULLWIDTH SOLIDUS already,
# so this table only covers the cases NFKC misses.
CONFUSABLE_SLASH_MAP = str.maketrans({
    "⁄": "/",  # FRACTION SLASH
    "∕": "/",  # DIVISION SLASH
})


@dataclass
class SanitizeResult:
    text: str           # cleaned text
    stripped: int       # count of code points removed
    bidi_hits: int
    tag_hits: int       # tag block + variation-selector supplement
    zw_hits: int
    fmt_hits: int       # discrete covert/deprecated format chars (FMT_COVERT)
    nfkc_changed: bool  # NFKC normalization changed text


def _in_tag_block(cp: int) -> bool:
    return TAG_BLOCK[0] <= cp <= TAG_BLOCK[1]


def _in_variation_selectors_supplement(cp: int) -> bool:
    return (
        VARIATION_SELECTORS_SUPPLEMENT[0]
        <= cp
        <= VARIATION_SELECTORS_SUPPLEMENT[1]
    )


def _check_profile(profile: str) -> None:
    if profile not in PROFILES:
        raise ValueError(f"unknown unicode_sanitize profile: {profile!r}")


def _classify(cp: int, code: bool) -> str | None:
    """Counter a hidden code point belongs to, or None if it is kept."""
    if _in_tag_block(cp) or _in_variation_selectors_supplement(cp):
        return "tag"
    if cp in BIDI_OVERRIDES:
        return "bidi"
    if cp in ZERO_WIDTH:
        return "zw"
    if cp in FMT_COVERT:
        return "fmt"
    if not code:
        return None
    if EMOJI_VARIATION_SELECTORS[0] <= cp <= EMOJI_VARIATION_SELECTORS[1]:
        return "tag"
    if cp in CODE_BIDI_MARKS:
        return "bidi"
    if cp in CODE_INVISIBLE or any(lo <= cp <= hi for lo, hi in PRIVATE_USE):
        return "fmt"
    if unicodedata.category(chr(cp)) == "Cf":
        return "fmt"
    return None


def is_hidden(cp: int, profile: str = "prose") -> bool:
    """True if `cp` is a covert/invisible code point under `profile`."""
    _check_profile(profile)
    return _classify(cp, profile == "code") is not None


def find_hidden(text: str, profile: str = "code") -> list[tuple[int, int]]:
    """(index, code point) of every hidden code point in `text`.

    For callers that must BLOCK on any hit (the pr-gate) rather than strip:
    no density test and no minimum count, so a two-character payload is
    reported.
    """
    _check_profile(profile)
    code = profile == "code"
    return [
        (i, ord(ch)) for i, ch in enumerate(text)
        if _classify(ord(ch), code) is not None
    ]


def sanitize(text: str, profile: str = "prose") -> SanitizeResult:
    _check_profile(profile)
    code = profile == "code"
    counts = {"bidi": 0, "tag": 0, "zw": 0, "fmt": 0}
    buf: list[str] = []
    for ch in text:
        kind = _classify(ord(ch), code)
        if kind is not None:
            counts[kind] += 1
            continue
        buf.append(ch)
    bidi, tag, zw, fmt = counts["bidi"], counts["tag"], counts["zw"], counts["fmt"]
    raw_clean = "".join(buf)
    nfkc = unicodedata.normalize("NFKC", raw_clean)
    # Fold confusable slashes that NFKC missed so downstream regex layers
    # don't have to carry parallel Unicode alternates.
    folded = nfkc.translate(CONFUSABLE_SLASH_MAP)
    return SanitizeResult(
        text=folded,
        stripped=bidi + tag + zw + fmt,
        bidi_hits=bidi,
        tag_hits=tag,
        zw_hits=zw,
        fmt_hits=fmt,
        nfkc_changed=(folded != raw_clean),
    )


# Density threshold: if more than this fraction of characters had to be
# stripped, the document is almost certainly hostile even post-sanitize
# (strip still happened, but pattern implies an adversary).
ANOMALY_DENSITY = 0.001  # 0.1%

# Absolute floor on stripped count before density can escalate to quarantine.
# A pure ratio test false-positives on SHORT docs: a single stray zero-width
# in a 200-char report is 0.5% > 0.1% and would be wrongly quarantined. This
# floor is SAFE because covert chars are STRIPPED regardless of this flag —
# the flag only governs escalation-to-quarantine, never whether the covert
# channel survives. So a floor can never let a hidden channel through; it only
# avoids over-escalating on incidental single-character noise.
ANOMALY_MIN_STRIPPED = 3


def is_anomalous(r: SanitizeResult, original_length: int) -> bool:
    if original_length == 0:
        return False
    if r.stripped < ANOMALY_MIN_STRIPPED:
        return False
    return (r.stripped / original_length) > ANOMALY_DENSITY
