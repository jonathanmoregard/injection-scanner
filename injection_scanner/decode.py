"""
Layer 1a-decode: deterministic decode-and-rescan support.

Encoded payloads (base64 / hex / rot13) sail through L0 unicode_sanitize
and L1b secret_shapes untouched, because nothing decodes them. An attacker
can encode a credential (or an injection) so the deterministic layers see
only opaque text, while a downstream frontier model happily decodes and
acts on it.

This module ONLY decodes. It finds candidate encoded blobs, applies strict
false-positive guards, and hands the decoded text back to the orchestrator,
which reruns the secret-shape scan on it. No secret logic lives here.

Design constraints:
  - DETERMINISTIC. No model calls, no network, no randomness.
  - LOW FALSE-POSITIVE. Every decoder has guards (length, alphabet, padding,
    printable-text ratio) so random prose does not produce spurious blobs.
  - LINEAR / ReDoS-safe. The base64/hex regexes are single bounded character
    classes with a greedy quantifier over one disjoint class each — no nested
    quantifiers, no backtracking blow-up.
  - BOUNDED COST. We inspect only a prefix of the input and cap the number of
    blobs returned, so a pathological input cannot force unbounded work.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
from dataclasses import dataclass

# Only inspect the first ~200 KB; encoded exfil that matters shows up early
# and this bounds worst-case decode cost on pathological inputs.
MAX_SCAN_LEN = 200_000

# Never return more than this many blobs; caps total downstream rescan work.
MAX_BLOBS = 50

# Minimum decoded length worth rescanning. Shorter decodes cannot hold any
# secret shape and only add noise.
MIN_DECODED_LEN = 12

# Minimum input length before any decoding is attempted. Below this there is
# no room for an encoded secret (a base64/hex-wrapped credential is far
# longer), so we skip all decoders including the otherwise-total rot13 pass.
MIN_INPUT_LEN = 16

# Fraction of decoded characters that must be printable text for the blob to
# be considered "really text" rather than binary noise that merely happened
# to base64/hex-decode.
PRINTABLE_RATIO = 0.90

# base64 / base64url: a run of alphabet chars (standard + url-safe) with
# optional `=` padding. Single bounded character class -> linear, ReDoS-safe.
_B64_RE = re.compile(r"[A-Za-z0-9+/_\-]{24,}={0,2}")

# hex: an even run of hex digits, >=32 chars. Single character class -> linear.
_HEX_RE = re.compile(r"[0-9a-fA-F]{32,}")


@dataclass
class DecodedBlob:
    encoding: str        # "base64" | "hex" | "rot13"
    decoded: str         # decoded text (kept in-process only; never audited)
    span_excerpt: str    # short excerpt of the ENCODED source span (no secret)


def _printable_text(data: bytes) -> str | None:
    """Return decoded text if `data` is >=PRINTABLE_RATIO printable UTF-8
    text, else None. Guards against binary blobs that merely decode.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    printable = sum(1 for c in text if c.isprintable() or c in "\t\n\r ")
    if printable / len(text) < PRINTABLE_RATIO:
        return None
    return text


def _try_base64(token: str) -> str | None:
    """Decode a base64/base64url candidate, or None if any FP guard trips."""
    # Normalize url-safe alphabet to standard before decoding.
    core = token.rstrip("=").replace("-", "+").replace("_", "/")
    # 4k+1 is never a valid base64 length; reject rather than mis-pad.
    if len(core) % 4 == 1:
        return None
    padded = core + "=" * ((-len(core)) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < MIN_DECODED_LEN:
        return None
    return _printable_text(raw)


def _try_hex(token: str) -> str | None:
    """Decode a hex candidate, or None if any FP guard trips."""
    if len(token) % 2 != 0:
        return None
    try:
        raw = bytes.fromhex(token)
    except ValueError:
        return None
    if len(raw) < MIN_DECODED_LEN:
        return None
    return _printable_text(raw)


def find_encoded_blobs(text: str) -> list[DecodedBlob]:
    """Find and decode base64 / hex / rot13 blobs in `text`.

    Returns a list of DecodedBlob (possibly empty). Only decoders whose FP
    guards pass are included. rot13 is applied once to the whole (capped)
    input as a single blob, since it is total and cheap.
    """
    if not text:
        return []

    scan = text[:MAX_SCAN_LEN]
    if len(scan) < MIN_INPUT_LEN:
        return []
    blobs: list[DecodedBlob] = []

    # base64 / base64url.
    for m in _B64_RE.finditer(scan):
        if len(blobs) >= MAX_BLOBS:
            return blobs
        decoded = _try_base64(m.group(0))
        if decoded is not None:
            blobs.append(
                DecodedBlob(
                    encoding="base64",
                    decoded=decoded,
                    span_excerpt=m.group(0)[:40],
                )
            )

    # hex.
    for m in _HEX_RE.finditer(scan):
        if len(blobs) >= MAX_BLOBS:
            return blobs
        if len(m.group(0)) % 2 != 0:
            continue
        decoded = _try_hex(m.group(0))
        if decoded is not None:
            blobs.append(
                DecodedBlob(
                    encoding="hex",
                    decoded=decoded,
                    span_excerpt=m.group(0)[:40],
                )
            )

    # rot13: total, cheap; apply once to the whole capped input.
    if len(blobs) < MAX_BLOBS:
        rot = codecs.decode(scan, "rot_13")
        blobs.append(
            DecodedBlob(
                encoding="rot13",
                decoded=rot,
                span_excerpt=scan[:40],
            )
        )

    return blobs
