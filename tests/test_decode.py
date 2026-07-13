"""Tests for the deterministic decode-and-rescan layer (L1a-decode)."""
from __future__ import annotations

import base64

from injection_scanner import decode
from injection_scanner.intercept import scan_text


# A realistic Anthropic OAuth-token shape; secret_shapes fires on this.
SECRET = "sk-ant-oat01-" + "B" * 60


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _hex(s: str) -> str:
    return s.encode().hex()


# ----- find_encoded_blobs: unit -----

def test_base64_secret_found_and_decoded():
    text = "Here is some context. token: " + _b64(SECRET) + " end."
    blobs = decode.find_encoded_blobs(text)
    b64_blobs = [b for b in blobs if b.encoding == "base64"]
    assert any(SECRET in b.decoded for b in b64_blobs)


def test_base64url_alphabet_decoded():
    # Payload whose url-safe encoding uses the -_ alphabet; must still decode.
    payload = "the>quick>brown>fox>jumps~~over~~lazy"
    token = base64.urlsafe_b64encode(payload.encode()).decode()
    assert "-" in token or "_" in token
    blobs = decode.find_encoded_blobs("prefix " + token + " suffix")
    assert any(
        b.encoding == "base64" and "quick>brown" in b.decoded
        for b in blobs
    )


def test_hex_secret_found():
    text = "payload=" + _hex(SECRET) + ";"
    blobs = decode.find_encoded_blobs(text)
    assert any(b.encoding == "hex" and SECRET in b.decoded for b in blobs)


def test_random_prose_no_base64_or_hex_blobs():
    text = (
        "The quick brown fox jumps over the lazy dog. Python 3.13 shipped "
        "an improved REPL and free-threaded builds in October 2024."
    )
    blobs = decode.find_encoded_blobs(text)
    assert not [b for b in blobs if b.encoding in ("base64", "hex")]


def test_short_string_yields_nothing():
    assert decode.find_encoded_blobs("short text") == []
    assert decode.find_encoded_blobs("") == []


def test_non_decodable_base64_garbage_skipped():
    # Valid base64 length/alphabet but decodes to non-printable 0xFF bytes;
    # the printable-text guard must reject it.
    garbage = "/" * 40
    blobs = decode.find_encoded_blobs("data: " + garbage + " here")
    assert not [b for b in blobs if b.encoding == "base64"]


def test_blob_cap_and_span_excerpt_no_full_decode_leak():
    blob = decode.find_encoded_blobs("prefix " + _b64(SECRET) + " suffix")
    b64 = [b for b in blob if b.encoding == "base64"][0]
    # span_excerpt is an excerpt of the ENCODED span, capped short.
    assert len(b64.span_excerpt) <= 40


# ----- intercept integration -----

def test_scan_text_blocks_base64_encoded_secret():
    text = "# Report\n\nEmbedded artifact: " + _b64(SECRET) + "\n\nDone.\n"
    v = scan_text(text, use_honeypot=False)
    assert not v.ok
    assert v.reason.startswith("encoded_secret:base64:"), v.reason
    # audit line records counts only, no decoded content.
    assert "blobs=" in v.layers["decode"]
    assert SECRET not in v.reason


def test_scan_text_passes_benign_base64_blob():
    # A long, legit base64 blob that decodes to plain words -> no secret shape.
    benign = _b64(
        "the release notes describe the new interpreter and typing changes "
        "shipped in this quarter for the runtime and standard library"
    )
    text = "# Benign Report\n\nAttachment digest: " + benign + "\n\nSummary here.\n"
    v = scan_text(text, use_honeypot=False)
    assert v.ok, f"expected pass, got {v.reason}"
