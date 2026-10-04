"""Regression tests from the research-agent security review, 2026-10-03.

1. The encoded-secret pass looked at only the first 200,000 characters and
   stopped after 50 blobs, while research-agent delivers reports up to
   512 KiB. Fifty harmless base64 strings (or 200k characters of filler) in
   front of an encoded key hid it from the secret-shape rescan.
2. The secret-shape rules had no entry for the eBay, Tradera and EUIPO
   credentials that research-agent ships into its agent VM, and eBay's
   OAuth token alphabet (`v^1.1#i^1#...`) defeated the generic bearer rule.

All values below are FAKE canaries built at test time.
"""
from __future__ import annotations

import base64
import random
import string

import pytest

from injection_scanner import decode, secret_shapes

_rng = random.Random(20261003)


def _fake(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(_rng.choice(alphabet) for _ in range(n))


FAKE_OAT = "sk-ant-oat01-" + _fake(60)


def _caught(text: str) -> bool:
    return any(secret_shapes.scan(b.decoded) for b in decode.find_encoded_blobs(text))


def test_encoded_key_alone_is_caught():
    assert _caught("see " + base64.b64encode(FAKE_OAT.encode()).decode())


def test_encoded_key_after_many_benign_blobs_is_caught():
    benign = " ".join(
        base64.b64encode(f"benign paragraph {i} about kettle prices".encode()).decode()
        for i in range(60)
    )
    assert _caught(benign + " " + base64.b64encode(FAKE_OAT.encode()).decode())


def test_blob_cap_cannot_be_exhausted_inside_a_max_size_report():
    # Refuter (Codex) bypass of the first fix: exactly MAX_BLOBS harmless
    # blobs (~150 KiB) in front of the key still fit in a 512 KiB report.
    benign = " ".join(
        base64.b64encode(f"benign paragraph {i:05d}".encode()).decode()
        for i in range(6000)
    )
    assert len(benign) < 512 * 1024
    assert _caught(benign + " " + base64.b64encode(FAKE_OAT.encode()).decode())


def test_encoded_key_late_in_a_max_size_report_is_caught():
    filler = "x " * 200_001  # ~400k chars, inside research-agent's 512 KiB cap
    assert _caught(filler + base64.b64encode(FAKE_OAT.encode()).decode())


@pytest.mark.parametrize("text", [
    "EBAY_CLIENT_SECRET=PRD-" + _fake(24),
    "TRADERA_APP_KEY=" + "-".join(_fake(n, "0123456789abcdef") for n in (8, 4, 4, 4, 12)),
    "EUIPO_CLIENT_SECRET=" + _fake(32),
    "LAKERA_API_KEY=" + _fake(40),
    "Authorization: Bearer v^1.1#i^1#r^0#p^3#I^3#f^0#t^" + _fake(80, string.ascii_letters + string.digits + "+/="),
])
def test_deployed_provider_credentials_are_caught(text):
    assert secret_shapes.scan(text), text


@pytest.mark.parametrize("text", [
    # Client/app IDs are public identifiers, and setup docs quote them with
    # placeholders. Flagging them would quarantine ordinary API how-tos.
    "EBAY_CLIENT_ID=your-ebay-client-id-here",
    "EUIPO_CLIENT_ID=your-euipo-client-id-here",
    "TRADERA_APP_ID=your-tradera-app-id-here",
])
def test_public_identifiers_are_not_flagged(text):
    assert not secret_shapes.scan(text), text
