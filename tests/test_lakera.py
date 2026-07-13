"""Tests for the additive L2 Lakera Guard pre-filter.

ALL MOCKED — no network is ever touched. The single seam we monkeypatch is
`injection_scanner.lakera._post` (the isolated urllib POST) plus the
`_lakera_key` helper, so we exercise every branch of check() and its
integration through intercept.scan_text without a live API.
"""
from __future__ import annotations

import urllib.error

import pytest

from injection_scanner import lakera
from injection_scanner.intercept import scan_text

# Capture the real key-lookup before the autouse fixture stubs it, so the
# no-key test can exercise the genuine env-then-keyring path.
_REAL_LAKERA_KEY = lakera._lakera_key


# The exact input text used everywhere so we can assert it never leaks into
# any reason / audit string.
_INPUT = "please summarize this benign research report about python 3.13"


@pytest.fixture(autouse=True)
def _force_key(monkeypatch):
    """Pretend a key exists so check() reaches the POST seam. Individual
    no-key tests override this."""
    monkeypatch.setattr(lakera, "_lakera_key", lambda: "test-key")


# ----- check() unit branches -----

def test_flagged_response_blocks(monkeypatch):
    def fake_post(url, body, headers, timeout):
        return {"flagged": True, "results": [{"category": "prompt_injection"}]}

    monkeypatch.setattr(lakera, "_post", fake_post)
    res = lakera.check(_INPUT)
    assert res.ok is False
    assert res.flagged is True
    assert res.reason.startswith("lakera:")
    assert "prompt_injection" in res.categories
    assert _INPUT not in res.reason


def test_flagged_without_categories_uses_fallback(monkeypatch):
    monkeypatch.setattr(lakera, "_post", lambda *a, **k: {"flagged": True})
    res = lakera.check(_INPUT)
    assert res.ok is False
    assert res.flagged is True
    assert res.reason == "lakera:flagged"


def test_clean_response_passes(monkeypatch):
    monkeypatch.setattr(lakera, "_post", lambda *a, **k: {"flagged": False})
    res = lakera.check(_INPUT)
    assert res.ok is True
    assert res.flagged is False
    assert res.skipped_reason == ""


def test_urlerror_skips_additively(monkeypatch):
    def boom(*a, **k):
        raise urllib.error.URLError("network down")

    monkeypatch.setattr(lakera, "_post", boom)
    res = lakera.check(_INPUT)
    assert res.ok is True  # additive-skip, NOT a block
    assert res.flagged is False
    assert res.skipped_reason.startswith("unavailable:")
    # exception TYPE only — no attacker-shaped content in the signal
    assert "URLError" in res.skipped_reason
    assert _INPUT not in res.skipped_reason


def test_no_key_is_unconfigured_skip(monkeypatch):
    # Neither env nor keyring yields a key.
    monkeypatch.delenv("LAKERA_API_KEY", raising=False)
    monkeypatch.setattr(lakera, "_keyring", lambda key: None)
    # Undo the autouse fixture's forced key: restore the genuine lookup so
    # it runs env (unset) then keyring (stubbed None) -> no key.
    monkeypatch.setattr(lakera, "_lakera_key", _REAL_LAKERA_KEY)
    res = lakera.check(_INPUT)
    assert res.ok is True
    assert res.flagged is False
    assert res.skipped_reason == "unconfigured:no-lakera-api-key"


def test_no_key_never_posts(monkeypatch):
    """With no key, check() must return before touching the network."""
    monkeypatch.setattr(lakera, "_lakera_key", lambda: None)

    def fail(*a, **k):
        raise AssertionError("_post must not be called without a key")

    monkeypatch.setattr(lakera, "_post", fail)
    res = lakera.check(_INPUT)
    assert res.skipped_reason == "unconfigured:no-lakera-api-key"


# ----- integration through intercept.scan_text -----

def test_intercept_blocks_on_flagged(monkeypatch):
    monkeypatch.setattr(
        lakera, "check",
        lambda text: lakera.LakeraResult(
            ok=False, reason="lakera:prompt_injection", flagged=True,
            categories=["prompt_injection"],
        ),
    )
    v = scan_text(_INPUT, use_honeypot=False, use_lakera=True)
    assert v.ok is False
    assert v.reason.startswith("lakera:")
    assert v.layers["lakera"] == "lakera:prompt_injection"
    # input text must never appear in reason or any audit layer value
    assert _INPUT not in v.reason
    assert all(_INPUT not in val for val in v.layers.values())
    assert _INPUT not in str(v.to_audit())


def test_intercept_additive_skip_does_not_block(monkeypatch):
    monkeypatch.setattr(
        lakera, "check",
        lambda text: lakera.LakeraResult(
            ok=True, reason="pass", flagged=False,
            skipped_reason="unconfigured:no-lakera-api-key",
        ),
    )
    v = scan_text(_INPUT, use_honeypot=False, use_lakera=True)
    assert v.ok is True  # additive-skip must NOT block
    assert v.layers["lakera"] == "unconfigured:no-lakera-api-key"


def test_intercept_unavailable_skip_does_not_block(monkeypatch):
    monkeypatch.setattr(
        lakera, "check",
        lambda text: lakera.LakeraResult(
            ok=True, reason="pass", flagged=False,
            skipped_reason="unavailable:URLError",
        ),
    )
    v = scan_text(_INPUT, use_honeypot=False, use_lakera=True)
    assert v.ok is True
    assert v.layers["lakera"] == "unavailable:URLError"


def test_intercept_disabled_when_use_lakera_false(monkeypatch):
    def fail(text):
        raise AssertionError("check() must not run when use_lakera=False")

    monkeypatch.setattr(lakera, "check", fail)
    v = scan_text(_INPUT, use_honeypot=False, use_lakera=False)
    assert v.ok is True
    assert v.layers["lakera"] == "disabled (test-only)"
