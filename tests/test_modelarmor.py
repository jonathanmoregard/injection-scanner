"""The Model Armor adapter's contract before its transport exists.

Until the adapter is implemented it must fail CLOSED with a reason that names
the condition: an absent credential is a deployment gap (`no-key`), a present
one is code that cannot use it yet (`not-implemented`). Neither may pass.
"""
from __future__ import annotations

from injection_scanner import modelarmor
from injection_scanner.vendor_http import VendorResult


def test_no_credential_is_no_key(monkeypatch):
    monkeypatch.delenv("MODEL_ARMOR_CREDENTIALS_FILE", raising=False)
    assert modelarmor.check("text") == VendorResult(
        ok=False, reason="model_armor_unavailable:no-key"
    )


def test_an_empty_credential_setting_is_no_key(monkeypatch):
    monkeypatch.setenv("MODEL_ARMOR_CREDENTIALS_FILE", "")
    assert modelarmor.check("text").reason == "model_armor_unavailable:no-key"


def test_a_configured_credential_is_not_implemented_yet(monkeypatch, tmp_path):
    monkeypatch.setenv("MODEL_ARMOR_CREDENTIALS_FILE", str(tmp_path / "creds.json"))
    assert modelarmor.check("text", max_wait_s=5.0) == VendorResult(
        ok=False, reason="model_armor_unavailable:not-implemented"
    )
