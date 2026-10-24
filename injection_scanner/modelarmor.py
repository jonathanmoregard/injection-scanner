"""
Layer 2 adapter: Google Cloud Model Armor, FAIL-CLOSED.

One member of the L2 panel (`injection_scanner.l2`). The transport is not
implemented yet, so every call is unavailable with a reason naming why:

  * `model_armor_unavailable:no-key`          — `MODEL_ARMOR_CREDENTIALS_FILE`
                                                unset or empty
  * `model_armor_unavailable:not-implemented` — a credential is configured,
                                                but this adapter cannot use it

The signature is the panel contract every adapter shares.
"""
from __future__ import annotations

import os

from injection_scanner import vendor_http
from injection_scanner.vendor_http import VendorResult

VENDOR = "model_armor"

ENV_CREDENTIALS_FILE = "MODEL_ARMOR_CREDENTIALS_FILE"


def check(text: str, *, max_wait_s: float | None = None) -> VendorResult:
    """Classify `text` with Model Armor. Never passes until implemented."""
    if not os.environ.get(ENV_CREDENTIALS_FILE):
        return vendor_http.unavailable(VENDOR, "no-key")
    return vendor_http.unavailable(VENDOR, "not-implemented")
