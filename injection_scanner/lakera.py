"""
Layer 2: hosted Lakera Guard classifier — a FAIL-CLOSED gate.

Lakera Guard (https://api.lakera.ai) is a hosted prompt-injection / jailbreak
classifier. This layer sits between L1b (secret_shapes) and L3 (honeypot) and
is wired as a GATE, not an additive skip.

Design principle (from the maintainer): **all config issues must lead to loud
REJECTION — fail-CLOSED, exactly like the honeypot.** This is the OPPOSITE of
an earlier additive design where a missing key silently degraded to "pass".
Here, ANYTHING that prevents us from getting a clean classification — no key,
a botched `*_FILE` mount, a network error, an HTTP error, a malformed JSON
response — collapses to `ok=False` and the report is quarantined. Silent
degradation of a detection layer is the exact failure mode operators must hear
about, so an outage rejects real reports until the layer is back.

Key resolution goes through injection_scanner.keyloader with FILE > env >
keyring precedence (the FILE tier is the agenix pattern). A configured-but-
broken FILE path raises KeyConfigError, which we catch into a fail-closed
reject rather than crashing the scan.

Invariant (honeypot-manufacturing Invariant 4 — "the caught bytes never
return"): the `reason` and `categories` strings carry ONLY detector /
category labels and exception TYPE names — never any fragment of the scanned
input, and never a stringified exception (some HTTP/JSON errors embed the
request/response body, which is itself the attacker-shaped bytes we sent).

No new dependency: the POST is issued with stdlib urllib.request, isolated in
`_post` so tests can monkeypatch it and never touch the network.
"""
from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass, field

from injection_scanner.keyloader import KeyConfigError, load_key

_DEFAULT_URL = "https://api.lakera.ai/v2/guard"
_DEFAULT_TIMEOUT_S = 10.0


@dataclass
class LakeraResult:
    ok: bool
    reason: str
    flagged: bool = False
    categories: list[str] = field(default_factory=list)


def _post(url: str, body: bytes, headers: dict, timeout: float) -> dict:
    """Isolated stdlib POST -> parsed JSON dict.

    Kept as a thin, monkeypatchable seam so the unit tests can inject
    responses (or raise) without any network access. Raises on network /
    HTTP / decode errors; the caller's blanket except turns those into a
    fail-closed reject.
    """
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    return json.loads(raw.decode("utf-8"))


def _lakera_key() -> str | None:
    return load_key(
        file_env="LAKERA_API_KEY_FILE",
        env_var="LAKERA_API_KEY",
        keyring_key="lakera-api-key",
    )


def check(text: str) -> LakeraResult:
    """Classify `text` with Lakera Guard. FAIL-CLOSED at every step.

    Outcomes (all non-pass outcomes REJECT — the caller treats ok=False as
    quarantine):
      * key config broken (`*_FILE` set but mount botched)
                                 -> ok=False reason "lakera_unavailable:key-config-error"
      * no key configured at all -> ok=False reason "lakera_unavailable:no-key"
      * any network/HTTP/JSON/timeout error
                                 -> ok=False reason "lakera_unavailable:<ExcType>"
      * bad/unknown response shape
                                 -> ok=False reason "lakera_unavailable:bad-response"
      * prompt_attack detected   -> ok=False reason "lakera:prompt_attack"
      * flagged (fallback, no breakdown)
                                 -> ok=False reason "lakera:flagged"
      * clean (or only moderation/PII fired)
                                 -> ok=True  reason "pass"
    """
    try:
        key = _lakera_key()
    except KeyConfigError:
        # A `*_FILE` path was configured but the mount is broken. Fail loud —
        # this is a botched deployment, not mere absence.
        return LakeraResult(ok=False, reason="lakera_unavailable:key-config-error")

    if not key:
        # Nothing configured. Under fail-closed semantics this now BLOCKS —
        # the Lakera gate is mandatory, so a missing key is a deployment
        # error the operator must hear about, not a quiet pass-through.
        return LakeraResult(ok=False, reason="lakera_unavailable:no-key")

    url = os.environ.get("LAKERA_GUARD_URL") or _DEFAULT_URL
    try:
        timeout = float(
            os.environ.get("INJECTION_SCANNER_LAKERA_TIMEOUT", _DEFAULT_TIMEOUT_S)
        )
    except (TypeError, ValueError):
        timeout = _DEFAULT_TIMEOUT_S

    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    # Lakera Guard v2, verified 2026: POST /v2/guard with the untrusted text as
    # the most-recent user message; `breakdown: true` asks for per-detector
    # detail so we can gate on the injection detector specifically rather than
    # the top-level `flagged` (which also fires on moderation/PII). An optional
    # LAKERA_PROJECT_ID points the request at a tuned project policy.
    payload: dict = {"messages": [{"role": "user", "content": text}], "breakdown": True}
    project_id = os.environ.get("LAKERA_PROJECT_ID")
    if project_id:
        payload["project_id"] = project_id
    body = json.dumps(payload).encode("utf-8")

    try:
        data = _post(url, body, headers, timeout)
    except Exception as e:  # noqa: BLE001 — any failure fails CLOSED
        # Exception TYPE only — never str(e). Some HTTP/JSON errors embed the
        # request/response body (the attacker-shaped bytes we sent), so
        # stringifying would flow input back into the caller-visible reason.
        return LakeraResult(ok=False, reason=f"lakera_unavailable:{type(e).__name__}")

    # Parse defensively: a malformed / unexpected response shape must not
    # fail-open. Any parse error collapses to a fail-closed reject with only
    # the exception type name in the reason.
    #
    # Lakera Guard v2, verified 2026: the response is a dict with a top-level
    # `flagged` bool and (because we requested it) a `breakdown` list. Each
    # breakdown entry carries `detector_type` (str) and `detected` (bool); all
    # other fields are optional. The prompt-injection / jailbreak detector's
    # `detector_type` is exactly "prompt_attack".
    try:
        if not isinstance(data, dict):
            # Not even a JSON object — cannot classify. Fail closed.
            return LakeraResult(ok=False, reason="lakera_unavailable:bad-response")

        breakdown = data.get("breakdown")
        if isinstance(breakdown, list):
            detected = [
                e for e in breakdown
                if isinstance(e, dict) and e.get("detected") is True
            ]
            categories = sorted({
                e["detector_type"]
                for e in detected
                if isinstance(e.get("detector_type"), str)
            })
            # Gate on the injection detector ONLY. We deliberately do NOT gate
            # on moderation (moderated_content/*) or PII detectors — those fire
            # on legitimate security-research prose and would over-reject.
            # Secret-exfil is covered by the deterministic secret_shapes layer.
            if any(e.get("detector_type") == "prompt_attack" for e in detected):
                return LakeraResult(
                    ok=False,
                    flagged=True,
                    categories=categories,
                    reason="lakera:prompt_attack",
                )
            return LakeraResult(ok=True, reason="pass")

        # Fallback: no usable breakdown (shouldn't happen since we request it),
        # but a top-level bool `flagged` is present -> gate conservatively.
        flagged = data.get("flagged")
        if isinstance(flagged, bool):
            if flagged:
                return LakeraResult(ok=False, flagged=True, reason="lakera:flagged")
            return LakeraResult(ok=True, reason="pass")

        # Neither a usable breakdown nor a bool flagged -> unknown shape.
        return LakeraResult(ok=False, reason="lakera_unavailable:bad-response")
    except Exception as e:  # noqa: BLE001 — defensive parse, fail CLOSED
        return LakeraResult(ok=False, reason=f"lakera_unavailable:{type(e).__name__}")
