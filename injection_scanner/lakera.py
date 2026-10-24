"""
Layer 2 adapter: hosted Lakera Guard classifier, FAIL-CLOSED.

One member of the L2 panel (`injection_scanner.l2`). This module owns only
what is Lakera's: the key, the pinned endpoint, the request payload and the
strict response parse. Transport, pacing and transport-failure reasons are
`injection_scanner.vendor_http`'s.

Anything that prevents a clean classification — no key, a botched `*_FILE`
mount, an untrusted endpoint, a throttled or broken limiter, any network /
HTTP / JSON error, a malformed response — is `ok=False`. Silent degradation of
a detection layer is the failure operators must hear about.

Key resolution goes through `keyloader` (FILE > env > keyring). Key and
endpoint are resolved BEFORE the limiter, so a call that cannot happen spends
no fleet token.

Invariant 4 ("the caught bytes never return"): `reason` carries only fixed
labels, exception TYPE names and a bounded HTTP status — never input text,
response text or a stringified exception.
"""
from __future__ import annotations

import json
import os
import urllib.parse

from injection_scanner import vendor_http
from injection_scanner.keyloader import KeyConfigError, load_key
from injection_scanner.vendor_http import VendorResult

VENDOR = "lakera"

_DEFAULT_URL = "https://api.lakera.ai/v2/guard"


def _is_trusted_endpoint(url: str) -> bool:
    """True only for the exact Lakera Guard HTTPS destination.

    `LAKERA_GUARD_URL` is an operator input, and the next thing that happens to
    the URL is that `Bearer <the shared Lakera key>` is attached to it. Scheme,
    host, port, credentials, path, query and fragment therefore form one
    allowlisted destination rather than independent best-effort checks.

    The raw spelling must be ASCII before case normalization, preventing
    Unicode case-folding confusables from becoming an allowlisted hostname.
    The round-trip check then rejects raw bytes that `urlsplit` silently
    strips, while normalizing only scheme casing because `urlunsplit` lowers
    it. It also distinguishes a bare trailing `?` or `#` from no
    query/fragment. Raw netloc matching rejects spellings such as an empty or
    zero-padded port even when `.port` normalizes them to `None` or `443`.
    Accessing `.port` can raise for malformed and out-of-range values, which
    makes the whole unverified endpoint invalid.
    """
    if not isinstance(url, str) or not url.isascii():
        return False
    try:
        parsed = urllib.parse.urlsplit(url)
        raw_scheme, separator, raw_after_scheme = url.partition(":")
        normalized_raw = f"{parsed.scheme}:{raw_after_scheme}"
        netloc = parsed.netloc.casefold()
        return (
            separator == ":"
            and raw_scheme.casefold() == parsed.scheme
            and normalized_raw == urllib.parse.urlunsplit(parsed)
            and parsed.scheme.lower() == "https"
            and netloc in ("api.lakera.ai", "api.lakera.ai:443")
            and parsed.hostname == "api.lakera.ai"
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and parsed.path == "/v2/guard"
            and not parsed.query
            and not parsed.fragment
            and "?" not in url
            and "#" not in url
        )
    except (TypeError, ValueError):
        return False


def _lakera_key() -> str | None:
    return load_key(
        file_env="LAKERA_API_KEY_FILE",
        env_var="LAKERA_API_KEY",
        keyring_key="lakera-api-key",
    )


def _unavailable(condition: str) -> VendorResult:
    return vendor_http.unavailable(VENDOR, condition)


def check(text: str, *, max_wait_s: float | None = None) -> VendorResult:
    """Classify `text` with Lakera Guard. FAIL-CLOSED at every step.

    The whole text goes in ONE request, unchunked. The Community plan lists an
    8k-token maximum; measured 2026-10-24 with the production key and project
    policy, Guard flagged an injection placed at ~10k tokens in ~12k tokens of
    benign prose and passed the same text without it. Larger sizes are
    unmeasured. See README "Prompt size".

    Reasons (closed vocabulary):
      * `lakera_unavailable:key-config-error` — `*_FILE` set but unreadable
      * `lakera_unavailable:no-key`           — no key configured
      * `lakera_unavailable:url-config-error` — `LAKERA_GUARD_URL` is not the
                                                exact trusted endpoint
      * `lakera_unavailable:throttled` / `:service-unavailable` /
        `:limiter-error` / `:<ExcType>[:<status>]` / `:bad-response`
                                              — see `vendor_http.paced_post`
      * `lakera_unavailable:bad-response`     — unknown response shape
      * `lakera:prompt_attack`                — flagged (ok=False, flagged=True)
      * `pass`                                — clean, or only moderation/PII
                                                detectors fired

    `max_wait_s` is how long this call may wait for a fleet token; `None`
    means `INJECTION_SCANNER_LAKERA_MAX_WAIT_S` (default 0).
    """
    try:
        key = _lakera_key()
    except KeyConfigError:
        return _unavailable("key-config-error")
    if not key:
        return _unavailable("no-key")

    # The full destination is pinned before the key goes near a header; the
    # offending URL is never echoed.
    url = os.environ.get("LAKERA_GUARD_URL") or _DEFAULT_URL
    if not _is_trusted_endpoint(url):
        return _unavailable("url-config-error")

    # Guard v2: the untrusted text as the most recent user message;
    # `breakdown: true` asks for per-detector results so the gate keys on the
    # injection detector rather than top-level `flagged` (which also fires on
    # moderation/PII). LAKERA_PROJECT_ID selects a tuned project policy.
    payload: dict = {"messages": [{"role": "user", "content": text}], "breakdown": True}
    project_id = os.environ.get("LAKERA_PROJECT_ID")
    if project_id:
        payload["project_id"] = project_id
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    reply = vendor_http.paced_post(
        VENDOR,
        url,
        json.dumps(payload).encode("utf-8"),
        headers,
        max_wait_s=max_wait_s,
    )
    if reply.failure is not None:
        return reply.failure
    try:
        return _parse(reply.data)
    except Exception:  # noqa: BLE001 — hostile decoded objects fail CLOSED
        return _unavailable("bad-response")


def _parse(data: object) -> VendorResult:
    """Strict Guard v2 response contract.

    An object with boolean `flagged` and a `breakdown` list whose entries
    carry string `detector_type` and boolean `detected`; exactly one
    `prompt_attack` entry; a detected prompt attack must agree with
    `flagged: true`. Unknown extra fields and non-prompt detectors are
    allowed. Every violation is the one fixed `bad-response` reason.
    """
    if not isinstance(data, dict):
        return _unavailable("bad-response")
    flagged = data.get("flagged")
    breakdown = data.get("breakdown")
    if type(flagged) is not bool or not isinstance(breakdown, list):
        return _unavailable("bad-response")

    prompt_decisions = []
    for entry in breakdown:
        if not isinstance(entry, dict):
            return _unavailable("bad-response")
        detector_type = entry.get("detector_type")
        detected = entry.get("detected")
        if type(detector_type) is not str or type(detected) is not bool:
            return _unavailable("bad-response")
        if detector_type == "prompt_attack":
            prompt_decisions.append(detected)

    if len(prompt_decisions) != 1:
        return _unavailable("bad-response")
    if prompt_decisions[0]:
        if flagged is not True:
            return _unavailable("bad-response")
        return VendorResult(ok=False, flagged=True, reason="lakera:prompt_attack")
    return VendorResult(ok=True, reason="pass")
