"""Turn a Verdict reason into an operator message naming the layer that failed.

The smoke test used to print one fixed hint ("Likely L2/L3 degraded — check
LAKERA_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY ...") whatever failed. On
2026-10-24 the honeypot hit a retired OpenAI model (404) and that hint sent
everyone to look at Lakera. `describe()` reads the reason the scanner actually
returned and says which layer, which provider/model, and which condition.

Reasons are already built from closed vocabulary (exception TYPE names, fixed
labels, bounded HTTP status integers), never from `str(e)` or response bodies.
This module still treats every segment as untrusted: a segment that is not a
short identifier, or a status that is not three digits, renders as `other`, so
nothing outside the vocabulary can reach the message even if a reason is
malformed upstream. Scenario and judge ids are only used as lookup keys into
this package's own tables; the provider and model names printed come from
those tables, not from the reason.
"""
from __future__ import annotations

import re

from .honeypot_scenarios import ALL_SCENARIOS
from .judge import _JUDGES

_IDENT = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
_STATUS = re.compile(r"[1-5][0-9]{2}\Z")
_SKIPPED = re.compile(r"\+skipped=([0-9]{1,2})/([0-9]{1,2})\Z")

_SCENARIO_MODEL = {s["name"]: (s["provider"], s["model"]) for s in ALL_SCENARIOS}
_JUDGE_MODEL = {j["id"]: (j["provider"], j["model"]) for j in _JUDGES}

# L2 vendor conditions with a fixed meaning (see vendor_http.paced_post, l2.py,
# each adapter's `check`, and the README's reason table). Anything else after
# `<vendor>_unavailable:` is a transport exception type, optionally followed
# by an HTTP status.
_PANEL_FIXED = {
    "throttled": "local fleet budget exhausted or quota breaker open (throttled)",
    "service-unavailable": "service breaker open after HTTP 503",
    "limiter-error": "shared limiter unusable (cache directory, lock or IO error)",
    "bad-result": "adapter result outside its closed vocabulary",
}
_VENDOR_FIXED = {
    "lakera": {
        **_PANEL_FIXED,
        "no-key": "no API key (set LAKERA_API_KEY or LAKERA_API_KEY_FILE)",
        "key-config-error": "API key configuration error (LAKERA_API_KEY_FILE unreadable or malformed)",
        "url-config-error": "endpoint configuration error (only https://api.lakera.ai/v2/guard is allowed)",
        "bad-response": "unreadable or malformed Guard response",
    },
    "model_armor": {
        **_PANEL_FIXED,
        "no-key": "no credential (set MODEL_ARMOR_CREDENTIALS_FILE)",
        "not-implemented": "adapter not implemented yet",
        "bad-response": "unreadable or malformed Model Armor response",
    },
}


def _seg(s: str) -> str:
    return s if _IDENT.match(s) else "other"


def _status_text(code: str) -> str:
    if not _STATUS.match(code):
        return "HTTP other"
    if code == "429":
        return "HTTP 429 (quota/rate limit)"
    return f"HTTP {code}"


def _provider_signal(parts: list[str]) -> str:
    """Describe a provider-call signal such as `openai-api-error:NotFoundError:404`."""
    if not parts:
        return "unavailable"
    head = _seg(parts[0])
    for provider in ("openai", "anthropic"):
        if head == f"{provider}-api-error":
            exc = _seg(parts[1]) if len(parts) > 1 else "other"
            if len(parts) > 2:
                return f"returned {_status_text(parts[2])} ({exc})"
            return f"API call failed ({exc})"
        if head == f"no-{provider}-api-key":
            return f"no API key (set {provider.upper()}_API_KEY)"
        if head == f"{provider}-lib-missing":
            return f"{provider} SDK not installed"
        if head == f"{provider}-parse-error":
            exc = _seg(parts[1]) if len(parts) > 1 else "other"
            return f"unparseable response ({exc})"
    if head == "unhandled":
        exc = _seg(parts[1]) if len(parts) > 1 else "other"
        return f"unhandled {exc}"
    return head


def _model_for(table: dict, key: str) -> str:
    provider, model = table.get(key, ("unknown provider", "unknown model"))
    return f"{provider} model {model}"


def _honeypot(rest: str, *, triggered: bool) -> str:
    skipped = ""
    m = _SKIPPED.search(rest)
    if m:
        skipped = f"; {m.group(1)}/{m.group(2)} scenarios skipped"
        rest = rest[: m.start()]
    parts = rest.split(":")
    if parts[0] == "unhandled":
        return f"honeypot: {_provider_signal(parts)}{skipped}"
    scenario = _seg(parts[0])
    where = f"{_model_for(_SCENARIO_MODEL, scenario)} (scenario {scenario})"
    if triggered:
        return f"honeypot: {where} was triggered by the benign probe{skipped}"
    signal = parts[1:]
    if signal and signal[0] == "unavailable":
        signal = signal[1:]
    return f"honeypot: {where}: {_provider_signal(signal)}{skipped}"


def _judge(rest: str) -> str:
    parts = rest.split(":")
    if parts[0] == "attack":
        judge = _seg(parts[1]) if len(parts) > 1 else "other"
        return f"judge: {_model_for(_JUDGE_MODEL, judge)} voted attack on the benign probe"
    if parts[0] == "unavailable" and len(parts) > 1:
        if parts[1] == "panel-incomplete":
            return "judge: panel incomplete"
        judge = _seg(parts[1])
        return f"judge: {_model_for(_JUDGE_MODEL, judge)}: {_provider_signal(parts[2:])}"
    return f"judge: {_seg(parts[0])}"


def _vendor(vendor: str, rest: str) -> str:
    fixed = _VENDOR_FIXED[vendor]
    if rest in fixed:
        return f"{vendor}: {fixed[rest]}"
    parts = rest.split(":")
    if parts[0] == "unhandled":
        return f"{vendor}: {_provider_signal(parts)}"
    exc = _seg(parts[0])
    if len(parts) > 1:
        return f"{vendor}: {_status_text(parts[1])} ({exc})"
    return f"{vendor}: transport error ({exc})"


def describe(reason: str) -> str:
    """One-line operator message for a Verdict `reason` (or a layer value)."""
    if not isinstance(reason, str) or not reason:
        return "unknown failure"
    head, _, rest = reason.partition(":")
    for vendor in _VENDOR_FIXED:
        if head == f"{vendor}_unavailable":
            return _vendor(vendor, rest)
        if head == vendor:
            label = rest if rest == "prompt_attack" else "other"
            return f"{vendor}: flagged the benign probe ({label})"
    if head == "l2_arbitration":
        return _judge(rest)
    if head == "judge_unavailable":
        return f"judge: {_provider_signal(rest.split(':'))}"
    if head == "honeypot_unavailable":
        return _honeypot(rest, triggered=False)
    if head == "honeypot":
        # Verdict reasons wrap the honeypot's own reason: `honeypot:honeypot_unavailable:...`.
        inner, _, inner_rest = rest.partition(":")
        if inner == "honeypot_unavailable":
            return _honeypot(inner_rest, triggered=False)
        if inner == "honeypot":
            return _honeypot(inner_rest, triggered=True)
        return _honeypot(rest, triggered=True)
    if head.endswith("_unavailable"):
        layer = _seg(head[: -len("_unavailable")])
        return f"{layer}: {_provider_signal(rest.split(':'))}"
    return f"{_seg(head)}: blocked the benign probe"
