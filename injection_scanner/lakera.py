"""
Layer 2 (additive): hosted Lakera Guard classifier pre-filter.

Runs BETWEEN the deterministic secret-shape scan (L1b) and the honeypot
(L3). Unlike the honeypot — which IS the gate and fail-CLOSES on any
outage — Lakera is an *additive* detection layer. If it's unconfigured
(no API key), errors, or times out, we SKIP it (record an audit line and
continue to the honeypot). Losing this pre-filter only costs one extra
signal; the honeypot still gates. ONLY a positive Lakera detection blocks.

The maintainer cannot self-host classifier models, so this layer targets
Lakera's *hosted* Guard API. It ships INERT: with no key present, check()
returns a skip result and never touches the network. It is exercised only
by MOCKED tests until a key is provisioned.

As with the rest of the package, the verdict `reason` / audit carries only
the detector name plus Lakera's category label — never any report content
or attacker-shaped bytes.
"""
from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field

_DEFAULT_URL = "https://api.lakera.ai/v2/guard"
_TIMEOUT_S = float(os.environ.get("INJECTION_SCANNER_LAKERA_TIMEOUT", "10"))


@dataclass
class LakeraResult:
    ok: bool
    reason: str
    flagged: bool
    categories: list[str] = field(default_factory=list)
    skipped_reason: str = ""


# ---------- secret loading ----------
# Mirrors honeypot.py's env-then-keyring pattern. Duplicated (~10 lines)
# rather than imported to keep this additive layer decoupled from the
# fail-closed honeypot module — see design note in the intercept docstring.

def _keyring_env() -> dict[str, str]:
    """Ensure secret-tool can reach the user's D-Bus session bus. MCP-server
    subprocesses may not inherit DBUS_SESSION_BUS_ADDRESS; fall back to the
    systemd per-user path."""
    import pathlib
    env = dict(os.environ)
    if "DBUS_SESSION_BUS_ADDRESS" not in env:
        bus = f"/run/user/{os.getuid()}/bus"
        if pathlib.Path(bus).exists():
            env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus}"
    if "XDG_RUNTIME_DIR" not in env:
        xdg = f"/run/user/{os.getuid()}"
        if pathlib.Path(xdg).is_dir():
            env["XDG_RUNTIME_DIR"] = xdg
    return env


def _keyring(key: str) -> str | None:
    try:
        r = subprocess.run(
            ["secret-tool", "lookup", "app", "research-agent", "key", key],
            capture_output=True, text=True, timeout=3,
            env=_keyring_env(),
        )
        return r.stdout.strip() or None
    except Exception:
        return None


def _lakera_key() -> str | None:
    return os.environ.get("LAKERA_API_KEY") or _keyring("lakera-api-key")


# ---------- raw POST (isolated for trivial mocking) ----------

def _post(url: str, body: bytes, headers: dict[str, str], timeout: float) -> dict:
    """Isolated urllib POST so tests can monkeypatch a single seam. Returns
    the parsed JSON payload as a dict. Any network/HTTP/JSON failure
    propagates to the caller, which converts it into an additive-skip."""
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — fixed https endpoint
        return json.loads(resp.read().decode("utf-8"))


def _extract_categories(payload: dict) -> list[str]:
    """Best-effort category-name extraction. Defensive about response shape:
    Lakera has historically returned per-detector results under a `results`
    list; we pull any string-ish category/detector-type field we can find
    and skip anything we can't understand. Category *labels* only — never
    any span text or excerpt from the payload."""
    cats: list[str] = []
    results = payload.get("results")
    if isinstance(results, list):
        for item in results:
            if not isinstance(item, dict):
                continue
            for field_name in ("category", "detector_type", "type", "name"):
                val = item.get(field_name)
                if isinstance(val, str) and val:
                    cats.append(val)
                    break
    # de-dup, preserve order
    seen: set[str] = set()
    out: list[str] = []
    for c in cats:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def check(text: str) -> LakeraResult:
    """Run the hosted Lakera Guard classifier over `text`.

    Additive semantics: no key / any error / timeout => skip (ok=True,
    flagged=False, skipped_reason set). Only a positive detection blocks
    (ok=False, flagged=True).
    """
    key = _lakera_key()
    if not key:
        return LakeraResult(
            ok=True,
            reason="pass",
            flagged=False,
            skipped_reason="unconfigured:no-lakera-api-key",
        )

    url = os.environ.get("LAKERA_GUARD_URL", _DEFAULT_URL)
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    # TODO(verify-live): confirm Lakera v2 Guard request/response schema
    # against current docs when the API key is provisioned. The request body
    # and the response parsing below (`flagged` top-level bool + category
    # names under `results`) are implemented FROM MEMORY and must be verified
    # against live docs before this layer is trusted to block.
    body = json.dumps(
        {"messages": [{"role": "user", "content": text}]}
    ).encode("utf-8")

    try:
        payload = _post(url, body, headers, _TIMEOUT_S)
        flagged = bool(payload.get("flagged"))
        categories = _extract_categories(payload) if flagged else []
    except Exception as e:  # noqa: BLE001 — additive-skip on ANY failure
        # Fail-OPEN for THIS layer only (honeypot still gates). Use the
        # exception TYPE only — never stringify the exception, which some
        # libraries fill with request/response fragments that could echo
        # attacker-shaped content back into the audit signal.
        return LakeraResult(
            ok=True,
            reason="pass",
            flagged=False,
            skipped_reason=f"unavailable:{type(e).__name__}",
        )

    if flagged:
        label = ",".join(categories) or "flagged"
        return LakeraResult(
            ok=False,
            reason=f"lakera:{label}",
            flagged=True,
            categories=categories,
        )
    return LakeraResult(ok=True, reason="pass", flagged=False)
