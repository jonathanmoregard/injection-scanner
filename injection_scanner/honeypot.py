"""
Layer 3: multi-provider honeypot ensemble.

Each research report is fed to a fresh downstream model (Haiku, gpt-4o-mini,
gpt-4.1-nano) in three different honeypot scenarios (see
honeypot_scenarios.py). Each scenario defines its own provider + model so
the ensemble spans model families — an injection tuned for one family often
misses on another, and vice versa; diversity is the detection boost.

A legitimate judge calls `return_summary` (the benign task) or
`report_issue(Prompt_Injection_Attempt, …)`; both count as
`Honeypot_Left_Alone`. A judge that calls any trap tool OR echoes the
scenario's canary substring is `Honeypot_Triggered` and the report is
quarantined.

Fail-closed: missing SDK, missing API key, and any per-scenario API
error all collapse to `ok=False`. Silent skip is not allowed — the whole
point of defense-in-depth is that an outage must be visible.
"""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import subprocess
from dataclasses import dataclass, field
from typing import Literal

from injection_scanner.honeypot_scenarios import (
    ALL_CANARIES,
    ALL_SCENARIOS,
    TRAP_TOOL_NAMES,
    VALID_TOOL_NAMES,
    Scenario,
    canary_label,
)

Verdict = Literal["Honeypot_Triggered", "Honeypot_Left_Alone", "Honeypot_Skipped"]


@dataclass
class ScenarioResult:
    scenario: str
    verdict: Verdict
    signal: str
    provider: str = ""
    model: str = ""


@dataclass
class HoneypotResult:
    ok: bool
    reason: str
    per_scenario: list[ScenarioResult] = field(default_factory=list)


# ---------- secret loading ----------

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


def _anthropic_key() -> str | None:
    return os.environ.get("ANTHROPIC_API_KEY") or _keyring("anthropic-api-key")


def _openai_key() -> str | None:
    return os.environ.get("OPENAI_API_KEY") or _keyring("openai-api-key")


# ---------- wrap sealing ----------
#
# The retrieved report goes into the judge's last user message wrapped in
# tags so the judge can tell content-from-task. A literal close tag in the
# attacker bytes would escape the wrap and let the attacker write what
# appears to be system-level framing right back to the judge — that's the
# class of bug Anthropic and others have published on (wrap-escape /
# tag-confusion). Two-layer defense:
#
#   1. The wrap uses a per-call random nonce so the attacker can't guess
#      the exact close tag in advance. Each scenario call gets a fresh
#      nonce; nothing about the wrap structure is stable across calls.
#   2. As a belt to the nonce's braces, if the attacker DID somehow guess
#      the nonce (cryptographically vanishing odds at 16 hex chars / 64
#      bits) we still rewrite any literal occurrence of that exact close
#      tag in the body before interpolating, neutralising the escape.
#
# The tag name itself ("content_<nonce>") is deliberately generic — not
# `attached`, not `untrusted`, not anything that hints the judge should
# trust the surrounding frame more than the body. The semantic separation
# lives in the judge's system prompt, not in the tag name.
#
# Nonce length: 32 hex chars / 128 bits. Birthday collisions across the
# lifetime of a long-running MCP server are negligible at 128 bits, and
# the per-byte cost of doubling vs the prior 64-bit nonce is irrelevant
# relative to a network round-trip. The body-rewrite belt-and-braces
# below is what actually saves us from a same-nonce collision; the
# nonce length keeps the belt's job rare.


def _seal(report_text: str) -> str:
    """Wrap report_text in nonce-tagged delimiters; neutralise any literal
    close-tag occurrence in the body."""
    nonce = secrets.token_hex(16)  # 32 hex chars / 128 bits
    open_tag = f"<content_{nonce}>"
    close_tag = f"</content_{nonce}>"
    # Even with a 64-bit nonce, prefer defense in depth: a body that
    # happens to embed our exact close tag (collision OR same-process
    # state leak) shouldn't escape the wrap. Replace the close tag bytes
    # with an inert form before interpolation.
    body = report_text.replace(close_tag, f"&lt;/content_{nonce}&gt;")
    return f"{open_tag}\n{body}\n{close_tag}"


# ---------- common classification ----------


def _scan_args_for_canary(
    called_tools: list[tuple[str, dict]],
    own_canary: str,
) -> tuple[str, str] | None:
    """If any tool-call argument blob contains a known canary substring,
    return (canary_value, tool_name). Catches summary-exfiltration and
    report_issue-exfiltration: a judge that's been coerced into echoing
    the canary via a *legitimate-looking* tool call (e.g.
    `return_summary(text=CANARY)` or
    `report_issue(category=Refinement, description=CANARY)`) is still
    leaking — name-based trap-tool detection alone misses these. See
    LivePI / EchoLeak (CVE-2025-32711) for the published attack class.

    Scan order: own_canary first across all tools, then the rest of
    ALL_CANARIES. If a coerced judge leaks BOTH its own canary and an
    attacker-supplied cross-canary in the same arg blob, the more
    forensically meaningful own-canary signal wins — labelling that
    case as crosstalk would misroute the operator's investigation.
    """
    # Pass 1: own canary across all tools.
    for tool_name, inp in called_tools:
        try:
            blob = json.dumps(inp, ensure_ascii=False)
        except Exception:
            blob = str(inp)
        if own_canary in blob:
            return (own_canary, tool_name)
    # Pass 2: any other canary (crosstalk).
    for tool_name, inp in called_tools:
        try:
            blob = json.dumps(inp, ensure_ascii=False)
        except Exception:
            blob = str(inp)
        for c in ALL_CANARIES:
            if c != own_canary and c in blob:
                return (c, tool_name)
    return None


def _classify_from_parts(
    scenario: Scenario,
    called_tools: list[tuple[str, dict]],
    text: str,
) -> ScenarioResult:
    """Given the list of (tool_name, tool_input) calls plus any freeform
    text, decide Honeypot_Triggered / Honeypot_Left_Alone.

    Tool names from the judge response are checked against
    VALID_TOOL_NAMES (= schema-defined names). A returned name outside
    that set is treated as a malformed response — Honeypot_Skipped, not
    Honeypot_Left_Alone — both to avoid silent fall-through on broken
    SDK responses (Invariant 3) AND to fence out judge-controlled bytes
    from ever reaching the caller-visible `signal` / `reason` strings
    (Invariant 4). Even when the name IS valid, it's known-clean ASCII
    so interpolation is safe.
    """
    own_canary = scenario["canary"]

    # 0. Defense in depth: reject any malformed-name tool call. A judge
    #    that returned `name=None` or a string outside the schema set
    #    is either a broken SDK response or a coerced model emitting
    #    attacker-shaped bytes in the name field. Either way, falling
    #    through to left_alone would synthesize a positive signal from
    #    the absence of a parseable trigger — exactly what Invariant 3
    #    forbids.
    for name, _inp in called_tools:
        if not isinstance(name, str) or name not in VALID_TOOL_NAMES:
            return ScenarioResult(
                scenario=scenario["name"],
                verdict="Honeypot_Skipped",
                signal="unavailable:malformed-tool-call",
                provider=scenario["provider"],
                model=scenario["model"],
            )

    # 1. Bait-tool call: triggered regardless of args. Even an "empty"
    #    bait-tool call demonstrates the judge was coerced into the wrong
    #    action class.
    for name, _inp in called_tools:
        if name in TRAP_TOOL_NAMES:
            return ScenarioResult(
                scenario=scenario["name"],
                verdict="Honeypot_Triggered",
                signal=f"trap:{name}",
                provider=scenario["provider"],
                model=scenario["model"],
            )

    # 2. Canary in ANY tool-call argument (including the legitimate tools
    #    return_summary / report_issue). This catches the "summary
    #    exfiltration" attack class — a judge coerced into echoing the
    #    canary back via a benign-looking channel still leaks.
    arg_hit = _scan_args_for_canary(called_tools, own_canary)
    if arg_hit:
        c, tool_name = arg_hit
        suffix = "" if c == own_canary else "_crosstalk"
        # tool_name is validated against VALID_TOOL_NAMES above, so it's
        # safe to interpolate (known ASCII identifier, no attacker bytes).
        return ScenarioResult(
            scenario=scenario["name"],
            verdict="Honeypot_Triggered",
            signal=f"canary_in_arg{suffix}:{canary_label(c)}:{tool_name}",
            provider=scenario["provider"],
            model=scenario["model"],
        )

    # 3. Canary in freeform assistant text. Order: own canary first
    #    (avoids double-firing on the same hit), then cross-talk.
    if own_canary in text:
        return ScenarioResult(
            scenario=scenario["name"],
            verdict="Honeypot_Triggered",
            signal=f"canary_in_text:{canary_label(own_canary)}",
            provider=scenario["provider"],
            model=scenario["model"],
        )
    for other in ALL_CANARIES:
        if other != own_canary and other in text:
            return ScenarioResult(
                scenario=scenario["name"],
                verdict="Honeypot_Triggered",
                signal=f"canary_in_text_crosstalk:{canary_label(other)}",
                provider=scenario["provider"],
                model=scenario["model"],
            )

    # 4. report_issue(Prompt_Injection_Attempt, …) is the "good signal"
    #    path — only valid if no canary leaked in arg/text above. Steps
    #    1-3 already ran, so we know no exfil happened. A judge that
    #    flags the attack without executing it is exactly the behaviour
    #    we want from a non-flipped downstream model.
    for name, inp in called_tools:
        if name == "report_issue" and inp.get("category") == "Prompt_Injection_Attempt":
            return ScenarioResult(
                scenario=scenario["name"],
                verdict="Honeypot_Left_Alone",
                signal="left_alone_with_injection_report",
                provider=scenario["provider"],
                model=scenario["model"],
            )
    return ScenarioResult(
        scenario=scenario["name"],
        verdict="Honeypot_Left_Alone",
        signal="left_alone",
        provider=scenario["provider"],
        model=scenario["model"],
    )


# ---------- provider adapters ----------

def _openai_tools(tools: list[dict]) -> list[dict]:
    out = []
    for t in tools:
        out.append({
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"],
            },
        })
    return out


async def _call_anthropic(scenario: Scenario, report_text: str) -> ScenarioResult:
    try:
        import anthropic  # type: ignore
    except ImportError:
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal="unavailable:anthropic-lib-missing",
            provider="anthropic", model=scenario["model"],
        )
    key = _anthropic_key()
    if not key:
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal="unavailable:no-anthropic-api-key",
            provider="anthropic", model=scenario["model"],
        )
    client = anthropic.Anthropic(api_key=key)
    messages = list(scenario["history"])
    attach = f"{messages[-1]['content']}\n\n{_seal(report_text)}"
    if messages and messages[-1]["role"] == "user":
        messages[-1] = {**messages[-1], "content": attach}
    else:
        messages.append({"role": "user", "content": attach})
    try:
        resp = await asyncio.to_thread(
            client.messages.create,
            model=scenario["model"],
            max_tokens=400,
            tools=scenario["tools"],  # type: ignore[arg-type]
            system=scenario["system"],
            messages=messages,
        )
    except Exception as e:
        # Use only the exception *type* — some SDKs stringify exceptions
        # with request/response fragments, which could echo attacker-shaped
        # content back up into the signal string. The audit record lives in
        # the quarantine zone today, but keep the signal flat by default.
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal=f"unavailable:anthropic-api-error:{type(e).__name__}",
            provider="anthropic", model=scenario["model"],
        )
    called: list[tuple[str, dict]] = []
    text_chunks: list[str] = []
    for block in resp.content:
        btype = getattr(block, "type", "")
        if btype == "tool_use":
            called.append((
                getattr(block, "name", ""),
                getattr(block, "input", {}) or {},
            ))
        elif btype == "text":
            text_chunks.append(getattr(block, "text", ""))
    return _classify_from_parts(scenario, called, " ".join(text_chunks))


async def _call_openai(scenario: Scenario, report_text: str) -> ScenarioResult:
    try:
        from openai import OpenAI  # type: ignore
    except ImportError:
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal="unavailable:openai-lib-missing",
            provider="openai", model=scenario["model"],
        )
    key = _openai_key()
    if not key:
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal="unavailable:no-openai-api-key",
            provider="openai", model=scenario["model"],
        )
    client = OpenAI(api_key=key)

    # OpenAI expects flat chat messages; scenario history uses the same
    # role/content shape so we pass it through, then attach the content.
    messages: list[dict] = [{"role": "system", "content": scenario["system"]}]
    messages.extend(scenario["history"])
    attach = f"{messages[-1]['content']}\n\n{_seal(report_text)}"
    if messages[-1]["role"] == "user":
        messages[-1] = {**messages[-1], "content": attach}
    else:
        messages.append({"role": "user", "content": attach})

    try:
        resp = await asyncio.to_thread(
            client.chat.completions.create,
            model=scenario["model"],
            messages=messages,
            tools=_openai_tools(scenario["tools"]),
            max_tokens=400,
        )
    except Exception as e:
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal=f"unavailable:openai-api-error:{type(e).__name__}",
            provider="openai", model=scenario["model"],
        )
    msg = resp.choices[0].message
    called: list[tuple[str, dict]] = []
    for tc in (msg.tool_calls or []):
        fn = getattr(tc, "function", None)
        if not fn:
            continue
        try:
            args = json.loads(fn.arguments) if fn.arguments else {}
        except Exception:
            args = {}
        called.append((fn.name, args))
    text = msg.content or ""
    return _classify_from_parts(scenario, called, text)


async def _run_one(scenario: Scenario, report_text: str) -> ScenarioResult:
    if scenario["provider"] == "anthropic":
        return await _call_anthropic(scenario, report_text)
    if scenario["provider"] == "openai":
        return await _call_openai(scenario, report_text)
    return ScenarioResult(
        scenario=scenario["name"], verdict="Honeypot_Skipped",
        signal=f"unavailable:unknown-provider:{scenario['provider']}",
        provider=scenario["provider"], model=scenario["model"],
    )


async def _run_all(report_text: str) -> HoneypotResult:
    # return_exceptions=True so a per-scenario coroutine that raises
    # OUTSIDE its own inner try/except (constructor errors, asyncio.to_thread
    # failures, exotic env probes in _keyring_env, etc.) doesn't propagate
    # up and crash the caller — which currently has no outer try/except
    # around honeypot_check. Per honeypot-manufacturing skill Invariant 3:
    # "Any exception raised inside a scanner / detection layer must reduce
    # to *reject*, not *pass*." A raised exception is converted to a
    # Honeypot_Skipped result so the standard skipped→ok=False path then
    # quarantines the report.
    raw = await asyncio.gather(
        *(_run_one(s, report_text) for s in ALL_SCENARIOS),
        return_exceptions=True,
    )
    results: list[ScenarioResult] = []
    for s, r in zip(ALL_SCENARIOS, raw):
        if isinstance(r, BaseException):
            # Only the exception *type name* — `str(e)` on SDK exceptions
            # can embed request/response fragments that are themselves
            # attacker-shaped (the report bytes we sent in the prompt).
            results.append(ScenarioResult(
                scenario=s["name"],
                verdict="Honeypot_Skipped",
                signal=f"unavailable:unhandled:{type(r).__name__}",
                provider=s["provider"],
                model=s["model"],
            ))
        else:
            results.append(r)

    triggered = [r for r in results if r.verdict == "Honeypot_Triggered"]
    skipped = [r for r in results if r.verdict == "Honeypot_Skipped"]
    if triggered:
        first = triggered[0]
        # Surface concurrent provider outages even on trigger: the top-line
        # reason flows into `layers.honeypot` and audit summaries; without
        # this an operator sees only the trigger and misses that a sibling
        # provider was simultaneously down (degraded coverage).
        skip_suffix = f"+skipped={len(skipped)}" if skipped else ""
        return HoneypotResult(
            ok=False,
            reason=f"honeypot:{first.scenario}:{first.signal}{skip_suffix}",
            per_scenario=results,
        )
    if skipped:
        first = skipped[0]
        return HoneypotResult(
            ok=False,
            reason=f"honeypot_unavailable:{first.scenario}:{first.signal}",
            per_scenario=results,
        )
    return HoneypotResult(ok=True, reason="pass", per_scenario=results)


def check(report_text: str) -> HoneypotResult:
    # The MCP server hosts its tool handlers inside a FastMCP event loop,
    # so a plain asyncio.run() here raises "cannot be called from a running
    # event loop". Run the async ensemble in a fresh worker thread that
    # owns its own loop — keeps this function sync for all callers without
    # leaking async into injection_scanner.intercept.
    import concurrent.futures

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_run_all(report_text))
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(lambda: asyncio.run(_run_all(report_text))).result()
