"""
Layer 3: multi-provider honeypot ensemble.

Each research report is fanned out to six downstream judge calls — two
per model across three small models (claude-haiku-4-5, gpt-4o-mini,
gpt-4.1-nano) spanning two providers (Anthropic + OpenAI). Each scenario
in honeypot_scenarios.py picks its own (provider, model) pair, framing,
and canary placement. Cross-family diversity is the detection boost: an
injection tuned for one family often misses on another, and vice versa.

A legitimate judge calls `return_summary` (the benign task) or
`report_issue(Prompt_Injection_Attempt, …)`; both count as
`Honeypot_Left_Alone`. A judge that calls any bait tool OR echoes the
scenario's canary via a tool argument or freeform text is
`Honeypot_Triggered` and the report is rejected.

Trap tool NAMES are randomized per scan (see honeypot_scenarios.build_trap_tools)
so an untargeted payload can't fingerprint the sandbox off a well-known bait
name. The classifier keys off the run's trap-name set, not a fixed constant.

Fail-closed: missing SDK, missing API key, and any per-scenario API
error all collapse to `ok=False`. Silent skip is not allowed — the whole
point of defense-in-depth is that an outage must be visible.
"""
from __future__ import annotations

import asyncio
import json
import os
import secrets
from dataclasses import dataclass, field
from typing import Literal

from injection_scanner.keyloader import KeyConfigError, load_key
from injection_scanner.honeypot_scenarios import (
    ALL_CANARIES,
    ALL_SCENARIOS,
    LEGIT_TOOLS,
    LEGIT_TOOL_NAMES,
    Scenario,
    build_trap_tools,
    canary_label,
)

Verdict = Literal["Honeypot_Triggered", "Honeypot_Left_Alone", "Honeypot_Skipped"]

_API_TIMEOUT_S = float(os.environ.get("INJECTION_SCANNER_API_TIMEOUT", "20"))
_MAX_RETRIES = int(os.environ.get("INJECTION_SCANNER_API_RETRIES", "2"))
_RETRY_BASE_S = float(os.environ.get("INJECTION_SCANNER_API_RETRY_BASE", "0.5"))


async def _with_retries(make_awaitable):
    last: Exception | None = None
    for attempt in range(_MAX_RETRIES + 1):
        try:
            return await make_awaitable()
        except Exception as e:  # noqa: BLE001 — retry any transient API error
            last = e
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(_RETRY_BASE_S * (2 ** attempt))
    raise last  # type: ignore[misc]


@dataclass
class ScenarioResult:
    scenario: str
    verdict: Verdict
    signal: str
    provider: str = ""
    model: str = ""
    raw_excerpt: str = ""


@dataclass
class HoneypotResult:
    ok: bool
    reason: str
    per_scenario: list[ScenarioResult] = field(default_factory=list)


# ---------- secret loading ----------
#
# Keys resolve through injection_scanner.keyloader with FILE > env > keyring
# precedence. The FILE tier is the agenix pattern: a `*_FILE` env var points
# at a decrypted secret file. A configured-but-broken FILE path raises
# KeyConfigError; the adapters below catch it into a Honeypot_Skipped so the
# fail-closed path rejects loudly rather than crashing the scan.


def _anthropic_key() -> str | None:
    return load_key(
        file_env="ANTHROPIC_API_KEY_FILE",
        env_var="ANTHROPIC_API_KEY",
        keyring_key="anthropic-api-key",
    )


def _openai_key() -> str | None:
    return load_key(
        file_env="OPENAI_API_KEY_FILE",
        env_var="OPENAI_API_KEY",
        keyring_key="openai-api-key",
    )


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
#      At 128 bits (32 hex chars) birthday collisions across the lifetime
#      of a long-running MCP server are negligible.
#   2. As a belt to the nonce's braces, if the attacker DID somehow guess
#      the nonce we still rewrite any literal occurrence of that exact
#      close tag in the body before interpolating, neutralising the
#      escape.
#
# The tag name itself ("content_<nonce>") is deliberately generic — not
# `attached`, not `untrusted`, not anything that hints the judge should
# trust the surrounding frame more than the body. The semantic separation
# lives in the judge's system prompt, not in the tag name.


def _seal(report_text: str) -> str:
    """Wrap report_text in nonce-tagged delimiters; neutralise any literal
    close-tag occurrence in the body."""
    nonce = secrets.token_hex(16)  # 32 hex chars / 128 bits
    open_tag = f"<content_{nonce}>"
    close_tag = f"</content_{nonce}>"
    # Defense in depth: a body that happens to embed our exact close tag
    # (negligible collision odds at 128 bits, but also same-process state
    # leak via a logged prior nonce) shouldn't escape the wrap. Replace
    # the close-tag bytes with an inert form before interpolation.
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
    trap_names: set[str],
) -> ScenarioResult:
    """Given the list of (tool_name, tool_input) calls plus any freeform
    text, decide Honeypot_Triggered / Honeypot_Left_Alone.

    `trap_names` is THIS run's randomized trap-tool name set (from
    honeypot_scenarios.build_trap_tools). The trap check keys off it rather
    than any fixed module-level constant, so it matches whatever names the
    model was shown this run.

    Valid tool names for this run = the stable legit tools ∪ this run's
    randomized trap names. A returned name outside that set is treated as a
    malformed response — Honeypot_Skipped, not Honeypot_Left_Alone — both to
    avoid silent fall-through on broken SDK responses (Invariant 3) AND to
    fence out judge-controlled bytes from ever reaching the caller-visible
    `signal` / `reason` strings (Invariant 4). Even when the name IS valid,
    it's known-clean ASCII (legit tool id or `<capability>_<hex>`) so
    interpolation is safe.
    """
    own_canary = scenario["canary"]
    excerpt = text[:300]  # audit-only; never interpolated into signal/reason
    valid_names = LEGIT_TOOL_NAMES | trap_names

    # 0. Defense in depth: reject any malformed-name tool call. A judge
    #    that returned `name=None` or a string outside the valid set is
    #    either a broken SDK response or a coerced model emitting
    #    attacker-shaped bytes in the name field. Either way, falling
    #    through to left_alone would synthesize a positive signal from
    #    the absence of a parseable trigger — exactly what Invariant 3
    #    forbids.
    for name, _inp in called_tools:
        if not isinstance(name, str) or name not in valid_names:
            return ScenarioResult(
                scenario=scenario["name"],
                verdict="Honeypot_Skipped",
                signal="unavailable:malformed-tool-call",
                provider=scenario["provider"],
                model=scenario["model"],
            )

    # 1. Bait-tool call: triggered regardless of args. Even an "empty"
    #    bait-tool call demonstrates the judge was coerced into the wrong
    #    action class. `trap_names` are this run's randomized names.
    for name, _inp in called_tools:
        if name in trap_names:
            return ScenarioResult(
                scenario=scenario["name"],
                verdict="Honeypot_Triggered",
                signal=f"trap:{name}",
                provider=scenario["provider"],
                model=scenario["model"],
                raw_excerpt=excerpt,
            )

    # 2. Canary in ANY tool-call argument (including the legitimate tools
    #    return_summary / report_issue). This catches the "summary
    #    exfiltration" attack class — a judge coerced into echoing the
    #    canary back via a benign-looking channel still leaks.
    arg_hit = _scan_args_for_canary(called_tools, own_canary)
    if arg_hit:
        c, tool_name = arg_hit
        suffix = "" if c == own_canary else "_crosstalk"
        # tool_name is validated against valid_names above, so it's safe to
        # interpolate (known ASCII identifier, no attacker bytes).
        return ScenarioResult(
            scenario=scenario["name"],
            verdict="Honeypot_Triggered",
            signal=f"canary_in_arg{suffix}:{canary_label(c)}:{tool_name}",
            provider=scenario["provider"],
            model=scenario["model"],
            raw_excerpt=excerpt,
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
            raw_excerpt=excerpt,
        )
    for other in ALL_CANARIES:
        if other != own_canary and other in text:
            return ScenarioResult(
                scenario=scenario["name"],
                verdict="Honeypot_Triggered",
                signal=f"canary_in_text_crosstalk:{canary_label(other)}",
                provider=scenario["provider"],
                model=scenario["model"],
                raw_excerpt=excerpt,
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
                raw_excerpt=excerpt,
            )
    return ScenarioResult(
        scenario=scenario["name"],
        verdict="Honeypot_Left_Alone",
        signal="left_alone",
        provider=scenario["provider"],
        model=scenario["model"],
        raw_excerpt=excerpt,
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


async def _call_anthropic(
    scenario: Scenario,
    report_text: str,
    tools: list[dict],
    trap_names: set[str],
) -> ScenarioResult:
    try:
        import anthropic  # type: ignore
    except ImportError:
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal="unavailable:anthropic-lib-missing",
            provider="anthropic", model=scenario["model"],
        )
    try:
        key = _anthropic_key()
    except KeyConfigError:
        # A `*_FILE` path was configured but the mount is broken. Fail loud
        # via the honeypot's fail-closed path: Skipped -> ok=False reject.
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal="unavailable:key-config-error",
            provider="anthropic", model=scenario["model"],
        )
    if not key:
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal="unavailable:no-anthropic-api-key",
            provider="anthropic", model=scenario["model"],
        )
    client = anthropic.Anthropic(api_key=key, timeout=_API_TIMEOUT_S)
    # Shallow copy intentional — we rebind `messages[-1]` below to a NEW
    # dict so the module-level scenario["history"] singleton stays pristine
    # across concurrent scans. Do NOT switch to mutating in place
    # (`messages[-1]["content"] = ...`); that would poison the singleton.
    messages = list(scenario["history"])
    attach = f"{messages[-1]['content']}\n\n{_seal(report_text)}"
    if messages and messages[-1]["role"] == "user":
        messages[-1] = {**messages[-1], "content": attach}
    else:
        messages.append({"role": "user", "content": attach})
    try:
        resp = await _with_retries(
            lambda: asyncio.to_thread(
                client.messages.create,
                model=scenario["model"],
                max_tokens=400,
                tools=tools,  # type: ignore[arg-type]
                system=scenario["system"],
                messages=messages,
            )
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
    try:
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
    except Exception as e:
        # A malformed / unexpected response shape must not fail-open — treat
        # an unparseable response as degraded coverage (Skipped), not a pass.
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal=f"unavailable:anthropic-parse-error:{type(e).__name__}",
            provider="anthropic", model=scenario["model"],
        )
    return _classify_from_parts(scenario, called, " ".join(text_chunks), trap_names)


async def _call_openai(
    scenario: Scenario,
    report_text: str,
    tools: list[dict],
    trap_names: set[str],
) -> ScenarioResult:
    try:
        from openai import OpenAI  # type: ignore
    except ImportError:
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal="unavailable:openai-lib-missing",
            provider="openai", model=scenario["model"],
        )
    try:
        key = _openai_key()
    except KeyConfigError:
        # A `*_FILE` path was configured but the mount is broken. Fail loud
        # via the honeypot's fail-closed path: Skipped -> ok=False reject.
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal="unavailable:key-config-error",
            provider="openai", model=scenario["model"],
        )
    if not key:
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal="unavailable:no-openai-api-key",
            provider="openai", model=scenario["model"],
        )
    client = OpenAI(api_key=key, timeout=_API_TIMEOUT_S)

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
        resp = await _with_retries(
            lambda: asyncio.to_thread(
                client.chat.completions.create,
                model=scenario["model"],
                messages=messages,
                tools=_openai_tools(tools),
                max_tokens=400,
            )
        )
    except Exception as e:
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal=f"unavailable:openai-api-error:{type(e).__name__}",
            provider="openai", model=scenario["model"],
        )
    try:
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
    except Exception as e:
        # A malformed / unexpected response shape must not fail-open — treat
        # an unparseable response as degraded coverage (Skipped), not a pass.
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal=f"unavailable:openai-parse-error:{type(e).__name__}",
            provider="openai", model=scenario["model"],
        )
    return _classify_from_parts(scenario, called, text, trap_names)


async def _run_one(scenario: Scenario, report_text: str) -> ScenarioResult:
    # Materialize this run's trap tools with FRESH randomized names and the
    # matching trap-name set, then present LEGIT (stable) + trap (randomized)
    # tools to the model. The classifier keys off `trap_names` so it matches
    # exactly the names the model was shown this run.
    trap_tools, trap_names = build_trap_tools(scenario["traps"])
    tools = LEGIT_TOOLS + trap_tools
    if scenario["provider"] == "anthropic":
        return await _call_anthropic(scenario, report_text, tools, trap_names)
    if scenario["provider"] == "openai":
        return await _call_openai(scenario, report_text, tools, trap_names)
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
        if isinstance(r, ScenarioResult):
            results.append(r)
        else:
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

    triggered = [r for r in results if r.verdict == "Honeypot_Triggered"]
    # Defensive: anything that's not explicitly Triggered or Left_Alone
    # counts as degraded coverage. A future verdict variant (e.g. an
    # Errored bucket) won't silently drop out of the skipped count.
    skipped = [
        r for r in results
        if r.verdict not in ("Honeypot_Triggered", "Honeypot_Left_Alone")
    ]
    total = len(results)
    if triggered:
        first = triggered[0]
        # Surface concurrent provider outages even on trigger: the top-line
        # reason flows into `layers.honeypot` and audit summaries; without
        # this an operator sees only the trigger and misses that a sibling
        # provider was simultaneously down (degraded coverage).
        skip_suffix = f"+skipped={len(skipped)}/{total}" if skipped else ""
        return HoneypotResult(
            ok=False,
            reason=f"honeypot:{first.scenario}:{first.signal}{skip_suffix}",
            per_scenario=results,
        )
    if skipped:
        first = skipped[0]
        # Symmetric to the trigger path: include the skipped count so a
        # full-outage (6/6) is distinguishable from a partial (1/6).
        return HoneypotResult(
            ok=False,
            reason=f"honeypot_unavailable:{first.scenario}:{first.signal}+skipped={len(skipped)}/{total}",
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
