"""
Intercept orchestrator: runs the layered shim and produces a single verdict.

Order (each layer can short-circuit):
  L0  unicode_sanitize      — strip covert channels, NFKC normalize, flag anomaly
  L1b secret_shapes         — high-precision API-key / JWT / PEM patterns
  L3  honeypot              — fan the report out to a 3-model judge ensemble
                              (claude-haiku-4-5, gpt-4o-mini, gpt-4.1-nano)
                              across 6 canary scenarios; if any judge gets
                              coerced into a bait-tool call or canary echo, fail
  (L2 LLM classifier and L4 LLM-as-judge are planned, not yet wired)

Caller passes the cleaned path and receives a Verdict dict the server can
use both to decide to deliver and to attach audit metadata.

Honeypot is opt-in: the server toggles it with the RESEARCH_HONEYPOT env
var so cheap local tests don't always pay the API call.

L1a regex was removed: the previous role-swap / instruction-override /
wrap-escape rules false-positived on legitimate research output that
quoted prompt-injection examples (security tooling docs, AI-safety
posts, the scanner's own README). Wrap-escape protection now lives at
the consumer's delivery boundary — research-agent encodes dangerous
tag chars on the report body before wrapping it. That's structurally
zero-FP and survives any future tag rename.
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path

from injection_scanner import secret_shapes, unicode_sanitize
from injection_scanner.honeypot import check as honeypot_check


@dataclass
class Verdict:
    ok: bool                       # True  -> deliver
    reason: str                    # short code e.g. "pass" / "secret_shape:aws_access_key"
    layers: dict[str, str]         # per-layer outcome for audit
    sanitize_stats: dict           # unicode_sanitize stats
    sanitized_text: str            # cleaned text the server should deliver

    def to_audit(self) -> dict:
        """Return an audit record safe to persist to disk or forward to an
        operator context. Never includes any report text — the whole point
        of a quarantine is that the bytes stay out of any interactive
        session. Callers needing the raw bytes must read the quarantined
        file directly outside the session.
        """
        d = asdict(self)
        d.pop("sanitized_text", None)
        d["sanitized_len"] = len(self.sanitized_text)
        if isinstance(d.get("sanitize_stats"), dict):
            d["sanitize_stats"] = {
                k: v for k, v in d["sanitize_stats"].items() if k != "text"
            }
        return d


def scan(path: Path, use_honeypot: bool = True) -> Verdict:
    """Run all layers on the file at `path`. Returns a Verdict.

    `use_honeypot` defaults to True and is kept only so tests can force it
    off for unit runs that must not hit the Anthropic API. In production
    call paths, callers should NOT pass this — the honeypot is always on.
    """
    return scan_text(
        path.read_text(encoding="utf-8", errors="replace"),
        use_honeypot=use_honeypot,
    )


def scan_text(raw: str, use_honeypot: bool = True) -> Verdict:
    """Run all layers on pre-read `raw` text. Returns a Verdict.

    Separate entry point so callers that need symlink/TOCTOU-safe reads can
    load the content into memory themselves (e.g. `os.open(..., O_NOFOLLOW)`)
    and scan the same bytes they've already snapshotted — no second disk
    read that could race against a file swap.

    Each scanner layer is wrapped in a try/except per honeypot-manufacturing
    Invariant 3: any exception inside a layer must reduce to *reject*, not
    propagate. The exception *type name* lands in the reason — never
    `str(e)`, which can echo input bytes back to the caller.
    """
    layers: dict[str, str] = {}

    # L0
    try:
        san = unicode_sanitize.sanitize(raw)
    except Exception as e:
        layers["unicode_sanitize"] = f"unhandled:{type(e).__name__}"
        return Verdict(
            ok=False,
            reason=f"unicode_sanitize_unavailable:unhandled:{type(e).__name__}",
            layers=layers,
            sanitize_stats={},
            sanitized_text="",
        )
    layers["unicode_sanitize"] = (
        f"stripped={san.stripped} bidi={san.bidi_hits} "
        f"tag={san.tag_hits} zw={san.zw_hits} nfkc_changed={san.nfkc_changed}"
    )
    if unicode_sanitize.is_anomalous(san, len(raw)):
        return Verdict(
            ok=False,
            reason=f"unicode_anomaly:stripped={san.stripped}/{len(raw)}",
            layers=layers,
            sanitize_stats=asdict(san),
            sanitized_text=san.text,
        )

    # L1b — secret-shape scan.
    try:
        hits = secret_shapes.scan(san.text)
    except Exception as e:
        layers["secret_shapes"] = f"unhandled:{type(e).__name__}"
        return Verdict(
            ok=False,
            reason=f"secret_shapes_unavailable:unhandled:{type(e).__name__}",
            layers=layers,
            sanitize_stats=asdict(san),
            sanitized_text=san.text,
        )
    layers["secret_shapes"] = "pass" if not hits else f"fail:{hits[0].name}"
    if hits:
        # Reason carries the matched rule NAME only — never the matched
        # snippet bytes. The 40-char snippet was attacker-controllable
        # (the bytes of a planted credential-shape that triggered the
        # rule); echoing it into `reason` flowed it back to the calling
        # LLM's context, violating honeypot-manufacturing Invariant 4
        # ("the caught bytes never return"). The full matched snippet
        # is available off-path in the operator-only secret_shapes log,
        # not in the caller-visible Verdict.
        return Verdict(
            ok=False,
            reason=f"secret_shape:{hits[0].name}",
            layers=layers,
            sanitize_stats=asdict(san),
            sanitized_text=san.text,
        )

    # L3 honeypot. Always runs in production.
    #
    # Fail-closed on degraded honeypot: honeypot_check returns ok=False
    # with reason="honeypot_unavailable:<scenario>:<why>" when the SDK
    # is missing, the API key is unset/revoked, or the provider is
    # unreachable. The `if not hp.ok` branch below catches both
    # triggered (real attack signal) and unavailable (degraded coverage)
    # outcomes. An outage quarantines real reports until the honeypot
    # is back — that's intentional, since silently lowered detection is
    # the exact failure mode operators must hear about. Diagnose via
    # `layers.honeypot` in the audit record.
    #
    # The `use_honeypot=False` path is used by unit tests that must not
    # hit the Anthropic API.
    if use_honeypot:
        # Blanket try/except per honeypot-manufacturing Invariant 3:
        # any exception raised inside a scanner layer must reduce to
        # *reject*, not propagate up and short-circuit downstream gates.
        # honeypot._run_all already converts per-scenario coroutine
        # raises to Skipped results; this catches the residual
        # possibility (import-time errors, scheduling failures, etc.)
        # so the scan boundary is fail-closed end-to-end. Only the
        # exception type name lands in the reason — `str(e)` on SDK
        # exceptions can echo the prompt body we sent.
        try:
            hp = honeypot_check(san.text)
        except Exception as e:
            layers["honeypot"] = f"unhandled:{type(e).__name__}"
            return Verdict(
                ok=False,
                reason=f"honeypot_unavailable:unhandled:{type(e).__name__}",
                layers=layers,
                sanitize_stats=asdict(san),
                sanitized_text=san.text,
            )
        layers["honeypot"] = hp.reason
        for s in hp.per_scenario:
            layers[f"honeypot.{s.scenario}"] = f"{s.verdict}:{s.signal}"
        if not hp.ok:
            return Verdict(
                ok=False,
                reason=f"honeypot:{hp.reason}",
                layers=layers,
                sanitize_stats=asdict(san),
                sanitized_text=san.text,
            )
    else:
        layers["honeypot"] = "disabled (test-only)"

    return Verdict(
        ok=True,
        reason="pass",
        layers=layers,
        sanitize_stats=asdict(san),
        sanitized_text=san.text,
    )
