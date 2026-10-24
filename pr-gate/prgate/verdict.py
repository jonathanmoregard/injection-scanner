"""Verdict rules and the PR review body.

The model's `file`/`explanation` strings and file paths are the only
attacker-shaped text that reaches the PR, and the next coding agent reads
it. They go through `neutralise`: one line of plain text, HTML-escaped,
no @mentions, no #refs, no links, no code spans, bounded length.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import re
from dataclasses import dataclass, field

from .checks import Hit, Scrutiny
from .llm import PassResult, render_hidden

BLOCKING_FINDINGS = {
    ("malicious", "medium"), ("malicious", "high"),
    ("obscure", "medium"), ("obscure", "high"),
    ("security", "high"),
}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
MAX_BODY = 60000
MAX_FINDINGS = 40
MAX_HITS = 40
# Review-body marker, authenticated with an HMAC keyed by the Anthropic API
# key: any workflow in the repo can post as github-actions[bot], but only the
# gate step holds that secret. An unsigned marker (dry-run) never verifies.
MARKER = "<!-- pr-gate:v2 verdict={verdict} head={head} hash={hash} mac={mac} -->"
UNSIGNED = "unsigned"
_MARKER_RE = re.compile(
    r"\A<!-- pr-gate:v2 verdict=(pass|block) head=([0-9a-f]{40}) hash=([0-9a-f]{64})"
    r" mac=([0-9a-f]{64}) -->"
)


@dataclass
class Result:
    block: bool
    reasons: list[str]                 # gate-written, closed vocabulary
    suspicion: int | None
    hits: list[Hit] = field(default_factory=list)
    scrutiny: list[Scrutiny] = field(default_factory=list)
    passes: list[PassResult] = field(default_factory=list)
    infra: list[str] = field(default_factory=list)  # "<pass>: <reason>"


def decide(hits: list[Hit], scrutiny: list[Scrutiny], passes: list[PassResult],
           threshold: int) -> Result:
    reasons: list[str] = []
    for rule in sorted({h.rule for h in hits}):
        reasons.append(f"deterministic check: {rule}")
    infra = [f"{p.name}: {p.reason}" for p in passes if p.status == "infra"]
    for p in passes:
        if p.status == "incomplete":
            reasons.append(f"reviewer did not complete: {p.name}: {p.reason}")
        if p.declined:
            reasons.append(f"reviewer declined (policy): {p.name}")
    scores = [p.suspicion for p in passes if p.status == "ok" and p.suspicion is not None]
    suspicion = max(scores) if scores else None
    if suspicion is not None and suspicion >= threshold:
        reasons.append(f"suspicion {suspicion} >= threshold {threshold}")
    seen = set()
    for p in passes:
        for f in p.findings:
            key = (f.category, f.severity)
            if key in BLOCKING_FINDINGS and key not in seen:
                seen.add(key)
                reasons.append(f"finding: {f.category} ({f.severity})")
    return Result(block=bool(reasons) or bool(infra), reasons=reasons, suspicion=suspicion,
                  hits=hits, scrutiny=scrutiny, passes=passes, infra=infra)


# ----- rendering ---------------------------------------------------------------

_FULLWIDTH = str.maketrans({"@": "＠", "#": "＃", "[": "［", "]": "］", "`": "ˋ", "|": "¦"})


def neutralise(text: str, limit: int = 600) -> str:
    text = render_hidden(str(text))
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[:limit] + "…"
    text = text.translate(_FULLWIDTH)
    text = html.escape(text, quote=False)
    text = re.sub(r"(?i)\b(gh)-(?=\d)", r"\1－", text)
    text = text.replace("://", "[:]//")
    text = re.sub(r"(?i)\bwww\.", "www[.]", text)
    return text


def marker_mac(key: bytes, *, verdict: str, repo: str, number: int, head: str,
               own_hash: str) -> str:
    """HMAC-SHA256 over a fixed JSON array: no field can bleed into another."""
    msg = json.dumps(["pr-gate-marker", "v2", verdict, repo.casefold(), number, head, own_hash],
                     separators=(",", ":"))
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).hexdigest()


def render_marker(key: bytes | None, *, verdict: str, repo: str, number: int, head: str,
                  own_hash: str) -> str:
    mac = (marker_mac(key, verdict=verdict, repo=repo, number=number, head=head,
                      own_hash=own_hash) if key else UNSIGNED)
    return MARKER.format(verdict=verdict, head=head, hash=own_hash, mac=mac)


def parse_marker(body) -> tuple[str, str, str, str] | None:
    """(verdict, head, own_hash, mac), unverified."""
    if not isinstance(body, str):
        return None
    m = _MARKER_RE.match(body)
    return (m.group(1), m.group(2), m.group(3), m.group(4)) if m else None


def verify_marker(body, key: bytes | None, *, repo: str, number: int
                  ) -> tuple[str, str, str] | None:
    """(verdict, head, own_hash) if the marker's MAC checks out under `key`
    for this repo and PR; None otherwise (treated as no marker)."""
    m = parse_marker(body)
    if not key or m is None:
        return None
    expected = marker_mac(key, verdict=m[0], repo=repo, number=number, head=m[1],
                          own_hash=m[2])
    return m[:3] if hmac.compare_digest(m[3], expected) else None


# A block GitHub would not take as REQUEST_CHANGES goes out as a COMMENT,
# and GitHub cannot dismiss a COMMENT review: there is no override.
UNDISMISSABLE = ("this block was posted as a comment (GitHub refused a request-changes "
                 "review), and a comment cannot be dismissed on GitHub, so it cannot be "
                 "overridden. The only way past a false alarm is the owner's ruleset "
                 "bypass, or temporarily removing the required ai-gate check")

_MODE_LINE = {
    "full": "",
    "owner-override": "The owner dismissed the gate's block of this head commit; the "
                      "model layers were not re-run. Only the always-on checks ran.",
    "carry-over": "The PR's own changes are identical to those of the gate's latest verdict, "
                  "a pass (a base-branch merge or a reopen), so that pass was carried over. "
                  "Only the always-on checks ran.",
}


def render_body(r: Result, *, key: bytes | None, repo: str, number: int, head: str,
                own_hash: str, threshold: int, model: str, effort: str, mode: str,
                dismissable: bool = True) -> str:
    """`key=None` (dry-run) renders an unsigned marker that never verifies.
    `dismissable=False`: the block goes out as a COMMENT, which GitHub
    cannot dismiss, so the body must not tell the owner to dismiss it."""
    verdict = "block" if r.block else "pass"
    out = [render_marker(key, verdict=verdict, repo=repo, number=number, head=head,
                         own_hash=own_hash)]
    out.append(f"### AI gate: {'BLOCKED' if r.block else 'passed'}")
    if _MODE_LINE[mode]:
        out.append(_MODE_LINE[mode])
    if r.passes:
        scores = ", ".join(
            f"{p.name} {p.suspicion}" for p in r.passes if p.suspicion is not None)
        out.append(f"Model {neutralise(model, 80)} (effort {neutralise(effort, 20)}). "
                   f"Suspicion: {r.suspicion if r.suspicion is not None else 'n/a'} "
                   f"(threshold {threshold}; {scores or 'no scores'}).")
    if r.reasons:
        out.append("**Why it blocks**")
        out += [f"- {x}" for x in r.reasons]
    if r.hits:
        out.append("**Deterministic checks**")
        for h in r.hits[:MAX_HITS]:
            note = "" if h.overridable else " (not clearable by override)"
            out.append(f"- {h.rule}{note}: {neutralise(h.path, 200)}: {neutralise(h.detail, 200)}")
        if len(r.hits) > MAX_HITS:
            out.append(f"- … and {len(r.hits) - MAX_HITS} more")
    findings = sorted((f for p in r.passes for f in p.findings),
                      key=lambda f: SEVERITY_ORDER[f.severity])
    if findings:
        out.append("**Findings** (model-written, untrusted plain text)")
        for f in findings[:MAX_FINDINGS]:
            out.append(f"- {f.severity} · {f.category} · {neutralise(f.file, 200)} "
                       f"({f.source}): {neutralise(f.explanation)}")
        if len(findings) > MAX_FINDINGS:
            out.append(f"- … and {len(findings) - MAX_FINDINGS} more")
    if r.scrutiny:
        out.append("**Extra scrutiny** (not blocking)")
        out += [f"- {neutralise(s.path, 200)}: {s.reason}" for s in r.scrutiny[:MAX_HITS]]
    if r.block and not dismissable:
        out.append(f"**This block cannot be dismissed:** {UNDISMISSABLE}.")
    elif r.block:
        out.append(
            "**To clear a false alarm:** the owner dismisses this review, then re-runs the "
            "failed ai-gate check. Hidden-Unicode, lockfile-host and text-binary hits "
            "cannot be cleared that way: fix the change instead.")
    body = "\n\n".join(out)
    if len(body) > MAX_BODY:
        body = body[:MAX_BODY - 20] + "\n\n… (truncated)"
    return body
