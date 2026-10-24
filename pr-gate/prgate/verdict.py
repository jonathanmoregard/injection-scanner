"""Verdict rules and the PR review body.

The model's `file`/`explanation` strings and file paths are the only
attacker-shaped text that reaches the PR, and the next coding agent reads
it. They go through `neutralise`: one line of plain text, HTML-escaped,
no @mentions, no #refs, no links, no code spans, bounded length.
"""
from __future__ import annotations

import html
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
MARKER = "<!-- pr-gate:v1 verdict={verdict} head={head} hash={hash} -->"
_MARKER_RE = re.compile(
    r"\A<!-- pr-gate:v1 verdict=(pass|block) head=([0-9a-f]{40}) hash=([0-9a-f]{64}) -->"
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


def parse_marker(body) -> tuple[str, str, str] | None:
    if not isinstance(body, str):
        return None
    m = _MARKER_RE.match(body)
    return (m.group(1), m.group(2), m.group(3)) if m else None


_MODE_LINE = {
    "full": "",
    "owner-override": "Cleared by the owner's approval of this head commit after an "
                      "earlier block; the model layers were not re-run. Only the "
                      "always-on checks ran.",
    "carry-over": "The PR's own changes are identical to those of the gate's latest verdict, "
                  "a pass (a base-branch merge or a reopen), so that pass was carried over. "
                  "Only the always-on checks ran.",
}


def render_body(r: Result, *, head: str, own_hash: str, threshold: int,
                model: str, effort: str, mode: str) -> str:
    verdict = "block" if r.block else "pass"
    out = [MARKER.format(verdict=verdict, head=head, hash=own_hash)]
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
            note = "" if h.overridable else " (not clearable by approval)"
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
    if r.block:
        out.append(
            f"**To clear a false alarm:** approve the PR at this head commit ({head}), "
            "then re-run the failed ai-gate check. Hidden-Unicode and lockfile-host hits "
            "cannot be cleared that way: fix the change instead.")
    body = "\n\n".join(out)
    if len(body) > MAX_BODY:
        body = body[:MAX_BODY - 20] + "\n\n… (truncated)"
    return body
