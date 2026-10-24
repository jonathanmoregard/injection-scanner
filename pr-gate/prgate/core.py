"""The gate's decision flow (design steps 1-8). Fails closed everywhere.

Three kinds of failure, deliberately different:
  - procedural (no auto-merge, wrong enabler, stale head, a push after
    auto-merge, an existing block without owner approval, unreadable diff):
    the check fails with a message and NO review is posted. In particular no
    REQUEST_CHANGES: that would arm the reroll guard on a head that was
    never reviewed.
  - infra (GitHub or model API errors): the check fails, no review; a
    re-run retries. A transport error is not a verdict on the PR.
  - verdict: a review is posted on the head SHA. Block = REQUEST_CHANGES
    (COMMENT if refused) and exit 1; pass = COMMENT, dismiss the gate's own
    earlier blocks, exit 0.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Callable

from . import checks, verdict
from .diffparse import DiffError, FileChange, own_changes_hash, parse
from .github import GitHubError, Review, TooLarge
from .llm import EFFORTS, PassResult

GATE_LOGIN = "github-actions[bot]"
ACTIONS = ("auto_merge_enabled", "synchronize", "reopened")
DIFF_LLM_CAP = 400_000        # bytes of diff the model passes may read
DIFF_HARD_CAP = 5_000_000     # bytes of diff the deterministic checks will read
CONTENTS_BUDGET = 400_000     # bytes of post-change file contents for Monitor B
FILE_FETCH_CAP = 25_000_000   # per binary file (magic bytes + content hash)
_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_SHA = re.compile(r"^[0-9a-f]{40}$")

ReviewFn = Callable[[str, dict, list, list], list[PassResult]]


@dataclass
class Config:
    owner: str
    model: str
    effort: str
    threshold: int
    exceptions: list[str] = field(default_factory=list)

    def validate(self) -> "Config":
        if not _LOGIN.match(self.owner or ""):
            raise ValueError("owner must be a GitHub login")
        if not (self.model or "").strip():
            raise ValueError("model must be set")
        if self.effort not in EFFORTS:
            raise ValueError(f"effort must be one of {', '.join(EFFORTS)}")
        if type(self.threshold) is not int or not 0 <= self.threshold <= 100:
            raise ValueError("suspicion-threshold must be an integer 0-100")
        return self


@dataclass(frozen=True)
class Event:
    action: str
    number: int
    head_sha: str
    base_ref: str


@dataclass
class Outcome:
    exit_code: int
    message: str


@dataclass
class Gathered:
    diff_bytes: bytes
    diff_text: str
    files: list[FileChange]
    binaries: dict[str, bytes]
    own_hash: str


def gather(gh, ev: Event) -> Gathered:
    """Fetch and parse the base...head diff; hash the PR's own changes.

    Binary contents are fetched here because the hash needs them: the diff
    shows only "Binary files differ", which would let a binary change ride
    a carried-over pass.
    """
    diff_bytes = gh.diff(ev.base_ref, ev.head_sha, DIFF_HARD_CAP)
    return gather_from(diff_bytes, lambda path: gh.file_content(path, ev.head_sha, FILE_FETCH_CAP))


def gather_from(diff_bytes: bytes, fetch_binary: Callable[[str], bytes]) -> Gathered:
    if len(diff_bytes) > DIFF_HARD_CAP:
        raise TooLarge("diff")
    diff_text = diff_bytes.decode("utf-8", errors="replace")
    files = parse(diff_text)
    binaries = {f.path: fetch_binary(f.path) for f in files if f.binary and f.status != "deleted"}
    digests = {p: hashlib.sha256(b).hexdigest() for p, b in binaries.items()}
    return Gathered(diff_bytes, diff_text, files, binaries, own_changes_hash(files, digests))


def full_review(g: Gathered, cfg: Config, review_fn: ReviewFn,
                fetch_contents: Callable[[], tuple[dict[str, str], list[str]]]) -> verdict.Result:
    """Steps 4-7: every deterministic check, then the model passes."""
    hits, scrutiny = checks.run_all(g.files, g.binaries, cfg.exceptions)
    passes: list[PassResult] = []
    if len(g.diff_bytes) > DIFF_LLM_CAP:
        hits.append(checks.Hit("too-large", "(whole diff)",
                               f"diff is too large for the AI gate ({len(g.diff_bytes)} bytes, "
                               f"limit {DIFF_LLM_CAP}); human review", True))
    else:
        contents, omitted = fetch_contents()
        passes = review_fn(g.diff_text, contents,
                           [(s.path, s.reason) for s in scrutiny], omitted)
    return verdict.decide(hits, scrutiny, passes, cfg.threshold)


def _gate_reviews(reviews: list[Review]):
    for r in reviews:
        if r.login == GATE_LOGIN:
            m = verdict.parse_marker(r.body)
            if m:
                yield r, m


def _blocked_before(reviews: list[Review], head: str) -> bool:
    return any(m[0] == "block" and (m[1] == head or r.commit_id == head)
               for r, m in _gate_reviews(reviews))


def _owner_approved(reviews: list[Review], owner: str, head: str) -> bool:
    states = [r.state for r in reviews
              if r.login.casefold() == owner.casefold() and r.commit_id == head
              and r.state in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED")]
    return bool(states) and states[-1] == "APPROVED"


def _last_pass_hash(reviews: list[Review]) -> str | None:
    passes = [m[2] for _, m in _gate_reviews(reviews) if m[0] == "pass"]
    return passes[-1] if passes else None


def _text_contents(gh, ev: Event, files: list[FileChange]) -> tuple[dict[str, str], list[str]]:
    contents: dict[str, str] = {}
    omitted: list[str] = []
    left = CONTENTS_BUDGET
    for f in files:
        if f.status == "deleted" or f.binary or f.new_mode in ("120000", "160000"):
            continue
        try:
            data = gh.file_content(f.path, ev.head_sha, left)
        except TooLarge:
            omitted.append(f.path)
            continue
        left -= len(data)
        contents[f.path] = data.decode("utf-8", errors="replace")
    return contents, omitted


def _report(gh, ev: Event, cfg: Config, result: verdict.Result, own_hash: str,
            mode: str, reviews: list[Review]) -> Outcome:
    body = verdict.render_body(result, head=ev.head_sha, own_hash=own_hash,
                               threshold=cfg.threshold, model=cfg.model,
                               effort=cfg.effort, mode=mode)
    if result.block:
        try:
            gh.post_review(ev.number, ev.head_sha, "REQUEST_CHANGES", body)
        except GitHubError:
            gh.post_review(ev.number, ev.head_sha, "COMMENT", body)
        return Outcome(1, "blocked: " + "; ".join(result.reasons))
    gh.post_review(ev.number, ev.head_sha, "COMMENT", body)
    undismissed = []
    for r, m in _gate_reviews(reviews):
        if m[0] == "block" and r.state == "CHANGES_REQUESTED":
            try:
                gh.dismiss_review(ev.number, r.id, "Superseded: the AI gate passed a later run.")
            except GitHubError:
                undismissed.append(r.id)
    msg = f"passed ({mode})"
    if undismissed:
        msg += "; could not dismiss earlier gate reviews, dismiss them by hand"
    return Outcome(0, msg)


def run(ev: Event, cfg: Config, gh, review_fn: ReviewFn) -> Outcome:
    try:
        return _run(ev, cfg, gh, review_fn)
    except GitHubError as e:
        return Outcome(1, f"infra: {e}; re-run the check")
    except TooLarge:
        return Outcome(1, "the diff is too large for the gate to read; split the PR")
    except DiffError:
        return Outcome(1, "could not parse the diff; human review needed")


def _run(ev: Event, cfg: Config, gh, review_fn: ReviewFn) -> Outcome:
    if ev.action not in ACTIONS:
        return Outcome(1, "unsupported pull_request_target action; see the caller template")
    if not _SHA.match(ev.head_sha):
        return Outcome(1, "event has no valid head SHA")

    # Step 1: owner intent and freshness.
    state = gh.pull_state(ev.number)
    if not state.auto_merge:
        return Outcome(1, "enable auto-merge to request the AI gate")
    if (state.enabled_by or "").casefold() != cfg.owner.casefold():
        return Outcome(1, f"auto-merge must be enabled by {cfg.owner}")
    if state.head_sha != ev.head_sha:
        return Outcome(1, "stale: the PR head moved since this event")

    reviews = gh.reviews(ev.number)
    g = gather(gh, ev)

    if ev.action == "synchronize":
        if _last_pass_hash(reviews) != g.own_hash:
            return Outcome(1, "head changed after auto-merge was enabled; disable and "
                              "re-enable auto-merge to re-request review")
        hits, scrutiny = checks.run_all(g.files, g.binaries, cfg.exceptions, always_on_only=True)
        result = verdict.decide(hits, scrutiny, [], cfg.threshold)
        return _report(gh, ev, cfg, result, g.own_hash, "carry-over", reviews)

    # Step 2: reroll guard / owner override.
    if _blocked_before(reviews, ev.head_sha):
        if not _owner_approved(reviews, cfg.owner, ev.head_sha):
            return Outcome(1, f"the gate already blocked {ev.head_sha}; {cfg.owner} must "
                              "approve that commit, then re-run this check")
        hits, scrutiny = checks.run_all(g.files, g.binaries, cfg.exceptions, always_on_only=True)
        result = verdict.decide(hits, scrutiny, [], cfg.threshold)
        return _report(gh, ev, cfg, result, g.own_hash, "owner-override", reviews)

    # Steps 3-7: full review.
    result = full_review(g, cfg, review_fn, lambda: _text_contents(gh, ev, g.files))
    if result.infra:
        return Outcome(1, "infra: model call failed (" + ", ".join(result.infra)
                          + "); re-run the check")
    return _report(gh, ev, cfg, result, g.own_hash, "full", reviews)
