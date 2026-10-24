"""The gate's decision flow. Fails closed everywhere.

  1. auto-merge on, enabled by the owner, head not stale
  2. the PR targets the default branch
  3. push / reopen: carry over iff the newest verified gate marker is a pass
     of these exact own changes; else fail
  4. a verified gate block on this head: override (always-on checks only)
     iff the OWNER dismissed that review and the head has not moved since;
     else fail
  5. a re-run (run attempt > 1) never asks the model: fail
  6. full review: deterministic checks + model passes

Three kinds of failure, deliberately different:
  - procedural (steps 1-5, unreadable diff): the check fails with a message
    and NO review is posted.
  - infra (GitHub or model API errors): the check fails, no review. Not a
    verdict on the PR; an owner auto-merge toggle retries.
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

RETRY = "disable and re-enable auto-merge to retry"

ReviewFn = Callable[[str, dict, list, list], list[PassResult]]


@dataclass
class Config:
    owner: str
    model: str
    effort: str
    threshold: int
    exceptions: list[str] = field(default_factory=list)
    # The Anthropic API key, also the HMAC key for review markers. Kept out
    # of repr so a stray print of the config cannot leak it.
    marker_key: bytes = field(default=b"", repr=False)

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
    repo: str          # "owner/name", part of every marker MAC
    default_branch: str
    run_attempt: int   # GITHUB_RUN_ATTEMPT: > 1 is a re-run, which any writer can start


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


def gather(gh, base_oid: str, ev: Event) -> Gathered:
    """Fetch and parse the base_oid...head diff; hash the PR's own changes.

    Binary contents are fetched here because the hash needs them: the diff
    shows only "Binary files differ", which would let a binary change ride
    a carried-over pass.
    """
    diff_bytes = gh.diff(base_oid, ev.head_sha, DIFF_HARD_CAP)
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
    """Step 6: every deterministic check, then the model passes."""
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


def _gate_reviews(reviews: list[Review], ev: Event, key: bytes):
    """Reviews carrying a VERIFIED gate marker. Anything else, including a
    github-actions[bot] review from another workflow, counts as no marker."""
    for r in reviews:
        if r.login == GATE_LOGIN:
            m = verdict.verify_marker(r.body, key, repo=ev.repo, number=ev.number)
            if m:
                yield r, m


def _carries_over(reviews: list[Review], ev: Event, key: bytes, own_hash: str) -> bool:
    """The NEWEST gate marker (pass or block) is a pass of these exact own
    changes. Markers are signed, so a pass can't be minted; a replayed real
    one only re-asserts content that was passed."""
    markers = [m for _, m in _gate_reviews(reviews, ev, key)]
    return bool(markers) and markers[-1][0] == "pass" and markers[-1][2] == own_hash


def _blocks_on_head(reviews: list[Review], ev: Event, key: bytes) -> list[int]:
    """Review ids of the gate's verified blocks of this exact head commit."""
    return [r.id for r, m in _gate_reviews(reviews, ev, key)
            if m[0] == "block" and m[1] == ev.head_sha]


def _owner_dismissed(gh, ev: Event, owner: str, review_ids: list[int]) -> bool:
    """The owner dismissed one of these blocks while the PR sat at this
    head, as far as the timeline can show it, scanned in order:
      - a force push or branch restore after a block was posted voids it:
        the head can only return to a blocked commit by a rewrite, and the
        later fast-forward back shows up as a `committed` event at the
        commit's own date, not at push time;
      - a `committed` event after the dismissal voids the dismissal.
    A dismissal of a block the timeline never showed being posted is ignored.
    """
    posted: set[int] = set()
    ok = False
    for e in gh.timeline(ev.number):
        if e.kind == "reviewed" and e.review_id in review_ids:
            posted.add(e.review_id)
        elif (e.kind == "dismissed" and e.review_id in posted
              and e.actor.casefold() == owner.casefold()):
            ok = True
        elif e.kind == "commit":
            ok = False
        elif e.kind == "rewrite":
            posted.clear()
            ok = False
    return ok


def _always_on(g: Gathered, cfg: Config) -> verdict.Result:
    hits, scrutiny = checks.run_all(g.files, g.binaries, cfg.exceptions, always_on_only=True)
    return verdict.decide(hits, scrutiny, [], cfg.threshold)


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
    body = verdict.render_body(result, key=cfg.marker_key, repo=ev.repo, number=ev.number,
                               head=ev.head_sha, own_hash=own_hash,
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
    for r, m in _gate_reviews(reviews, ev, cfg.marker_key):
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
        return Outcome(1, f"infra: {e}; {RETRY}")
    except TooLarge:
        return Outcome(1, "the diff is too large for the gate to read; split the PR")
    except DiffError:
        return Outcome(1, "could not parse the diff; human review needed")


def _run(ev: Event, cfg: Config, gh, review_fn: ReviewFn) -> Outcome:
    if ev.action not in ACTIONS:
        return Outcome(1, "unsupported pull_request_target action; see the caller template")
    if not _SHA.match(ev.head_sha):
        return Outcome(1, "event has no valid head SHA")
    if not cfg.marker_key:
        return Outcome(1, "config: anthropic-api-key is empty (it also signs the gate's "
                          "review markers)")

    # Step 1: owner intent and freshness.
    state = gh.pull_state(ev.number)
    if not state.auto_merge:
        return Outcome(1, "enable auto-merge to request the AI gate")
    if (state.enabled_by or "").casefold() != cfg.owner.casefold():
        return Outcome(1, f"auto-merge must be enabled by {cfg.owner}")
    if state.head_sha != ev.head_sha:
        return Outcome(1, "stale: the PR head moved since this event")

    # Step 2: a check result lives on the head SHA, so a pass for a PR into
    # another branch would satisfy a later PR of the same head into main.
    # The live base: a re-run replays the original event payload.
    if not ev.default_branch or state.base_ref != ev.default_branch:
        return Outcome(1, f"the AI gate only reviews PRs into {ev.default_branch}")

    reviews = gh.reviews(ev.number)
    g = gather(gh, state.base_oid, ev)

    # Step 3: a push or a close/reopen while auto-merge stays on is not an
    # owner click: no model roll, only a carry-over of identical own changes.
    if ev.action in ("synchronize", "reopened"):
        if not _carries_over(reviews, ev, cfg.marker_key, g.own_hash):
            return Outcome(1, "the PR was pushed to or reopened after auto-merge was "
                              "enabled; disable and re-enable auto-merge to re-request review")
        return _report(gh, ev, cfg, _always_on(g, cfg), g.own_hash, "carry-over", reviews)

    # Step 4: the gate blocked this commit. Only the owner's dismissal of
    # that review clears it (GitHub forbids approving your own PR).
    blocks = _blocks_on_head(reviews, ev, cfg.marker_key)
    if blocks:
        if not _owner_dismissed(gh, ev, cfg.owner, blocks):
            return Outcome(1, f"the gate blocked this commit; {cfg.owner} must dismiss its "
                              "review to override, then re-run this check")
        return _report(gh, ev, cfg, _always_on(g, cfg), g.own_hash, "owner-override", reviews)

    # Step 5: any writer can re-run a check; only an owner click buys a roll.
    if ev.run_attempt > 1:
        return Outcome(1, "a re-run never asks the model again; dismiss the gate's review "
                          "to override, or disable and re-enable auto-merge for a fresh review")

    # Step 6: full review.
    result = full_review(g, cfg, review_fn, lambda: _text_contents(gh, ev, g.files))
    if result.infra:
        return Outcome(1, "infra: model call failed (" + ", ".join(result.infra)
                          + f"); {RETRY}")
    return _report(gh, ev, cfg, result, g.own_hash, "full", reviews)
