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
    verdict on the PR; an owner auto-merge toggle retries. A model 4xx other
    than 408/409/429 (model name, key, prompt size), or a timeline 403/404
    (no `issues: read`), is reported as a config error instead: retrying
    the same request cannot help.
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
from .llm import EFFORTS, PassResult, is_config_error

GATE_LOGIN = "github-actions[bot]"
ACTIONS = ("auto_merge_enabled", "synchronize", "reopened")
DIFF_LLM_CAP = 400_000        # bytes of diff the model passes may read
DIFF_HARD_CAP = 5_000_000     # bytes of diff the deterministic checks will read
CONTENTS_BUDGET = 400_000     # bytes of post-change file contents for Monitor B
FILE_FETCH_CAP = 25_000_000   # per binary file (magic bytes + content hash) or lockfile
_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_SHA = re.compile(r"^[0-9a-f]{40}$")

RETRY = "disable and re-enable auto-merge to retry"
# The timeline answers 403/404 on every run without `issues: read`, and
# the fix is a workflow change the gate blocks, whose override needs the
# timeline: "toggle to retry" would loop.
NO_TIMELINE = ("config: the gate cannot read the PR timeline (who dismissed a review): "
               "the calling workflow lacks `issues: read` (setup step 1, "
               "caller-example.yml). Retrying will not help. The workflow fix is a "
               ".github/ change this gate blocks, and overriding that block needs the "
               "timeline too: land the fix through the owner's ruleset bypass, or by "
               "removing the required ai-gate check for that one merge and restoring it")

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
    lockfiles: dict[str, checks.Lockfile]


def gather(gh, base_oid: str, ev: Event) -> Gathered:
    """Fetch and parse the base_oid...head diff; hash the PR's own changes.

    Binary contents are fetched here because the hash needs them: the diff
    shows only "Binary files differ", which would let a binary change ride
    a carried-over pass. Parsed lockfiles (and line-checked ones renamed
    from another kind) are fetched whole, head and live base, for the
    always-on lockfile check that every path runs.
    """
    diff_bytes = gh.diff(base_oid, ev.head_sha, DIFF_HARD_CAP)
    return gather_from(diff_bytes,
                       lambda path: gh.file_content(path, ev.head_sha, FILE_FETCH_CAP),
                       lambda f: _lockfile(gh, f, base_oid, ev.head_sha))


def _lockfile(gh, f: FileChange, base_oid: str, head: str) -> checks.Lockfile:
    """Head and base contents; None where over the cap or (base) absent.
    The base is the old path of a rename only if that was the same kind of
    lockfile: any other file was never checked as one."""
    try:
        head_data = gh.file_content(f.path, head, FILE_FETCH_CAP)
    except TooLarge:
        head_data = None
    if checks.renamed_from_other_kind(f):
        return checks.Lockfile(head_data, None)
    try:
        base_data = gh.file_content(f.old_path or f.path, base_oid, FILE_FETCH_CAP)
    except TooLarge:
        base_data = None
    except GitHubError as e:
        if e.status != 404:
            raise
        base_data = None
    return checks.Lockfile(head_data, base_data)


def gather_from(diff_bytes: bytes, fetch_binary: Callable[[str], bytes],
                fetch_lockfile: Callable[[FileChange], checks.Lockfile]) -> Gathered:
    if len(diff_bytes) > DIFF_HARD_CAP:
        raise TooLarge("diff")
    diff_text = diff_bytes.decode("utf-8", errors="replace")
    files = parse(diff_text)
    binaries = {f.path: fetch_binary(f.path) for f in files if f.binary and f.status != "deleted"}
    lockfiles = {f.path: fetch_lockfile(f) for f in files if checks.fetched_lockfile(f)}
    # The hash reads the diff with every invalid byte kept distinct
    # (surrogateescape); "replace" maps them all to U+FFFD, so swapping one
    # for another would ride a carried-over pass. Same files, same order:
    # only the characters differ.
    exact = parse(diff_bytes.decode("utf-8", errors="surrogateescape"))
    if len(exact) != len(files):
        raise DiffError("diff parses differently")
    digests = {e.path: hashlib.sha256(binaries[f.path]).hexdigest()
               for f, e in zip(files, exact) if f.path in binaries}
    return Gathered(diff_bytes, diff_text, files, binaries, own_changes_hash(exact, digests),
                    lockfiles)


def full_review(g: Gathered, cfg: Config, review_fn: ReviewFn,
                fetch_contents: Callable[[], tuple[dict[str, str], list[str]]]) -> verdict.Result:
    """Step 6: every deterministic check, then the model passes."""
    hits, scrutiny = checks.run_all(g.files, g.binaries, cfg.exceptions, g.lockfiles)
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
    head, as far as the timeline can show it, scanned in order. A force
    push or branch restore after a block was posted voids it: the head can
    only leave a blocked commit and come back to it by a rewrite. (A plain
    push moves the head off it, so step 4 never sees that block again.)
    `committed` events are not read: GitHub places them at the commit's
    own, writer-chosen date, so a future-dated head would void every
    dismissal. A dismissal of a block the timeline never showed being
    posted is ignored.
    """
    posted: set[int] = set()
    ok = False
    for e in gh.timeline(ev.number):
        if e.kind == "reviewed" and e.review_id in review_ids:
            posted.add(e.review_id)
        elif (e.kind == "dismissed" and e.review_id in posted
              and e.actor.casefold() == owner.casefold()):
            ok = True
        elif e.kind == "rewrite":
            posted.clear()
            ok = False
    return ok


def _always_on(g: Gathered, cfg: Config) -> verdict.Result:
    hits, scrutiny = checks.run_all(g.files, g.binaries, cfg.exceptions, g.lockfiles,
                                    always_on_only=True)
    return verdict.decide(hits, scrutiny, [], cfg.threshold)


def _text_contents(gh, ev: Event, files: list[FileChange]) -> tuple[dict[str, str], list[str]]:
    contents: dict[str, str] = {}
    omitted: list[str] = []
    left = CONTENTS_BUDGET
    for f in files:
        if f.status == "deleted" or f.binary or f.gitlink or f.new_mode == "120000":
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
        # The pass stands: those blocks guard older commits only, so leaving
        # them is the restrictive side. Never send the owner to dismiss one:
        # a dismissal IS the override, and would count if that head returned.
        retry = ("re-run this check (no model call)" if mode != "full" else
                 "a re-run of this check would fail; the next auto-merge toggle "
                 "retries, with a fresh model review")
        msg += ("; earlier gate reviews could not be dismissed; never dismiss a gate "
                "review by hand, a dismissal is an override. Check that GitHub Actions "
                f"may dismiss reviews (setup step 2), then {retry}")
    return Outcome(0, msg)


def run(ev: Event, cfg: Config, gh, review_fn: ReviewFn) -> Outcome:
    try:
        return _run(ev, cfg, gh, review_fn)
    except GitHubError as e:
        if e.op == "timeline" and e.status in (403, 404):
            return Outcome(1, NO_TIMELINE)
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
            # A review can be dismissed only once.
            if all(r.state == "DISMISSED" for r in reviews if r.id in blocks):
                return Outcome(1, "the gate blocked this commit and its review is already "
                                  "dismissed, but that dismissal does not count: it was not "
                                  f"by {cfg.owner}, or a force push or branch restore came "
                                  "after the block. A review cannot be dismissed twice: push "
                                  "a new commit to the PR, then disable and re-enable "
                                  "auto-merge for a fresh review")
            return Outcome(1, f"the gate blocked this commit; {cfg.owner} must dismiss its "
                              "review to override, then re-run this check")
        return _report(gh, ev, cfg, _always_on(g, cfg), g.own_hash, "owner-override", reviews)

    # Step 5: any writer can re-run a check; only an owner click buys a roll.
    # No verified block on this head is left to dismiss here. If one was
    # posted, another workflow edited or removed it, and a blind toggle
    # would hand that edit a fresh model roll: send the owner to the PR.
    if ev.run_attempt > 1:
        return Outcome(1, "a re-run never asks the model again, and this commit has no "
                          "verified gate block to override. If an earlier run blocked it, "
                          "that review was edited or removed: look at the PR before "
                          "anything else. Disabling and re-enabling auto-merge starts a "
                          "fresh model review")

    # Step 6: full review.
    result = full_review(g, cfg, review_fn, lambda: _text_contents(gh, ev, g.files))
    if result.infra:
        failed = ", ".join(result.infra)
        if any(p.status == "infra" and is_config_error(p.reason) for p in result.passes):
            return Outcome(1, f"config: the model API rejected the request ({failed}); "
                              "check the model name, the anthropic-api-key secret and the "
                              "PR size (a prompt too long needs a smaller PR). Retrying "
                              "will not help until that is fixed")
        return Outcome(1, f"infra: model call failed ({failed}); {RETRY}")
    return _report(gh, ev, cfg, result, g.own_hash, "full", reviews)
