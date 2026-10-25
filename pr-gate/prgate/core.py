"""The gate's decision flow. Fails closed everywhere.

  1. auto-merge on, enabled by the owner, head not stale
  2. the PR targets the default branch; GitHub's test merge of this exact
     base and head exists (awaited briefly) and has no conflicts. Every
     later step reads the change as base...merge, i.e. what would land
  3. push / reopen: carry over iff the newest verified gate marker is a pass
     of these exact own changes; else fail
  4. a verified gate block on this head AND this landed change (own-changes
     hash): override (always-on checks only) iff the OWNER dismissed that
     review and the head has not moved since; else fail. A block of this
     head on an older base is stale: no override, no bar to a fresh review
  5. a re-run (run attempt > 1) never asks the model: fail
  6. full review: deterministic checks + model passes

Three kinds of failure, deliberately different:
  - procedural (steps 1-5, merge conflicts, unreadable diff): the check
    fails with a message and NO review is posted.
  - infra (GitHub or model API errors, a test merge GitHub has not
    computed in time): the check fails, no review. Not a
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
import time
from dataclasses import dataclass, field
from typing import Callable

from . import checks, verdict
from .diffparse import DiffError, FileChange, own_changes_hash, parse
from .github import GitHubError, Review, TooLarge
from .llm import EFFORTS, PASS_NAMES, STATUSES, PassResult, is_config_error

GATE_LOGIN = "github-actions[bot]"
ACTIONS = ("auto_merge_enabled", "synchronize", "reopened")
DIFF_LLM_CAP = 400_000        # bytes of diff the model passes may read
DIFF_HARD_CAP = 5_000_000     # bytes of diff the deterministic checks will read
CONTENTS_BUDGET = 400_000     # bytes of post-change file contents for Monitor B
FILE_FETCH_CAP = 25_000_000   # per binary file (magic bytes + content hash) or lockfile
GIT_BINARY_PEEK = 8000        # git's buffer_is_binary: a NUL in the first 8000 bytes
_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_SHA = re.compile(r"^[0-9a-f]{40}$")

RETRY = "disable and re-enable auto-merge to retry"
CONFLICTS = "the PR has merge conflicts; resolve them"
STALE_BLOCK = ("the gate blocked this commit, but the base has moved since and changed what "
               "would land, so that block and any dismissal of it no longer apply. A re-run "
               "never asks the model: disable and re-enable auto-merge for a fresh model review")
# GitHub computes the test merge in the background after a push or a base
# move: re-read with these pauses (30 s in all), then give up as infra.
MERGE_WAITS = (2, 4, 8, 16)
_sleep = time.sleep
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
    # The lockfile-hosts input: hostnames every lockfile accepts on top of
    # the built-in allowlists (checks.parse_lockfile_hosts).
    lockfile_hosts: frozenset[str] = frozenset()
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


def gather(gh, base_oid: str, ref: str) -> Gathered:
    """Fetch and parse the base_oid...ref diff; hash the PR's own changes.
    `ref` is the test merge commit, so file contents are what would land.

    Binary contents are fetched here because the hash needs them: the diff
    shows only "Binary files differ", which would let a binary change ride
    a carried-over pass. Parsed lockfiles (and line-checked ones renamed
    from another kind) are fetched whole, at `ref` and the live base, for
    the always-on lockfile check that every path runs.
    """
    diff_bytes = gh.diff(base_oid, ref, DIFF_HARD_CAP)
    return gather_from(diff_bytes,
                       lambda path: gh.file_content(path, ref, FILE_FETCH_CAP),
                       lambda f: _lockfile(gh, f, base_oid, ref))


def _lockfile(gh, f: FileChange, base_oid: str, ref: str) -> checks.Lockfile:
    """Contents at `ref` and the base; None where over the cap or (base) absent.
    The base is the old path of a rename only if that was the same kind of
    lockfile: any other file was never checked as one."""
    try:
        head_data = gh.file_content(f.path, ref, FILE_FETCH_CAP)
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
    binaries: dict[str, bytes] = {}
    for f in files:
        if f.status == "deleted":
            continue
        if f.binary:
            binaries[f.path] = fetch_binary(f.path)
        elif f.status == "renamed" and not f.body and not f.gitlink:
            # A pure (100%) rename or copy has no hunks and no "Binary files"
            # line: git says nothing about the content. Read it and decide as
            # git does (a NUL in the first 8000 bytes); a binary is then
            # checked and hashed under its new path like any other.
            data = fetch_binary(f.path)
            if b"\0" in data[:GIT_BINARY_PEEK]:
                f.binary = True
                binaries[f.path] = data
    lockfiles = {f.path: fetch_lockfile(f) for f in files if checks.fetched_lockfile(f)}
    # The hash reads the diff with every invalid byte kept distinct
    # (surrogateescape); "replace" maps them all to U+FFFD, so swapping one
    # for another would ride a carried-over pass. Same files, same order:
    # only the characters differ.
    exact = parse(diff_bytes.decode("utf-8", errors="surrogateescape"))
    if len(exact) != len(files):
        raise DiffError("diff parses differently")
    for f, e in zip(files, exact):
        e.binary = f.binary   # a pure rename found binary above
    digests = {e.path: hashlib.sha256(binaries[f.path]).hexdigest()
               for f, e in zip(files, exact) if f.path in binaries}
    return Gathered(diff_bytes, diff_text, files, binaries, own_changes_hash(exact, digests),
                    lockfiles)


def full_review(g: Gathered, cfg: Config, review_fn: ReviewFn,
                fetch_contents: Callable[[], tuple[dict[str, str], list[str]]], *,
                require_passes: bool = True) -> verdict.Result:
    """Step 6: every deterministic check, then the model passes. Fails
    closed unless exactly the three passes came back, each with a known
    status (anything but "ok" blocks in `decide`). `require_passes=False`
    is dry-run --no-llm only."""
    hits, scrutiny = checks.run_all(g.files, g.binaries, cfg.exceptions, g.lockfiles,
                                    extra_hosts=cfg.lockfile_hosts)
    passes: list[PassResult] = []
    asked = len(g.diff_bytes) <= DIFF_LLM_CAP
    if not asked:
        hits.append(checks.Hit("too-large", "(whole diff)",
                               f"diff is too large for the AI gate ({len(g.diff_bytes)} bytes, "
                               f"limit {DIFF_LLM_CAP}); human review", True))
    else:
        contents, omitted = fetch_contents()
        passes = review_fn(g.diff_text, contents,
                           [(s.path, s.reason) for s in scrutiny], omitted)
    result = verdict.decide(hits, scrutiny, passes, cfg.threshold)
    if require_passes and asked and not (
            sorted(p.name for p in passes) == sorted(PASS_NAMES)
            and all(p.status in STATUSES for p in passes)):
        result.reasons.append("reviewer passes missing or malformed")
        result.block = True
    return result


def _gate_reviews(reviews: list[Review], ev: Event, key: bytes):
    """Reviews carrying a VERIFIED gate marker. Anything else, including a
    github-actions[bot] review from another workflow, counts as no marker.
    Oldest first by review id (ids grow over time), whatever order the API
    returned: callers take the last one as the newest."""
    for r in sorted(reviews, key=lambda r: r.id):
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


def _blocks_on_head(reviews: list[Review], ev: Event, key: bytes,
                    own_hash: str | None) -> list[int]:
    """Review ids of the gate's verified blocks of this exact head commit
    and, unless own_hash is None, of this exact landed change. A block of
    the same head on an older base guarded a different merge: the owner's
    dismissal of it says nothing about this one."""
    return [r.id for r, m in _gate_reviews(reviews, ev, key)
            if m[0] == "block" and m[1] == ev.head_sha
            and (own_hash is None or m[2] == own_hash)]


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
                                    always_on_only=True, extra_hosts=cfg.lockfile_hosts)
    return verdict.decide(hits, scrutiny, [], cfg.threshold)


def _text_contents(gh, ref: str, files: list[FileChange]) -> tuple[dict[str, str], list[str]]:
    contents: dict[str, str] = {}
    omitted: list[str] = []
    left = CONTENTS_BUDGET
    for f in files:
        if f.status == "deleted" or f.binary or f.gitlink or f.new_mode == "120000":
            continue
        try:
            data = gh.file_content(f.path, ref, left)
        except TooLarge:
            omitted.append(f.path)
            continue
        left -= len(data)
        contents[f.path] = data.decode("utf-8", errors="replace")
    return contents, omitted


def _report(gh, ev: Event, cfg: Config, result: verdict.Result, own_hash: str,
            mode: str, reviews: list[Review]) -> Outcome:
    def body(dismissable: bool = True) -> str:
        return verdict.render_body(result, key=cfg.marker_key, repo=ev.repo, number=ev.number,
                                   head=ev.head_sha, own_hash=own_hash,
                                   threshold=cfg.threshold, model=cfg.model,
                                   effort=cfg.effort, mode=mode, dismissable=dismissable)

    if result.block:
        blocked = "blocked: " + "; ".join(result.reasons)
        try:
            gh.post_review(ev.number, ev.head_sha, "REQUEST_CHANGES", body())
        except GitHubError:
            gh.post_review(ev.number, ev.head_sha, "COMMENT", body(dismissable=False))
            return Outcome(1, f"{blocked}; {verdict.UNDISMISSABLE}")
        return Outcome(1, blocked)
    gh.post_review(ev.number, ev.head_sha, "COMMENT", body())
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


def _preflight(state, ev: Event, cfg: Config) -> Outcome | None:
    # Step 1: owner intent and freshness.
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
    return None


def _merge_ready(gh, ev: Event, cfg: Config):
    """The live PR state once GitHub's test merge is the merge of exactly
    this base and head, or the Outcome that ends the run. Steps 1-2 run on
    every read, so a procedural failure never waits."""
    for wait in (0, *MERGE_WAITS):
        if wait:
            _sleep(wait)
        state = gh.pull_state(ev.number)
        failed = _preflight(state, ev, cfg)
        if failed:
            return failed
        if state.mergeable == "CONFLICTING":
            return Outcome(1, CONFLICTS)
        if (state.mergeable == "MERGEABLE" and state.merge_sha
                and state.merge_parents == (state.base_oid, state.head_sha)):
            return state
    return Outcome(1, "infra: GitHub has not computed the PR's test merge of the current "
                      f"base and head; {RETRY}")


def _run(ev: Event, cfg: Config, gh, review_fn: ReviewFn) -> Outcome:
    if ev.action not in ACTIONS:
        return Outcome(1, "unsupported pull_request_target action; see the caller template")
    if not _SHA.match(ev.head_sha):
        return Outcome(1, "event has no valid head SHA")
    if not cfg.marker_key:
        return Outcome(1, "config: anthropic-api-key is empty (it also signs the gate's "
                          "review markers)")

    state = _merge_ready(gh, ev, cfg)
    if isinstance(state, Outcome):
        return state
    reviews = gh.reviews(ev.number)
    # What lands is the merge, not base...head: in a criss-cross history the
    # merge-base diff can hide a revert of an earlier PR. base_oid is a
    # parent of the merge, so this three-dot diff is the merge's own diff.
    # Content is read at the merge; identity (reviews, markers) is the head.
    g = gather(gh, state.base_oid, state.merge_sha)

    # Step 3: a push or a close/reopen while auto-merge stays on is not an
    # owner click: no model roll, only a carry-over of identical own changes.
    if ev.action in ("synchronize", "reopened"):
        if not _carries_over(reviews, ev, cfg.marker_key, g.own_hash):
            return Outcome(1, "the PR was pushed to or reopened after auto-merge was "
                              "enabled; disable and re-enable auto-merge to re-request review")
        return _report(gh, ev, cfg, _always_on(g, cfg), g.own_hash, "carry-over", reviews)

    # Step 4: the gate blocked this commit. Only the owner's dismissal of
    # that review clears it (GitHub forbids approving your own PR).
    blocks = _blocks_on_head(reviews, ev, cfg.marker_key, g.own_hash)
    if blocks:
        if not _owner_dismissed(gh, ev, cfg.owner, blocks):
            states = {r.state for r in reviews if r.id in blocks}
            if "CHANGES_REQUESTED" in states:
                return Outcome(1, f"the gate blocked this commit; {cfg.owner} must dismiss "
                                  "its review to override, then re-run this check")
            if "DISMISSED" not in states:  # only COMMENT blocks: not dismissable
                return Outcome(1, f"the gate blocked this commit; {verdict.UNDISMISSABLE}")
            # Dismissed already, and a review can be dismissed only once.
            return Outcome(1, "the gate blocked this commit and its review is already "
                              "dismissed, but that dismissal does not count: it was not "
                              f"by {cfg.owner}, or a force push or branch restore came "
                              "after the block. A review cannot be dismissed twice: push "
                              "a new commit to the PR, then disable and re-enable "
                              "auto-merge for a fresh review")
        return _report(gh, ev, cfg, _always_on(g, cfg), g.own_hash, "owner-override", reviews)

    # Step 5: any writer can re-run a check; only an owner click buys a roll.
    # No verified block on this head is left to dismiss here. If one was
    # posted, another workflow edited or removed it, and a blind toggle
    # would hand that edit a fresh model roll: send the owner to the PR.
    if ev.run_attempt > 1:
        if _blocks_on_head(reviews, ev, cfg.marker_key, None):
            return Outcome(1, STALE_BLOCK)
        return Outcome(1, "a re-run never asks the model again, and this commit has no "
                          "verified gate block to override. If an earlier run blocked it, "
                          "that review was edited or removed: look at the PR before "
                          "anything else. Disabling and re-enabling auto-merge starts a "
                          "fresh model review")

    # Step 6: full review.
    result = full_review(g, cfg, review_fn,
                         lambda: _text_contents(gh, state.merge_sha, g.files))
    if result.infra:
        failed = ", ".join(result.infra)
        if any(p.status == "infra" and is_config_error(p.reason) for p in result.passes):
            return Outcome(1, f"config: the model API rejected the request ({failed}); "
                              "check the model name, the anthropic-api-key secret and the "
                              "PR size (a prompt too long needs a smaller PR). Retrying "
                              "will not help until that is fixed")
        return Outcome(1, f"infra: model call failed ({failed}); {RETRY}")
    return _report(gh, ev, cfg, result, g.own_hash, "full", reviews)
