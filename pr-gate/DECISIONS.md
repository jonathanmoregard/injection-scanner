# pr-gate v1: builder decisions

Decisions the design left to the builder, or where the build deviates from
it, each with the reason. Design: `docs/superpowers/specs/2026-10-24-pr-gate-design.md`.

## Deviations from the design text

1. **The own-changes hash keeps context lines.** The design says "added and
   removed lines, no context lines, no hunk offsets". Without context, moving
   an added line (say `return True`) from a harmless function into
   `verify_signature()` leaves both lists identical, so a push doing exactly
   that would carry a pass over unreviewed. The hash therefore covers the hunk
   bodies (context, `+` and `-` lines in order) with only the `@@` headers
   dropped. A base merge still carries over unless the base changed lines
   within three lines of the PR's own changes; then the owner re-clicks
   (fail-safe direction).
   **Accepted v1 residual:** with the offsets dropped, a hunk moved to
   another spot whose three context lines above and below are identical
   (repeated boilerplate, say two `except ...: return True` blocks) hashes
   the same, so a push that moves an added line there carries the earlier
   pass over unreviewed. Accepted because putting offsets back would break
   carry-over on every base merge that adds lines above the change, and
   base-merge carry-over is an owner directive; the move also needs
   byte-identical surroundings. Follow-up idea: hash each touched region
   with wider context (e.g. the enclosing function, or N lines until the
   context is unique in the file) instead of the fixed three lines.
2. **Binary content is in the hash** (SHA-256 of the blob at the test merge, fetched
   anyway for the magic-byte check). The diff shows only "Binary files
   differ", so without it a swapped binary would ride a carried-over pass.
   File modes and renames are in the hash too. The hash reads the diff
   bytes decoded with `surrogateescape`, so every invalid UTF-8 byte stays
   distinct (JSON with `ensure_ascii` keeps the surrogates apart); the
   model and the checks get the `replace`-decoded text, where any invalid
   byte is U+FFFD and a swap of one for another would look identical.
   Valid UTF-8 decodes the same both ways, so existing hashes are unchanged.
   The `\ No newline at end of file` marker is part of the hunk body in
   the hash (never an added or removed line), so a push that only adds or
   drops a file's final newline does not carry a pass over. Diffs without
   the marker hash exactly as before.
3. **A declined pass blocks.** The server-side refusal fallback is enabled
   (`fallbacks: "default"`), but if the configured model declines and a
   fallback model answers, the run blocks ("reviewer declined (policy)").
   Otherwise a PR could steer review away from Fable to a weaker fallback by
   provoking a policy decline. The fallback's findings are still shown.
4. **No text-JSON fallback** for models without structured outputs: both
   target models support them, and a 400 from an unsupported model is a
   config failure (check fails, no review; item 6). Output is still parsed
   and validated in code.
5. **Exceptions also never cover `.github/actions/`** (local actions run
   inside workflows, same power as `.github/workflows/`).

## Failure classes

6. Three classes, deliberately different:
   - *Procedural* (no auto-merge, wrong enabler, stale head, base not the
     default branch, merge conflicts, push after auto-merge, a block on
     this head the owner has not dismissed, a re-run, unreadable or over-5
     MB diff): check fails, **no review**.
   - *Infra* (GitHub or Anthropic API errors, missing key, a test merge of
     the live base and head not computed within 30 s): check fails, no
     review. A transport error is not a verdict. The retry is an auto-merge
     toggle, since a re-run never asks the model. A model API 4xx other than
     408/409/429 (bad model name or key, prompt too long) is reported as a
     *config* error with that diagnosis instead of "toggle to retry": the
     same request fails the same way every time. Still fail closed, no
     review; the reason is the closed `api-status-<code>` vocabulary, never
     the provider's error body. Likewise a timeline 403/404: the caller
     lacks `issues: read`, every run fails the same way, and the fix is a
     workflow change the gate blocks whose override needs the timeline, so
     "toggle to retry" would loop. The fixed message names the missing
     permission and the way out (the owner's ruleset bypass, or removing
     the required check for that one merge).
   - *Verdict* (including refusal, `max_tokens`, malformed or out-of-range
     output): REQUEST_CHANGES review. These are outcomes on the PR's
     content; only the owner's dismissal overrides them.
7. Messages and annotations use a closed vocabulary: gate-written reasons,
   validated owner login, SHAs, bounded HTTP status codes, exception class
   names. No exception message, HTTP body or model text is printed.

7a. **A pass that cannot dismiss the gate's earlier blocks still passes**
    (exit 0). Those blocks guard older commits only, so leaving them is the
    restrictive side. The message never tells the owner to dismiss them by
    hand: dismissing a gate review IS the override, and a hand dismissal of
    an old head's block would count if the PR ever returned to that commit
    without a rewrite event. It says the reviews could not be dismissed,
    warns against dismissing them by hand, points at the dismissal
    permission (setup step 2), and says how to retry: re-run the check after
    a carry-over or override pass (no model call); after a full review a
    re-run would fail (step 5), so the retry is the next auto-merge toggle,
    which is a fresh model review.

## Flow details

8. **Model passes run even when a deterministic check already blocks.**
   Otherwise an owner override of, say, a `.github/` change would merge the
   rest of the PR without any model review.
9. **Size caps.** Diff over 400 kB: the model passes are skipped and a
   `too-large` hit (owner-overridable) blocks. The deterministic checks still
   read diffs up to 5 MB; beyond that, or when GitHub refuses the compare
   diff with 406 (its own size limits), the run fails procedurally with
   "split the PR", not as a retryable infra error. Monitor B
   gets up to 400 kB of post-change contents; files past the budget are
   listed to the model as omitted. Binaries are fetched up to 25 MB.
10. **Block on this head** = a review by `github-actions[bot]` whose body
    starts with a VERIFIED gate marker `verdict=block` whose (MAC'd) head is
    this head AND whose (MAC'd) own-changes hash is the hash of what would
    land now (item 27), in any state (dismissed or COMMENT-fallback
    included). An unverifiable block marker is not a block.
    **The hash too, not only the head:** the override passes on the
    always-on checks only, so it must apply to the change the model and
    the owner saw. If the base moves between the block and the dismissal,
    the same head merges into a different result (a criss-cross revert
    can land exactly this way), which neither saw. A verified block of
    this head with another own-changes hash is stale: it neither enables
    an override nor stops a fresh review. A re-run (step 5) fails with
    fixed text saying the base moved and to toggle auto-merge
    (`STALE_BLOCK`); the owner's toggle reaches step 6, a fresh model
    review of the current landed diff, and a pass then dismisses the
    stale block like any earlier one. A base move elsewhere that leaves
    the landed change's hash alone keeps the override.
10a. **A COMMENT-fallback block says it cannot be dismissed.** GitHub
    cannot dismiss a COMMENT review (the dismissals endpoint answers 422),
    so "dismiss to override" would leave the owner stuck. No new override
    mechanism: when the block goes out as a COMMENT, the review body and
    the check message say, in fixed text (`verdict.UNDISMISSABLE`), that
    it cannot be dismissed and that the only way past a false alarm is the
    owner's ruleset bypass or temporarily removing the required check.
    Step 4 says the same when every verified block on the head is a
    COMMENT; "must dismiss" only when one is still CHANGES_REQUESTED.
11. **Owner override = dismissal, not approval** (replaces the earlier
    approve-then-re-run rule). The run passes on the always-on checks only
    if the issue timeline has a `review_dismissed` event whose
    `actor.login` is the owner (casefolded) and whose
    `dismissed_review.review_id` is one of the blocks on this head
    (paginated, fail closed), and the head has provably not moved since
    (item 11a). Why: GitHub forbids approving your own PR, so
    approval could never clear a block on a PR authored as the owner, which
    is common when agents act as the owner; and three review rounds kept
    finding holes in the review-state guard (approval ordering, forged,
    edited or bot-dismissed bot reviews, carry-over after an override). A
    review's state says nothing about who dismissed it; the timeline does.
11a. **A dismissal counts only while the head stayed put.** One ordered
    timeline scan (reviewed, review_dismissed, head_ref_force_pushed,
    head_ref_restored; a malformed relevant event fails closed): the
    owner's dismissal of a block on this head counts iff the timeline shows
    that block being posted and no force push or branch restore follows the
    block's posting. Why: otherwise a stale dismissal is a permanent token
    (block H, push a clean H2 that passes, owner dismisses the stale block,
    push back to H, re-run). Leaving a commit and coming back to it always
    takes a rewrite, and rewrite, review and dismissal events carry server
    timestamps. `committed` events are not read at all: GitHub places one
    at the commit's own, writer-chosen date, not at push time. An earlier
    "a `committed` event after the dismissal voids it" rule protected
    nothing: while the head is still the blocked commit H, a `committed`
    event after the dismissal can only be one of H's own ancestry sorted
    late by its date (anything else got there by a rewrite, which already
    voids), and a plain push moves the head off H, so step 4 never sees
    that block. It only let a future-dated head commit (or writer clock
    skew) void every owner dismissal, with no fresh review either, since
    step 4 comes before step 6.
12. **Re-runs never ask the model** (replaces "any bot REQUEST_CHANGES arms
    the guard" and the same-own-changes reroll guard). With
    `GITHUB_RUN_ATTEMPT` > 1 and no override, the run fails with no model
    call. Re-runs are something any writer can start; an owner auto-merge
    click starts a new run (attempt 1). This bounds the reroll budget to
    owner clicks, so an amend/rebase to a new SHA with the same changes no
    longer needs its own guard: it fails on `synchronize` and gets a fresh
    review only when the owner toggles auto-merge.
13. **Carry-over** looks only at the NEWEST verified gate marker (by review
    id, which grows over time, not by the order the API lists them), pass or
    block: it carries over iff that marker is a pass with an identical
    own-changes hash. Nothing else (the "ever blocked + owner approved its
    head" rule is gone): markers are HMAC-signed, so a pass can't be
    minted, and a replayed real pass only re-asserts content a model or the
    owner passed; the reroll budget is bounded by item 12. Owner override
    and carry-over passes also record their hash, so repeated "Update
    branch" clicks after an override keep carrying over. `reopened` is
    handled exactly like `synchronize`.
14. **Base = default branch** (from the event's `repository.default_branch`),
    compared to the PR's LIVE `baseRefName` from the GraphQL pull state, not
    the event payload (a re-run replays the payload). A check result is
    attached to the head SHA; a pass on a PR into another branch would
    otherwise satisfy a later PR of the same head into the default branch.
15. **No token input.** The gate always uses `github.token`, so its reviews
    are by `github-actions[bot]`, the only login it trusts (`GATE_LOGIN`).
    A custom token would post reviews the next run ignores. Caller
    permissions: `contents: read`, `pull-requests: write`, `issues: read`
    (the timeline is an issues endpoint). The test merge (item 17a) needs
    nothing new: its oid and parents come with the GraphQL pull state, its
    diff and contents through the same compare and contents calls.
16. **Always-on checks run on carry-over and override runs**: exactly the
    non-overridable hits (hidden Unicode, lockfile host, text-binary).
17. The diff is `compare/<baseRefOid>...<test merge SHA>`: the base
    branch's current tip as a commit oid read live from GraphQL and
    validated as 40-hex (else fail closed), against GitHub's test merge of
    the head into it (item 17a). Never a branch name: a writer can push a
    tag named like the base branch, and a name could resolve to it, making
    the reviewed diff attacker-chosen.
17a. **The merge result, not the merge-base diff** (replaces
    `compare/<baseRefOid>...<head SHA>`). A three-dot compare against the
    head diffs from the merge base, but with a criss-cross history git
    merges from a virtual merge base, so what lands can differ. Reproduced:
    a head that merged an already-landed PR's tip with `-s ours` (keeping
    the file that PR fixed at its old content) plus a benign commit shows
    only the benign file in `base...head`, while the real merge also
    reverts the fix. Standard design: review the would-be merge result.
    The GraphQL pull state now also reads `mergeable` and
    `potentialMergeCommit { oid parents }` in the same query as head and
    base (the REST `merge_commit_sha`, with its parents, in one consistent
    snapshot and one call instead of two; same commit, checked on a live
    PR). The run proceeds only when `mergeable` is `MERGEABLE` and the
    merge's parents are exactly `[baseRefOid, head SHA]` as read in that
    same snapshot; otherwise it re-reads after 2, 4, 8 and 16 s (GitHub
    computes the test merge in the background after a push or base move)
    and then fails as infra. `CONFLICTING` fails at once, procedurally:
    "the PR has merge conflicts; resolve them". Any other `mergeable`
    value reads as `UNKNOWN`; a malformed merge oid or parent fails the
    pull-state read closed. Steps 1-2 run on every re-read, so a stale
    head or a missing auto-merge never waits. Since the base is a parent
    of the merge, `base...merge` is the merge's own two-dot diff: exactly
    the tree change that lands. Every CONTENT read (binaries, lockfiles at
    the PR side, Monitor B contents) uses the merge SHA; everything about
    identity (the review's `commit_id`, markers, blocks on this head, the
    stale check) stays on the head SHA. The own-changes hash is over this
    diff; after "Update branch" the head already contains the base, so the
    merge's tree is the head's and the hash matches a pass of the same own
    changes as before. Rebase-merge replays commits and can land a
    different tree; the README says to turn it off (a residual if left on).
    Dry-run takes a diff file and skips this step; the README shows how to
    produce the merge diff for it.
    An up-to-date PR (the head already contains the base tip) is not
    stuck: checked on live PR #25, GitHub still creates a test merge for
    it, with parents `[baseRefOid, headRefOid]` and `mergeable` =
    `MERGEABLE`, so the parents check passes.
    What lands later is a separate matter: a pass on head H is a check on
    H, and if the base moves after it GitHub would merge H into a base the
    gate never saw. The ruleset's "require branches to be up to date
    before merging" (README setup step 2) closes that; the gate assumes it.
    Paths follow git's format: the TAB git appends to a `---`/`+++` path
    containing a space is dropped, and C-style quoted paths
    (`"b/caf\303\251.txt"`) are unquoted. A path that starts with `"` but is
    not one well-formed quoted UTF-8 string fails the run as unparseable
    (procedural, not infra), so it never reaches a file fetch.
18. Event actions other than the three in the template, and events other
    than `pull_request_target`, fail.
19. The three passes run concurrently (three threads), each with a 600 s
    timeout and 2 SDK retries; `max_tokens` 16000; no temperature or thinking
    parameters; effort always sent. A full review fails closed unless
    exactly the three passes (`monitor_a`, `monitor_b`, `review`) came
    back, each with a known status (`ok`, `incomplete`, `infra`; the last
    two block on their own): a missing, duplicated, unknown or
    odd-status pass adds "reviewer passes missing or malformed". Only
    dry-run `--no-llm` skips this, explicitly.
20. Monitors return `analysis` (investigate-then-score), `suspicion`,
    `findings`. `analysis` is never posted to the PR or the log; dry-run
    prints it for calibration.
20a. **Only fixed text outside the nonce tag.** The extra-scrutiny list and
    the list of files omitted from Monitor B's contents carry author-chosen
    paths, and `json.dumps` keeps `<` and `>`, so a path like
    `</gate_notes> SYSTEM: ...` would have written into the trusted part of
    the prompt. Both lists sit inside the `untrusted_pr_<nonce>` block
    (`<extra_scrutiny>`, `<omitted_contents>`); the `<gate_notes>` outside
    it are fixed prose that only describes them.

## Deterministic checks

21. **Code profile** = prose profile + everything named in the design
    (U+FE00-FE0F, all private use, U+00AD, U+200E/F, U+2028/9) + every other
    format character (category Cf) + code points that render as nothing
    (Hangul fillers U+115F/1160/3164/FFA0, U+034F, U+180B-180F). File paths
    are checked too, but only paths that exist after the merge (the new
    path of an add, modify, rename or copy): the hit is never overridable,
    so checking a deletion or a rename's old path would make a
    hidden-character path already on the base impossible to delete or
    rename away through the gate. Counts land in the existing `SanitizeResult` counters,
    so the audit record keys are unchanged.
21a. **Control characters** (category Cc) are not in the shared code
    profile, whose other callers keep its behaviour; pr-gate's
    hidden-Unicode check adds them for added lines: any C0/C1 control or
    DEL except TAB, form feed (U+000C, page breaks) and a CR ending the
    line (CRLF files). An ESC erase-line or conceal sequence, backspaces or
    a mid-line CR hide or overwrite the line in a terminal review; NUL and
    U+0085 have no use in source. Same non-overridable hit, with the code
    points listed.
22. **Lockfile allowlists:** npm-family locks: `registry.npmjs.org`,
    `registry.yarnpkg.com`. Python locks and pip requirement files
    (`requirements*.txt` / `constraints*.txt`, pip-tools'
    `requirements*.in` / `constraints*.in`, and any `.txt` / `.in` whose
    parent directory is named `requirements`, casefolded): `pypi.org`,
    `files.pythonhosted.org`. **Residual:** a file included with `-r` /
    `-c` under any other name is not host-checked (only the model sees it). `Cargo.lock`:
    `github.com` (crates.io index), `index.crates.io`, `static.crates.io`.
    `flake.lock`: `github.com`, `channels.nixos.org`, `releases.nixos.org`;
    flake input types other than github/git/tarball/file/path/indirect and
    any `"host"` outside the list are hits. `Gemfile.lock`: `rubygems.org`.
    Schemes must be https-based or ssh; plain `http`/`git`/`ftp`/`file`
    are hits. A URL is a scheme from a fixed set (http, https, ftp, ws, wss,
    git, ssh, file, or `<word>+` one of those, case-insensitive) followed by
    `:` and ANY run of `/` or `\` (even none, as WHATWG/npm parse it), then
    the authority up to `/ \ ? #`, whitespace or a quote; any other
    `scheme://` counts too. Scheme candidates are scanned one `word:` at a
    time, so a junk prefix (`x:https://evil.x`) can't hide the URL after it.
    A candidate (URL scheme or hosted-git protocol) preceded by a letter,
    digit, `+ . -` or `/` is not one: it is the end of a word or of a path
    segment, as in Berry's `link:../ws::locator=...`, where `ws:` would
    otherwise read as the WebSocket scheme. No consumer fetches a URL that
    starts mid-path.
    Bracketed IPv6 hosts reach the host check (never allowlisted).
    git's scp-like remote `user@host:path` (no scheme, no slashes, as in a
    Gemfile.lock `remote: git@evil.x:o/r.git`) is an ssh fetch too: its
    host is checked against the same allowlist and the user must be `git`
    (`git@github.com:o/r` passes where github.com is allowlisted). To keep
    `name@version` and `git@npm:^1` out, the host must be dotted with a
    top label starting with a letter, IPv4 or `[IPv6]`, a path must
    follow the `:` (so a yarn v1 key line `x@1.0.0-alpha.beta:` is not
    one), and a user right after `/ : @` is inside a URL, which the URL
    check reads. **Residual:** an scp remote to a dotless host
    (`git@intranet:o/r`) is not recognised.
    Per-line formats (below) decode JSON/TOML/YAML string escapes (`\/`,
    `\uXXXX`, `\UXXXXXXXX`, `\xXX`, the one-letter ones) before the check;
    an escape the decoder does not know, on a line with a scheme-like
    token, is a hit (fail closed). An added per-line lockfile line ending in
    a backslash-newline continuation is a hit on its own: an odd trailing
    backslash run (trailing whitespace ignored; an even run is escaped
    backslashes). In pip requirement files pip joins on any trailing run, so
    parity does not count there; instead a run preceded by whitespace is
    fine, which is how pip-compile writes its `pkg==1.0 \` / `--hash=... \`
    lines and which cannot glue a URL together.
    pip requirement lines are also checked the way pip reads their options
    (`req/req_file.py`): comment dropped, everything from the first token
    starting with `-` shlex-split (quotes joined, backslashes dropped), and
    a value attached to a short option that takes one (`-i -f -e -r -c`,
    the URL-taking options in pip's `SUPPORTED_OPTIONS`; optparse accepts
    `-ihttps://evil.x`) split off before the URL check. `--index-url=`,
    `--extra-index-url=`, `--find-links=` and `--editable=` already put
    the URL after `=`. Options shlex cannot split are a hit: pip refuses
    that line too. The requirement part before the options is not
    shlex-split, as in pip (markers use quotes).
22a. **Lockfiles are parsed, not read line by line** (replaces the round-6
    rule that joined consecutive added lines). Re-implementing YAML/TOML
    string folding line by line kept losing: a blank line inside a YAML
    block scalar, or a double-quoted scalar folding across a blank line,
    rebuilt `https://registry.npmjs.org` + `.evil.x` past it. So, as
    lockfile-lint does, the gate parses the file and checks parsed values.
    For each added, modified or renamed JSON lockfile (`package-lock.json`,
    `npm-shrinkwrap.json`, `Pipfile.lock`, `flake.lock`, and `bun.lock`
    after dropping trailing commas outside strings, its only JSONC feature
    in practice; a comment does not parse), TOML lockfile (`Cargo.lock`,
    `uv.lock`, `poetry.lock`, `pdm.lock`; `tomllib`) or YAML lockfile
    (`pnpm-lock.yaml`, `yarn.lock`; PyYAML's safe loader, libyaml when
    present), core fetches the whole file at the head and at the live base
    oid (a 404 there means "not in the base"; any other error is infra).
    For a rename or copy the base is the old path only if it is the same
    kind of lockfile (same lockfile name, or both `requirements`-style);
    from any other path there is no base: PR 1 adding
    `tests/fixtures/lock.json` (not a lockfile name, so never checked) and
    PR 2 renaming it unchanged to `package-lock.json` would otherwise diff
    the file against itself and find nothing new. A line-checked lockfile
    renamed from another kind is fetched and every line of it checked,
    since a rename shows only the lines it changed. Every string, mapping keys included, gets
    the URL/host/userinfo/scheme checks above after WHATWG normalisation
    (tab/CR/LF stripped, backslash to slash). A string holding a line break
    (U+0085/2028/2029 included), a tab or another control character is a
    finding on its own: generated lockfiles have none, and a URL with one
    is a different URL to WHATWG/rust-url. `flake.lock` input `type`/`host`
    are read from the parsed `nodes.*.locked` / `nodes.*.original`, not by
    regex. Findings are counted (a multiset) and only those NEW relative to
    the base are hits, so a value already on the default branch does not
    block every later lockfile change, while one more package pointing at
    that same host does. A finding is keyed on the WHOLE offending value
    (the string, or for a structural finding the JSON of the slot or flake
    node), not on its host: keyed on the host, repointing an already-bad
    `git+ssh://git@github.com/trusted/x` to `.../evil/x` added nothing.
    The hit still reports only what is wrong (the host). Cost: in a repo
    whose lockfile already uses a non-allowlisted host, every change to
    one of those entries (a version bump) is a hit, not only a new one.
    All are non-overridable `lockfile-host` hits,
    including "lockfile does not parse" (head only; a base that does not
    parse counts as having no findings) and "lockfile too large to check"
    (over the 25 MB fetch cap; no lockfile in this repo or its fixtures
    comes near it). To close parser differentials, duplicate keys (JSON,
    YAML) do not parse, since parsers disagree on which one wins, and
    neither does a YAML alias (a container reached twice; that also stops
    alias bombs); YAML `!!binary` values are checked as UTF-8 text, since a
    JS consumer stringifies them. Any other value that is not a mapping,
    list, string or a string-free scalar (number, bool, null, date or
    time), such as a YAML `!!set`, does not parse either: the string walk
    would not look inside it. Escape decoding is the parser's job.
    pip requirement files (pip reads per line) and `Gemfile.lock` (no
    multi-line strings) stay on the per-line check. `yarn.lock` with the
    `# yarn lockfile v1` header (yarn's own test for the format) is checked
    per line AND, where PyYAML parses it, as YAML: classic yarn falls back
    to reading a lockfile as YAML when its own parser fails, so the header
    alone does not decide which reading applies. Without the header it is
    Berry's YAML and must parse. **Residual:** a construct Python's parser
    and the package manager's read differently (beyond the ones closed
    above) is a gap, and so is yarn's YAML reading of a v1 yarn.lock that
    PyYAML cannot parse. Owner-override and carry-over runs check the same
    contents, fetched in `gather` like binaries; the check itself stays a
    pure function over them.
22b. **npm-family package specs.** npm/pacote, yarn, pnpm and bun fetch
    `"resolved": "github:atk/x#sha"` (or `gitlab:`, `bitbucket:`, `gist:`,
    or a bare `atk/x#sha`) from that host, and no URL appears, so the URL
    check alone saw nothing. In `package-lock.json`,
    `npm-shrinkwrap.json`, `bun.lock`, `yarn.lock` and `pnpm-lock.yaml`,
    two more rules feed the same base-relative multiset:
    (a) every string: a hosted-git protocol anywhere
    (`[x+]git|github|gitlab|bitbucket|gist[+x]:`, not followed by
    whitespace, so prose like `Deprecated: use b` is not one), and a
    leading `word:` that is neither a URL scheme nor in the safe set
    `npm: workspace: catalog: patch: file: link: portal:` (the last three
    only with a relative path: no leading `/ \ ~`, no `:` before any `#`
    or `::` params). Applied to npm-family files only: Python lockfiles
    are full of `sha256:` hashes.
    (b) every fetch slot must be an https URL (the URL check judges its
    host) or local: package-lock `packages.*.resolved` (a bare relative
    path only with `link: true`, as npm writes workspace links; else
    `file:` + relative path) and lockfile v1 `dependencies.*.resolved` at
    any depth; pnpm `packages.*.resolution` (no `repo`, `type` absent or
    `directory`, `tarball` https or `file:` relative, `directory`
    relative); bun `packages.*[0]` `name@spec` (a version, an https URL or
    a safe protocol) and, for a registry entry, `[1]` empty or https;
    Berry `resolution` (same spec rule); yarn v1 `resolved` lines (per
    line, with the hosted-git rule). Strings with `%` are also checked
    percent-decoded, since Berry encodes a custom tarball URL as
    `npm:1.0.0::__archiveUrl=https%3A%2F%2F...`.
    Deviation from the brief: `file:` + relative path is accepted in npm
    `resolved` without `link: true`, because npm writes exactly that for
    a local tarball dependency (`"resolved": "file:../x.tgz"`). `patch:`
    is safe because its inner (percent-encoded) locator is resolved as its
    own lockfile entry; the decoded form is checked as well.
    **Residual:** that rests on Berry listing a patch's inner locator as
    its own entry, which was not verified against Berry's source; a patch
    whose inner locator only appears inside the `patch:` reference is
    covered by the decoded-form URL and hosted-git checks alone (a bare
    `owner/repo` there is not caught).
    **Known false positive:** a Berry local reference to a directory
    named like a URL scheme with no `./` or `../` in front
    (`x@link:ws::locator=...`) still reads `ws:` as a scheme and is a hit;
    Berry normally writes such paths with a `./` or `../` prefix.
    **Metadata exempt from every string check** (npm family only): a
    package entry's `funding` (a string, `{type, url}`, or a list of
    those), `deprecated` (npm, pnpm) and `license`. No package manager
    fetches from them, and npm 7+ writes sponsor URLs (github.com/sponsors,
    opencollective, tidelift) and deprecation messages with links into
    `package-lock.json`, so checking them made every dependency bump that
    pulled in such a package an un-overridable hit. A small denylist of
    keys, not a narrowing of the URL check to fetch slots: every other
    string stays checked. The exemption needs both the place and the
    shape. The place is structural, by position in each format, never a
    sibling key: package-lock `packages.<path>` and v1
    `dependencies.<name>` entries (nested to any depth), pnpm
    `packages.<key>` / `snapshots.<key>`, bun's metadata object inside a
    `packages.<name>` tuple, yarn's top-level entries. Any mapping nested
    in one of those (`dependencies`, `requires`, `peerDependencies`,
    `overrides`, ...) or elsewhere (pnpm importers, bun workspaces) is a
    name -> spec map, where a package NAMED `funding`, `deprecated` or
    `license` is a dependency npm fetches from its spec, so it is checked.
    (An earlier rule, "a mapping with a `version` sibling", let
    `dependencies: {version: ^1, funding: https://evil.x/x.tgz}` through.)
    Exempt values still get the control-character check; only the URL
    and spec checks are skipped. A YAML alias cannot make one mapping both
    an entry and a dependency map: aliases do not parse. Fetch slots are
    checked structurally as well (below), unaffected.
    **Cost:** a legitimate git dependency in an npm-family lockfile is a
    non-overridable hit (it already was whenever a URL to github.com
    appeared, which npm usually writes). **Residual:** a fetch slot this
    list does not name (a future lockfile field) is covered only by rule
    (a) and the URL check.
22c. **`lockfile-hosts`: an owner-set extension of the allowlists**
    (owner directive 2026-10-25: "the host list should be
    configurable/extendable using parameters to the job"). One global list
    of extra hostnames, accepted by every lockfile kind on top of its
    built-in list: the owner vouches for a host, so per-ecosystem precision
    buys little and would double the input surface. It only extends:
    built-ins cannot be removed, schemes stay `https` / `ssh` (no http), and
    matching stays exact (no subdomains), exactly as for the built-ins, so
    every path (URLs in parsed and line-checked lockfiles, scp-like
    remotes, flake `host`, pip options) reads the same merged set. Each
    non-blank, non-`#` line must be a plain DNS hostname: labels
    `[a-z0-9-]` not starting or ending in `-`, at least two, the last not
    all digits (no IPv4), ASCII only, at most 253 characters; case and a
    trailing dot are normalised. Anything else (wildcard, scheme, port,
    path, userinfo, IP literal, inline comment) fails the run as a config
    error, `lockfile-hosts line N is not a plain DNS hostname`, before any
    GitHub or model call: the line number only, never the value (closed
    vocabulary). Why the PR cannot widen it: the input lives in the caller
    workflow, which runs on `pull_request_target` and therefore always
    comes from the BASE branch, so a PR's edit to the list has no effect on
    its own run; and changing the list is a `.github/workflows/` change,
    a sensitive-path block the owner must dismiss.
22d. **Binary pure renames and copies.** A 100%-similarity rename or copy
    has no hunks and no "Binary files" line, so the parsed file was never
    binary and the binary / text-binary rules never ran: an earlier
    overridden `data.bin` could be renamed `run.sh` with no deterministic
    hit. `gather_from` now fetches every pure rename or copy (no hunks, not
    a gitlink) at the merge with the binary fetch and cap, and marks it
    binary the way git decides (`buffer_is_binary`: a NUL in the first 8000
    bytes). It is then an ordinary binary under its NEW path: the
    overridable/non-overridable split follows the new extension and the
    magic bytes, and its SHA-256 goes into the own-changes hash like any
    binary's. Text pure renames are untouched; their hash is pinned by a
    test, so no existing marker changes. Cost: one contents fetch per pure
    rename. Residual: a renamed symlink is read through the contents API,
    which follows a link to an in-repo file, so a link to a binary file
    counts as a binary.
23. **Binary magic** table covers common images, fonts, archives, PDF, and
    executables (ELF, PE, Mach-O, wasm, `#!` scripts); executables are
    labelled. Every binary blocks either way (design option (a)). Which
    git-binary files the owner may override is an ALLOWLIST (replaces the
    round-5/6 text-extension and text-name denylists, which kept missing
    types: `.vbs .pyw .csproj .props .targets .sln .reg .mdx .htm .jsonl
    .el .vim .service .mod .sum .fs .clj`, and UTF-16 text is git-binary
    whatever its name). A git-binary file gets the overridable `binary` hit
    only if its extension is in `_KNOWN_BINARY` (`prgate/checks.py`: the
    `_EXT_KIND` magic table's extensions plus common binary types with no
    magic entry: more images, audio/video, `eot`, archives and packages,
    native libraries and executables, `class`/`pyc`, databases, `mo`, data
    and model files, legacy and OpenDocument office files, key stores,
    `bin`, `dat`) AND its magic does not contradict it. Everything else is
    the NON-overridable `text-binary` hit: an unknown type, no extension, a
    `#!` start whatever the extension (an ASCII magic like `#!`, `MZ`,
    `BZh` is trivial to put at the top of a text file whose NUL byte hides
    the rest), and a known type whose recognised magic is a different kind
    (`logo.png` holding ELF), which keeps the "mismatch: content is X,
    extension says Y" detail. Unrecognised magic on a known type is not a
    contradiction (many formats have no table entry). Cost: unknown binary
    types are non-overridable until added to the set, and so is a binary
    whose real kind differs from its extension's (a CFF font named `.ttf`):
    rename it to match, build it in CI, or extend the set.
23a. **An added or bumped gitlink blocks, owner-overridable** (was
    scrutiny only). A submodule pointer names a commit in another repo,
    with a `.gitmodules` URL possibly an attacker's: no reviewer sees that
    content, the same argument as for a text-binary file. Unlike a
    text-binary, the owner can inspect the target repo and commit, so the
    `submodule` hit is overridable. A gitlink is recognised by
    `new file mode 160000` / `new mode 160000` and by the mode on the
    `index a..b 160000` line, which is the only place a bumped gitlink
    shows it. Deleting a gitlink is no hit; `.gitmodules` stays in
    scrutiny. Gitlinks are never fetched as file contents.
24. **Extra scrutiny** (listed to the model, never blocks): `*.nix`,
    lockfiles, `build.rs`, install/setup scripts, package manifests and
    `.gitattributes`/`.gitmodules`/`.npmrc`, minified or vendored paths,
    symlinks, submodules, added lines over 500 characters,
    exception-downgraded paths, and (`dev-autorun`) files a dev tool runs
    or obeys on its own: `.envrc`, `.devcontainer/**`,
    `.vscode/{tasks,settings,launch}.json`, `.pre-commit-config.yaml`,
    `mise.toml`, `.mise.toml`, `.tool-versions`, `.cargo/config(.toml)`,
    `.pnpmfile.cjs`, `bunfig.toml`, `.husky/**`, `lefthook.yml`, at any
    depth. Scrutiny only: they run on a developer's machine, not in the
    gate or CI, and blocking every editor-settings change would train the
    owner to dismiss.
25. **Exception globs** use `fnmatch` semantics: `*` also matches `/`.

## Report

26. **Neutralisation** of model text and paths: one line, hidden characters
    shown as `<U+XXXX>`, `@ # [ ] \` |` replaced by fullwidth or lookalike
    characters, HTML-escaped, `://` and `www.` defanged, `GH-<n>` broken,
    bounded length. Body capped at 60 000 characters.
27. The review body starts with a machine marker
    `<!-- pr-gate:v3 verdict=... head=... hash=... mac=... -->` used by the
    override check, carry-over and the dismissal of the gate's own blocks.
    Any workflow in the repo can post as `github-actions[bot]`, so the marker
    carries an HMAC-SHA256 keyed by the Anthropic API key (only the gate step
    gets that secret) over the JSON array `["pr-gate-marker", "v3", verdict,
    repo (casefolded), PR number, head SHA, own-changes hash, body digest]`,
    checked with `hmac.compare_digest`. The body digest is the SHA-256 of
    everything after the marker line, with line endings read as `\n` and
    trailing whitespace at the end dropped (so GitHub's storage cannot void
    it), computed by the verifier from the review's CURRENT body. It is
    signed last, over the final text (after truncation, and over the
    re-rendered text when a block falls back to a COMMENT). Why: v2 signed
    the fields only, so another workflow could rewrite a real block's
    findings under the intact marker line, or post a new review with a
    copied marker over benign text; the owner's dismissal of that
    benign-looking review was a valid override, and the pass then
    bot-dismissed the real block as superseded. Under v3 any edit voids the
    marker, and a copied marker verifies only on a byte-identical body,
    which shows the owner exactly the gate's findings: dismissing such a
    duplicate is an informed override of the same change (tested), so
    `_blocks_on_head` and `_owner_dismissed` need no change. v2 markers no
    longer parse (v1 never shipped): open PRs need an auto-merge re-click. Only reviews by `github-actions[bot]` whose marker
    verifies count; anything else is treated as no marker everywhere, and
    only verified blocks are dismissed. An empty key fails the run as a
    config error before anything is read or posted. Key rotation invalidates
    old markers: re-click auto-merge. Dry-run renders `mac=unsigned`, which
    never parses. v1 markers (unsigned) are ignored. A workflow with a write
    token can still copy, edit or dismiss the gate's own reviews (same bot
    identity). A replayed pass re-asserts passed content and only the
    owner's dismissal overrides (items 11-13); a block edited in any way
    (findings, an appended line, the marker) no longer verifies and is just
    no block: a re-run still never reaches the model, yet the owner's next
    auto-merge toggle is a fresh model roll at the same change. Accepted:
    each roll costs an owner click, and the step-5 re-run message tells the
    owner that the commit has no verified block and to look at the PR before
    toggling. The earlier rule that made an unverified bot
    CHANGES_REQUESTED a procedural fail (replaced by item 12) is
    deliberately not reintroduced.

## Packaging

28. **`injection_scanner` is imported from the action's own checkout**
    (`gate.py` puts `$GITHUB_ACTION_PATH/..` on `sys.path`) instead of being
    pip-installed: installing the local package would let pip's build
    isolation fetch an unpinned `setuptools`. Same pinned SHA either way.
29. **Runner Python:** the runner's `python3` in a fresh venv, run with `-I`;
    no `actions/setup-python` (keeps the action free of other actions).
    `requirements.txt` carries hashes for every published wheel of each pin,
    so a newer runner Python still installs as long as wheels exist; the
    template pins `ubuntu-24.04` (CPython 3.12) for stability.
30. The pinned SDK is `anthropic==1.17.0`, the version the offline tests ran
    against when this was built.
