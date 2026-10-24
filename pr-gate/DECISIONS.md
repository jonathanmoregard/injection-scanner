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
2. **Binary content is in the hash** (SHA-256 of the head blob, fetched
   anyway for the magic-byte check). The diff shows only "Binary files
   differ", so without it a swapped binary would ride a carried-over pass.
   File modes and renames are in the hash too.
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
     default branch, push after auto-merge, a block on this head the owner
     has not dismissed, a re-run, unreadable or over-5 MB diff): check
     fails, **no review**.
   - *Infra* (GitHub or Anthropic API errors, missing key): check fails, no
     review. A transport error is not a verdict. The retry is an auto-merge
     toggle, since a re-run never asks the model. A model API 4xx other than
     408/409/429 (bad model name or key, prompt too long) is reported as a
     *config* error with that diagnosis instead of "toggle to retry": the
     same request fails the same way every time. Still fail closed, no
     review; the reason is the closed `api-status-<code>` vocabulary, never
     the provider's error body.
   - *Verdict* (including refusal, `max_tokens`, malformed or out-of-range
     output): REQUEST_CHANGES review. These are outcomes on the PR's
     content; only the owner's dismissal overrides them.
7. Messages and annotations use a closed vocabulary: gate-written reasons,
   validated owner login, SHAs, bounded HTTP status codes, exception class
   names. No exception message, HTTP body or model text is printed.

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
    this head (item 27), in any state (dismissed or COMMENT-fallback
    included). An unverifiable block marker is not a block.
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
    timeline scan (reviewed, review_dismissed, committed,
    head_ref_force_pushed, head_ref_restored; a malformed relevant event
    fails closed): the owner's dismissal of a block on this head counts iff
    the timeline shows that block being posted, no `committed` event
    follows the dismissal, and no force push or branch restore follows the
    block's posting. Why: otherwise a stale dismissal is a permanent token
    (block H, push a clean H2 that passes, owner dismisses the stale block,
    push back to H, re-run). The rewrite rule is needed on top of "no head
    change after the dismissal": GitHub places a `committed` event at the
    commit's own, writer-chosen date, not at push time, so a fast-forward
    back to a blocked commit (after a force push to its parent) looks like
    it happened before the dismissal. Leaving a commit and coming back to
    it always takes a rewrite, and rewrite, review and dismissal events
    carry server timestamps. Known cost, fail closed: a head commit dated
    in the future (writer clock skew) sorts after the dismissal, so that
    head needs a fresh review instead of an override.
12. **Re-runs never ask the model** (replaces "any bot REQUEST_CHANGES arms
    the guard" and the same-own-changes reroll guard). With
    `GITHUB_RUN_ATTEMPT` > 1 and no override, the run fails with no model
    call. Re-runs are something any writer can start; an owner auto-merge
    click starts a new run (attempt 1). This bounds the reroll budget to
    owner clicks, so an amend/rebase to a new SHA with the same changes no
    longer needs its own guard: it fails on `synchronize` and gets a fresh
    review only when the owner toggles auto-merge.
13. **Carry-over** looks only at the NEWEST verified gate marker, pass or
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
    (the timeline is an issues endpoint).
16. **Always-on checks run on carry-over and override runs**: exactly the
    non-overridable hits (hidden Unicode, lockfile host, text-binary).
17. The diff is `compare/<baseRefOid>...<head SHA>`: the base branch's
    current tip (what "Update branch" merged) as a commit oid read live
    from GraphQL and validated as 40-hex (else fail closed), the head pinned
    by SHA. Never a branch name: a writer can push a tag named like the base
    branch, and a name could resolve to it, making the reviewed diff
    attacker-chosen.
    Paths follow git's format: the TAB git appends to a `---`/`+++` path
    containing a space is dropped, and C-style quoted paths
    (`"b/caf\303\251.txt"`) are unquoted. A path that starts with `"` but is
    not one well-formed quoted UTF-8 string fails the run as unparseable
    (procedural, not infra), so it never reaches a file fetch.
18. Event actions other than the three in the template, and events other
    than `pull_request_target`, fail.
19. The three passes run concurrently (three threads), each with a 600 s
    timeout and 2 SDK retries; `max_tokens` 16000; no temperature or thinking
    parameters; effort always sent.
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
    are checked too. Counts land in the existing `SanitizeResult` counters,
    so the audit record keys are unchanged.
22. **Lockfile allowlists:** npm-family locks: `registry.npmjs.org`,
    `registry.yarnpkg.com`. Python locks and `requirements*.txt` /
    `constraints*.txt`: `pypi.org`, `files.pythonhosted.org`. `Cargo.lock`:
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
    Bracketed IPv6 hosts reach the host check (never allowlisted).
    Each added line is checked after decoding JSON/TOML/YAML string escapes
    (`\/`, `\uXXXX`, `\UXXXXXXXX`, `\xXX`, the one-letter ones), because
    package managers decode them before resolving the URL. An escape the
    decoder does not know, on a line with a scheme-like token, is a hit
    (fail closed). Lines are checked one at a time, so a backslash-newline
    continuation (YAML double-quoted, TOML multi-line strings, pip) could
    split a URL across two lines (`"https://registry.npmjs.org\` +
    `.evil.x/p.tgz"`). An added lockfile line ending in such a
    continuation is therefore a hit on its own: an odd trailing backslash
    run (trailing whitespace ignored; an even run is escaped backslashes).
    In `requirements*.txt` pip joins on any trailing run, so parity does not
    count there; instead a run preceded by whitespace is fine, which is how
    pip-compile writes its `pkg==1.0 \` / `--hash=... \` lines and which
    cannot glue a URL together. Joining lines before checking was the
    alternative; a per-line rule is simpler and lockfiles have no
    legitimate need for a URL-splitting continuation.
23. **Binary magic** table covers common images, fonts, archives, PDF, and
    executables (ELF, PE, Mach-O, wasm, `#!` scripts); executables are
    labelled. Every binary blocks either way (design option (a)). A binary
    with a source/text extension (js, py, sh, json, yaml, toml, md, lock,
    svg, ... see `_TEXT_EXTS`) is a NON-overridable `text-binary` hit,
    whatever its magic: git calls it binary (e.g. a NUL byte in a comment),
    so no model, Unicode or lockfile check sees it, and an ASCII magic
    (`MZ`, `BZh`, `GIF89a`, `#!`) is trivial to put at the top of a text
    file. A real binary renamed to a text extension blocks the same way.
24. **Extra scrutiny** (listed to the model, never blocks): `*.nix`,
    lockfiles, `build.rs`, install/setup scripts, package manifests and
    `.gitattributes`/`.gitmodules`/`.npmrc`, minified or vendored paths,
    symlinks, submodules, added lines over 500 characters,
    exception-downgraded paths.
25. **Exception globs** use `fnmatch` semantics: `*` also matches `/`.

## Report

26. **Neutralisation** of model text and paths: one line, hidden characters
    shown as `<U+XXXX>`, `@ # [ ] \` |` replaced by fullwidth or lookalike
    characters, HTML-escaped, `://` and `www.` defanged, `GH-<n>` broken,
    bounded length. Body capped at 60 000 characters.
27. The review body starts with a machine marker
    `<!-- pr-gate:v2 verdict=... head=... hash=... mac=... -->` used by the
    override check, carry-over and the dismissal of the gate's own blocks.
    Any workflow in the repo can post as `github-actions[bot]`, so the marker
    carries an HMAC-SHA256 keyed by the Anthropic API key (only the gate step
    gets that secret) over the JSON array `["pr-gate-marker", "v2", verdict,
    repo (casefolded), PR number, head SHA, own-changes hash]`, checked with
    `hmac.compare_digest`. Only reviews by `github-actions[bot]` whose marker
    verifies count; anything else is treated as no marker everywhere, and
    only verified blocks are dismissed. An empty key fails the run as a
    config error before anything is read or posted. Key rotation invalidates
    old markers: re-click auto-merge. Dry-run renders `mac=unsigned`, which
    never parses. v1 markers (unsigned) are ignored. A workflow with a write
    token can still copy, edit or dismiss the gate's own reviews (same bot
    identity). A replayed pass re-asserts passed content and only the
    owner's dismissal overrides (items 11-13), but an edited block is just
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
