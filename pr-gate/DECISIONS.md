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
   target models support them, and a 400 from an unsupported model is an
   infra failure (check fails, re-run retries). Output is still parsed and
   validated in code.
5. **Exceptions also never cover `.github/actions/`** (local actions run
   inside workflows, same power as `.github/workflows/`).

## Failure classes

6. Three classes, deliberately different:
   - *Procedural* (no auto-merge, wrong enabler, stale head, push after
     auto-merge, existing block without owner approval, unreadable or
     over-5 MB diff): check fails, **no review**. Posting REQUEST_CHANGES
     here would arm the reroll guard on a head that was never reviewed.
   - *Infra* (GitHub or Anthropic API errors, missing key): check fails, no
     review, a re-run retries. A transport error is not a verdict.
   - *Verdict* (including refusal, `max_tokens`, malformed or out-of-range
     output): REQUEST_CHANGES review, reroll guard applies. These are
     outcomes on the PR's content, so a re-run must not re-roll them.
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
10. **Prior block** = a review by `github-actions[bot]` whose body starts with
    the gate marker `verdict=block` for this head, in any state (dismissed or
    COMMENT-fallback included).
11. **Owner approval** = the owner's latest APPROVED / CHANGES_REQUESTED /
    DISMISSED review on this head commit is APPROVED.
12. **Carry-over** looks only at the NEWEST gate marker, pass or block: it
    carries over only if that marker is a pass with an identical own-changes
    hash. An older pass never outlives a later block of the same changes
    (owner re-requests review, that roll blocks, a pure base merge must not
    resurrect the pass). Owner override and carry-over passes also record
    their hash, so an "Update branch" after an override carries over too.
    `reopened` is handled exactly like `synchronize`: auto-merge can survive
    a close/reopen, and a reopen is not an owner click, so it must not buy a
    fresh model roll.
13. **Always-on checks run on carry-over and override runs.**
14. The diff is `compare/<base branch>...<head SHA>`: the base branch's
    current tip (what "Update branch" merged), the head pinned by SHA.
    Paths follow git's format: the TAB git appends to a `---`/`+++` path
    containing a space is dropped, and C-style quoted paths
    (`"b/caf\303\251.txt"`) are unquoted. A path that starts with `"` but is
    not one well-formed quoted UTF-8 string fails the run as unparseable
    (procedural, not infra), so it never reaches a file fetch.
15. Event actions other than the three in the template, and events other
    than `pull_request_target`, fail.
16. The three passes run concurrently (three threads), each with a 600 s
    timeout and 2 SDK retries; `max_tokens` 16000; no temperature or thinking
    parameters; effort always sent.
17. Monitors return `analysis` (investigate-then-score), `suspicion`,
    `findings`. `analysis` is never posted to the PR or the log; dry-run
    prints it for calibration.

## Deterministic checks

18. **Code profile** = prose profile + everything named in the design
    (U+FE00-FE0F, all private use, U+00AD, U+200E/F, U+2028/9) + every other
    format character (category Cf) + code points that render as nothing
    (Hangul fillers U+115F/1160/3164/FFA0, U+034F, U+180B-180F). File paths
    are checked too. Counts land in the existing `SanitizeResult` counters,
    so the audit record keys are unchanged.
19. **Lockfile allowlists:** npm-family locks: `registry.npmjs.org`,
    `registry.yarnpkg.com`. Python locks and `requirements*.txt` /
    `constraints*.txt`: `pypi.org`, `files.pythonhosted.org`. `Cargo.lock`:
    `github.com` (crates.io index), `index.crates.io`, `static.crates.io`.
    `flake.lock`: `github.com`, `channels.nixos.org`, `releases.nixos.org`;
    flake input types other than github/git/tarball/file/path/indirect and
    any `"host"` outside the list are hits. `Gemfile.lock`: `rubygems.org`.
    Schemes must be https-based or ssh; plain `http`/`git` are hits.
    Each added line is checked after decoding JSON/TOML/YAML string escapes
    (`\/`, `\uXXXX`, `\UXXXXXXXX`, `\xXX`, the one-letter ones), because
    package managers decode them before resolving the URL. An escape the
    decoder does not know, on a line with a scheme-like token, is a hit
    (fail closed).
20. **Binary magic** table covers common images, fonts, archives, PDF, and
    executables (ELF, PE, Mach-O, wasm, `#!` scripts); executables are
    labelled. Every binary blocks either way (design option (a)).
21. **Extra scrutiny** (listed to the model, never blocks): `*.nix`,
    lockfiles, `build.rs`, install/setup scripts, package manifests and
    `.gitattributes`/`.gitmodules`/`.npmrc`, minified or vendored paths,
    symlinks, submodules, added lines over 500 characters,
    exception-downgraded paths.
22. **Exception globs** use `fnmatch` semantics: `*` also matches `/`.

## Report

23. **Neutralisation** of model text and paths: one line, hidden characters
    shown as `<U+XXXX>`, `@ # [ ] \` |` replaced by fullwidth or lookalike
    characters, HTML-escaped, `://` and `www.` defanged, `GH-<n>` broken,
    bounded length. Body capped at 60 000 characters.
24. The review body starts with a machine marker
    `<!-- pr-gate:v1 verdict=... head=... hash=... -->` used by the reroll
    guard and carry-over. Only reviews by `github-actions[bot]` are trusted.

## Packaging

25. **`injection_scanner` is imported from the action's own checkout**
    (`gate.py` puts `$GITHUB_ACTION_PATH/..` on `sys.path`) instead of being
    pip-installed: installing the local package would let pip's build
    isolation fetch an unpinned `setuptools`. Same pinned SHA either way.
26. **Runner Python:** the runner's `python3` in a fresh venv, run with `-I`;
    no `actions/setup-python` (keeps the action free of other actions).
    `requirements.txt` carries hashes for every published wheel of each pin,
    so a newer runner Python still installs as long as wheels exist; the
    template pins `ubuntu-24.04` (CPython 3.12) for stability.
27. The pinned SDK is `anthropic==1.17.0`, the version the offline tests ran
    against when this was built.
