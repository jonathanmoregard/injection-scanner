# pr-gate

An AI merge gate against sabotage by prompt-injected coding agents. It is a
required status check (`ai-gate`) that reads a PR's diff, runs deterministic
checks and three tool-less Claude passes, and **blocks** (failing check plus a
REQUEST_CHANGES review) until the owner looks. It never approves anything.

Design: [`docs/superpowers/specs/2026-10-24-pr-gate-design.md`](../docs/superpowers/specs/2026-10-24-pr-gate-design.md).
Builder decisions: [`DECISIONS.md`](DECISIONS.md).

## Threat model

1. Most PRs are written by AI agents that read untrusted text; a hijacked agent can slip a backdoor, exfiltration, CI tampering, a dependency swap or an obfuscated payload into a routine-looking PR.
2. The PR's author controls the diff, comments, file names, title and description, and can address the reviewer model directly; nothing the PR controls may decide whether or how the gate runs.
3. The gate has no tools, runs no PR code and never checks it out, so its API key is not reachable from PR content.

## What it does

The run is triggered by `pull_request_target` (the workflow always comes from
the base branch). In order, failing closed at every step:

1. **Owner intent.** Auto-merge must be on and enabled by `owner`; the head must
   not have moved since the event. Otherwise the check fails (no review posted).
2. **Default branch only.** The PR must target the repository's default
   branch. A check result lives on the head commit, so a pass on a PR into
   another branch would otherwise count for a later PR of the same commit
   into the default branch.
   **The merge result is what is reviewed.** Every later step reads the
   change as GitHub's test merge of the head into the live base
   (`base...merge`), i.e. what a merge or squash lands, never the
   merge-base diff (`base...head`): in a criss-cross history (the head
   merged an earlier PR's tip with `-s ours`) the merge-base diff can show
   only a benign file while the merge silently reverts that earlier PR.
   File contents (Monitor B, binaries, lockfiles) are read at the merge
   commit; reviews and markers still go on the head. GitHub computes the
   test merge in the background after a push or a base move, so the gate
   re-reads for up to 30 s until it is the merge of exactly the live base
   and head, then fails as infra (toggle auto-merge to retry). A PR with
   merge conflicts fails with "the PR has merge conflicts; resolve them",
   no model call.
3. **Pushes or a reopen after auto-merge** (`synchronize`, `reopened`) fail,
   with no model call, unless the gate's newest verdict on this PR is a pass
   of identical own changes (a pure "Update branch" merge from the base, or a
   reopen with nothing changed). Then the pass carries over.
4. **Override.** If the gate blocked this head commit, the model is not asked
   again: the run passes (always-on checks only) once `owner` has dismissed
   that review while the PR sat at this commit; until then it fails. A block
   counts only for the change it saw: if the base has since moved so that
   what would land differs (another own-changes hash), the block is stale.
   Dismissing it overrides nothing; a re-run fails saying so, and the
   owner's next auto-merge toggle gets a fresh model review.
5. **Re-runs never ask the model.** Any other re-run of the check fails with
   no model call. A fresh review takes an auto-merge toggle.
6. **Deterministic checks** (any hit blocks):
   - hidden Unicode in added lines or in file paths the merge leaves
     (deleting or renaming away an existing one is fine) (`unicode_sanitize` strict
     `profile="code"`: invisible, bidi, tag, variation-selector, private-use,
     soft-hyphen, line-separator characters), and control characters in
     added lines (ESC sequences that erase or conceal a line in a terminal,
     NUL, backspace, DEL, C1 such as U+0085; TAB, form feed and a trailing CR
     are fine). **Never overridable.**
   - lockfile entries resolving to a host outside the per-ecosystem allowlist
     (npm/yarn registries, crates.io, PyPI, github.com and NixOS release hosts
     for flakes, rubygems). JSON, TOML and YAML lockfiles (`package-lock.json`,
     `pnpm-lock.yaml`, `uv.lock`, `Cargo.lock`, `flake.lock`, `bun.lock`, yarn
     Berry, ...) are parsed whole, at the merge result and at the base, and every
     string in them is checked, so escapes, block scalars and line folding
     resolve as the package manager resolves them. Only values new relative
     to the base count. For a rename the base is the old path only if that
     was the same kind of lockfile; a file renamed into a lockfile name from
     anything else (`fixtures/lock.json` to `package-lock.json`) counts as
     all new, and a line-checked one is then checked whole. A lockfile that
     does not parse or is too large to fetch, or a string holding a line
     break or control character, is a hit too. pip requirement files
     (`requirements*.txt`, `constraints*.txt`, pip-tools'
     `requirements*.in` / `constraints*.in`, and any `.txt` or `.in` in a
     directory named `requirements`), `Gemfile.lock` and yarn v1 lockfiles
     have no multi-line strings and are checked one added line at a time;
     an added line ending in a backslash continuation that could glue the
     next line onto a URL is a hit (in pip requirement files any run not
     preceded by whitespace, since pip joins them all). Any URL form a package manager
     accepts counts (`https:evil.x`, `https:\\evil.x`, escaped slashes, IPv6
     hosts). npm-family lockfiles (`package-lock.json`,
     `npm-shrinkwrap.json`, `bun.lock`, `yarn.lock`, `pnpm-lock.yaml`) can
     also fetch from a host with no URL at all: a hosted-git spec
     (`github:`, `gitlab:`, `bitbucket:`, `gist:`, `git+...:`) anywhere,
     or a leading protocol other than `npm:`, `workspace:`, `catalog:`,
     `patch:` or a relative `file:` / `link:` / `portal:` path, is a hit;
     and every fetch slot (npm `resolved`, pnpm `resolution`, bun and yarn
     Berry `name@spec` entries, yarn v1 `resolved`) must be an https URL
     or a local relative path, so a bare `owner/repo#sha` there is a hit.
     A package entry's `funding`, `deprecated` and `license` fields are
     metadata nothing fetches from (sponsor links, deprecation messages)
     and are not checked.
     **Never overridable.**
   - a file git treats as binary (so no model and no other check can see
     it) that is not a known binary type: a text file with a NUL byte (`.js`,
     `.vbs`, `.csproj`, ...), UTF-16 text, a file with no extension, one
     starting with `#!`, or one whose magic bytes contradict its extension.
     The known binary types (images, audio/video, fonts, archives, packages,
     executables and libraries, data and model files, ...) are the set
     `_KNOWN_BINARY` in `prgate/checks.py`. **Never overridable.**
   - other added or modified binary files (a known binary type whose magic
     bytes match or are not recognised).
   - an added or bumped submodule pointer (gitlink): the commit it points
     at lives in another repo that no reviewer sees. Check the target repo
     (`.gitmodules`) and commit before dismissing. Deleting one is fine.
   - changes under `.github/` and to agent-instruction files (`CLAUDE.md`,
     `AGENTS.md`, `.claude/`, `.codex/`, `.mcp.json`).
   - a diff over 400 kB (too large for the model passes).
7. **Model passes** on the configured model: Monitor A (hostile-author prompt,
   diff only), Monitor B (same prompt, diff plus post-change file contents),
   and a security/correctness review. The PR title, body, commit messages and
   comments never reach a model.
8. **Verdict.** Block on any deterministic hit, max suspicion at or above the
   threshold, any `malicious` or `obscure` finding of medium or high severity,
   any high `security` finding, any pass that did not complete (refusal,
   truncation, malformed output) or was declined by the configured model,
   or a review missing any of the three passes.
   Bugs never block.
9. **Report.** One review on the head commit. Block: REQUEST_CHANGES (COMMENT
   if GitHub refuses it), check fails. Pass: COMMENT, the gate dismisses its
   own earlier REQUEST_CHANGES reviews, check passes.

API or network errors fail the check without posting a review; since a
re-run never asks the model, retry by disabling and re-enabling auto-merge.
A model API 4xx other than 408/409/429 (wrong model name or key, prompt too
long) is reported as a config error instead, since retrying the same
request cannot help: fix the input or split the PR first. The annotation on
the check says what failed.

## Setup checklist (per consuming repo, once)

1. Copy [`caller-example.yml`](caller-example.yml) to
   `.github/workflows/ai-gate.yml`. Replace `<FULL_SHA>` with a full
   injection-scanner commit SHA, set `owner` and `model`. Keep the job's
   `name: ai-gate` and never add a job-level `if:` (a skipped required check
   counts as passing).
2. Ruleset on the default branch: require a pull request; require status
   check `ai-gate` with source **GitHub Actions**; **require branches to be
   up to date before merging**; block force pushes; **no bypass actors**.
   The up-to-date rule is what stops a pass on head H from landing on a
   base that moved after the check: the check result lives on H, and
   without the rule GitHub would merge H into the newer base, a merge
   nobody reviewed. With it, the PR must first take the new base ("Update
   branch"), and that push only carries the pass over if the PR's own
   changes are unchanged. If offered, restrict who can dismiss reviews to the owner
   **and GitHub Actions**: the gate dismisses its own superseded blocks when
   a later run passes. Without that they stay on the PR; never dismiss them
   by hand, since dismissing a gate review is the override (a dismissal by
   anyone but `owner` never clears a block either way).
3. Settings → General: allow auto-merge; turn off "Allow rebase merging"
   (see Limitations).
4. Secret `AI_GATE_ANTHROPIC_KEY`: a dedicated key from its own Anthropic
   Console workspace with a spend limit at or below the monthly API credit.
   Never the subscription OAuth token. The gate also uses it as the HMAC key
   that signs its review markers; rotating it invalidates earlier gate
   verdicts (re-click auto-merge on open PRs).
5. The agents' GitHub App or token must **not** have the `workflows`
   permission. Otherwise a PR can add a second workflow whose job is also
   named `ai-gate` and reports a fake pass.
6. Settings → Actions → General → Workflow permissions: **read repository
   contents** (read-only default token), for the repo or the org. No other
   workflow may grant itself `checks: write` or `statuses: write`, and no
   workflow that runs PR code (builds, tests, `pull_request_target` with a
   checkout) may hold any write scope. A token with `checks: write` can
   create a check run named `ai-gate` with conclusion success on the head,
   from the same GitHub Actions app the ruleset trusts, so the required
   check passes without the gate; one with `pull-requests: write` posts
   reviews as `github-actions[bot]` (see Limitations).

Org repos need their own secret and ruleset.

## Day to day

- **Request a review:** enable auto-merge. Nothing runs before that, so
  drafts cost nothing.
- **Clear a block** (false alarm): read the findings, **dismiss the gate's
  review**, then **re-run** the failed `ai-gate` check. The re-run sees your
  dismissal and passes without a model call. This works on your own PRs too
  (GitHub won't let you approve those). Hidden-Unicode, lockfile-host and
  text-binary hits cannot be cleared this way: fix the change.
- **A block posted as a COMMENT cannot be dismissed.** If GitHub refuses
  the gate's REQUEST_CHANGES review, the block goes out as a COMMENT, and
  GitHub cannot dismiss a COMMENT review, so there is no override. The
  review body and the check say so. Past a false alarm the only way is
  your ruleset bypass, or temporarily removing the required `ai-gate`
  check for that merge (or push a change and re-enable auto-merge for a
  fresh review).
- **Dismissing the gate's review IS the override**, not housekeeping. It
  applies only to the commit the PR is at when you dismiss, only if `owner`
  did it, and only while the PR stays there: a later commit voids it, and so
  does any force push after the gate posted that block. A review can be
  dismissed only once, so a voided dismissal (or one by someone else) means
  that commit can no longer be overridden: push a new commit, then
  re-enable auto-merge for a fresh review. Don't dismiss a
  block of an older commit to tidy up; a passing run dismisses those itself.
  A dismissal also covers only the change the gate blocked: if the base
  moved in between and changed what would land, it does not count, and the
  check says to toggle auto-merge for a fresh review.
- **Re-runs never call the model.** A re-run either applies your override or
  fails with "a re-run never asks the model again" (or, for a block the
  base has since outdated, a message saying so). For a fresh review
  (after an infra error, say), disable and re-enable auto-merge.
- **Pushes:** any push while auto-merge is on fails the gate. Disable and
  re-enable auto-merge to request a fresh review. Exception: "Update branch"
  (merging the base into the PR) passes on its own as long as the PR's own
  changes are unchanged; a conflict resolution or any extra edit needs the
  re-click. Closing and reopening the PR is treated like a push.
- **Key rotation:** a new `AI_GATE_ANTHROPIC_KEY` invalidates the gate's
  earlier verdicts (their markers no longer verify). Open PRs need a
  re-click of auto-merge. So does a gate update that changes the marker
  version (v2 to v3: the signature now covers the whole review text).
- **"enable auto-merge to request the AI gate"** on a new PR is expected:
  that is the gate waiting for you.
- **PRs must target the default branch.** Into any other branch the check
  fails with "the AI gate only reviews PRs into main".
- **Merge conflicts** fail the check ("the PR has merge conflicts; resolve
  them"). Resolving them is a push: it carries a pass over only if the
  PR's own changes come out identical, otherwise re-enable auto-merge.

## Inputs

| Input | Default | Notes |
|---|---|---|
| `owner` | (required) | Login whose auto-merge click and review dismissal count. Not `github.repository_owner` (that is the org for org repos). |
| `model` | `claude-opus-5-5` | Use `claude-fable-5-1` for sensitive repos (klaffat, nixos-config, `.claude`). Set in the caller file, which the gate itself protects; never a repo variable. |
| `effort` | `high` | `low`, `medium`, `high`, `xhigh`, `max`. |
| `suspicion-threshold` | `25` | Calibrate on past honest PRs (below). |
| `exceptions` | empty | Newline-separated globs (`*` crosses `/`) whose sensitive-path rule becomes extra scrutiny instead of a block, e.g. `.claude/*` for the `.claude` repo. Never covers `.github/workflows/`, `.github/actions/`, hidden Unicode or lockfile hosts. |
| `lockfile-hosts` | empty | Newline-separated extra hostnames (e.g. a private registry, `npm.mycompany.example`) that every lockfile check accepts on top of its built-in allowlist. Exact match only: no subdomains, wildcards, schemes, ports, paths or IP literals; blank and `#` comment lines are skipped, case and a trailing dot normalised. Any other line fails the run as a config error naming the line number. It only extends: built-in hosts stay, and URLs must still be https (or ssh for git). Lives in the caller workflow, so a PR cannot extend its own allowlist (DECISIONS item 22c). |
| `anthropic-api-key` | (required) | `${{ secrets.AI_GATE_ANTHROPIC_KEY }}`. Reaches only the gate step's env. |

There is no token input: the gate always uses the workflow's `github.token`
(`contents: read`, `pull-requests: write`, `issues: read` in the caller), so
its reviews come from `github-actions[bot]`, the only author it trusts.
`contents: read` also covers the test merge commit: its parents come with
the PR state in one GraphQL query, and its diff and file contents are read
with the same compare and contents calls as any other commit.
`issues: read` is for the timeline endpoint that records who dismissed a
review; without it the owner-override path cannot see dismissals, and the
gate fails with a config error saying so (retrying will not help).
**Recovery:** the workflow fix is itself a `.github/` change the gate
blocks, and overriding that block needs the timeline too. Land the fix by
temporarily removing the required `ai-gate` check from the ruleset (or
adding the owner as a bypass actor) for that one merge, then restore the
ruleset.

## Cost (estimate, not measured)

About 30k input / 4k output tokens per pass, three passes per run. Opus 5.5
($4/$20 per MTok): about $0.60 per run. Fable 5.1 ($10/$50): about $1.50 per
run. Carry-overs and owner overrides make no model call. Watch the Console
for the first month.

## Calibration: dry-run

Runs the same checks and model passes locally on a diff file and prints the
verdict JSON (including the monitors' `analysis`). No GitHub calls.

```bash
git fetch origin pull/123/merge         # GitHub's test merge of PR 123
git diff FETCH_HEAD^1...FETCH_HEAD > /tmp/pr123.diff   # base...merge: what would land
python pr-gate/gate.py --dry-run --diff /tmp/pr123.diff --no-llm       # deterministic only
ANTHROPIC_API_KEY=... python pr-gate/gate.py --dry-run --diff /tmp/pr123.diff \
    [--files-dir CHECKOUT] [--model claude-fable-5-1] [--effort high] [--threshold 25] \
    [--exceptions-file globs.txt] [--lockfile-hosts-file hosts.txt]
```

Dry-run reviews the diff it is given as-is and does not compute a merge
result: feed it the diff that would land, as above (`gh pr diff` and
`git diff main...HEAD` are merge-base diffs, which can differ in a
criss-cross history). `--files-dir` points at a checkout of that merge
(post-change contents for Monitor B and binary magic bytes). Exit 0 pass,
1 block, 2 setup error. Run it
over 20-50 past merged PRs per repo type and set the threshold just above
their maximum suspicion.

## Limitations

- A single model reviewer is beatable: published work finds refined attacks
  get past a strong monitor roughly 40% of the time. This is a tripwire that
  forces a human look, not a guarantee.
- Binary files are blocked, not scanned (malware scanning is a follow-up).
  A binary whose type is not in `_KNOWN_BINARY` (`prgate/checks.py`),
  including one with no extension (a compiled `bin/tool`), one starting
  with `#!`, or one whose content contradicts its extension (a TrueType
  font named `.otf`), cannot be overridden: give it a known, matching
  extension, build it in CI, or add the type to the set in a gate change.
- Carry-over compares the PR's own changes without line offsets, so base
  merges keep a pass. The price: a push that moves an added line to
  another spot with the same three context lines above and below (repeated
  boilerplate) counts as identical and carries the pass over unreviewed.
  Accepted for v1 because offsets would break carry-over on every base
  merge; the follow-up is to hash each touched region with wider context
  (see DECISIONS item 1).
- A PR whose diff is too large for GitHub to serve (GitHub answers 406 above
  roughly 300 files or 20 000 lines) or over 5 MB cannot pass the gate: the
  check fails with "the diff is too large for the gate to read; split the PR",
  and a re-run does not help. Split the PR, or merge it with an admin bypass
  outside the gate.
- The gate reviews the tree a merge or squash lands (GitHub's test merge).
  Rebase-merge replays the head's commits one by one onto the base, which
  can land a different tree than the test merge in a criss-cross history.
  Disable "Allow rebase merging" in repos using the gate (Settings →
  General); if left on, that difference is a residual gap.
- A pass is on the head commit, but what lands depends on the base too.
  The gate relies on the ruleset's "require branches to be up to date"
  (setup step 2) so that a pass is never merged onto a base that moved
  after the check. Without that rule, a base move after a pass lands a
  merge result nobody reviewed.
- The fake-check defence rests on no agent credential having the `workflows`
  permission; a host PAT with that scope defeats it.
- The gate's guarantees assume setup step 6: a read-only default workflow
  token, no other workflow with `checks: write` or `statuses: write`, and
  no write scope in any workflow that runs PR code. A workflow that breaks
  this can report a fake `ai-gate` success (same GitHub Actions app), and
  with `pull-requests: write` it can also re-post a byte-identical older
  gate pass: that is the newest verified marker, so it carries over across
  a later "Update branch" even past a later block of the same change.
- Any workflow in the repo can post reviews as `github-actions[bot]`, so the
  gate signs its review markers with an HMAC keyed by the Anthropic API key,
  which only the gate step receives. The signature covers the whole review
  text, not just the marker line, so any edit to a review (or the marker
  copied onto other text) voids it, and a marker that does not verify
  counts as no marker. Another workflow with a write token (e.g. CI that
  builds PR code) therefore cannot mint a pass or a block, nor dress a
  block up as benign for you to dismiss. It can still copy, edit or
  dismiss the gate's own reviews (same bot identity). A byte-identical copy
  shows the gate's own findings, a re-posted real pass only re-asserts
  content that was passed, and only the owner's dismissal clears a block.
  But an edited block no longer verifies, so it stops guarding its commit: a re-run still never asks the model, yet the owner's
  next auto-merge toggle gets a fresh model review, a second roll at the
  same change. Only the owner's toggle triggers it, so it costs the owner a
  click, not nothing. When a re-run reports "no verified gate block" on a
  commit you expected to be blocked, look at the PR before toggling. Keep
  `pull-requests: write` away from workflows that run PR code.
- Reviews and the PR timeline are read 100 per page, at most 30 pages
  (3 000 entries each). Past that the gate fails as infra on every run,
  since it cannot see every review or dismissal; the way out is a new PR
  with the same changes.
- Anyone acting as `owner` (including an agent with the owner's token) can
  enable auto-merge and dismiss the gate's review, so the gate is only as
  strong as the custody of that identity.
- A block posted as a COMMENT (GitHub refused REQUEST_CHANGES) cannot be
  dismissed, so it cannot be overridden: push a fix and re-enable
  auto-merge, or use the owner's ruleset bypass (or temporarily remove
  the required check) for a false alarm.
- The lockfile check parses with Python's parsers (`json`, `tomllib`,
  PyYAML's safe loader), not each package manager's own. Duplicate keys,
  YAML aliases and YAML tags beyond the safe set do not parse, which closes
  the differentials known to matter; any other disagreement between the two
  parsers is a gap. A yarn v1 lockfile that classic yarn cannot read is read
  as YAML by yarn; the gate checks that reading only where PyYAML parses it.
  A lockfile over 25 MB cannot pass the gate.
- The lockfile check judges hosts, not repos. Where a code host is
  allowlisted (`github.com` for `Cargo.lock` git sources and `flake.lock`
  inputs), a dependency on ANY repo there passes the deterministic check;
  only the model passes see which repo and commit it is. A value already
  on the default branch that is changed in any way (another repo or
  commit on the same foreign host) counts as new.
- Lockfile hosts outside the built-in allowlist (e.g. a private registry)
  cannot be cleared by an override; list them in the caller's
  `lockfile-hosts` input instead (that edit is itself a `.github/` change
  the owner must dismiss a block for). Local `file:../pkg`
  references are not host-checked (the referenced path is in the diff);
  `file://` URLs are hits. So is every git dependency in an npm-family
  lockfile (`github:o/r`, `git+ssh://...`), legitimate or not: only values
  new relative to the base count, but a PR adding one cannot pass.
- A pip requirement file is recognised by its name or a `requirements/`
  parent directory. A file pulled in with `-r` / `-c` under any other name
  (`deps/base.txt`) is not host-checked; the model passes still see it.
- A single emoji presentation selector straight after an emoji (the usual
  spelling of a warning-sign emoji) is allowed. Anything else with variation
  selectors, zero-width joiners or other invisible characters (including
  emoji ZWJ sequences such as family emoji) trips the hidden-Unicode check and
  cannot be overridden; rewrite the text without it.
- Things to verify on the first pilot are listed in the design doc ("Must be
  verified empirically"), notably whether the REQUEST_CHANGES review from
  `github-actions[bot]` (posted with `GITHUB_TOKEN`) is accepted on
  personal repos (if not, every block is an undismissable COMMENT and
  false alarms need the ruleset bypass) and whether
  `auto_merge_enabled` fires reliably.

## Updating the gate

Change code here, then bump `<FULL_SHA>` in each caller by PR (that PR is
itself gated). To bump the SDK: edit `requirements.in`, regenerate
`requirements.txt` with the command in it, and run the test suite against
that version (the tests drive the real SDK over a stub transport).
