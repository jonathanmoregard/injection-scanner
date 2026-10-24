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
2. **Pushes after auto-merge** (`synchronize`) fail, with no model call, unless
   the PR's own changes are identical to a head the gate already passed (a pure
   "Update branch" merge from the base). Then the pass carries over.
3. **Reroll guard.** If the gate already blocked this exact head, the model is
   not asked again: the run passes only if `owner` approved that head commit.
4. **Deterministic checks** (any hit blocks):
   - hidden Unicode in added lines or file paths (`unicode_sanitize` strict
     `profile="code"`: invisible, bidi, tag, variation-selector, private-use,
     soft-hyphen, line-separator characters). **Never clearable by approval.**
   - lockfile entries resolving to a host outside the per-ecosystem allowlist
     (npm/yarn registries, crates.io, PyPI, github.com and NixOS release hosts
     for flakes, rubygems). **Never clearable by approval.**
   - added or modified binary files, with a magic-byte vs extension check.
   - changes under `.github/` and to agent-instruction files (`CLAUDE.md`,
     `AGENTS.md`, `.claude/`, `.codex/`, `.mcp.json`).
   - a diff over 400 kB (too large for the model passes).
5. **Model passes** on the configured model: Monitor A (hostile-author prompt,
   diff only), Monitor B (same prompt, diff plus post-change file contents),
   and a security/correctness review. The PR title, body, commit messages and
   comments never reach a model.
6. **Verdict.** Block on any deterministic hit, max suspicion at or above the
   threshold, any `malicious` or `obscure` finding of medium or high severity,
   any high `security` finding, or any pass that did not complete (refusal,
   truncation, malformed output) or was declined by the configured model.
   Bugs never block.
7. **Report.** One review on the head commit. Block: REQUEST_CHANGES (COMMENT
   if GitHub refuses it), check fails. Pass: COMMENT, the gate dismisses its
   own earlier REQUEST_CHANGES reviews, check passes.

API or network errors fail the check without posting a review, so a re-run
retries; the annotation on the check says what failed.

## Setup checklist (per consuming repo, once)

1. Copy [`caller-example.yml`](caller-example.yml) to
   `.github/workflows/ai-gate.yml`. Replace `<FULL_SHA>` with a full
   injection-scanner commit SHA, set `owner` and `model`. Keep the job's
   `name: ai-gate` and never add a job-level `if:` (a skipped required check
   counts as passing).
2. Ruleset on the default branch: require a pull request; require status
   check `ai-gate` with source **GitHub Actions**; block force pushes; **no
   bypass actors**. If offered, restrict who can dismiss reviews to the owner.
3. Settings → General: allow auto-merge.
4. Secret `AI_GATE_ANTHROPIC_KEY`: a dedicated key from its own Anthropic
   Console workspace with a spend limit at or below the monthly API credit.
   Never the subscription OAuth token.
5. The agents' GitHub App or token must **not** have the `workflows`
   permission. Otherwise a PR can add a second workflow whose job is also
   named `ai-gate` and reports a fake pass.

Org repos need their own secret and ruleset.

## Day to day

- **Request a review:** enable auto-merge. Nothing runs before that, so
  drafts cost nothing.
- **Clear a block** (false alarm): read the findings, **approve the PR at the
  blocked head commit**, then **re-run** the failed `ai-gate` check. The
  re-run sees the approval and passes without a model call. Hidden-Unicode
  and lockfile-host hits cannot be cleared this way: fix the change. An
  approval of an older commit does not count.
- **Pushes:** any push while auto-merge is on fails the gate. Disable and
  re-enable auto-merge to request a fresh review. Exception: "Update branch"
  (merging the base into the PR) passes on its own as long as the PR's own
  changes are unchanged; a conflict resolution or any extra edit needs the
  re-click.
- **"enable auto-merge to request the AI gate"** on a new PR is expected:
  that is the gate waiting for you.

## Inputs

| Input | Default | Notes |
|---|---|---|
| `owner` | (required) | Login whose auto-merge click and approval count. Not `github.repository_owner` (that is the org for org repos). |
| `model` | `claude-opus-5-5` | Use `claude-fable-5-1` for sensitive repos (klaffat, nixos-config, `.claude`). Set in the caller file, which the gate itself protects; never a repo variable. |
| `effort` | `high` | `low`, `medium`, `high`, `xhigh`, `max`. |
| `suspicion-threshold` | `25` | Calibrate on past honest PRs (below). |
| `exceptions` | empty | Newline-separated globs (`*` crosses `/`) whose sensitive-path rule becomes extra scrutiny instead of a block, e.g. `.claude/*` for the `.claude` repo. Never covers `.github/workflows/`, `.github/actions/`, hidden Unicode or lockfile hosts. |
| `anthropic-api-key` | (required) | `${{ secrets.AI_GATE_ANTHROPIC_KEY }}`. Reaches only the gate step's env. |
| `github-token` | `${{ github.token }}` | Needs `contents: read`, `pull-requests: write`. |

## Cost (estimate, not measured)

About 30k input / 4k output tokens per pass, three passes per run. Opus 5.5
($4/$20 per MTok): about $0.60 per run. Fable 5.1 ($10/$50): about $1.50 per
run. Carry-overs and owner overrides make no model call. Watch the Console
for the first month.

## Calibration: dry-run

Runs the same checks and model passes locally on a diff file and prints the
verdict JSON (including the monitors' `analysis`). No GitHub calls.

```bash
gh pr diff 123 > /tmp/pr123.diff        # or: git diff main...HEAD
python pr-gate/gate.py --dry-run --diff /tmp/pr123.diff --no-llm       # deterministic only
ANTHROPIC_API_KEY=... python pr-gate/gate.py --dry-run --diff /tmp/pr123.diff \
    [--files-dir CHECKOUT] [--model claude-fable-5-1] [--effort high] [--threshold 25] \
    [--exceptions-file globs.txt]
```

`--files-dir` points at a checkout of the PR head (post-change contents for
Monitor B and binary magic bytes). Exit 0 pass, 1 block, 2 setup error. Run it
over 20-50 past merged PRs per repo type and set the threshold just above
their maximum suspicion.

## Limitations

- A single model reviewer is beatable: published work finds refined attacks
  get past a strong monitor roughly 40% of the time. This is a tripwire that
  forces a human look, not a guarantee.
- Binary files are blocked, not scanned (malware scanning is a follow-up).
- The fake-check defence rests on no agent credential having the `workflows`
  permission; a host PAT with that scope defeats it.
- A forged gate review would need a `github-actions[bot]` token, i.e. a
  workflow, i.e. the same `workflows` permission.
- Lockfile hosts outside the allowlist (e.g. a private registry) cannot be
  cleared per repo; that needs a gate change.
- A single emoji presentation selector straight after an emoji (the usual
  spelling of a warning-sign emoji) is allowed. Anything else with variation
  selectors, zero-width joiners or other invisible characters (including
  emoji ZWJ sequences such as family emoji) trips the hidden-Unicode check and
  cannot be approved through; rewrite the text without it.
- Things to verify on the first pilot are listed in the design doc ("Must be
  verified empirically"), notably whether the REQUEST_CHANGES review from
  `github-actions[bot]` is accepted on personal repos and whether
  `auto_merge_enabled` fires reliably.

## Updating the gate

Change code here, then bump `<FULL_SHA>` in each caller by PR (that PR is
itself gated). To bump the SDK: edit `requirements.in`, regenerate
`requirements.txt` with the command in it, and run the test suite against
that version (the tests drive the real SDK over a stub transport).
