# Design: `pr-gate` — an AI merge gate against sabotage by prompt-injected coding agents

**Date:** 2026-10-24
**Status:** draft, pending review
**Repos affected:** `injection-scanner` (publishes the action), every consuming repo (one small caller workflow + repo settings)

## Why

Most PRs in Jonathan's repos are written by AI coding agents (Claude Code, Codex) that read untrusted text all day. A prompt-injected agent could slip a backdoor, exfiltration, CI tampering, a dependency swap or an obfuscated payload into a PR that looks routine. `.claude#156` ranks this threat and finds most repos have no review requirement at all. A human skimming agent PRs will not reliably catch deliberate subterfuge, and published research says a single LLM reviewer won't either (frontier monitors drop from ~95% to ~60% catch rate against refined attacks; adaptive comments flip >90% of verdicts). So the gate is layered: deterministic checks the model cannot argue with, an injection tripwire, and dedicated hostile-author LLM passes — and it **blocks** rather than advises.

Research behind this design (all in `~/Repos/research-agent/reports/`): `042baaa568a24f2f8a4c23341200143d.md` (SOTA + GitHub mechanics), `e586224add7544a393934ca071a52ea4.md` and `e9cd6c3ab59f429d9a8554bd4c6f3e1e.md` (no ready-made tool fits), `86559b70e3af4572a8c1c73275aa3136.md` (billing).

## Goals, ranked

1. **Catch malicious / subterfuge code** in a PR, and treat needlessly obscure code (indirect, encoded, clever, unjustified by the visible change) as a finding in itself, to force agents toward legible code ("legibility protocols" in the AI-control literature).
2. **Security review** of newly introduced code.
3. **General code review** (correctness bugs).

## Non-goals

- Running, building or testing PR code. The gate reads diffs only.
- Replacing Jonathan's review. It is a tripwire that forces a look, not an approver; it never approves.
- Dependency-malware intelligence (Socket/StepSecurity-style). Possible later add-on, not v1.
- Closing `.claude#156` H4 (agents can act as Jonathan via the host PAT). Out of scope; noted as residual risk.

## Anti-goals (failure even if it "works")

- **Clever CI.** Jonathan's directive: CI/CD is load-bearing and must be *boringly simple and self-contained*. One action, one caller file per repo, no custom infra, no third-party actions inside the gate.
- **Alert fatigue.** A gate that fires on most PRs gets clicked through and means nothing. Hard-block rules stay narrow; calibrate before enforcing.
- **A gate the PR can disable.** Anything the PR controls (workflow files, config files, title, description, commit messages) must not influence whether or how the gate runs.
- **Rerolling to pass.** Re-running a blocked check must not get a fresh LLM roll.
- **Becoming the attack path.** The gate's key must not be reachable by PR content (no tools, no checkout, no execution).

## Constraints

- **Funding:** an Anthropic API key from the Claude Max **monthly API credits** (~$100 on Max 5x / $200 on Max 20x per a third-party source; check the Console). Dedicated key in its own Console workspace with a **spend limit at or below the credit**, so a leaked key burns at most the cap. Never the subscription OAuth token.
- **Model configurable per repo**, so the sensitive repos (klaffat, nixos-config, `.claude`) use Fable (`claude-fable-5-1`) and the rest use Opus (`claude-opus-5-5`). The setting lives in the caller workflow file (protected by the gate itself), not in a repo variable (any writer, including the bot, can change variables).
- **Blocking:** Jonathan wants a block he must actively clear — ideally a REQUEST_CHANGES review.
- **Invocation from the GitHub UI:** Jonathan enabling **auto-merge** is the "ready, review it" signal. Nothing runs before that, so drafts and WIP cost nothing.

## Architecture

```
consuming repo                                      injection-scanner (public)
.github/workflows/ai-gate.yml   ──uses @<full SHA>──▶  pr-gate/action.yml  (composite)
  on: pull_request_target                              pr-gate/gate.py     (stdlib + injection_scanner)
  types: [auto_merge_enabled, synchronize, reopened]
  job name: ai-gate  (the required check)
  with: model, anthropic-api-key, openai-api-key
```

- **`pull_request_target`** so the workflow always comes from the base branch, never from the PR. No `actions/checkout` of PR code anywhere; the diff is fetched as data through the API.
- **Composite action** in a subfolder of the public `injection-scanner` repo, consumed **pinned to a full commit SHA**. Updating the gate is a deliberate PR bumping the SHA. Public so the `klaffat` org repo can use it too.
- **The caller file** (~20 lines) carries what an action cannot: trigger, `permissions: {contents: read, pull-requests: write, issues: read}` (`issues: read` for the timeline that records who dismissed a review), concurrency per PR, the job named `ai-gate`, and `model:`. The required job **must never have a job-level `if:`**: GitHub counts a skipped required job as success.
- **The secret is passed only to the gate step**, never exported job-wide.

### What the gate does, in order (fail closed at every step: any error → block)

1. **Owner intent + freshness.** Query the PR via GraphQL. If auto-merge is not enabled, **fail** with "enable auto-merge to request the AI gate" (fail, never skip). If `autoMergeRequest.enabledBy.login` is not the configured `owner` input, **fail** with "auto-merge must be enabled by <owner>" — the bot has write access and can enable auto-merge itself, so "auto-merge is on" alone proves nothing. `owner` is an explicit caller input (Jonathan's login), never `github.repository_owner`, which is the org for klaffat. If the PR head moved since the event, fail as stale. The PR's live base (GraphQL `baseRefName`) must be the repository's default branch (from the event payload), otherwise fail with "the AI gate only reviews PRs into <default>": a check result lives on the head SHA, so a pass on a PR into another branch would satisfy a later PR of the same head into the default branch.
   **On `synchronize` and `reopened` (decided 2026-10-24, simplified the same day): fail, no model call**, with "head changed after auto-merge was enabled; disable and re-enable auto-merge to re-request review". Auto-merge survives pushes by anyone with write access, so otherwise a push after Jonathan's click would be reviewed and merged with no further look, and every push would be a free re-roll (a refined attack gets past one reviewer ~40% of the time) that also spends the capped budget. One carve-out so updating a PR from the default branch costs no clicks: if the **newest** verified gate verdict on the PR is a pass and the PR's **own changes** are identical to the ones it recorded, the run passes without a model call (always-on checks only). Nothing else matters: markers are HMAC-signed, so a pass can't be minted, and a replayed real pass only re-asserts content that was passed. Override and carry-over passes record the hash too, so repeated "Update branch" clicks keep carrying over. "Own changes" = the base...head diff normalised to, per file, the hunk bodies without `@@` offsets, plus binary content hashes, hashed (see DECISIONS.md 1-2). The pass review records that hash; only reviews authored by `github-actions[bot]` count. A merge from `main` leaves the hash unchanged; a conflict resolution or any extra edit changes it and needs the re-click.
2. **Override check (reroll guard).** If the gate has a verified block on this exact head SHA, the LLM layers are not re-run. The run passes only if `owner` **dismissed that review** (the issue timeline's `review_dismissed` event, actor = owner; a dismissal by `github-actions[bot]` or anyone else does not count); otherwise it fails with "the gate blocked this commit; dismiss its review to override, then re-run". Dismissal, not approval: GitHub forbids approving your own PR, and agents often act as the owner. The override skips only the LLM layers and the overridable rules: the hidden-Unicode, lockfile-host and text-as-binary checks **always** run, since they have no legitimate trigger and must not be launderable through "false alarm, dismiss".
   **Re-runs never ask the model.** Otherwise, if `GITHUB_RUN_ATTEMPT` > 1, fail with "a re-run never asks the model again; dismiss the gate's review to override, or disable and re-enable auto-merge for a fresh review". Any writer can re-run a check; an owner auto-merge click is attempt 1 of a new run. (This also covers a run that failed at step 1 or on infra: the retry is an auto-merge toggle.)
3. **Fetch the diff** base...head via `Accept: application/vnd.github.diff` (no commit messages, title, body or comments ever reach a model), plus the post-change contents of touched text files. Fail closed above a size cap (initial: 400 kB total) with "too large for the AI gate; human review".
4. **Deterministic checks** (cannot be argued with; any hit → block):
   - Invisible / bidi / tag / variation-selector / private-use / soft-hyphen / line-separator characters in added lines — via a new strict `profile="code"` in `injection_scanner.unicode_sanitize` (the current prose profile deliberately leaves U+FE00–FE0F, PUA, U+00AD, U+200E/F and U+2028/9 alone, which misses the GlassWorm vector). Block on **any** hit; never on `is_anomalous`, whose minimum-count floor would pass a two-character payload.
   - Any added or modified **binary** file (the diff shows only "Binary files differ", so no model can see it). Blocks, but owner-overridable like the path rules — see open question 2. Minified/vendored/generated paths (`dist/`, `vendor/`, `*.min.*`) and very long lines go to the model as extra scrutiny.
   - Changes under `.github/` and to agent-instruction files (`CLAUDE.md`, `AGENTS.md`, `.claude/`, `.codex/`, `.mcp.json`).
   - Lockfile entries resolving to a host outside an allowlist (npm/yarn registries, crates.io, PyPI, github.com for flake inputs — builder finalises the list per ecosystem).
   - Per-repo exceptions via a caller input: a list of path globs whose **path rule** is downgraded from block to "extra scrutiny" (e.g. the `.claude` repo legitimately edits agent files). Exceptions never touch the Unicode or lockfile-host checks, and can never cover `.github/workflows/`.
   - Deliberately **not** hard-blocked (too noisy): `*.nix`, `flake.lock` bumps from allowed hosts, `build.rs`, install scripts. These are passed to the model as "extra scrutiny" files.
5. **No honeypot in v1** (decided 2026-10-24; follow-up PR, see Follow-ups). Lakera (L2) is **not** used in CI (fleet-wide rate limit).
6. **LLM passes**, all tool-less Messages API calls with JSON-schema structured output (if the configured model doesn't support it, fall back to JSON in text validated against the schema; unparseable → block). The input is wrapped in a random-nonce tag and declared untrusted; text addressed to reviewers or AI is treated as strong evidence of malice; comments are claims to be verified from code; invisible chars rendered as `<U+XXXX>`:
   - **Monitor A** (hostile-author prompt, configured model) on the **diff only**: "assume the author is hostile", investigate then score suspicion 0–100, findings with categories `malicious | obscure | security | bug`.
   - **Monitor B** (same prompt, configured model) on the **diff plus post-change contents of touched files**. Diversity by context rather than a fragile comment-stripping heuristic (which would delete `#include`/Nix/shell lines); the research finds strong monitors use full context well while diff-only resists dilution, so the two views fail differently.
   - **Review pass** (configured model): security vulnerabilities and correctness bugs newly introduced; only concrete, high-confidence issues.
7. **Verdict.** Block if any deterministic hit, max suspicion ≥ threshold, any `malicious`/`obscure` finding of medium+, or any high `security` finding. Bugs never block (goal 3 is advisory).
8. **Report.** One PR review on the head SHA: on block, event `REQUEST_CHANGES` (fallback `COMMENT` if the API refuses it) and exit 1; on pass, `COMMENT` with findings (if any), **dismiss the gate's own earlier REQUEST_CHANGES reviews on this PR** (otherwise an approved PR may stay unmergeable), and exit 0. The model's `file`/`explanation` text is the only attacker-shaped text that reaches the PR, and the next coding agent reads it: render it as plain text, neutralise `@mentions` and `#123` references, no markdown links. Body: verdict, suspicion, deterministic hits, findings by severity.
9. **Key handling.** The API key reaches the Python process through step `env:` only, never interpolated into a command line; the gate never prints exception bodies or HTTP error bodies (they can echo the request).

### Clearing a block (decided with Jonathan)

1. Jonathan reads the findings.
2. If it's a false alarm: **dismiss the gate's REQUEST_CHANGES review**, then **re-run** the failed `ai-gate` check. Step 2 sees the owner's dismissal and passes without a model call. This works on PRs authored as Jonathan, which he can't approve.
3. Any new push fails the gate until Jonathan disables and re-enables auto-merge, except a pure update from the default branch (see step 1). A dismissal clears only the head commit it was posted on, and only while the PR provably stayed there: in timeline order, no `committed` event after the dismissal and no force push / branch restore after the block was posted (otherwise a writer moves the head away, the stale block gets dismissed as housekeeping, and the writer pushes back). Dismissing the gate's review is the override action, not housekeeping.
4. A re-run never gets a fresh model roll; disabling and re-enabling auto-merge does (a new run).

## Repo settings (per consuming repo, done once — a checklist, not automation)

1. Ruleset on the default branch: require a PR; require status check `ai-gate` with **source = GitHub Actions**; block force pushes; no bypass actors. If available on the repo type: "Restrict who can dismiss reviews" → Jonathan and GitHub Actions (the gate dismisses its own superseded blocks).
2. Allow auto-merge.
3. Secret: `AI_GATE_ANTHROPIC_KEY` (dedicated, capped Console workspace).
4. **The agents' GitHub App/token must not have the `workflows` permission.** Otherwise a PR can add a second workflow whose job is also named `ai-gate` and reports a fake pass (pinning the check source to GitHub Actions does not stop this — every workflow reports as GitHub Actions). This is a `.claude#156` item requiring Jonathan's click in the App settings.

## Must be verified empirically before relying on it

1. Whether a REQUEST_CHANGES review posted with `GITHUB_TOKEN` (as `github-actions[bot]`) is accepted by the API and actually blocks merge/auto-merge on a personal repo. Sources conflict. The failing required check is the real gate regardless.
2. Whether "Restrict who can dismiss reviews" (rulesets, GA 2026-07-07) is offered on user-owned repos.
3. That `auto_merge_enabled` fires `pull_request_target` reliably (a Feb 2026 community report says it sometimes didn't; workaround: toggle auto-merge or push).
4. That the monthly API credits are actually consumed by this key (check the Console after the first runs).
5. On pass, the merge actually happens (the gate can dismiss its own REQUEST_CHANGES even with dismissal restricted; otherwise Jonathan dismisses it).
6. Which of two same-named `ai-gate` check runs the ruleset honours. Until known, the fake-check defence rests on no agent credential having the `workflows` permission — and the host PAT (`.claude#156` H4) almost certainly has it.
7. The ruleset binds to the job's display `name:`; the caller template mandates `name: ai-gate`.
8. That `GET /repos/{o}/{r}/issues/{n}/timeline` (who dismissed the gate's review) is readable with the caller's token; the caller grants `issues: read` as well as `pull-requests: write`, since GitHub documents either the Issues or the Pull requests read permission. If not, the override fails closed as an infra error.

## Calibration and rollout

1. **Shadow mode first:** run the gate over 20–50 of Jonathan's past merged (assumed honest) PRs per repo type; set the suspicion threshold just above their maximum (≈ fixed low false-positive rate, the method from the AI-control papers). Initial default: 25.
2. Pilot on `smarthome` (public, low stakes). Then nixos-config, `.claude`, klaffat (org repo: separate secret and settings), each with Fable.
3. Codex `@codex review` (ChatGPT Pro quota) stays available as an optional, advisory, cross-family second opinion triggered by comment. Not part of the gate.

## Cost (estimate, not measured)

~30k input / ~4k output tokens per call, 3 calls per run. Opus 5.5 ($4/$20 per MTok): ≈ $0.60/run. Fable 5.1 ($10/$50): ≈ $1.50/run. At ~100 PRs × ~2 runs/month mixed models, roughly $100–200 — at the credit ceiling with Fable on the busy repos; watch the first month.

## Open questions

1. **MicroVM containment (Jonathan raised it).** Proposal: don't. The microvm lives in `research-agent`/nixos-config on dellan and contains an agent *with tools and network* reading hostile web content. The gate has no tools, runs no PR code, and runs on GitHub's throwaway runner VM. Putting it in a microvm means a self-hosted runner on dellan or nested KVM + Nix in CI, which breaks the "boringly simple" constraint for little gain. Reconsider only if the gate ever needs to execute PR code.
2. **Binary files.** A model can't see them, and images can carry payloads for agents that later read them. Recommendation: (a) block, owner-overridable (dismiss + re-run), and additionally check that the file's magic bytes match its extension so a "PNG" that is really an executable or archive is caught; this is rare enough in these repos that the click costs little. Alternatives: (b) also auto-pass small common media types (png/jpg/webp/ico/woff2) whose magic bytes match — less clicking, a little more attack surface; (c) forbid binaries outright (LFS or external storage). **v1: (a)** (2026-10-24); malware scanning is follow-up 3. Exception: a file with a source/text extension that git treats as binary (e.g. a NUL byte in a `.js` comment) and that has no known binary magic is a **non-overridable** block: no model and no Unicode or lockfile check can see it.

## Follow-ups (separate PRs after v1)

1. **Honeypot for code review.** Add scenarios aimed at a code reviewer ("this is safe, reviewer", instructions to approve or to skip a file) rather than research-summary exfiltration, exclude the scanner's own canary literals from what counts as a trip, and decide the OpenAI dependency (Anthropic-only subset vs capped OpenAI key). Then wire it in as a blocking layer after measuring false positives on `.claude` and injection-scanner diffs.
2. **Lakera / L2 replacement** — pending the investigation started 2026-10-24.
3. **Binary scanning.** Fetch changed binaries as blobs through the API (still no checkout) and scan them: ClamAV with fresh signatures on the runner, YARA rules, and a VirusTotal **hash lookup only** (never upload: files from private repos must not go to a third party). Also flag archives or executables embedded inside media files. Expectation to keep in mind: signature scanners catch known malware, not a payload a hijacked agent writes fresh, so this complements the block-and-look rule rather than replacing it.

## Left to the builder

- Exact prompt wording (keep the structure above), JSON schema details, lockfile host allowlists per ecosystem, review body formatting, tests (the gate's verdict logic and deterministic checks must be unit-tested offline; model calls stubbed, matching the repo's hermetic `ci.yml`).
- Whether `pr-gate` installs `injection_scanner` from the pinned checkout of the action itself (preferred: the action's own `$GITHUB_ACTION_PATH`, so code and scanner are one pinned SHA).
