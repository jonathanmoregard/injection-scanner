# 003 — Multi-turn drift in L3 honeypot stage

**Status:** proposal
**Source:** SOTA-vs-setup review of `repo-check` Phase C honeypot
(2026-04-28). Cross-ref: `repo-check/proposals/003`.

## Gap

`L3/honeypot` tempts a downstream Haiku with trap tools and fails
the report if the report coerces a tool call. The current shape
is single-turn: feed the report, observe one round of tool
decisions.

A patient injection chains across turns: turn 1 establishes a
benign tool-use pattern, turn 2 introduces ambiguity, turn 3
slips the exfil. Single-turn honeypots miss this because the bait
call only becomes "rational" in light of the prior context the
injection planted.

## Why it matters

Microsoft PyRIT, NVIDIA garak, and AgentDojo's "delayed payload"
threat model all use multi-turn sequences (typically 5–20 turns).
Single-turn coverage is the easiest evasion to author once a
defender publishes their setup.

## Proposal

Extend L3 to optionally run an extended-session mode:

- After the initial report-as-context turn, the honeypot Haiku
  receives N follow-up turns from a small auto-prompter. Prompts
  are bland follow-ups ("anything else?", "elaborate on point 2",
  "summarize for a non-expert") sourced from a real-conversation
  corpus, not synthetic.
- Each turn's tool-call decisions are evaluated against the trap
  table. First trap call → fail.
- Cap turns (e.g. N=10) and wall time (e.g. 90 s) per scan to
  bound cost.

Mode controlled by per-call config (callers like `research-agent`
may opt out for fast scans, `repo-check` opts in for vetting
runs).

## Effort

~120 lines (auto-prompter loop, follow-up corpus loader, config
plumbing). Cost per scan ~10× current L3 single-turn.

## Risk if skipped

Single-turn honeypots become public state-of-art for evading.
Defensive value of L3 erodes within months of the setup being
visible.
