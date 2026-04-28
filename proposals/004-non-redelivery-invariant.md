# 004 — Document the "non-redelivery invariant" as a library promise

**Status:** proposal
**Source:** SOTA-vs-setup review of `repo-check` Phase C honeypot
(2026-04-28). Cross-ref: `repo-check/proposals/007`.

## Gap

The shared invariant — *bytes captured from a triggered attack
pathway must not flow back into any LLM's input* — is upheld
inside `repo-check` (genericized response, deny-listed quarantine
audit dir) but not stated as a library-level contract of
`injection-scanner`.

A future caller (or refactor of an existing caller) can build on
top of this scanner and accidentally re-feed flagged content into
a downstream LLM. Worst case: a "summarize why we rejected this"
pass that reads the offending bytes back into a model. The
library's API does nothing today to prevent that.

## Why it matters

Standard literature does not name this invariant. Greshake et
al. (2023) argue for content/system separation but stop short of
forbidding LLM re-read of caught payload. NIST AI RMF mentions
data lineage but not the specific "no LLM ingest of attack bytes
post-detection" rule.

A defended pipeline that re-feeds caught bytes becomes a
**re-delivery vehicle** for the very injection it caught. This is
strictly worse than no defense, because the attacker reaches an
LLM (operator's host session reading audit, summarizer LLMs
ingesting structured findings) they otherwise would not have.

## Proposal

Two changes:

1. **Doc**: add `docs/non-redelivery-invariant.md` (and link from
   README) defining the rule and the explicit audit/test that
   enforces it. Recommend that callers structure their findings
   surface so attacker-influenced strings never get inlined into
   downstream prompts.

2. **API**: scanner's findings dataclass exposes
   `safe_summary: str` (operator-facing, no attacker bytes) and
   `raw_payload: bytes` (must not be passed to any LLM). The two
   are typed differently (or `raw_payload` access requires going
   through a function named `_for_human_audit_only_*`) so a
   future programmer who tries to `f"detected: {finding.raw}"` is
   immediately suspicious in code review.

## Effort

~1 page of doc + ~30 lines of API restructure + ~15 lines of CI
test that grep-fails if `raw_payload` references appear outside
a small audit-log path.

## Risk if skipped

Future caller, or a refactor of an existing caller, accidentally
re-feeds caught bytes into a model. The library currently does
nothing to make this an obvious mistake at code-review time.
