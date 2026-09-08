# Lakera 429 Resilience Design

## Problem

Research-agent production calls generate valid reports, then lose them at the
delivery boundary when Lakera Guard returns HTTP 429. A 900-second pause does
not help because all research-agent processes and live checks share one
monthly Lakera budget. Meanwhile injection-scanner PR #15 already contains a
reviewed cross-process token bucket, circuit breaker, smoke liveness cache,
and hermetic CI split, but it never merged. Strict honeypot tool-call handling
merged later in PR #16 from the old main, so production contains the strict
honeypot and none of the budget controls.

## Goals

- Pace every Lakera call across local processes and cache boot liveness.
- Keep strict, schema-enforced honeypot tool calls from PR #16.
- Keep reports usable during Lakera quota throttling without treating
  unscanned content as safe.
- Reject on every attack signal, malformed scanner response, or unavailable
  fallback dependency.
- Keep reasons and layer metadata inside existing closed vocabularies; no
  report or provider bytes cross the isolation boundary.
- Keep pull-request CI hermetic. Live vendor checks remain scheduled or
  manually dispatched only.

## Non-goals

- General fallback for missing keys, bad configuration, authentication
  failures, malformed Lakera responses, timeouts, or non-429 server errors.
- Disabling Lakera or any other layer.
- Changing report storage, retry semantics, or audit visibility.
- Merging either repository's pull request automatically.

## Prior Art and Options

| Option | Design | Result |
|---|---|---|
| A — chosen | Integrate PR #15. On exact Lakera quota states, require strict honeypot pass plus unanimous existing cross-family judge pass. | Preserves layered scanning and remains usable during quota exhaustion. |
| B | Integrate limiter only; reject on local throttling and remote 429. | Stops request storms but still makes normal/deep research unavailable when quota is exhausted. |
| C | On 429, skip Lakera and trust honeypot alone. | Smallest change, but discards existing independent arbitration signal. |

## Architecture

### 1. Budget control

Integrate `feat/lakera-debounce` onto current `origin/main`. Its
`CrossProcessLimiter` remains the only Lakera admission point and retains its
reviewed token-bucket, circuit-breaker, on-disk locking, bounded untrusted
`Retry-After` parsing, liveness cache, and hermetic CI behavior.

No second limiter is added in research-agent. Every local caller reaches the
same scanner package and shared cache directory, so one boundary owns the
budget.

### 2. Exact quota-state classification

`intercept.scan_text` classifies only these fixed Lakera reasons as quota
degradation:

- `lakera_unavailable:HTTPError:429`
- `lakera_unavailable:throttled`

Matching is exact membership in a hardcoded immutable set. No prefix,
substring, exception body, response body, or report content influences this
decision. All other Lakera failures keep today's immediate rejection.

PR #15 originally returned the same `throttled` decision for an empty quota
bucket, a 429-opened breaker, and a 503-opened breaker. That would let a 503
silently enter the quota fallback on the next call. Integration therefore
adds a persisted closed breaker cause (`quota` or `service`) and distinct
limiter decisions. Bucket exhaustion and a 429 breaker retain
`lakera_unavailable:throttled`; a 503 breaker returns the new fixed reason
`lakera_unavailable:service-unavailable`. A service cause cannot be downgraded
to quota while its breaker window remains open. The state schema is bumped;
older state is treated as foreign and safely reinitialized under the existing
lock.

### 3. Degraded scan path

When Lakera returns a quota state and production honeypot scanning is enabled:

1. Defer delivery and continue to L3.
2. Run the strict honeypot ensemble unchanged.
3. Reject if any scenario triggers, skips, raises, returns malformed tool
   arguments, or otherwise fails.
4. Only after a fully clean honeypot, run the existing L4 cross-family judge
   panel.
5. Deliver only when every judge returns the exact benign enum. Any attack
   vote, missing vote, provider outage, malformed response, or exception
   rejects.

This is degraded coverage, not disabled coverage: two independent scanners
must affirmatively pass. The layer map retains the exact safe Lakera reason
and judge outcome for offline audit. Caller-visible success stays `pass` and
contains no outage or report-derived text.

When `use_honeypot=False`, quota degradation remains a hard reject. This keeps
deterministic/offline measurement calls from accidentally converting one
disabled layer plus one unavailable layer into a pass.

### 4. Existing Lakera-positive arbitration

The current `lakera:prompt_attack` plus clean honeypot path remains unchanged:
unanimous benign arbitration can clear known false positives. Quota fallback
reuses the same judge execution, `lakera_arbitration:*` rejection vocabulary,
and fail-closed result handling. Audit distinguishes paths through the exact
safe `layers["lakera"]` value, avoiding another outward-facing reason prefix.

### 5. Boot health

The smoke probe tests whether the production scan stack can safely process a
benign document, not whether every preferred provider is independently
available. A quota-degraded scan counts as healthy only when its verdict is
`ok=True`, honeypot layer is `pass`, Lakera layer is one exact quota state, and
judge layer is `benign-unanimous`. This lets research-agent start while its
strict fallback is viable. Other degraded states still fail smoke.

A verified quota-fallback pass may populate the existing liveness cache. The
cache remains only a short-lived claim that the complete scan stack passed;
it never stores a content verdict or outage reason. Cache-hit logging stops
claiming specific vendors were freshly contacted. Live logging distinguishes
full Lakera success from quota fallback.

## Failure Semantics

| Condition | Outcome |
|---|---|
| Lakera clean + honeypot clean | Pass, unchanged |
| Lakera attack + honeypot clean + unanimous benign judges | Pass, unchanged |
| Lakera attack + any fallback failure | Reject, unchanged |
| Lakera 429/local throttle + honeypot clean + unanimous benign judges | Pass |
| Lakera 429/local throttle + honeypot trigger/outage/malformed reply | Reject |
| Lakera 429/local throttle + judge attack/outage/malformed reply | Reject |
| Lakera 503, including later calls while its breaker is open | Reject before honeypot |
| Any other Lakera failure | Reject before honeypot, unchanged |

## Tests

All new tests are offline and deterministic.

- Exact remote 429 enters honeypot and judge fallback.
- Local limiter throttle enters same fallback.
- Clean strict honeypot plus unanimous benign judges passes.
- Honeypot trigger rejects without running judge.
- Honeypot outage rejects without running judge.
- Judge attack, outage, incomplete panel, and exception reject.
- 401, 503, no-key, bad-response, timeout, and limiter-error never enter
  fallback.
- Limiter state preserves 429 versus 503 breaker cause across processes; an
  overlapping 429 cannot downgrade an open service breaker to quota fallback.
- `use_honeypot=False` never enters fallback.
- Smoke accepts and caches only a fully verified quota fallback, while every
  other degraded layer still fails.
- Existing strict honeypot request-shape tests stay green.
- Full key-free suite stays hermetic.

## Rollout

1. Open injection-scanner PR from session-owned branch based on strict main.
2. Open research-agent PR pinning exact scanner commit.
3. Sync research-agent environment from its lock file; new MCP spawns use that
   exact commit without merging either PR.
4. Run scanner smoke once, then supplied deep-research prompts.
5. Accept rollout only if both calls return clean report paths and logs show no
   report delivery without successful fallback layers.
