# Lakera debouncer — cross-process rate limiting for the L2 gate

Date: 2026-09-05. Status: approved (placement A confirmed by the maintainer; the rest settled by
discernment under the standing instruction "fix the problem in a robust and comprehensive and
straightforward way").

## 1. Problem

Lakera Guard is called from one function, `injection_scanner.lakera.check()`, by several
independent processes that share ONE Lakera account:

| caller | Lakera calls per event | measured 2026-09-05 |
|---|---|---|
| research-agent boot smoke (one server per Claude Code pane) | 1 | 5–7 spawns in 12 s on a kitty session restore |
| research-agent degraded recheck | 1 | on demand, ≥ 60 s apart per pane, ~6 panes |
| research-agent per-report scan | 1 | per `research()` / `retry_research()` |
| CI `smoke` job | 1 | per workflow run |
| CI `eval` job (`--use-lakera --confirm-disagreements 2`) | 16 + ≤ 2 per disagreeing case | ~7 runs → ~130 calls in one afternoon |
| local `eval` runs | 16+ | ad hoc |

From ~15:00 local on 2026-09-05 Lakera answered HTTP 429 on roughly three of every four calls
(190–280 ms, immediate server-side rejection), about one success per 4–5 minutes fleet-wide
regardless of attempt count. Nothing in the code base reacts to a 429: `lakera.check()` fails
closed on the spot, every caller retries on its own schedule, and no process knows what any other
process just did. CI adds 16-call bursts on top, and two CI runs (a PR push and a main push, or two
PR pushes) can overlap. On the scoring side, `eval` counts an outage verdict (`ok=False`) as
BLOCK, so a throttled Lakera *agrees* with every injection-labelled case and inflates recall.

Maintainer directives (verbatim, from `session-constraints.md`):

> "if this fails, wait for 4h, then run research call to check lakera rate limiting numbers, and add
> a debouncer to make sure we don't trigger lakera throttling again"

> "make CI not hammer lakera pls, mind the relations"

## 2. Goals and non-goals

Goals:

1. The fleet-wide Lakera call rate is bounded by a configured budget, independent of how many
   processes are alive.
2. After a 429 (or 503) nobody in the fleet calls Lakera again until `Retry-After` — or a capped
   exponential backoff when the header is absent — has elapsed.
3. Per-push CI makes no external calls at all. The live checks run once nightly and on manual
   dispatch, never overlap, and never start the 16-call `eval` when the 1-call `smoke` already
   shows Lakera down.
4. An outage never scores as a classification: `eval` aborts loudly on the first infra verdict.
5. Every limit is an input (environment or CLI), never a constant fitted to today's numbers; the
   defaults are provisional until the 2026-09-06 00:12 measurement lands.
6. Fail-closed semantics and Invariant 4 ("the caught bytes never return") are unchanged. In
   particular the server-supplied `Retry-After` text never reaches a `reason`.
7. Tests are key-free, deterministic, and never touch the network.

Non-goals (deliberately out of scope):

- A shared smoke-verdict cache or singleflight across panes (option B). Revisit only if the 00:12
  measurement shows boot bursts still matter with the limiter in place.
- Changing the Lakera plan, or a dedicated CI key/project to split budgets. Operator decision after
  the measurement; the design works either way.
- `selfupdate.py` (inert, fate decided separately).

## 3. Architecture

```
research-agent smoke/recheck/scan ─┐
CI smoke ──────────────────────────┤
CI eval / local eval ──────────────┤
                                   ▼
        intercept.scan / scan_text(lakera_max_wait_s=…)
                                   │
                                   ▼
        lakera.check(text, max_wait_s=…)          ← key resolution first (no token burnt on no-key)
                │  acquire(max_wait_s)
                ▼
        throttle.CrossProcessLimiter  ── flock ──▶  $CACHE_DIR/lakera-throttle.{json,lock}
                │  ALLOWED / THROTTLED / ERROR
                ▼
        _post() ──▶ record_success() | record_throttled(Retry-After)
```

Files touched: new `injection_scanner/throttle.py`; `lakera.py` (integration); `intercept.py`
(one keyword plumbed); `eval.py` (`--lakera-max-wait`, infra abort); `.github/workflows/ci.yml`;
`README.md`; new `tests/test_throttle.py`, `tests/conftest.py`; extended `tests/test_lakera.py`,
`tests/test_eval.py`, `tests/test_intercept.py`.

### 3.1 `throttle.py` — `CrossProcessLimiter`

One token bucket plus one circuit breaker, state on disk, every operation a read-modify-write under
an exclusive `fcntl.flock`. Wall-clock `time.time()` throughout (monotonic clocks are not comparable
across processes).

```python
@dataclass(frozen=True)
class LimiterConfig:
    min_interval_s: float   # sustained: one call per this many seconds, fleet-wide
    burst: int              # bucket capacity
    backoff_base_s: float   # breaker delay after the 1st consecutive 429 without Retry-After
    backoff_max_s: float    # cap on any breaker delay, INCLUDING a server-supplied Retry-After
    lock_wait_s: float      # bounded wait for the flock

class Decision(enum.Enum):
    ALLOWED = "allowed"
    THROTTLED = "throttled"   # bucket empty or breaker open beyond max_wait_s
    ERROR = "error"           # limiter itself unusable (dir unwritable, lock wait exceeded, IO error)

class CrossProcessLimiter:
    def __init__(self, state_dir: Path, config: LimiterConfig, *, name: str = "lakera",
                 clock=time.time, sleep=time.sleep): ...
    @classmethod
    def from_env(cls, name: str = "lakera") -> "CrossProcessLimiter": ...
    def acquire(self, max_wait_s: float = 0.0) -> Decision: ...
    def record_success(self) -> None: ...
    def record_throttled(self, retry_after: str | None) -> None: ...
```

State file `<name>-throttle.json`:

```json
{"schema": 1, "tokens": 1.0, "updated_at": 1757100000.0, "open_until": 0.0, "failures": 0}
```

Lock file `<name>-throttle.lock`, opened fresh for every operation (so the lock also serialises
threads within one process — each open is its own open file description). `LOCK_EX | LOCK_NB`,
retried every 50 ms until `lock_wait_s` elapses, then `ERROR`. flock releases on process death, so
there are no stale locks to reap. State is written to `<file>.tmp` then `os.replace`d, inside the
lock. The directory is created with mode `0700` if missing.

`acquire(max_wait_s)`:

```
deadline = clock() + max_wait_s
loop:
    with lock:                                   # ERROR on lock timeout / OSError
        st = load()                              # missing/corrupt/foreign schema → fresh state
        now = clock()
        elapsed = max(0.0, now - st.updated_at)  # clock went backwards → 0
        st.tokens = burst if min_interval_s <= 0 else min(burst, st.tokens + elapsed / min_interval_s)
        st.updated_at = now
        if now < st.open_until:      wait = st.open_until - now          # breaker open: no token spent
        elif st.tokens >= 1.0:       st.tokens -= 1.0; save(st); return ALLOWED
        else:                        wait = (1.0 - st.tokens) * min_interval_s
        save(st)                                 # persist the refill even when refusing
    if clock() + wait > deadline:  return THROTTLED
    sleep(min(wait, 1.0))                        # re-read: another process may have changed things
```

`max_wait_s = 0` (production default) therefore returns on the first pass: `ALLOWED` or
`THROTTLED`, sub-millisecond, no network. A positive `max_wait_s` (batch callers) blocks until a
token is available and the breaker is closed, or the deadline passes.

`record_throttled(retry_after)`:

```
failures += 1
delay = parse_retry_after(retry_after)                     # None when absent/unparseable
if delay is None: delay = backoff_base_s * 2 ** (failures - 1)
delay = min(max(delay, 0.0), backoff_max_s)
open_until = max(open_until, now + delay)
```

`parse_retry_after` accepts a non-negative integer/float number of seconds or an HTTP-date
(`email.utils.parsedate_to_datetime`, converted to seconds from now, floored at 0). Anything else,
including any exception, is `None`. The header is server-supplied TEXT and is treated as such: it
is parsed into a clamped number inside the limiter and is never stored, logged, or interpolated
anywhere. `backoff_max_s` caps a server-supplied value too — an absurd `Retry-After` from a buggy
or hostile server must not park the fleet indefinitely.

`record_success()`: `failures = 0; open_until = 0.0`. Called on any HTTP 200, flagged or not — the
account is evidently not throttling us.

Half-open behaviour falls out of the state: once `open_until` passes, the first caller with a token
goes through; a further 429 increments `failures` and opens the breaker for longer (capped).

Errors: any exception inside `acquire` (IO, lock timeout, malformed state that slipped past the
loader, arithmetic) yields `ERROR` — `intercept.py` does not wrap `lakera.check`, so an escapee would
abort the whole scan instead of failing it closed. `record_*` swallow their own errors — if the state cannot be written, the very next `acquire` fails the same way and refuses, so
a broken limiter can never turn into a hammer. A corrupt, truncated, or foreign-schema state file
is NOT an error: it is replaced by a fresh state (full bucket, breaker closed).

Aggregate guarantee, with N processes sharing the file: at most `burst + elapsed / min_interval_s`
calls reach Lakera in any window of length `elapsed`, and zero calls while the breaker is open.
N does not appear in the bound.

### 3.2 Configuration — all inputs, no on/off switch

Read by `CrossProcessLimiter.from_env()` with tolerant parsing (malformed → default, then clamp):

| environment variable | default | clamp | meaning |
|---|---|---|---|
| `INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S` | `15` | `[0, 3600]` | sustained fleet-wide interval; `0` disables the bucket (breaker still applies) |
| `INJECTION_SCANNER_LAKERA_BURST` | `2` | `[1, 1000]` | bucket capacity |
| `INJECTION_SCANNER_LAKERA_BACKOFF_BASE_S` | `30` | `[0, 3600]` | breaker delay after the first 429 without `Retry-After` |
| `INJECTION_SCANNER_LAKERA_BACKOFF_MAX_S` | `600` | `[0, 86400]` | cap on every breaker delay, `Retry-After` included |
| `INJECTION_SCANNER_LAKERA_LOCK_WAIT_S` | `2` | `[0, 60]` | bounded flock wait before `ERROR` |
| `INJECTION_SCANNER_LAKERA_MAX_WAIT_S` | `0` | `[0, 86400]` | default `max_wait_s` for `check()` when the caller passes none |
| `INJECTION_SCANNER_CACHE_DIR` | `~/.cache/injection-scanner` | — | state directory (same dir `selfupdate.py` already uses) |

There is no feature flag. "Off" is `MIN_INTERVAL_S=0` (bucket always full) plus `BACKOFF_MAX_S=0`
(breaker delay clamps to zero); nobody should want that in production, and a switch that ships
defaulted-off is the failure mode the `avoiding-unrequested-feature-flags` rule exists to prevent.

The defaults encode today's best guess: the healthy pre-onset fleet averaged ~0.6 calls/min with
zero failures, and the interval keeps the worst case (fleet + CI) at ~6 calls/min. They are
PROVISIONAL and are retuned from the 2026-09-06 00:12 measurement of Lakera's actual limits — by
changing env values, or these defaults in a follow-up commit, never by editing the algorithm.

### 3.3 `lakera.py` integration

`check(text: str, *, max_wait_s: float | None = None) -> LakeraResult`. `None` means "use
`INJECTION_SCANNER_LAKERA_MAX_WAIT_S`". Order inside `check()`:

1. Key resolution as today (`key-config-error`, `no-key`) — BEFORE the limiter, so a call that
   cannot happen does not spend a token.
2. `limiter = CrossProcessLimiter.from_env()` (built per call; a few env reads, no cache to
   invalidate) and `decision = limiter.acquire(max_wait_s)`.
   - `THROTTLED` → `LakeraResult(ok=False, reason="lakera_unavailable:throttled")`
   - `ERROR` → `LakeraResult(ok=False, reason="lakera_unavailable:limiter-error")`
3. `_post()` as today. On `urllib.error.HTTPError` with `code in (429, 503)`:
   `limiter.record_throttled(e.headers.get("Retry-After"))`, then the existing
   `_transport_reason(e)` return (e.g. `lakera_unavailable:HTTPError:429`). Other exceptions:
   breaker untouched, existing reason.
4. On a parsed 200 response (pass, `prompt_attack`, or `flagged`): `limiter.record_success()`.

Both new reasons are fixed literals from a closed vocabulary; they carry no data. Both are
fail-closed: the report is rejected exactly as for any other `lakera_unavailable:*`. A locally
refused call costs ~1 ms and no network.

### 3.4 `intercept.py` plumbing

`scan(path, use_honeypot=True, use_lakera=True, lakera_max_wait_s=None)` and `scan_text(...)`
gain the one keyword and pass it unconditionally to
`lakera.check(san.text, max_wait_s=lakera_max_wait_s)`. No other behaviour change; the
deferred-arbitration path is untouched. Existing one-argument `lakera.check` stubs in
`tests/test_intercept.py` are updated to accept the keyword — a conditional call site that only
passes it when set would hide the signature change from those tests.

### 3.5 `eval.py` — batch caller, honest scorecard

- New CLI flag `--lakera-max-wait SECONDS` (float, default `900`), threaded through
  `run_eval(..., lakera_max_wait_s=...)` to `scan_text`. A batch run waits for its turn instead of
  being refused; the default is on the CLI because `eval` is always a batch caller and should not
  depend on the operator remembering an env var.
- Infra abort. `evaluate` classifies every verdict with `_is_infra_reason(reason)`, the same
  head-anchored, closed rule research-agent uses (`mcp_server/server.py::_is_infra_reason`):
  the first `:`-segment ends with `_unavailable`; or the first segment is `honeypot` /
  `lakera_arbitration` and the second ends with `_unavailable`; or the whole reason is one of
  `no-key`, `key-config-error`, `bad-response`. Never a substring search; default `False`. On the
  first infra verdict `evaluate` raises `EvalInfraError(case_id, reason)`; `_main()` prints
  `INFRA <case_id> <reason>` to stderr and exits with code `3` (distinct from `1` = gate failed,
  `2` = usage). No further cases are scanned, so a throttled Lakera costs at most one probe per
  breaker window and the scorecard can never report recall earned by an outage.

### 3.6 CI: hermetic merge gate, live checks on a schedule

Maintainer directive 2026-09-06 (verbatim): *"ci tests should not call external services in
general, smell. Sceptical of calling lakera/honeypots in ci."* Resolved as: the per-push workflow
makes no external calls at all; the live checks move to their own scheduled / on-demand workflow.

**`.github/workflows/ci.yml`** (`pull_request` + `push: main`) keeps ONLY the `test` job (python
3.12 / 3.13 matrix, `pytest tests/`). The `smoke` and `eval` jobs, their fork guards and every
`secrets.*` reference are removed. A workflow-level concurrency block is added so superseded PR
pushes are cancelled instead of stacking:

```yaml
concurrency:
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
```

**`.github/workflows/live-eval.yml`** (new) carries the live pipeline, unchanged in what it runs:

```yaml
name: live-eval
on:
  schedule:
    - cron: "17 3 * * *"          # once nightly, off the hour
  workflow_dispatch: {}           # on demand, incl. on a branch: gh workflow run live-eval.yml --ref <branch>
permissions:
  contents: read
# At most ONE Lakera-touching job anywhere in this repo at any time; queue, never cancel.
concurrency:
  group: lakera-live
  cancel-in-progress: false
jobs:
  smoke:
    timeout-minutes: 10
    env:
      INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S: "30"   # CI paces itself stricter than the fleet
    ...                                             # the former ci.yml smoke job, keys via secrets
  eval:
    needs: smoke                    # the 1-call smoke is the canary for the 16-call eval
    timeout-minutes: 30
    env:
      INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S: "30"
    ...                                             # the former eval job, plus --lakera-max-wait 900
```

Relations this encodes: PR CI touches no vendor, needs no secret, and cannot go red because a
vendor is down or throttled; live checks cost ~17 Lakera calls per day instead of ~17 per push;
`smoke` and `eval` never overlap within a run (`needs`) or across runs (the workflow-level group);
a Lakera outage fails `smoke` (1 call) and `eval` is skipped (0 calls). GitHub notifies the last
committer of a scheduled workflow on failure, so a nightly red is seen without extra machinery. A
detection-quality-sensitive PR is checked by dispatching `live-eval` on its branch before merge —
deliberately a human gesture, like the merge click. The CI runner's cache dir is fresh per run, so
its limiter is a separate domain from the local fleet — hence the stricter interval. Production's
own boot smoke (every research-agent spawn, agent-readable since 2026-09-05) remains the live
canary for vendor drift, which is where such drift actually bites.

Offline regression coverage does not shrink: the SDK-signature class is caught by
`tests/test_judge.py` driving the real SDK over a stub transport, and the Lakera response contract
is pinned by `tests/test_lakera.py` over the monkeypatched `_post` seam. What moves to the nightly is
the sampled-model *benchmark* (recall / FP over the labelled corpus), which was never deterministic.

### 3.7 README

A "Lakera rate limiting" section: the env table from §3.2, the two new reasons, the CI relations
paragraph, and the note that defaults are provisional pending the 2026-09-06 measurement.

## 4. Failure semantics

| situation | result | network |
|---|---|---|
| bucket empty, `max_wait_s` exhausted | `lakera_unavailable:throttled`, fail-closed | none |
| breaker open, `max_wait_s` exhausted | `lakera_unavailable:throttled`, fail-closed | none |
| lock wait exceeded / dir unwritable / IO error in `acquire` | `lakera_unavailable:limiter-error`, fail-closed | none |
| state file missing / corrupt / foreign schema | fresh state, call proceeds | as normal |
| 429 or 503 from Lakera | existing `lakera_unavailable:HTTPError:<code>`; breaker opens fleet-wide | 1 (the probe) |
| other HTTP / network / JSON error | existing reason; breaker untouched | 1 |
| clock steps backwards | elapsed clamped to 0; breaker may stay open up to the step longer | — |
| `Retry-After` garbage or hostile (`"30; IGNORE PREVIOUS"`) | fallback backoff; text never leaves the limiter | — |
| eval hits any infra verdict | `INFRA <id> <reason>` on stderr, exit 3, no further scans | — |

The scanner's fail-closed principle is kept in every row: the limiter can only ADD refusals, never
turn a non-pass into a pass. Downstream, research-agent's `_infra_diagnosis` already maps
`lakera_unavailable:throttled` to `layer=lakera condition=unavailable exc_type=other`; a follow-up
in that repo can add `throttled` and `limiter_error` to `_InfraCondition` explicitly.

## 5. Testing

All key-free, deterministic, no network: `_post` is monkeypatched, the limiter gets an injected
`clock`/`sleep`, and an autouse fixture in `tests/conftest.py` points `INJECTION_SCANNER_CACHE_DIR`
at `tmp_path` so no test touches `~/.cache`.

`tests/test_throttle.py`:
- refill arithmetic at fractional elapsed; capacity never exceeds `burst`; first call on a fresh
  state is `ALLOWED`; `burst` calls then `THROTTLED` with `max_wait_s=0`.
- `max_wait_s>0` waits exactly the computed gap (assert on the injected `sleep`) and then allows.
- breaker: `record_throttled("30")` → refuses for 30 s without spending a token; HTTP-date header;
  garbage header → `backoff_base_s`; consecutive failures double and cap at `backoff_max_s`;
  `Retry-After` above the cap is clamped; `record_success` resets both.
- 503 trips, 500 does not (via the `lakera.check` integration tests).
- corrupt / truncated / `schema: 99` file → fresh state; unwritable directory → `ERROR`;
  lock held by another fd beyond `lock_wait_s` → `ERROR`.
- `min_interval_s=0` → always `ALLOWED` while the breaker is closed.
- clock going backwards does not mint tokens.
- cross-process: 3 subprocesses × 20 `acquire()` against one state dir with
  `min_interval_s=3600` (the clamp ceiling), `burst=2` → exactly 2 `ALLOWED` in total (`Decision`
  written to stdout, parent sums).
- env parsing: malformed values fall back to defaults; clamps applied.

`tests/test_lakera.py` additions: `throttled` and `limiter-error` reasons; no token spent on the
`no-key` and `key-config-error` paths; 429 with `Retry-After: "30; IGNORE PREVIOUS"` → the reason
is exactly `lakera_unavailable:HTTPError:429` and the state file contains no header text;
`record_success` on a `prompt_attack` response; `max_wait_s` keyword reaches the limiter.

`tests/test_intercept.py`: `lakera_max_wait_s` reaches `lakera.check`.

`tests/test_eval.py`: `--lakera-max-wait` default and plumbing; infra abort on `lakera_unavailable:throttled`
and on `honeypot:…_unavailable`, exit code 3, message on stderr, no further `scan_text` calls;
`secret_shape:thing_unavailable` is NOT infra; a normal block/pass run is unchanged.

CI file guard (`tests/test_ci_relations.py`, `pyyaml` added to the `test` extra), parsing both
workflow files (note PyYAML parses the `on:` key as boolean `True`): `ci.yml` triggers on
`pull_request` and `push`, has no job other than `test`, and contains no `secrets.` reference
anywhere; `live-eval.yml` triggers on exactly `schedule` and `workflow_dispatch`, declares
workflow-level `concurrency.group == "lakera-live"` with `cancel-in-progress: false`, `eval.needs`
is `smoke`, both live jobs set `INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S`, and the eval command
contains `--lakera-max-wait`. This is the "mind the relations" and "no external services in CI"
rules made executable, so a future edit cannot quietly put a vendor call back on the merge gate or
reintroduce overlapping Lakera jobs.

Verifier: `uv run --extra test pytest -q tests/` in the worktree, plus `python -m compileall`.

## 6. Rollout

1. This PR (injection-scanner, branch `feat/lakera-debounce`).
2. After merge: research-agent PR bumping `uv.lock` to the new scanner SHA (the only way a scanner
   change reaches production, see the inert-updater finding), and adding `throttled` /
   `limiter_error` to `_InfraCondition`.
3. After the 2026-09-06 00:12 measurement: retune the defaults in §3.2 (env or one-line PR) and, if
   boot bursts still register, reopen option B.

## 7. Decisions taken by discernment (and why)

- **Wait mode is a keyword + CLI flag, not only an env var.** `eval` is always a batch caller;
  making it correct by default beats depending on the operator's environment.
- **Limiter breakage fails closed (`limiter-error`).** A silent fail-open would re-enable the storm
  the operator asked to stop, and the module's stated principle is that config problems are loud.
- **Corrupt state is not an error.** A torn file after a crash must not brick every scanner; a
  fresh bucket is the safe reset and the breaker re-learns within one 429.
- **`backoff_max_s` also caps `Retry-After`.** One knob, and it bounds the blast radius of a bad
  header.
- **503 trips the breaker alongside 429.** RFC 9110 puts `Retry-After` on both; a Lakera-side
  outage deserves the same courtesy and it costs nothing.
- **Live checks leave the merge gate.** A per-push gate coupled to sampled models and a vendor's
  quota is non-deterministic by construction (today's flake, today's 429s) and buys no correctness
  the offline SDK-over-stub-transport tests do not already buy. The live pipeline is a benchmark
  plus a vendor canary: nightly + on-demand, serialised, paced — and production's boot smoke stays
  the real-time canary.
- **No verdict cache for CI.** Caching security verdicts to save calls is a second system with its
  own staleness and poisoning questions; out of scope.
