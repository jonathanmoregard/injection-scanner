# Lakera Debouncer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (default) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put one cross-process token bucket plus one circuit breaker behind `lakera.check()` so the whole fleet (research-agent servers, CI, local eval) cannot collectively push Lakera Guard into HTTP 429 again, serialise and pace the two CI jobs that touch Lakera, and make `eval` abort on an outage instead of scoring it as a classification.

**Architecture:** A new stdlib-only module `injection_scanner/throttle.py` keeps a token bucket and a circuit breaker in one JSON file under `$INJECTION_SCANNER_CACHE_DIR` (default `~/.cache/injection-scanner`, the directory `selfupdate.py` already uses). Every operation is a read-modify-write under an exclusive `fcntl.flock`, so N processes share ONE budget and N does not appear in the bound. `lakera.check()` resolves the key first (a call that cannot happen spends no token), then `acquire()`s; `THROTTLED` and `ERROR` become the fail-closed reasons `lakera_unavailable:throttled` and `lakera_unavailable:limiter-error`. A 429 or 503 from Lakera opens the breaker fleet-wide; any HTTP 200 closes it. `intercept` plumbs one keyword through; `eval` gains a batch wait budget and aborts loudly on the first infra verdict; CI puts both Lakera-touching jobs in one `lakera-live` concurrency group and makes the 1-call smoke a canary for the 16-call eval.

**Tech Stack:** Python 3.12+, standard library only for the limiter (`fcntl`, `json`, `os`, `time`, `math`, `errno`, `enum`, `contextlib`, `dataclasses`, `email.utils`, `pathlib`, `datetime`). Tests: `pytest` (existing `[test]` extra), `pyyaml>=6,<7` added to that extra for the CI-relations guard only. No new runtime dependency.

**Authoritative spec:** `docs/superpowers/specs/2026-09-05-lakera-debounce-design.md` (commit `cfe30f4`).
**Binding constraints:** `tasks/session-constraints.md` — read in full before the first edit; paste verbatim into any sub-brief.

---

## Ground rules for every task

- Work only inside `~/worktrees/injection-scanner-lakera-debounce` on branch `feat/lakera-debounce`. Never touch `~/Repos/injection-scanner`, another worktree, or `~/Repos/research-agent`.
- Never call Lakera, Anthropic or OpenAI from a test. There are no API keys on this host. `lakera._post` is monkeypatched everywhere.
- Never put the word that names the isolation directory (`q-u-a-r-a-n-t-i-n-e`) into a shell command string — a harness deny rule refuses the whole command. Use the Read/Edit/Write tools instead.
- Never `git add -A`. `tasks` is a symlink to userspace notes and is gitignored; stage named paths only.
- Verifier form (pytest lives only in the `test` extra; plain `uv run pytest` fails):

```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/
```

- **Measured baseline in this worktree, before any change: `443 passed in 12.50s`.** Every task must leave the full suite green and the count monotonically rising.
- One commit per task. Normal prose, no Conventional-Commit prefix required by the repo but the existing history uses one — follow the existing history (`feat(scanner): …`, `fix(mcp): …`). Every message ends with the trailer:

```
Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
```

---

## File structure

| File | Created / Modified | Single responsibility |
|---|---|---|
| `injection_scanner/throttle.py` | **Create** | The whole limiter: config parsing + clamps, on-disk state, flock, token bucket, circuit breaker, `Retry-After` parsing. Knows nothing about HTTP, Lakera, or reasons. |
| `injection_scanner/lakera.py` | Modify (`check`, + 2 private helpers) | The only place the limiter is wired to a real call: key first, `acquire`, `record_throttled` on 429/503, `record_success` on 200. Owns the two new reason literals. |
| `injection_scanner/intercept.py` | Modify (`scan`, `scan_text` signatures + one call) | Plumbing only — one keyword from the caller to `lakera.check`. No behaviour change. |
| `injection_scanner/eval.py` | Modify (`evaluate`, `_main`, + infra classifier) | Batch-caller policy: a wait budget on the CLI, and "an outage is not a classification" (`EvalInfraError`, exit 3). |
| `.github/workflows/ci.yml` | Modify | The HERMETIC merge gate: the deterministic `test` job and nothing else — no vendor call, no secret, no fork guard. Plus per-ref concurrency so superseded PR pushes are cancelled. |
| `.github/workflows/live-eval.yml` | **Create** | The live pipeline, off the merge gate: nightly + `workflow_dispatch`, one Lakera-touching job at a time, smoke as the canary for eval, stricter pacing, bounded job time. |
| `README.md` | Modify | Operator-facing documentation of the env table, the two new reasons, and the CI relations. |
| `pyproject.toml` | Modify | `pyyaml>=6,<7` in the `[test]` extra (needed only by the CI guard test). |
| `tests/conftest.py` | **Create** | Suite-wide isolation: every test gets its own limiter state directory and the documented "off" configuration, so no test touches `~/.cache` and no test is throttled by accident. |
| `tests/test_throttle.py` | **Create** | Every limiter property, including the 3-subprocess cross-process budget test. |
| `tests/test_lakera.py` | Modify (additions only) | The integration contract: new reasons, no token on the keyless paths, hostile `Retry-After` containment, 503 trips / 500 does not. |
| `tests/test_intercept.py` | Modify (3 stubs + 2 new tests) | `lakera_max_wait_s` reaches `lakera.check` from both entry points. |
| `tests/test_eval.py` | Modify (1 stub + new tests) | `--lakera-max-wait` plumbing, `_is_infra_reason`, the abort, exit code 3. |
| `tests/test_ci_relations.py` | **Create** | "No external services in CI" and "mind the relations" made executable: a future edit cannot quietly put a vendor call back on the merge gate, nor reintroduce overlapping Lakera jobs. |

---

## Task 1: `tests/conftest.py` + `injection_scanner/throttle.py`

**Files:**
- Create: `tests/conftest.py`
- Create: `injection_scanner/throttle.py`
- Create: `tests/test_throttle.py`

> **Decision (D1):** the autouse fixture pins the limiter to its documented "off" configuration — `INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S=0` (bucket always full) and `INJECTION_SCANNER_LAKERA_BACKOFF_MAX_S=0` (every breaker delay clamps to zero) — on top of an isolated `INJECTION_SCANNER_CACHE_DIR`. Reason: with the production defaults (`burst=2`), the third `lakera.check()` inside `tests/test_lakera.py::test_throttling_is_distinguishable_from_an_expired_key` would return `lakera_unavailable:throttled`, and the 429 in that same test would open the breaker over the 401 and 503 calls that follow it. Limiter-behaviour tests opt back in explicitly.

> **Decision (D2):** the flock retry loop uses the INJECTED `clock`/`sleep`, not real time. Reason: the lock-timeout test then runs in microseconds and is deterministic, and production still gets `time.time`/`time.sleep` from the constructor defaults.

> **Decision (D3):** `acquire` catches `Exception` (a superset of the spec's `OSError`/`ValueError`) and returns `ERROR`. Reason: `intercept.scan_text` does NOT wrap `lakera.check` in a try/except (`injection_scanner/intercept.py:323`), so an escaping exception would abort the scan instead of failing closed. `ERROR` is itself fail-closed, so the superset only ever adds refusals.

> **Decision (D4):** the state loader rejects non-finite numbers as corrupt. Reason: `json.loads` accepts bare `NaN` and `Infinity` by default, and a `NaN` in `tokens` makes every comparison false.

> **Decision (D5):** the doubling exponent is capped at 32. Reason: `2.0 ** (failures - 1)` raises `OverflowError` past ~1024 consecutive failures, and the value is clamped to `backoff_max_s` immediately afterwards anyway.

> **Decision (D6):** all limiter env parsing lives in `throttle.py` (`LimiterConfig.from_env`, `cache_dir`, `default_max_wait_s`). `lakera.py` reads no limiter env var of its own. Reason: one place to audit the clamps.

> **Decision (D7):** the cross-process test uses `min_interval_s=3600`, not the spec's `1e6`. Reason: §3.2 clamps the interval to `[0, 3600]`, so `1e6` and `3600` are the same limiter; the test should state the number the limiter actually uses.

> **Decision (D8):** the "unusable state directory" case is produced by pointing the limiter at a regular FILE, not by `chmod`. Reason: a chmod-based test is wrong when run as root; `Path.mkdir(exist_ok=True)` raises `FileExistsError` on an existing non-directory regardless of uid.

---

- [ ] **Step 1.1: Write `tests/conftest.py`**

```python
"""Suite-wide isolation for the on-disk Lakera limiter.

`injection_scanner.throttle` keeps a token bucket and a circuit breaker in a
JSON file under `$INJECTION_SCANNER_CACHE_DIR` (default
`~/.cache/injection-scanner`). Two consequences the test suite has to
neutralise, autouse, for EVERY test rather than per-file:

  1. Without an override, a unit run would read and write the developer's or
     the CI runner's real cache directory — shared state between test
     processes, and a suite that could leave a fleet-wide breaker open.
     `tmp_path` is function-scoped, so each test gets a private directory.

  2. With the production defaults (`burst=2`, `backoff_base_s=30`), tests
     that legitimately call `lakera.check()` more than twice, or that raise a
     429 and then expect the NEXT call to report a different HTTP status,
     would start seeing `lakera_unavailable:throttled` instead. That is not a
     regression in those tests; it is the limiter doing its job in a context
     where pacing is meaningless. So the suite runs the limiter in its
     documented "off" configuration — `MIN_INTERVAL_S=0` (bucket always full)
     plus `BACKOFF_MAX_S=0` (every breaker delay clamps to zero). There is no
     feature flag to set; this IS the off switch, spelled as inputs.

Tests that exercise the limiter opt back in: either by constructing a
`CrossProcessLimiter` with an explicit `LimiterConfig` and an injected clock,
or by `monkeypatch.setenv`-ing the specific budget they mean to test.
"""
from __future__ import annotations

import pytest

# Every environment variable `throttle.LimiterConfig.from_env` reads, minus
# the cache dir (set below rather than cleared). Listed explicitly so a new
# knob has to be added here on purpose — a stray value in the developer's
# shell must never change what the suite measures.
_LIMITER_ENV = (
    "INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S",
    "INJECTION_SCANNER_LAKERA_BURST",
    "INJECTION_SCANNER_LAKERA_BACKOFF_BASE_S",
    "INJECTION_SCANNER_LAKERA_BACKOFF_MAX_S",
    "INJECTION_SCANNER_LAKERA_LOCK_WAIT_S",
    "INJECTION_SCANNER_LAKERA_MAX_WAIT_S",
)


@pytest.fixture(autouse=True)
def _isolated_limiter_state(monkeypatch, tmp_path):
    """Private limiter state directory + the documented "off" budget."""
    for name in _LIMITER_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("INJECTION_SCANNER_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S", "0")
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_BACKOFF_MAX_S", "0")
```

- [ ] **Step 1.2: Run the whole suite — the fixture must be inert today**

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/
```
Expected: `443 passed` — identical to the baseline. The fixture only sets environment variables nothing reads yet.

- [ ] **Step 1.3: Write the first failing test — config parsing and clamps**

Create `tests/test_throttle.py` with the header and the config tests:

```python
"""The cross-process Lakera limiter (injection_scanner.throttle).

Deterministic and key-free: the limiter takes its clock and its sleep as
constructor keywords, so every test drives simulated time by hand and no test
sleeps, waits on a real lock, or touches the network. The one exception is the
cross-process test at the bottom, which really does fork three interpreters —
that is the property it exists to prove, and it uses a real (tiny) flock wait.

What is pinned here:

  * the token bucket's arithmetic, including fractional refill and the cap at
    `burst`, so the aggregate bound (`burst + elapsed / min_interval_s` calls
    per window, independent of process count) is a measured fact;
  * the circuit breaker's response to a `Retry-After` header that is a number,
    an HTTP-date, absent, or hostile — and the fact that the header TEXT never
    reaches the state file;
  * that every unusable-limiter path returns `ERROR` (fail-closed) rather than
    raising or waving the call through;
  * that a corrupt, truncated or foreign-schema state file is a RESET, not an
    error — a torn file after a crash must not brick every scanner on the box.
"""
from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from email.utils import formatdate
from pathlib import Path

import pytest

from injection_scanner import throttle
from injection_scanner.throttle import (
    CrossProcessLimiter,
    Decision,
    LimiterConfig,
)


@dataclass
class _Fake:
    """Simulated wall clock. `sleep` advances it and records the request.

    The limiter takes `clock` and `sleep` as constructor keywords precisely so
    a test can be exact about both the DECISION and the WAITING: asserting on
    `sleeps` is how "it waited for a token" is distinguished from "it spun".
    """

    now: float = 1_700_000_000.0
    sleeps: list[float] = field(default_factory=list)

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _limiter(tmp_path: Path, fake: _Fake, **overrides) -> CrossProcessLimiter:
    cfg = LimiterConfig(
        min_interval_s=overrides.pop("min_interval_s", 10.0),
        burst=overrides.pop("burst", 1),
        backoff_base_s=overrides.pop("backoff_base_s", 30.0),
        backoff_max_s=overrides.pop("backoff_max_s", 600.0),
        lock_wait_s=overrides.pop("lock_wait_s", 2.0),
    )
    assert not overrides, f"unknown config override(s): {sorted(overrides)}"
    return CrossProcessLimiter(
        tmp_path / "state", cfg, clock=fake.time, sleep=fake.sleep
    )


def _state(lim: CrossProcessLimiter) -> dict:
    return json.loads(lim.state_path.read_text(encoding="utf-8"))


def _open_for(lim: CrossProcessLimiter, fake: _Fake) -> float:
    """Seconds the breaker is still open, from the fake clock's `now`."""
    return _state(lim)["open_until"] - fake.now


# ---------- configuration: every limit is an INPUT ----------

def test_from_env_uses_the_documented_defaults(monkeypatch, tmp_path):
    for name in (
        "INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S",
        "INJECTION_SCANNER_LAKERA_BURST",
        "INJECTION_SCANNER_LAKERA_BACKOFF_BASE_S",
        "INJECTION_SCANNER_LAKERA_BACKOFF_MAX_S",
        "INJECTION_SCANNER_LAKERA_LOCK_WAIT_S",
        "INJECTION_SCANNER_LAKERA_MAX_WAIT_S",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("INJECTION_SCANNER_CACHE_DIR", str(tmp_path))

    assert LimiterConfig.from_env() == LimiterConfig(
        min_interval_s=15.0,
        burst=2,
        backoff_base_s=30.0,
        backoff_max_s=600.0,
        lock_wait_s=2.0,
    )
    assert throttle.default_max_wait_s() == 0.0

    lim = CrossProcessLimiter.from_env()
    assert lim.state_path == tmp_path / "lakera-throttle.json"
    assert lim.lock_path == tmp_path / "lakera-throttle.lock"


@pytest.mark.parametrize("raw", ["", "   ", "abc", "1e", "None", "--3", "nan"])
def test_malformed_env_values_fall_back_to_the_default(monkeypatch, raw):
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S", raw)
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_BURST", raw)
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_BACKOFF_BASE_S", raw)
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_BACKOFF_MAX_S", raw)
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_LOCK_WAIT_S", raw)
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_MAX_WAIT_S", raw)

    assert LimiterConfig.from_env() == LimiterConfig(
        min_interval_s=15.0,
        burst=2,
        backoff_base_s=30.0,
        backoff_max_s=600.0,
        lock_wait_s=2.0,
    )
    assert throttle.default_max_wait_s() == 0.0


def test_env_values_are_clamped_to_their_documented_ranges(monkeypatch):
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S", "99999")
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_BURST", "99999")
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_BACKOFF_BASE_S", "-5")
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_BACKOFF_MAX_S", "999999")
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_LOCK_WAIT_S", "600")
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_MAX_WAIT_S", "-1")

    assert LimiterConfig.from_env() == LimiterConfig(
        min_interval_s=3600.0,
        burst=1000,
        backoff_base_s=0.0,
        backoff_max_s=86400.0,
        lock_wait_s=60.0,
    )
    assert throttle.default_max_wait_s() == 0.0

    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_BURST", "0")
    assert LimiterConfig.from_env().burst == 1


def test_the_cache_dir_env_var_selects_the_state_directory(monkeypatch, tmp_path):
    monkeypatch.setenv("INJECTION_SCANNER_CACHE_DIR", str(tmp_path / "elsewhere"))
    assert throttle.cache_dir() == tmp_path / "elsewhere"
    monkeypatch.delenv("INJECTION_SCANNER_CACHE_DIR", raising=False)
    assert throttle.cache_dir() == Path.home() / ".cache" / "injection-scanner"
```

- [ ] **Step 1.4: Run it to verify it fails**

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/test_throttle.py
```
Expected: collection error — `ModuleNotFoundError: No module named 'injection_scanner.throttle'`.

- [ ] **Step 1.5: Write `injection_scanner/throttle.py` — the complete module**

```python
"""Cross-process rate limiting for the hosted Lakera Guard gate (L2).

Lakera Guard is called from ONE function — `injection_scanner.lakera.check()`
— by several independent processes that share a single Lakera account: a
research-agent MCP server per Claude Code pane (boot smoke, degraded recheck,
per-report scan), the CI `smoke` job, the CI `eval` job, and ad-hoc local
`eval` runs. Measured 2026-09-05: from ~15:00 local, Lakera answered HTTP 429
to roughly three of every four calls (190-280 ms, immediate server-side
rejection), about one success per 4-5 minutes fleet-wide regardless of how
many attempts were made. Nothing in the code reacted: `check()` failed closed
on the spot, every caller retried on its own schedule, and no process knew
what any other had just done.

This module is the shared memory those processes were missing. One token
bucket plus one circuit breaker, both in a single JSON file under the cache
directory, every operation a read-modify-write under an exclusive
`fcntl.flock`. The aggregate guarantee is the point: with N processes sharing
the file, at most `burst + elapsed / min_interval_s` calls reach Lakera in any
window of length `elapsed`, and zero while the breaker is open. N does not
appear in the bound, so adding a pane or a CI runner cannot raise the ceiling.

Wall-clock `time.time()` throughout, deliberately. `time.monotonic()` is not
comparable across processes, and this state is read by processes that did not
exist when it was written. A clock that steps BACKWARDS is handled by clamping
elapsed at zero, so a step can delay calls but can never mint tokens.

Fail-closed, like every other layer. The three outcomes are `ALLOWED`,
`THROTTLED` (bucket empty or breaker open beyond the caller's wait budget) and
`ERROR` (the limiter itself is unusable — unwritable directory, lock wait
exceeded, IO error). `lakera.check` turns the latter two into
`lakera_unavailable:throttled` / `lakera_unavailable:limiter-error`, which
reject the report exactly as any other outage does. A limiter that cannot
write its state REFUSES rather than waving calls through: a silent fail-open
would re-enable the storm this module exists to stop. `record_success` and
`record_throttled` swallow their own errors for the same reason — if the state
cannot be written, the very next `acquire` fails the same way and refuses, so
a broken limiter can never turn into a hammer.

A corrupt, truncated or foreign-schema state file is NOT an error: it is
replaced by a fresh state (full bucket, breaker closed). A torn file after a
crash must not brick every scanner on the machine, and the breaker re-learns
within one 429.

Invariant 4 ("the caught bytes never return") applies here in an unusual
direction. `Retry-After` is server-supplied TEXT and a hostile or buggy server
can put anything in it. It is parsed into a clamped number INSIDE this module
(`_parse_retry_after`) and the string itself is never stored in the state
file, never logged, and never interpolated into a reason. `backoff_max_s` caps
the PARSED value too, so an absurd header cannot park the fleet indefinitely.

There is NO on/off switch. "Off" is `min_interval_s=0` (bucket always full)
plus `backoff_max_s=0` (every breaker delay clamps to zero); the test suite
runs in exactly that configuration and nobody should want it in production. A
feature flag shipped defaulted-off is the failure mode the
`avoiding-unrequested-feature-flags` rule exists to prevent.

Every limit is an INPUT (`LimiterConfig.from_env`), never a constant fitted to
today's numbers. The defaults are PROVISIONAL and are retuned from a
measurement of Lakera's actual limits by changing env values or these
defaults — never by editing the algorithm.
"""
from __future__ import annotations

import contextlib
import enum
import errno
import fcntl
import json
import math
import os
import time
from dataclasses import dataclass
from datetime import timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

# Bumped only when the on-disk shape changes. A file carrying any other value
# is FOREIGN, not corrupt, and is discarded the same way: an older or newer
# scanner sharing the cache directory must never be able to hand this one a
# bucket it would misread.
_SCHEMA = 1

# ---------- environment variable names ----------

ENV_CACHE_DIR = "INJECTION_SCANNER_CACHE_DIR"
ENV_MIN_INTERVAL_S = "INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S"
ENV_BURST = "INJECTION_SCANNER_LAKERA_BURST"
ENV_BACKOFF_BASE_S = "INJECTION_SCANNER_LAKERA_BACKOFF_BASE_S"
ENV_BACKOFF_MAX_S = "INJECTION_SCANNER_LAKERA_BACKOFF_MAX_S"
ENV_LOCK_WAIT_S = "INJECTION_SCANNER_LAKERA_LOCK_WAIT_S"
ENV_MAX_WAIT_S = "INJECTION_SCANNER_LAKERA_MAX_WAIT_S"

# ---------- defaults + clamps ----------
#
# PROVISIONAL, and labelled as such on purpose. The healthy pre-onset fleet
# averaged ~0.6 calls/min with zero failures; a 15 s sustained interval keeps
# the worst case (six panes + CI) at ~4 calls/min. These are the numbers to
# change when Lakera's published limits are measured — not the algorithm.
#
# Each clamp is a RANGE, so a typo in an environment variable degrades to a
# sane limiter instead of either disabling the bucket or parking the fleet.

DEFAULT_MIN_INTERVAL_S = 15.0
DEFAULT_BURST = 2
DEFAULT_BACKOFF_BASE_S = 30.0
DEFAULT_BACKOFF_MAX_S = 600.0
DEFAULT_LOCK_WAIT_S = 2.0
DEFAULT_MAX_WAIT_S = 0.0

MIN_INTERVAL_RANGE = (0.0, 3600.0)
BURST_RANGE = (1, 1000)
BACKOFF_BASE_RANGE = (0.0, 3600.0)
BACKOFF_MAX_RANGE = (0.0, 86400.0)
LOCK_WAIT_RANGE = (0.0, 60.0)
MAX_WAIT_RANGE = (0.0, 86400.0)

# Fixed by design, not configurable: the lock is held for microseconds, so a
# 50 ms retry is already generous, and a 1 s poll ceiling means a process
# waiting for a token re-reads often enough to notice that a PEER finished
# early (returned a token, or closed the breaker) rather than sleeping through
# the whole computed gap on stale state.
_LOCK_RETRY_SLEEP_S = 0.05
_MAX_POLL_SLEEP_S = 1.0

# `backoff_base_s * 2 ** (failures - 1)` raises OverflowError past ~1024
# consecutive failures. The product is clamped to `backoff_max_s` immediately
# afterwards, so capping the exponent changes no reachable outcome and removes
# the only arithmetic in here that can raise.
_MAX_BACKOFF_DOUBLINGS = 32


def _clamp_float(value: float, bounds: tuple[float, float]) -> float:
    lo, hi = bounds
    return min(max(value, lo), hi)


def _env_float(name: str, default: float, bounds: tuple[float, float]) -> float:
    """A float from the environment: malformed -> default, then clamp.

    NaN is turned back explicitly. It parses fine, survives `min`/`max`
    unchanged on CPython, and would then make every comparison in `acquire`
    false — a limiter that neither allows nor refuses.
    """
    raw = os.environ.get(name)
    value = default
    if raw is not None:
        try:
            value = float(raw)
        except (TypeError, ValueError):
            value = default
    if not math.isfinite(value):
        value = default
    return _clamp_float(value, bounds)


def _env_int(name: str, default: int, bounds: tuple[int, int]) -> int:
    raw = os.environ.get(name)
    value = default
    if raw is not None:
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value = default
    lo, hi = bounds
    return min(max(value, lo), hi)


def cache_dir() -> Path:
    """The limiter's state directory.

    Same directory `selfupdate.py` already uses, so an operator has one place
    to look and one place to clear.
    """
    raw = os.environ.get(ENV_CACHE_DIR)
    if raw:
        return Path(raw)
    return Path.home() / ".cache" / "injection-scanner"


def default_max_wait_s() -> float:
    """`acquire`'s wait budget when the caller does not name one.

    Default 0: an interactive scan refuses immediately rather than parking a
    report behind the fleet's budget. Batch callers (`eval`) pass their own.
    """
    return _env_float(ENV_MAX_WAIT_S, DEFAULT_MAX_WAIT_S, MAX_WAIT_RANGE)


@dataclass(frozen=True)
class LimiterConfig:
    min_interval_s: float
    """Sustained fleet-wide interval: one call per this many seconds. 0
    disables the bucket entirely (the breaker still applies)."""

    burst: int
    """Bucket capacity — how many calls may go out back-to-back after an idle
    period."""

    backoff_base_s: float
    """Breaker delay after the FIRST consecutive throttle that carried no
    usable `Retry-After`. Doubles per consecutive failure."""

    backoff_max_s: float
    """Cap on EVERY breaker delay, a server-supplied `Retry-After` included.
    One knob, and it bounds the blast radius of a bad header."""

    lock_wait_s: float
    """Bounded wait for the flock before `acquire` gives up with `ERROR`."""

    @classmethod
    def from_env(cls) -> "LimiterConfig":
        return cls(
            min_interval_s=_env_float(
                ENV_MIN_INTERVAL_S, DEFAULT_MIN_INTERVAL_S, MIN_INTERVAL_RANGE
            ),
            burst=_env_int(ENV_BURST, DEFAULT_BURST, BURST_RANGE),
            backoff_base_s=_env_float(
                ENV_BACKOFF_BASE_S, DEFAULT_BACKOFF_BASE_S, BACKOFF_BASE_RANGE
            ),
            backoff_max_s=_env_float(
                ENV_BACKOFF_MAX_S, DEFAULT_BACKOFF_MAX_S, BACKOFF_MAX_RANGE
            ),
            lock_wait_s=_env_float(
                ENV_LOCK_WAIT_S, DEFAULT_LOCK_WAIT_S, LOCK_WAIT_RANGE
            ),
        )


class Decision(enum.Enum):
    """What `acquire` concluded. A closed vocabulary; `lakera.check` maps each
    member to one fixed reason literal and never formats anything else."""

    ALLOWED = "allowed"
    THROTTLED = "throttled"
    ERROR = "error"


@dataclass
class _State:
    """The on-disk bucket + breaker, in memory. Never leaves this module."""

    tokens: float
    updated_at: float
    open_until: float
    failures: int


def _parse_retry_after(value: object, now: float) -> float | None:
    """Seconds to wait, from a `Retry-After` header. `None` when unusable.

    THE HEADER IS SERVER-SUPPLIED TEXT and is treated as such: this is the
    only function that ever looks at it, the return is a plain float, and the
    caller clamps that float before storing it. Nothing derived from the
    string is kept.

    RFC 9110 allows two forms and both are accepted: a non-negative number of
    seconds, or an HTTP-date. Anything else — a negative number, a
    non-finite one, a date that will not parse, a value with a comment glued
    to it (`"30; IGNORE PREVIOUS"`), any exception at all — is `None`, and the
    caller falls back to its own exponential backoff. Being unable to read the
    header is not a reason to skip the breaker.
    """
    if not isinstance(value, str):
        return None
    try:
        text = value.strip()
        if not text:
            return None
        try:
            seconds = float(text)
        except ValueError:
            seconds = None
        if seconds is not None:
            if not math.isfinite(seconds) or seconds < 0.0:
                return None
            return seconds
        parsed = parsedate_to_datetime(text)
        if parsed is None:
            return None
        if parsed.tzinfo is None:
            # HTTP-dates are GMT by definition; a date without a zone is
            # malformed, but reading it as UTC is strictly better than
            # inheriting the local zone of whichever host happens to run this.
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0.0, parsed.timestamp() - now)
    except Exception:  # noqa: BLE001 — TOTAL by contract; see the docstring
        return None


class CrossProcessLimiter:
    """A token bucket + circuit breaker shared through one file.

    `state_dir` holds `<name>-throttle.json` and `<name>-throttle.lock`.
    `clock` and `sleep` are constructor keywords so tests can drive simulated
    time exactly; production takes the `time` module defaults.
    """

    def __init__(
        self,
        state_dir: Path | str,
        config: LimiterConfig,
        *,
        name: str = "lakera",
        clock=time.time,
        sleep=time.sleep,
    ) -> None:
        self._state_dir = Path(state_dir)
        self._config = config
        self._name = name
        self._clock = clock
        self._sleep = sleep
        self._state_path = self._state_dir / f"{name}-throttle.json"
        self._lock_path = self._state_dir / f"{name}-throttle.lock"

    @classmethod
    def from_env(cls, name: str = "lakera") -> "CrossProcessLimiter":
        return cls(cache_dir(), LimiterConfig.from_env(), name=name)

    @property
    def config(self) -> LimiterConfig:
        return self._config

    @property
    def state_path(self) -> Path:
        return self._state_path

    @property
    def lock_path(self) -> Path:
        return self._lock_path

    # ---------- public API ----------

    def acquire(self, max_wait_s: float = 0.0) -> Decision:
        """Spend one token, waiting up to `max_wait_s` seconds for one.

        `max_wait_s = 0` (the production default) returns on the first pass:
        `ALLOWED` or `THROTTLED`, sub-millisecond, no network. A positive
        budget blocks until a token is available AND the breaker is closed, or
        the deadline passes.

        Never raises. Every failure of the limiter itself becomes `ERROR`,
        which the caller renders as a fail-closed reject. That is deliberately
        wider than "OSError and ValueError": `intercept.scan_text` does not
        wrap `lakera.check`, so an exception escaping here would abort the
        scan instead of rejecting the report.
        """
        budget = max_wait_s
        try:
            budget = float(budget)
        except (TypeError, ValueError):
            budget = 0.0
        if not math.isfinite(budget) or budget < 0.0:
            budget = 0.0

        try:
            deadline = self._clock() + budget
            while True:
                wait = self._attempt()
                if wait is None:
                    return Decision.ALLOWED
                if self._clock() + wait > deadline:
                    return Decision.THROTTLED
                # Re-read after a bounded nap rather than sleeping the whole
                # computed gap: another process may return a token or close
                # the breaker while this one waits.
                self._sleep(min(wait, _MAX_POLL_SLEEP_S))
        except Exception:  # noqa: BLE001 — see the docstring
            return Decision.ERROR

    def record_success(self) -> None:
        """Called on any HTTP 200, flagged or not.

        A 200 means the account is evidently not throttling us, so the breaker
        closes and the consecutive-failure count resets. Swallows its own
        errors: if the state cannot be written, the next `acquire` fails the
        same way and refuses.
        """
        try:
            with self._locked():
                now = self._clock()
                st = self._load(now)
                st.failures = 0
                st.open_until = 0.0
                self._save(st)
        except Exception:  # noqa: BLE001 — see the docstring
            return

    def record_throttled(self, retry_after: str | None) -> None:
        """Open the breaker after a throttling response (429 or 503).

        `retry_after` is the RAW header value and goes no further than
        `_parse_retry_after`, which turns it into a number or `None`. The
        number is clamped to `backoff_max_s` before it is stored, so a hostile
        or buggy `Retry-After: 999999999` cannot park the fleet.

        No token is spent and none is returned: the bucket accounts for calls
        made, and this call was made.
        """
        try:
            with self._locked():
                now = self._clock()
                delay = _parse_retry_after(retry_after, now)
                st = self._load(now)
                st.failures += 1
                if delay is None:
                    doublings = min(st.failures - 1, _MAX_BACKOFF_DOUBLINGS)
                    delay = self._config.backoff_base_s * (2.0**doublings)
                if not math.isfinite(delay) or delay < 0.0:
                    delay = 0.0
                delay = min(delay, self._config.backoff_max_s)
                st.open_until = max(st.open_until, now + delay)
                self._save(st)
        except Exception:  # noqa: BLE001 — see the docstring
            return

    # ---------- internals ----------

    def _attempt(self) -> float | None:
        """One locked pass. `None` == a token was spent; else seconds to wait.

        Note what is saved on the REFUSING branches: the refill is persisted
        even when the call is turned down, so a process that polls does not
        keep re-deriving the same elapsed window, and `updated_at` stays the
        single source of truth for refill accounting.
        """
        with self._locked():
            now = self._clock()
            st = self._load(now)
            elapsed = max(0.0, now - st.updated_at)  # clock stepped back -> 0
            if self._config.min_interval_s <= 0.0:
                st.tokens = float(self._config.burst)
            else:
                st.tokens = min(
                    float(self._config.burst),
                    st.tokens + elapsed / self._config.min_interval_s,
                )
            st.updated_at = now

            if now < st.open_until:
                # Breaker open. No token is spent — the call is not happening,
                # so it must not be billed against the bucket.
                wait = st.open_until - now
            elif st.tokens >= 1.0:
                st.tokens -= 1.0
                self._save(st)
                return None
            else:
                wait = (1.0 - st.tokens) * self._config.min_interval_s

            self._save(st)
            return wait

    @contextlib.contextmanager
    def _locked(self):
        """Exclusive `flock` over `<name>-throttle.lock`, bounded by config.

        The file is opened FRESH for every operation, so the lock also
        serialises threads inside one process: flock is associated with the
        open file description, and each `os.open` makes its own. flock is
        released by the kernel when the holder dies, so there are no stale
        locks to reap after a crash.

        `LOCK_NB` plus a retry, rather than a blocking `LOCK_EX`, because the
        wait has to be BOUNDED: a wedged peer must degrade to `ERROR` (a
        fail-closed reject) rather than hanging a scan forever.
        """
        self._state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        deadline = self._clock() + self._config.lock_wait_s
        fd = os.open(self._lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as e:
                    if e.errno not in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                        raise
                    if self._clock() >= deadline:
                        raise TimeoutError("lakera limiter lock wait exceeded") from None
                    self._sleep(_LOCK_RETRY_SLEEP_S)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _fresh(self, now: float) -> _State:
        return _State(
            tokens=float(self._config.burst),
            updated_at=now,
            open_until=0.0,
            failures=0,
        )

    def _load(self, now: float) -> _State:
        """Read the state, or synthesize a fresh one.

        Missing, truncated, non-JSON, wrong shape, foreign schema, or carrying
        a non-finite number all mean the same thing: this file cannot be
        trusted to describe the fleet's budget. That is a RESET (full bucket,
        breaker closed), not an error — a torn file after a crash must not
        brick every scanner on the box, and the breaker re-learns within one
        429. `json.loads` accepts bare `NaN`/`Infinity`, which is why the
        finiteness check is explicit rather than implied by `float()`.
        """
        try:
            obj = json.loads(self._state_path.read_text(encoding="utf-8"))
            if not isinstance(obj, dict) or obj.get("schema") != _SCHEMA:
                return self._fresh(now)
            tokens = float(obj["tokens"])
            updated_at = float(obj["updated_at"])
            open_until = float(obj["open_until"])
            failures = int(obj["failures"])
        except (OSError, ValueError, TypeError, KeyError):
            return self._fresh(now)
        if not all(math.isfinite(v) for v in (tokens, updated_at, open_until)):
            return self._fresh(now)
        return _State(
            tokens=min(max(tokens, 0.0), float(self._config.burst)),
            updated_at=updated_at,
            open_until=open_until,
            failures=max(failures, 0),
        )

    def _save(self, st: _State) -> None:
        """Write via `<file>.tmp` + `os.replace`, inside the lock.

        The replace is atomic, so a reader without the lock — or a process
        killed mid-write — never sees a half-written bucket. Only the five
        fields below are written; the payload is built by NAMING them, so a
        field added to `_State` tomorrow is invisible until it is added here
        on purpose.
        """
        payload = {
            "schema": _SCHEMA,
            "tokens": st.tokens,
            "updated_at": st.updated_at,
            "open_until": st.open_until,
            "failures": st.failures,
        }
        tmp = self._state_path.parent / (self._state_path.name + ".tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, self._state_path)
```

- [ ] **Step 1.6: Run the config tests to verify they pass**

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/test_throttle.py
```
Expected: `10 passed` (3 named config tests + 7 parametrised malformed-value cases).

- [ ] **Step 1.7: Add the bucket tests, then run them**

Append to `tests/test_throttle.py`:

```python
# ---------- the token bucket ----------

def test_a_fresh_bucket_allows_the_first_call(tmp_path):
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=10.0, burst=1)
    assert lim.acquire() is Decision.ALLOWED
    assert fake.sleeps == []


def test_refill_is_fractional_and_never_exceeds_burst(tmp_path):
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=10.0, burst=2)

    assert lim.acquire() is Decision.ALLOWED   # 2.0 -> 1.0
    assert lim.acquire() is Decision.ALLOWED   # 1.0 -> 0.0
    assert lim.acquire() is Decision.THROTTLED

    fake.now += 5.0                            # half a token
    assert lim.acquire() is Decision.THROTTLED
    fake.now += 5.0                            # the other half
    assert lim.acquire() is Decision.ALLOWED

    fake.now += 10_000.0                       # would mint 1000 tokens
    assert lim.acquire() is Decision.ALLOWED
    assert lim.acquire() is Decision.ALLOWED
    assert lim.acquire() is Decision.THROTTLED, "capacity must cap at burst"


def test_a_zero_wait_budget_refuses_immediately(tmp_path):
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=10.0, burst=1)
    assert lim.acquire() is Decision.ALLOWED
    fake.sleeps.clear()
    assert lim.acquire(max_wait_s=0.0) is Decision.THROTTLED
    assert fake.sleeps == [], "max_wait_s=0 must not wait at all"


def test_a_wait_budget_shorter_than_the_gap_refuses_without_waiting(tmp_path):
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=10.0, burst=1)
    assert lim.acquire() is Decision.ALLOWED
    fake.sleeps.clear()
    assert lim.acquire(max_wait_s=3.0) is Decision.THROTTLED
    assert fake.sleeps == [], "a 10 s gap against a 3 s budget is hopeless"


def test_a_positive_wait_budget_sleeps_until_a_token_arrives(tmp_path):
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=10.0, burst=1)
    assert lim.acquire() is Decision.ALLOWED
    fake.sleeps.clear()

    assert lim.acquire(max_wait_s=30.0) is Decision.ALLOWED
    # Ten 1 s naps, not one 10 s nap: the poll ceiling exists so a waiter
    # notices a peer closing the breaker instead of sleeping through it.
    assert fake.sleeps == [1.0] * 10
    assert fake.now == 1_700_000_010.0


def test_zero_min_interval_disables_the_bucket_but_not_the_breaker(tmp_path):
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=0.0, burst=1)
    for _ in range(50):
        assert lim.acquire() is Decision.ALLOWED
    lim.record_throttled("30")
    assert lim.acquire() is Decision.THROTTLED


def test_a_backwards_clock_does_not_mint_tokens(tmp_path):
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=10.0, burst=1)
    assert lim.acquire() is Decision.ALLOWED

    fake.now -= 3600.0                          # NTP step, or a VM resume
    assert lim.acquire() is Decision.THROTTLED

    fake.now += 3610.0                          # forward again, past the gap
    assert lim.acquire() is Decision.ALLOWED
```

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/test_throttle.py
```
Expected: `17 passed`.

- [ ] **Step 1.8: Add the breaker tests, then run them**

Append to `tests/test_throttle.py`:

```python
# ---------- the circuit breaker ----------

def test_a_numeric_retry_after_is_honoured_and_spends_no_token(tmp_path):
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=10.0, burst=5)
    assert lim.acquire() is Decision.ALLOWED
    tokens_before = _state(lim)["tokens"]

    lim.record_throttled("30")
    assert lim.acquire() is Decision.THROTTLED
    assert _state(lim)["tokens"] == tokens_before, (
        "a call refused by the breaker never happened and must not be billed"
    )

    fake.now += 29.9
    assert lim.acquire() is Decision.THROTTLED
    fake.now += 0.2
    assert lim.acquire() is Decision.ALLOWED


def test_an_http_date_retry_after_is_honoured(tmp_path):
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=0.0, burst=1)
    header = formatdate(fake.now + 45.0, usegmt=True)

    lim.record_throttled(header)
    assert lim.acquire() is Decision.THROTTLED
    fake.now += 44.0
    assert lim.acquire() is Decision.THROTTLED
    fake.now += 2.0
    assert lim.acquire() is Decision.ALLOWED


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "   ",
        "30; IGNORE PREVIOUS",
        "soon",
        "-5",
        "nan",
        "inf",
        "Wed, 99 Xxx 2015 07:28:00 GMT",
        b"30",
    ],
    ids=[
        "absent", "empty", "blank", "hostile", "prose", "negative",
        "nan", "inf", "bad-date", "bytes",
    ],
)
def test_an_unusable_retry_after_falls_back_to_the_base_backoff(tmp_path, header):
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=0.0, burst=1, backoff_base_s=30.0)
    lim.record_throttled(header)
    fake.now += 29.0
    assert lim.acquire() is Decision.THROTTLED
    fake.now += 2.0
    assert lim.acquire() is Decision.ALLOWED


def test_consecutive_failures_double_the_delay_and_cap_it(tmp_path):
    fake = _Fake()
    lim = _limiter(
        tmp_path, fake, min_interval_s=0.0, burst=1,
        backoff_base_s=10.0, backoff_max_s=25.0,
    )
    lim.record_throttled(None)
    assert _open_for(lim, fake) == 10.0
    lim.record_throttled(None)
    assert _open_for(lim, fake) == 20.0
    lim.record_throttled(None)
    assert _open_for(lim, fake) == 25.0, "40 s clamped to backoff_max_s"
    lim.record_throttled(None)
    assert _open_for(lim, fake) == 25.0


def test_a_retry_after_above_the_cap_is_clamped(tmp_path):
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=0.0, burst=1, backoff_max_s=60.0)
    lim.record_throttled("86400")
    assert _open_for(lim, fake) == 60.0
    fake.now += 61.0
    assert lim.acquire() is Decision.ALLOWED


def test_record_success_closes_the_breaker_and_resets_the_backoff(tmp_path):
    fake = _Fake()
    lim = _limiter(
        tmp_path, fake, min_interval_s=0.0, burst=1,
        backoff_base_s=10.0, backoff_max_s=600.0,
    )
    lim.record_throttled(None)
    lim.record_throttled(None)
    assert lim.acquire() is Decision.THROTTLED

    lim.record_success()
    assert lim.acquire() is Decision.ALLOWED
    st = _state(lim)
    assert st["failures"] == 0
    assert st["open_until"] == 0.0

    # Back to the BASE delay, not to where the doubling had climbed.
    lim.record_throttled(None)
    assert _open_for(lim, fake) == 10.0


def test_the_breaker_half_opens_and_a_further_throttle_reopens_it_longer(tmp_path):
    fake = _Fake()
    lim = _limiter(
        tmp_path, fake, min_interval_s=0.0, burst=1,
        backoff_base_s=10.0, backoff_max_s=600.0,
    )
    lim.record_throttled(None)
    fake.now += 11.0
    assert lim.acquire() is Decision.ALLOWED, "half-open: one probe gets through"
    lim.record_throttled(None)
    assert _open_for(lim, fake) == 20.0
```

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/test_throttle.py
```
Expected: `33 passed` (17 + 6 named breaker tests + 10 parametrised header cases).

- [ ] **Step 1.9: Add the durability / failure-mode tests, then run them**

Append to `tests/test_throttle.py`:

```python
# ---------- durability and failure modes ----------

@pytest.mark.parametrize(
    "blob",
    [
        "",
        "{",
        "null",
        "[]",
        "not json at all",
        '{"schema": 99, "tokens": 0.0, "updated_at": 0.0, '
        '"open_until": 9999999999.0, "failures": 7}',
        '{"schema": 1, "tokens": "lots"}',
        '{"schema": 1, "tokens": NaN, "updated_at": 0.0, '
        '"open_until": 0.0, "failures": 0}',
    ],
    ids=[
        "empty", "truncated", "null", "array", "garbage",
        "foreign-schema", "wrong-type", "nan",
    ],
)
def test_an_unusable_state_file_is_a_reset_not_an_error(tmp_path, blob):
    """A torn file after a crash must not brick every scanner on the box.

    The foreign-schema case carries an `open_until` far in the future on
    purpose: a breaker this limiter cannot read must not be able to park it.
    """
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=10.0, burst=1)
    lim.state_path.parent.mkdir(parents=True, exist_ok=True)
    lim.state_path.write_text(blob, encoding="utf-8")

    assert lim.acquire() is Decision.ALLOWED
    assert _state(lim)["schema"] == 1


def test_an_unusable_state_directory_is_an_error_and_never_raises(tmp_path):
    """A regular file where the state directory should be. Root-proof: this
    fails for every uid, unlike a chmod-based fixture."""
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    fake = _Fake()
    lim = CrossProcessLimiter(
        blocked,
        LimiterConfig(
            min_interval_s=10.0, burst=1, backoff_base_s=30.0,
            backoff_max_s=600.0, lock_wait_s=2.0,
        ),
        clock=fake.time,
        sleep=fake.sleep,
    )
    assert lim.acquire() is Decision.ERROR
    assert lim.acquire(max_wait_s=60.0) is Decision.ERROR
    # The recorders swallow their own errors — a broken limiter must not
    # become an exception in the middle of a fail-closed result.
    lim.record_throttled("30")
    lim.record_success()


def test_a_lock_held_past_the_wait_budget_is_an_error(tmp_path):
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=10.0, burst=1, lock_wait_s=2.0)
    assert lim.acquire() is Decision.ALLOWED  # creates the dir and both files

    # A SEPARATE open file description, so flock genuinely conflicts even
    # though this is the same process.
    holder = os.open(str(lim.lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(holder, fcntl.LOCK_EX)
        fake.sleeps.clear()
        assert lim.acquire() is Decision.ERROR
        assert set(fake.sleeps) == {0.05}, "50 ms retry interval"
        assert abs(sum(fake.sleeps) - 2.0) < 0.1, "bounded by lock_wait_s"
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN)
        os.close(holder)

    # Lock free again: back to an ordinary refusal, not an error.
    assert lim.acquire() is Decision.THROTTLED


def test_a_zero_lock_wait_budget_is_an_error_when_the_lock_is_held(tmp_path):
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=0.0, burst=1, lock_wait_s=0.0)
    assert lim.acquire() is Decision.ALLOWED
    holder = os.open(str(lim.lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(holder, fcntl.LOCK_EX)
        assert lim.acquire() is Decision.ERROR
        assert fake.sleeps == []
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN)
        os.close(holder)


def test_the_state_file_is_written_atomically(tmp_path):
    """`.tmp` + `os.replace`, so no reader ever sees a half-written bucket."""
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=10.0, burst=1)
    assert lim.acquire() is Decision.ALLOWED
    assert lim.state_path.exists()
    leftovers = list(lim.state_path.parent.glob("*.tmp"))
    assert leftovers == [], f"temp file not replaced: {leftovers}"
```

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/test_throttle.py
```
Expected: `45 passed` (33 + 8 parametrised corrupt-state cases + 4 named tests).

- [ ] **Step 1.10: Add the cross-process test, then run it**

Append to `tests/test_throttle.py`:

```python
# ---------- the property the whole module exists for ----------

# Run in each child. `from_env()` is used deliberately: this exercises the
# exact construction path production uses, so the test also proves the env
# plumbing, not just the algorithm.
_CHILD = """
import sys
from injection_scanner.throttle import CrossProcessLimiter, Decision

lim = CrossProcessLimiter.from_env()
allowed = sum(1 for _ in range(20) if lim.acquire() is Decision.ALLOWED)
sys.stdout.write(str(allowed))
"""


def test_the_budget_is_shared_across_processes(tmp_path):
    """Three interpreters, sixty attempts, one bucket of two.

    This is the guarantee the design rests on: the bound is
    `burst + elapsed / min_interval_s`, and the number of processes does not
    appear in it. A limiter that only saw one process would let each child
    through twice and hand Lakera six calls.
    """
    env = dict(os.environ)
    env["INJECTION_SCANNER_CACHE_DIR"] = str(tmp_path / "shared")
    env["INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S"] = "3600"  # no refill in-test
    env["INJECTION_SCANNER_LAKERA_BURST"] = "2"
    env["INJECTION_SCANNER_LAKERA_BACKOFF_MAX_S"] = "600"
    env["INJECTION_SCANNER_LAKERA_LOCK_WAIT_S"] = "30"       # real contention
    env["INJECTION_SCANNER_LAKERA_MAX_WAIT_S"] = "0"
    # Importable regardless of how the venv installed the package.
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])

    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _CHILD],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(3)
    ]
    results = []
    for p in procs:
        out, err = p.communicate(timeout=60)
        assert p.returncode == 0, f"child failed: {err}"
        results.append(int(out.strip()))

    assert sum(results) == 2, f"per-child allowances: {results}"
```

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/test_throttle.py
```
Expected: `46 passed`.

- [ ] **Step 1.11: Run the whole suite**

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test python -m compileall -q injection_scanner tests \
  && env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/
```
Expected: `compileall` silent (exit 0), then `489 passed` (443 baseline + 46).

- [ ] **Step 1.12: Commit**

```bash
git -C ~/worktrees/injection-scanner-lakera-debounce add injection_scanner/throttle.py tests/conftest.py tests/test_throttle.py
git -C ~/worktrees/injection-scanner-lakera-debounce commit \
  -m "feat(throttle): a cross-process token bucket and circuit breaker for Lakera" \
  -m "Several independent processes share one Lakera account: an MCP server per
Claude Code pane, the CI smoke job, the CI eval job and local eval runs. On
2026-09-05 they collectively pushed Lakera Guard into HTTP 429 on roughly
three of every four calls, and nothing in the code reacted, because no
process knew what any other had just done.

This adds the shared memory they were missing: one token bucket plus one
circuit breaker in a JSON file under the cache directory, every operation a
read-modify-write under an exclusive flock. The aggregate bound is
burst + elapsed / min_interval_s calls per window, with the process count
absent from it, and zero calls while the breaker is open. A cross-process
test forks three interpreters over one state directory and proves sixty
attempts yield exactly two calls.

Every limit is an environment input with a clamped range, not a fitted
constant. There is no on/off switch: 'off' is min_interval_s=0 plus
backoff_max_s=0, which is what the test suite runs. A Retry-After header is
server-supplied text and is parsed into a clamped number inside the limiter;
the string is never stored, logged or interpolated anywhere. An unusable
limiter yields ERROR, which the caller renders as a fail-closed reject, so a
broken limiter can never turn into a hammer." \
  -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Task 2: wire the limiter into `lakera.check`

**Files:**
- Modify: `injection_scanner/lakera.py` (imports, 2 new private helpers, `check`)
- Modify: `tests/test_lakera.py` (additions only)

> **Decision (D9):** `record_success()` is called immediately after `_post` returns — i.e. on ANY HTTP 200 — rather than inside each of the three parse branches. Spec §3.1 says "called on any HTTP 200, flagged or not"; §3.3 step 4 lists three named outcomes. The single call site is the simpler superset, matches §3.1's stated rationale ("the account is evidently not throttling us"), and a future parse branch cannot forget it.

> **Decision (D10):** the breaker's status read goes through a local `_breaker_code`, which reuses `http_status.bounded_status` behind a guarded `getattr`. A rebound or raising `.code` must not be what decides whether the whole fleet stops calling Lakera.

> **Decision (D11):** the raw `Retry-After` value is passed straight from `HTTPError.headers` into `limiter.record_throttled(...)` as an argument. It is never bound to a local that reason-building code can reach.

- [ ] **Step 2.1: Write the failing tests**

Append to `tests/test_lakera.py`:

```python
# ---------- (g) the cross-process limiter (2026-09-05) -----------------------
#
# Measured 2026-09-05: the fleet pushed the shared Lakera account into HTTP
# 429 on ~3 of every 4 calls for hours, and every caller kept retrying because
# no process could see what any other had done. `lakera.check` now spends a
# token from a shared on-disk bucket before it calls out, and opens a
# fleet-wide breaker when Lakera says 429 or 503.
#
# Two invariants these tests exist to pin:
#   * a call that CANNOT happen spends no token (key resolution comes first);
#   * the `Retry-After` header is server-supplied TEXT — it decides a number
#     inside the limiter and reaches neither the reason nor the state file.

import json as _json_mod

from injection_scanner import throttle
from injection_scanner.throttle import CrossProcessLimiter, Decision, LimiterConfig


def _state_file():
    return throttle.cache_dir() / "lakera-throttle.json"


class _SpyLimiter:
    """Stands in for the real limiter to observe what `check` asks of it."""

    def __init__(self, decision=Decision.ALLOWED):
        self.decision = decision
        self.acquired: list[float] = []
        self.throttled: list[object] = []
        self.successes = 0

    def acquire(self, max_wait_s: float = 0.0) -> Decision:
        self.acquired.append(max_wait_s)
        return self.decision

    def record_success(self) -> None:
        self.successes += 1

    def record_throttled(self, retry_after) -> None:
        self.throttled.append(retry_after)


def _install_spy(monkeypatch, spy: _SpyLimiter) -> None:
    monkeypatch.setattr(
        CrossProcessLimiter,
        "from_env",
        classmethod(lambda cls, name="lakera": spy),
    )


def test_an_empty_bucket_rejects_without_calling_lakera(monkeypatch):
    _with_key(monkeypatch)
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S", "3600")
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_BURST", "1")
    calls = []

    def _post(*_a, **_kw):
        calls.append(1)
        return {
            "flagged": False,
            "breakdown": [{"detector_type": "prompt_attack", "detected": False}],
        }

    monkeypatch.setattr(lakera, "_post", _post)
    assert lakera.check("first").ok is True
    res = lakera.check("second")
    assert res.ok is False
    assert res.reason == "lakera_unavailable:throttled"
    assert len(calls) == 1, "the refused call must not reach the network"


def test_a_broken_limiter_rejects_and_never_calls_lakera(monkeypatch, tmp_path):
    """Fail-CLOSED, not fail-open: a limiter that cannot keep state refuses.

    A silent fail-open here would re-enable exactly the storm the limiter was
    added to stop, and it is the one failure mode nobody would notice.
    """
    _with_key(monkeypatch)
    blocked = tmp_path / "blocked-cache"
    blocked.write_text("not a directory", encoding="utf-8")
    monkeypatch.setenv("INJECTION_SCANNER_CACHE_DIR", str(blocked))

    def _should_not_call(*_a, **_kw):
        raise AssertionError("_post called with a broken limiter")

    monkeypatch.setattr(lakera, "_post", _should_not_call)
    res = lakera.check("anything")
    assert res.ok is False
    assert res.reason == "lakera_unavailable:limiter-error"


@pytest.mark.parametrize(
    "setup,expected",
    [
        (lambda mp, tp: None, "lakera_unavailable:no-key"),
        (
            lambda mp, tp: mp.setenv("LAKERA_API_KEY_FILE", str(tp / "missing")),
            "lakera_unavailable:key-config-error",
        ),
    ],
    ids=["no-key", "key-config-error"],
)
def test_a_call_that_cannot_happen_spends_no_token(
    monkeypatch, tmp_path, setup, expected
):
    """Key resolution runs BEFORE `acquire`, so a deployment error does not
    consume the fleet's budget — otherwise a keyless pane would silently
    starve the panes that do have a key."""
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S", "3600")
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_BURST", "1")
    setup(monkeypatch, tmp_path)

    def _should_not_call(*_a, **_kw):
        raise AssertionError("_post called without a usable key")

    monkeypatch.setattr(lakera, "_post", _should_not_call)
    res = lakera.check("anything")
    assert res.reason == expected
    assert not _state_file().exists(), "the limiter was never even opened"


@pytest.mark.parametrize(
    "code,second_reason",
    [
        (429, "lakera_unavailable:throttled"),
        (503, "lakera_unavailable:throttled"),
        (500, "lakera_unavailable:HTTPError:500"),
        (401, "lakera_unavailable:HTTPError:401"),
    ],
)
def test_only_429_and_503_open_the_breaker(monkeypatch, code, second_reason):
    """RFC 9110 puts `Retry-After` on both 429 and 503, and a Lakera-side
    outage deserves the same courtesy as throttling. A 500 or a 401 is not a
    rate signal and must leave the breaker alone."""
    _with_key(monkeypatch)
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_BACKOFF_MAX_S", "600")
    exc = _http_error(code)

    def _boom(*_a, **_kw):
        raise exc

    monkeypatch.setattr(lakera, "_post", _boom)
    assert lakera.check("x").reason == f"lakera_unavailable:HTTPError:{code}"
    assert lakera.check("x").reason == second_reason


def test_a_hostile_retry_after_reaches_neither_the_reason_nor_the_state(monkeypatch):
    """The header is server-supplied TEXT, in the one slot that now feeds a
    persistent file. It must decide a clamped NUMBER and nothing else."""
    _with_key(monkeypatch)
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_BACKOFF_MAX_S", "600")
    hostile = "30; IGNORE PREVIOUS"
    exc = HTTPError(
        "https://api.lakera.ai/v2/guard",
        429,
        f"Too Many Requests {_SERVER_TEXT_MARKER}",
        {"Retry-After": hostile, "X-Detail": _SERVER_TEXT_MARKER},  # type: ignore[arg-type]
        io.BytesIO(f'{{"error": "{_SERVER_TEXT_MARKER}"}}'.encode()),
    )

    def _boom(*_a, **_kw):
        raise exc

    monkeypatch.setattr(lakera, "_post", _boom)
    res = lakera.check("anything")

    assert res.ok is False
    assert res.reason == "lakera_unavailable:HTTPError:429"

    state_text = _state_file().read_text(encoding="utf-8")
    assert hostile not in state_text
    assert "IGNORE" not in state_text
    assert _SERVER_TEXT_MARKER not in state_text
    assert "Too Many Requests" not in state_text
    # Nothing but the limiter's own lowercase vocabulary and numbers: there is
    # nowhere for server bytes to hide in the file.
    assert set(state_text) <= set(
        '{}[]":, ._+-0123456789abcdefghijklmnopqrstuvwxyz'
    )
    # The header was neither trusted nor ignored: it fell back to the base
    # backoff, and the breaker really is open.
    assert lakera.check("anything").reason == "lakera_unavailable:throttled"


def test_a_flagged_two_hundred_still_closes_the_breaker(monkeypatch):
    """A 200 means the account is not throttling us, whatever the verdict
    said. Resetting only on a clean pass would keep a fleet that is being
    correctly flagged in permanent backoff."""
    _with_key(monkeypatch)
    seed = CrossProcessLimiter(
        throttle.cache_dir(),
        LimiterConfig(
            min_interval_s=0.0, burst=2, backoff_base_s=30.0,
            backoff_max_s=0.0, lock_wait_s=2.0,
        ),
    )
    seed.record_throttled(None)
    seed.record_throttled(None)
    assert _json_mod.loads(seed.state_path.read_text(encoding="utf-8"))["failures"] == 2

    monkeypatch.setattr(
        lakera, "_post",
        lambda *a, **k: {
            "flagged": True,
            "breakdown": [{"detector_type": "prompt_attack", "detected": True}],
        },
    )
    res = lakera.check("attack text")
    assert res.reason == "lakera:prompt_attack"
    st = _json_mod.loads(seed.state_path.read_text(encoding="utf-8"))
    assert st["failures"] == 0
    assert st["open_until"] == 0.0


def test_the_max_wait_keyword_reaches_the_limiter(monkeypatch):
    _with_key(monkeypatch)
    spy = _SpyLimiter(Decision.THROTTLED)
    _install_spy(monkeypatch, spy)

    def _should_not_call(*_a, **_kw):
        raise AssertionError("_post called after a THROTTLED decision")

    monkeypatch.setattr(lakera, "_post", _should_not_call)
    res = lakera.check("x", max_wait_s=12.5)
    assert res.reason == "lakera_unavailable:throttled"
    assert spy.acquired == [12.5]


def test_an_absent_max_wait_falls_back_to_the_environment(monkeypatch):
    """The default is an INPUT too, so a batch consumer can set it once for a
    whole process instead of threading a keyword through every call site."""
    _with_key(monkeypatch)
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_MAX_WAIT_S", "42")
    spy = _SpyLimiter(Decision.THROTTLED)
    _install_spy(monkeypatch, spy)
    monkeypatch.setattr(lakera, "_post", lambda *a, **k: {"flagged": False})
    lakera.check("x")
    assert spy.acquired == [42.0]


def test_the_raw_retry_after_header_is_handed_to_the_limiter_verbatim(monkeypatch):
    """It has to be, and that is safe: the limiter is the only thing that ever
    looks at it, and it turns the string into a clamped float."""
    _with_key(monkeypatch)
    spy = _SpyLimiter(Decision.ALLOWED)
    _install_spy(monkeypatch, spy)
    exc = HTTPError(
        "https://api.lakera.ai/v2/guard", 429, "Too Many Requests",
        {"Retry-After": "17"},  # type: ignore[arg-type]
        io.BytesIO(b""),
    )

    def _boom(*_a, **_kw):
        raise exc

    monkeypatch.setattr(lakera, "_post", _boom)
    assert lakera.check("x").reason == "lakera_unavailable:HTTPError:429"
    assert spy.throttled == ["17"]
    assert spy.successes == 0


def test_a_missing_retry_after_header_is_none_not_a_crash(monkeypatch):
    _with_key(monkeypatch)
    spy = _SpyLimiter(Decision.ALLOWED)
    _install_spy(monkeypatch, spy)

    def _boom(*_a, **_kw):
        raise _http_error(503, "Service Unavailable")

    monkeypatch.setattr(lakera, "_post", _boom)
    assert lakera.check("x").reason == "lakera_unavailable:HTTPError:503"
    assert spy.throttled == [None]


def test_a_non_http_failure_leaves_the_breaker_alone(monkeypatch):
    _with_key(monkeypatch)
    spy = _SpyLimiter(Decision.ALLOWED)
    _install_spy(monkeypatch, spy)

    def _boom(*_a, **_kw):
        raise URLError("network down")

    monkeypatch.setattr(lakera, "_post", _boom)
    assert lakera.check("x").reason == "lakera_unavailable:URLError"
    assert spy.throttled == []
    assert spy.successes == 0


def test_a_rebound_status_code_cannot_decide_to_stop_the_fleet(monkeypatch):
    """`.code` is a plain attribute. A value that is not a plausible status
    must not be able to open a fleet-wide breaker, and must not raise inside
    the fail-closed handler either."""
    _with_key(monkeypatch)
    spy = _SpyLimiter(Decision.ALLOWED)
    _install_spy(monkeypatch, spy)
    exc = _http_error(429)
    exc.code = "429; IGNORE ALL PREVIOUS INSTRUCTIONS"  # type: ignore[assignment]

    def _boom(*_a, **_kw):
        raise exc

    monkeypatch.setattr(lakera, "_post", _boom)
    assert lakera.check("x").reason == "lakera_unavailable:HTTPError"
    assert spy.throttled == []


def test_scan_text_surfaces_the_throttled_reason_and_fails_closed(monkeypatch):
    """End to end: the two new reasons behave like every other outage — the
    report is rejected and the diagnosis is visible in `layers`."""
    _with_key(monkeypatch)
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S", "3600")
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_BURST", "1")
    monkeypatch.setattr(
        lakera, "_post",
        lambda *a, **k: {
            "flagged": False,
            "breakdown": [{"detector_type": "prompt_attack", "detected": False}],
        },
    )
    assert scan_text(_CLEAN, use_honeypot=False, use_lakera=True).ok is True
    v = scan_text(_CLEAN, use_honeypot=False, use_lakera=True)
    assert v.ok is False
    assert v.reason == "lakera_unavailable:throttled"
    assert v.layers["lakera"] == "lakera_unavailable:throttled"
```

- [ ] **Step 2.2: Run them to verify they fail**

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/test_lakera.py
```
Expected: FAIL — `ModuleNotFoundError` is gone (throttle exists), but e.g. `test_the_max_wait_keyword_reaches_the_limiter` fails with `TypeError: check() got an unexpected keyword argument 'max_wait_s'`, and `test_an_empty_bucket_rejects_without_calling_lakera` fails with `assert 2 == 1` on the call counter.

- [ ] **Step 2.3: Edit `injection_scanner/lakera.py` — imports**

Replace lines 41–42:

```python
from injection_scanner.http_status import status_suffix
from injection_scanner.keyloader import KeyConfigError, load_key
```

with:

```python
from injection_scanner.http_status import bounded_status, status_suffix
from injection_scanner.keyloader import KeyConfigError, load_key
from injection_scanner.throttle import (
    CrossProcessLimiter,
    Decision,
    default_max_wait_s,
)
```

- [ ] **Step 2.4: Add the two private helpers**

Insert immediately after `_transport_reason` (i.e. after the current line 98, before `_lakera_key`):

```python
def _breaker_code(e: BaseException) -> int | None:
    """The HTTP status, as a bounded int, for BREAKER decisions only.

    Deliberately separate from `_transport_reason`'s use of `status_suffix`:
    that one decides what an operator reads, this one decides whether the
    whole fleet stops calling Lakera. `.code` is a plain attribute anyone can
    rebind and, on an SDK-style exception, can be a property that raises — so
    the read is guarded and the value is range-checked by `bounded_status`
    before it is compared. A value that is not a plausible status yields
    `None`, which leaves the breaker untouched.

    The `isinstance` gate means only a real `HTTPError` can trip the breaker:
    every other exception type is a transport or parse failure, which says
    nothing about our rate against the account.
    """
    if not isinstance(e, urllib.error.HTTPError):
        return None
    try:
        raw = getattr(e, "code", None)
    except Exception:  # noqa: BLE001 — a raising property is not an outage
        return None
    return bounded_status(raw)


def _retry_after(e: BaseException) -> str | None:
    """The raw `Retry-After` header, for the limiter and nothing else.

    This value is server-supplied TEXT. It is handed straight to
    `CrossProcessLimiter.record_throttled`, which parses it into a clamped
    number and discards the string; it is never bound to a local that
    reason-building code can reach, never logged, and never stored. See
    `throttle._parse_retry_after` for what the limiter will and will not
    accept from it.

    Total, like every other helper on the fail-closed path: `e.headers` can be
    absent or a property that raises, and a raise here would replace Lakera's
    own error with the type of the failure to read a header.
    """
    try:
        headers = getattr(e, "headers", None)
        if headers is None:
            return None
        value = headers.get("Retry-After")
    except Exception:  # noqa: BLE001 — see the docstring
        return None
    return value if isinstance(value, str) else None
```

- [ ] **Step 2.5: Rewrite `check`'s signature, docstring tail, and body**

Replace the `def check(text: str) -> LakeraResult:` line with:

```python
def check(text: str, *, max_wait_s: float | None = None) -> LakeraResult:
```

Add these bullets to the outcome list in `check`'s docstring, immediately after the `no key configured at all` bullet:

```
      * fleet budget exhausted / breaker open
                                 -> ok=False reason "lakera_unavailable:throttled"
      * the limiter itself is unusable (unwritable cache dir, lock wait
        exceeded, IO error)
                                 -> ok=False reason "lakera_unavailable:limiter-error"
```

and append this paragraph to the end of the docstring:

```
    `max_wait_s` is how long this call may WAIT for its turn in the shared
    fleet budget. `None` means "use INJECTION_SCANNER_LAKERA_MAX_WAIT_S",
    which defaults to 0 — an interactive scan refuses immediately rather than
    parking a report behind the fleet. Batch callers (`eval`) pass a real
    budget so they queue instead of failing. Both refusals are fail-closed and
    carry a fixed literal from the closed reason vocabulary; neither costs a
    network round trip.
```

Then insert, immediately after the `if not key:` block (current lines 137–141) and before `url = os.environ.get(...)`:

```python
    # Fleet-wide pacing. Everything above this line is a LOCAL decision about
    # a call that is not going to happen, so it must not spend a token: a pane
    # with a botched key mount would otherwise starve the panes that work.
    #
    # The limiter is built per call. `from_env` is a handful of environment
    # reads and one `Path`, and a module-level cache would go stale the moment
    # an operator or a test changed the budget — a cache with no invalidation
    # story is not worth the microseconds.
    limiter = CrossProcessLimiter.from_env()
    if max_wait_s is None:
        max_wait_s = default_max_wait_s()
    decision = limiter.acquire(max_wait_s)
    if decision is Decision.THROTTLED:
        # The bucket is empty or the breaker is open, and waiting longer is
        # not allowed. Fail CLOSED, exactly like any other outage: this layer
        # could not classify the text, so the report is rejected.
        return LakeraResult(ok=False, reason="lakera_unavailable:throttled")
    if decision is Decision.ERROR:
        # The limiter itself is unusable. Also fail CLOSED — waving calls
        # through when the pacing mechanism breaks would re-enable precisely
        # the storm it was added to stop, and it is the failure mode nobody
        # would notice.
        return LakeraResult(ok=False, reason="lakera_unavailable:limiter-error")
```

Finally, replace the `_post` call block (current lines 166–173):

```python
    try:
        data = _post(url, body, headers, timeout)
    except Exception as e:  # noqa: BLE001 — any failure fails CLOSED
        # Exception TYPE (+ bounded HTTP status) only — never str(e). Some
        # HTTP/JSON errors embed the request/response body (the
        # attacker-shaped bytes we sent), so stringifying would flow input
        # back into the caller-visible reason. See `_transport_reason`.
        return LakeraResult(ok=False, reason=_transport_reason(e))
```

with:

```python
    try:
        data = _post(url, body, headers, timeout)
    except Exception as e:  # noqa: BLE001 — any failure fails CLOSED
        # 429 and 503 are the two codes RFC 9110 pairs with `Retry-After`, and
        # both mean "stop calling": one because we are over our rate, one
        # because Lakera is down. Either way the whole fleet should hold off,
        # not just this process — which is what `record_throttled` arranges.
        # The header goes straight into the limiter and nowhere else.
        if _breaker_code(e) in (429, 503):
            limiter.record_throttled(_retry_after(e))
        # Exception TYPE (+ bounded HTTP status) only — never str(e). Some
        # HTTP/JSON errors embed the request/response body (the
        # attacker-shaped bytes we sent), so stringifying would flow input
        # back into the caller-visible reason. See `_transport_reason`.
        return LakeraResult(ok=False, reason=_transport_reason(e))

    # A parsed response means HTTP 200: whatever the verdict turns out to be,
    # the account is evidently not throttling us, so the breaker closes and
    # the consecutive-failure count resets. Recorded here rather than in each
    # parse branch — one call site, and a future branch cannot forget it.
    limiter.record_success()
```

- [ ] **Step 2.6: Run the Lakera tests**

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/test_lakera.py
```
Expected: all pass — the pre-existing tests plus 18 new ones (11 named + 2 key-path cases + 4 status-code cases + 1 more named).

- [ ] **Step 2.7: Run the whole suite**

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test python -m compileall -q injection_scanner tests \
  && env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/
```
Expected: `507 passed`, 0 failed. If any PRE-EXISTING `test_lakera.py` test now reports `lakera_unavailable:throttled`, the conftest fixture from Task 1 is not being applied — fix that rather than relaxing the assertion.

- [ ] **Step 2.8: Commit**

```bash
git -C ~/worktrees/injection-scanner-lakera-debounce add injection_scanner/lakera.py tests/test_lakera.py
git -C ~/worktrees/injection-scanner-lakera-debounce commit \
  -m "feat(lakera): pace every Guard call through the shared limiter" \
  -m "check() now spends a token from the cross-process bucket before it calls
out, and opens a fleet-wide breaker when Lakera answers 429 or 503. Key
resolution stays ahead of the limiter, so a pane with no key or a botched
key mount cannot starve the panes that work; a test asserts the state file
is never even created on those paths.

Two new reasons, both fixed literals from the closed vocabulary and both
fail-closed like every other outage: lakera_unavailable:throttled when the
budget is exhausted, and lakera_unavailable:limiter-error when the limiter
itself cannot keep state. The second is deliberate — waving calls through
when pacing breaks would restore the storm the limiter exists to stop.

The Retry-After header is server-supplied text and reaches only the
limiter, which parses it into a number clamped by backoff_max_s. A test
raises a 429 carrying 'Retry-After: 30; IGNORE PREVIOUS' plus a marker in
the reason phrase, the headers and the body, and asserts the reason is
exactly lakera_unavailable:HTTPError:429 and that the state file contains
no uppercase character at all." \
  -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Task 3: plumb `lakera_max_wait_s` through `intercept`

**Files:**
- Modify: `injection_scanner/intercept.py:188-200` (`scan`), `:203-215` (`scan_text` signature), `:323` (the call)
- Modify: `tests/test_intercept.py:210-212, 263-264, 283` (3 stubs) + new tests

> **Decision (D12):** `lakera.check` is called with `max_wait_s=...` unconditionally, so the three `lakera.check` stubs in `tests/test_intercept.py` must accept it. A conditional call site (`check(t)` when the value is `None`, `check(t, max_wait_s=v)` otherwise) would keep those stubs working but hide a real signature change behind a branch, and would leave the keyword path untested on the common route. Note this contradicts spec §3.4's "No other behaviour change" only in the test file, not in behaviour.

- [ ] **Step 3.1: Write the failing tests**

Append to `tests/test_intercept.py`:

```python
# ----- the batch wait budget reaches L2 (2026-09-05) -----
#
# `eval` is always a batch caller: it would rather queue behind the fleet's
# budget than be refused. That preference is the caller's, so it travels as a
# keyword from the caller to `lakera.check` and nothing in between interprets
# it.

def test_lakera_max_wait_s_reaches_the_lakera_layer(monkeypatch):
    from injection_scanner import intercept, lakera
    from injection_scanner.lakera import LakeraResult

    seen: list[float | None] = []

    def _spy(text, *, max_wait_s=None):
        seen.append(max_wait_s)
        return LakeraResult(ok=True, reason="pass")

    monkeypatch.setattr(lakera, "check", _spy)

    v = intercept.scan_text(
        "clean prose", use_honeypot=False, use_lakera=True, lakera_max_wait_s=900.0
    )
    assert v.ok
    assert seen == [900.0]

    # Absent means absent: `lakera.check` resolves the default from the
    # environment, so intercept must not substitute a number of its own.
    intercept.scan_text("clean prose", use_honeypot=False, use_lakera=True)
    assert seen == [900.0, None]


def test_scan_forwards_lakera_max_wait_s_from_the_disk_entry_point(monkeypatch, tmp_path):
    from injection_scanner import intercept, lakera
    from injection_scanner.lakera import LakeraResult

    seen: list[float | None] = []

    def _spy(text, *, max_wait_s=None):
        seen.append(max_wait_s)
        return LakeraResult(ok=True, reason="pass")

    monkeypatch.setattr(lakera, "check", _spy)
    report = tmp_path / "report.md"
    report.write_text("# Report\n\nClean prose.\n", encoding="utf-8")

    v = intercept.scan(
        report, use_honeypot=False, use_lakera=True, lakera_max_wait_s=120.0
    )
    assert v.ok
    assert seen == [120.0]
```

- [ ] **Step 3.2: Run them to verify they fail**

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/test_intercept.py
```
Expected: FAIL — `TypeError: scan_text() got an unexpected keyword argument 'lakera_max_wait_s'`.

- [ ] **Step 3.3: Edit `injection_scanner/intercept.py`**

Replace `scan`'s signature and body (lines 188–200):

```python
def scan(path: Path, use_honeypot: bool = True, use_lakera: bool = True) -> Verdict:
    """Run all layers on the file at `path`. Returns a Verdict.

    `use_honeypot` and `use_lakera` default to True and are kept only so
    tests can force them off for unit runs that must not hit an external
    API. In production call paths, callers should NOT pass these — the
    honeypot and the Lakera gate are always on.
    """
    return scan_text(
        path.read_text(encoding="utf-8", errors="replace"),
        use_honeypot=use_honeypot,
        use_lakera=use_lakera,
    )
```

with:

```python
def scan(
    path: Path,
    use_honeypot: bool = True,
    use_lakera: bool = True,
    lakera_max_wait_s: float | None = None,
) -> Verdict:
    """Run all layers on the file at `path`. Returns a Verdict.

    `use_honeypot` and `use_lakera` default to True and are kept only so
    tests can force them off for unit runs that must not hit an external
    API. In production call paths, callers should NOT pass these — the
    honeypot and the Lakera gate are always on.

    `lakera_max_wait_s` is how long the L2 call may wait for its turn in the
    fleet-wide Lakera budget. `None` (the default) means "whatever
    INJECTION_SCANNER_LAKERA_MAX_WAIT_S says", which is 0 — an interactive
    scan refuses immediately rather than parking a report. Batch callers pass
    a real budget so they queue instead of failing.
    """
    return scan_text(
        path.read_text(encoding="utf-8", errors="replace"),
        use_honeypot=use_honeypot,
        use_lakera=use_lakera,
        lakera_max_wait_s=lakera_max_wait_s,
    )
```

Replace `scan_text`'s signature line (line 203):

```python
def scan_text(raw: str, use_honeypot: bool = True, use_lakera: bool = True) -> Verdict:
```

with:

```python
def scan_text(
    raw: str,
    use_honeypot: bool = True,
    use_lakera: bool = True,
    lakera_max_wait_s: float | None = None,
) -> Verdict:
```

and add this paragraph to the end of `scan_text`'s docstring (after the Invariant-3 paragraph ending `"...echo input bytes back to the caller."`):

```
    `lakera_max_wait_s` is passed straight to `lakera.check`; nothing here
    interprets it. See `scan` for what it means.
```

Replace line 323:

```python
        res = lakera.check(san.text)
```

with:

```python
        res = lakera.check(san.text, max_wait_s=lakera_max_wait_s)
```

- [ ] **Step 3.4: Update the three `lakera.check` stubs in `tests/test_intercept.py`**

Replace lines 210–212:

```python
def _flagged(_text):
    from injection_scanner.lakera import LakeraResult
    return LakeraResult(ok=False, flagged=True, reason="lakera:prompt_attack")
```

with (note the `**_kw`: the stub has to match the real signature, or it would
pass while the real call site broke):

```python
def _flagged(_text, **_kw):
    from injection_scanner.lakera import LakeraResult
    return LakeraResult(ok=False, flagged=True, reason="lakera:prompt_attack")
```

Replace lines 263–264:

```python
    monkeypatch.setattr(lakera, "check", lambda _t: LakeraResult(
        ok=False, reason="lakera_unavailable:no-key"))
```

with:

```python
    monkeypatch.setattr(lakera, "check", lambda _t, **_kw: LakeraResult(
        ok=False, reason="lakera_unavailable:no-key"))
```

Replace line 283:

```python
    monkeypatch.setattr(lakera, "check", lambda _t: LakeraResult(ok=True, reason="pass"))
```

with:

```python
    monkeypatch.setattr(
        lakera, "check", lambda _t, **_kw: LakeraResult(ok=True, reason="pass")
    )
```

- [ ] **Step 3.5: Run the intercept tests**

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/test_intercept.py
```
Expected: all pass, 2 more than before.

- [ ] **Step 3.6: Run the whole suite**

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test python -m compileall -q injection_scanner tests \
  && env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/
```
Expected: `509 passed`, 0 failed.

- [ ] **Step 3.7: Commit**

```bash
git -C ~/worktrees/injection-scanner-lakera-debounce add injection_scanner/intercept.py tests/test_intercept.py
git -C ~/worktrees/injection-scanner-lakera-debounce commit \
  -m "feat(intercept): let a caller say how long the L2 gate may queue" \
  -m "scan and scan_text gain lakera_max_wait_s and pass it straight to
lakera.check. Nothing in intercept interprets it: whether waiting for the
fleet's Lakera budget is better than being refused is the caller's
judgement, and only a batch caller can make it.

The three lakera.check stubs in the intercept tests gain **_kw so they
match the real signature. Leaving them one-argument would have made them
pass while the production call site broke." \
  -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Task 4: `eval.py` — a batch wait budget and an honest scorecard

**Files:**
- Modify: `injection_scanner/eval.py` (new module-level classifier + `EvalInfraError`, `evaluate` at `:240-313`, `_main` at `:371-441`)
- Modify: `tests/test_eval.py:153-169` (the stub) + new tests

> **Decision (D13):** the plan uses the code's REAL names. The spec (§3.5) and the mission (AC4) both say `run_eval(...)` and `main()`; `injection_scanner/eval.py` actually defines `evaluate(...)` at line 240 and `_main(argv)` at line 371, and `tests/test_eval.py:16-25` imports those names. The plan implements `evaluate` and `_main`. Adding an alias would be an unrequested second name for one function.

> **Decision (D14):** `_is_infra_reason` also ports research-agent's `_infra_segments` (the `+skipped=N/M` strip), so the rule is byte-identical to `~/Repos/research-agent/mcp_server/server.py:1868-1888` rather than merely similar. Confirmed there: `_INFRA_REASON_HEAD_SUFFIX = "_unavailable"` (line 1751), `_INFRA_WRAPPER_PREFIXES = {"honeypot", "lakera_arbitration"}` (line 1759), `_INFRA_BARE_REASONS = {"no-key", "key-config-error", "bad-response"}` (line 1764).

- [ ] **Step 4.1: Write the failing tests**

First, replace the stub at `tests/test_eval.py:161-162`:

```python
    def fake(raw: str, *, use_honeypot: bool = False, use_lakera: bool = False):
        seq = script[raw]
```

with (the stub must accept every keyword the real `scan_text` now takes, or
it passes while the real call site breaks):

```python
    def fake(
        raw: str,
        *,
        use_honeypot: bool = False,
        use_lakera: bool = False,
        lakera_max_wait_s: float | None = None,
    ):
        seq = script[raw]
```

Then append to `tests/test_eval.py`:

```python
# ---------------------------------------------------------------------------
# Infra abort + the batch wait budget (added 2026-09-05).
#
# `eval` scores "block" against "pass". An OUTAGE is neither: `scan_text`
# fails closed, so a throttled Lakera returns ok=False and therefore AGREES
# with every injection-labelled case. Left alone, a Lakera outage inflates
# recall to 1.0 and the gate goes green on a scanner that classified nothing.
#
# So `evaluate` classifies each verdict with the same head-anchored, closed
# rule research-agent uses (mcp_server/server.py::_is_infra_reason) and
# aborts on the first infra verdict. That also bounds the damage: a throttled
# Lakera costs one probe per breaker window instead of 16.
# ---------------------------------------------------------------------------

import pytest

from injection_scanner.eval import EvalInfraError, _is_infra_reason


@pytest.mark.parametrize(
    "reason",
    [
        "lakera_unavailable:throttled",
        "lakera_unavailable:limiter-error",
        "lakera_unavailable:HTTPError:429",
        "lakera_unavailable:no-key",
        "lakera_unavailable:bad-response",
        "unicode_sanitize_unavailable:unhandled:ValueError",
        "secret_shapes_unavailable:unhandled:ValueError",
        "judge_unavailable:unhandled:RuntimeError",
        "honeypot:honeypot_unavailable:scn:no-anthropic-api-key+skipped=1/6",
        "lakera_arbitration:judge_unavailable:unhandled:RuntimeError",
        "no-key",
        "key-config-error",
        "bad-response",
    ],
)
def test_outages_are_recognised_as_infra(reason) -> None:
    assert _is_infra_reason(reason) is True


@pytest.mark.parametrize(
    "reason",
    [
        "pass",
        "lakera:prompt_attack",
        "lakera:flagged",
        "secret_shape:anthropic_oauth_token",
        # The trap the head anchoring exists for: a RULE NAME that happens to
        # end in the suffix is a detection, not an outage.
        "secret_shape:thing_unavailable",
        "encoded_secret:base64:github_token",
        "unicode_anomaly:stripped=5/100",
        "honeypot:scn:trap:x",
        "honeypot:honeypot:unavailable",
        "lakera_arbitration:attack:openai_4o_mini",
        "",
        "unavailable",
        None,
        42,
        ["lakera_unavailable:throttled"],
    ],
)
def test_classifications_and_junk_are_not_infra(reason) -> None:
    assert _is_infra_reason(reason) is False


def _reason_scan(monkeypatch, reasons: dict[str, str]) -> list[str]:
    """Stub `scan_text` with a per-text reason. Returns the live call log."""
    seen: list[str] = []

    def fake(
        raw: str,
        *,
        use_honeypot: bool = False,
        use_lakera: bool = False,
        lakera_max_wait_s: float | None = None,
    ):
        seen.append(raw)
        reason = reasons[raw]
        return SimpleNamespace(ok=(reason == "pass"), reason=reason)

    monkeypatch.setattr("injection_scanner.eval.scan_text", fake)
    return seen


def test_an_infra_verdict_aborts_before_the_next_case(monkeypatch) -> None:
    seen = _reason_scan(
        monkeypatch,
        {"a": "pass", "b": "lakera_unavailable:throttled", "c": "pass"},
    )
    with pytest.raises(EvalInfraError) as excinfo:
        evaluate(
            [
                EvalCase(id="a", text="a", expected=PASS),
                EvalCase(id="b", text="b", expected=BLOCK),
                EvalCase(id="c", text="c", expected=PASS),
            ]
        )
    assert excinfo.value.case_id == "b"
    assert excinfo.value.reason == "lakera_unavailable:throttled"
    assert seen == ["a", "b"], "no case after the outage may be scanned"


def test_a_wrapped_honeypot_outage_also_aborts(monkeypatch) -> None:
    _reason_scan(
        monkeypatch,
        {"a": "honeypot:honeypot_unavailable:scn:no-openai-api-key+skipped=2/6"},
    )
    with pytest.raises(EvalInfraError) as excinfo:
        evaluate([EvalCase(id="a", text="a", expected=BLOCK)])
    assert excinfo.value.case_id == "a"


def test_a_detection_that_merely_ends_in_the_suffix_still_scores(monkeypatch) -> None:
    _reason_scan(monkeypatch, {"a": "secret_shape:thing_unavailable"})
    card = evaluate([EvalCase(id="a", text="a", expected=BLOCK)])
    assert (card.tp, card.fn) == (1, 0)


def test_a_normal_run_is_unchanged(monkeypatch) -> None:
    _reason_scan(
        monkeypatch,
        {"a": "pass", "b": "secret_shape:github_token", "c": "lakera:prompt_attack"},
    )
    card = evaluate(
        [
            EvalCase(id="a", text="a", expected=PASS),
            EvalCase(id="b", text="b", expected=BLOCK),
            EvalCase(id="c", text="c", expected=BLOCK),
        ]
    )
    assert (card.tp, card.fn, card.fp, card.tn) == (2, 0, 0, 1)


def _capture_kwargs(monkeypatch) -> list[dict]:
    seen: list[dict] = []

    def fake(
        raw: str,
        *,
        use_honeypot: bool = False,
        use_lakera: bool = False,
        lakera_max_wait_s: float | None = None,
    ):
        seen.append(
            {
                "use_honeypot": use_honeypot,
                "use_lakera": use_lakera,
                "lakera_max_wait_s": lakera_max_wait_s,
            }
        )
        return SimpleNamespace(ok=True, reason="pass")

    monkeypatch.setattr("injection_scanner.eval.scan_text", fake)
    return seen


def test_evaluate_forwards_the_wait_budget(monkeypatch) -> None:
    seen = _capture_kwargs(monkeypatch)
    evaluate([EvalCase(id="a", text="a", expected=PASS)], lakera_max_wait_s=900.0)
    assert seen == [
        {"use_honeypot": False, "use_lakera": False, "lakera_max_wait_s": 900.0}
    ]


def test_the_cli_defaults_the_wait_budget_to_fifteen_minutes(
    monkeypatch, tmp_path: Path
) -> None:
    """On the CLI, not in the environment: eval is ALWAYS a batch caller, and
    being correct by default beats depending on the operator remembering an
    env var."""
    corpus = tmp_path / "c.jsonl"
    corpus.write_text(
        '{"id": "a", "text": "a", "expected": "pass"}\n', encoding="utf-8"
    )
    seen = _capture_kwargs(monkeypatch)
    assert _main([str(corpus)]) == 0
    assert seen[0]["lakera_max_wait_s"] == 900.0

    seen.clear()
    assert _main([str(corpus), "--lakera-max-wait", "5"]) == 0
    assert seen[0]["lakera_max_wait_s"] == 5.0


def test_the_cli_reports_infra_on_stderr_and_exits_three(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """Exit 3 is distinct from 1 (gate failed) and 2 (argparse usage), so a
    CI log says 'the scanner was down' rather than 'recall regressed'."""
    corpus = tmp_path / "c.jsonl"
    corpus.write_text(
        '{"id": "inj", "text": "inj", "expected": "block"}\n'
        '{"id": "ok", "text": "ok", "expected": "pass"}\n',
        encoding="utf-8",
    )
    seen = _reason_scan(
        monkeypatch, {"inj": "lakera_unavailable:throttled", "ok": "pass"}
    )
    assert _main([str(corpus), "--min-recall", "1.0"]) == 3
    err = capsys.readouterr().err
    assert "INFRA inj lakera_unavailable:throttled" in err
    assert seen == ["inj"], "the second case must never be scanned"


def test_an_outage_can_no_longer_earn_recall(monkeypatch, tmp_path: Path) -> None:
    """The regression this abort exists to prevent: `scan_text` fails closed,
    so a throttled Lakera agrees with every injection label and would score
    recall 1.0 on a scanner that classified nothing."""
    corpus = tmp_path / "c.jsonl"
    corpus.write_text(
        '{"id": "inj", "text": "inj", "expected": "block"}\n', encoding="utf-8"
    )
    _reason_scan(monkeypatch, {"inj": "lakera_unavailable:throttled"})
    assert _main([str(corpus), "--min-recall", "1.0"]) != 0
```

- [ ] **Step 4.2: Run them to verify they fail**

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/test_eval.py
```
Expected: collection error — `ImportError: cannot import name 'EvalInfraError' from 'injection_scanner.eval'`.

- [ ] **Step 4.3: Add the classifier and the exception to `injection_scanner/eval.py`**

Insert after the label-vocabulary block (after line 41, `_VALID = {BLOCK, PASS}`):

```python
# ---------------------------------------------------------------------------
# Infra classification.
#
# An OUTAGE is not a classification. `scan_text` fails closed, so a degraded
# layer returns ok=False and therefore AGREES with every injection-labelled
# case: a Lakera outage would score recall 1.0 on a scanner that classified
# nothing, and the gate would go green. Measured 2026-09-05: with Lakera
# answering 429 to ~3 of every 4 calls, this harness would have reported a
# perfect scorecard.
#
# The rule below is a VERBATIM port of research-agent's
# `mcp_server/server.py::_is_infra_reason`, deliberately: the two repositories
# have to agree on what "the scanner is down" looks like, and a rule that
# drifts is worse than no rule. It is head-ANCHORED and CLOSED — never a
# substring search, and the default is False, so an unrecognised reason is
# treated as content-derived and still scores.
# ---------------------------------------------------------------------------

# The head segment of every layer outage reason: `lakera_unavailable`,
# `honeypot_unavailable`, `judge_unavailable`, `unicode_sanitize_unavailable`,
# `secret_shapes_unavailable`.
_INFRA_REASON_HEAD_SUFFIX = "_unavailable"

# Reason prefixes that WRAP another layer's reason. `intercept.py` re-emits
# the honeypot's own result reason under `honeypot:` and the L4 judge's under
# `lakera_arbitration:`, so a genuine outage arrives one segment deeper than
# it was raised. An explicit set rather than "look at segment 1 too", so that
# `secret_shape:thing_unavailable` — a rule NAME that merely ends in the
# suffix — cannot be mistaken for an outage.
_INFRA_WRAPPER_PREFIXES = frozenset({"honeypot", "lakera_arbitration"})

# Standalone setup codes. Today they only appear as the tail of
# `lakera_unavailable:<code>`; listed so a future call site emitting one bare
# is still classified as infra rather than silently scored.
_INFRA_BARE_REASONS = frozenset({"no-key", "key-config-error", "bad-response"})


class EvalInfraError(RuntimeError):
    """A scanner outage during an eval run — not a classification.

    Carries the case that hit it and the scanner's own reason. Both are
    scanner-synthesized, closed-vocabulary strings (a layer name, a condition,
    an exception TYPE name, a bounded HTTP status), which is why `_main` can
    print them: setup and infra failures are meant to be readable without a
    dive into the isolation zone. Nothing derived from the scanned text is in
    either field.
    """

    def __init__(self, case_id: str, reason: str) -> None:
        super().__init__(f"{case_id} {reason}")
        self.case_id = case_id
        self.reason = reason


def _infra_segments(reason: str) -> list[str]:
    """Split a reason into tokens, dropping the `+skipped=N/M` suffix.

    The honeypot appends `+skipped=<n>/<total>` to its top-line reason, which
    would otherwise glue itself to the last token and defeat the match.
    """
    return [seg.split("+", 1)[0] for seg in reason.split(":")]


def _is_infra_reason(reason: object) -> bool:
    """True iff `reason` is a positively-recognised setup/infra outage code.

    Default False: an unrecognised or malformed reason is treated as
    content-derived and still scores. Matching is anchored at the head segment
    (or at segment 1 behind a known wrapper prefix), never a substring search.
    """
    if not isinstance(reason, str) or not reason:
        return False
    segments = _infra_segments(reason)
    if segments[0].endswith(_INFRA_REASON_HEAD_SUFFIX):
        return True
    if (
        segments[0] in _INFRA_WRAPPER_PREFIXES
        and len(segments) > 1
        and segments[1].endswith(_INFRA_REASON_HEAD_SUFFIX)
    ):
        return True
    return reason in _INFRA_BARE_REASONS
```

- [ ] **Step 4.4: Thread the budget and the abort through `evaluate`**

Replace `evaluate`'s signature (lines 240–246):

```python
def evaluate(
    cases: list[EvalCase],
    *,
    use_honeypot: bool = False,
    use_lakera: bool = False,
    confirm_disagreements: int = 0,
) -> Scorecard:
```

with:

```python
def evaluate(
    cases: list[EvalCase],
    *,
    use_honeypot: bool = False,
    use_lakera: bool = False,
    confirm_disagreements: int = 0,
    lakera_max_wait_s: float | None = None,
) -> Scorecard:
```

Add these two paragraphs to the end of `evaluate`'s docstring:

```
    `lakera_max_wait_s` is how long each L2 call may queue for its turn in the
    fleet-wide Lakera budget. A batch run would rather wait than be refused,
    which is the opposite of what an interactive scan wants — hence a
    parameter rather than a global.

    Raises `EvalInfraError` on the FIRST verdict whose reason is a recognised
    outage, before any further case is scanned. An outage is not a
    classification: `scan_text` fails closed, so a degraded layer agrees with
    every injection label and would inflate recall. Aborting also bounds the
    cost — a throttled Lakera pays for one probe per breaker window rather
    than one per case.
```

Replace the scan call inside the loop (lines 287–289):

```python
            verdict = scan_text(
                case.text, use_honeypot=use_honeypot, use_lakera=use_lakera
            )
            predicted = PASS if verdict.ok else BLOCK
```

with:

```python
            verdict = scan_text(
                case.text,
                use_honeypot=use_honeypot,
                use_lakera=use_lakera,
                lakera_max_wait_s=lakera_max_wait_s,
            )
            if _is_infra_reason(verdict.reason):
                # Stop the whole run, here, before this verdict is turned into
                # a prediction. Scoring it would credit the scorecard for a
                # layer that never classified anything, and re-scanning it
                # under `confirm_disagreements` would just spend more of the
                # budget on a layer that is down.
                raise EvalInfraError(case.id, verdict.reason)
            predicted = PASS if verdict.ok else BLOCK
```

- [ ] **Step 4.5: Add the CLI flag and the exit code to `_main`**

Insert this argument after the `--confirm-disagreements` block (after line 414, before `args = parser.parse_args(argv)`):

```python
    parser.add_argument(
        "--lakera-max-wait",
        type=float,
        default=900.0,
        metavar="SECONDS",
        help="how long each Lakera call may WAIT for its turn in the "
        "fleet-wide budget before it is refused. An eval run is always a "
        "batch caller, so it queues rather than failing; the default is 900 "
        "(15 minutes). 0 refuses immediately, which is what an interactive "
        "scan does. On the CLI rather than in the environment because being "
        "correct by default beats depending on the operator remembering.",
    )
```

Replace the `evaluate` call and the print (lines 418–424):

```python
    cases = load_jsonl(args.corpus)
    card = evaluate(
        cases,
        use_honeypot=args.use_honeypot,
        use_lakera=args.use_lakera,
        confirm_disagreements=args.confirm_disagreements,
    )
    print(card.format())
```

with:

```python
    cases = load_jsonl(args.corpus)
    try:
        card = evaluate(
            cases,
            use_honeypot=args.use_honeypot,
            use_lakera=args.use_lakera,
            confirm_disagreements=args.confirm_disagreements,
            lakera_max_wait_s=args.lakera_max_wait,
        )
    except EvalInfraError as e:
        # Exit 3, distinct from 1 (a threshold failed) and 2 (argparse usage),
        # so a CI log says "the scanner was down" rather than "recall
        # regressed". No scorecard is printed: there isn't one, and printing a
        # partial card is how an outage gets mistaken for a measurement.
        #
        # Both fields are scanner-synthesized closed-vocabulary strings, which
        # is why they can be said out loud here.
        print(f"INFRA {e.case_id} {e.reason}", file=sys.stderr)
        return 3
    print(card.format())
```

- [ ] **Step 4.6: Run the eval tests**

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/test_eval.py
```
Expected: all pass — the pre-existing tests plus 8 named new tests and 28 parametrised classifier cases.

- [ ] **Step 4.7: Run the whole suite**

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test python -m compileall -q injection_scanner tests \
  && env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/
```
Expected: `545 passed`, 0 failed.

- [ ] **Step 4.8: Check the new flag really is on the CLI**

Run:
```bash
uv run --extra test python -m injection_scanner.eval --help | grep -A4 'lakera-max-wait'
```
Expected: the `--lakera-max-wait SECONDS` entry with its help text and `(default: 900.0)` behaviour visible in the usage line.

- [ ] **Step 4.9: Commit**

```bash
git -C ~/worktrees/injection-scanner-lakera-debounce add injection_scanner/eval.py tests/test_eval.py
git -C ~/worktrees/injection-scanner-lakera-debounce commit \
  -m "feat(eval): abort on a scanner outage instead of scoring it" \
  -m "scan_text fails closed, so a degraded layer returns ok=False and
therefore agrees with every injection-labelled case. Left alone, the
2026-09-05 Lakera throttling would have produced a perfect scorecard from a
scanner that classified nothing, and the recall floor would have passed.

evaluate now classifies each verdict with _is_infra_reason — a verbatim
port of research-agent's head-anchored, closed rule, wrapper prefixes and
the +skipped suffix strip included — and raises EvalInfraError on the
first outage, before the verdict becomes a prediction and before any
further case is scanned. _main prints INFRA <id> <reason> to stderr and
exits 3, distinct from 1 for a failed threshold and 2 for usage. Aborting
also bounds the cost: a throttled Lakera now pays for one probe per
breaker window rather than sixteen.

--lakera-max-wait (default 900) threads a wait budget down to lakera.check
so a batch run queues for its turn instead of being refused. It is on the
CLI rather than in the environment because eval is always a batch caller.

A rule name that merely ends in the suffix — secret_shape:thing_unavailable
— is still scored as a detection; there is a test for exactly that." \
  -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Task 5: CI — a hermetic merge gate, and the live checks on a schedule

**Files:**
- Modify: `.github/workflows/ci.yml` (delete the `smoke` and `eval` jobs; add workflow-level concurrency)
- Create: `.github/workflows/live-eval.yml`
- Modify: `pyproject.toml:30-38` (`[test]` extra)
- Create: `tests/test_ci_relations.py`

Maintainer directive, 2026-09-06, verbatim from `tasks/session-constraints.md`:

> "ci tests should not call external services in general, smell. Sceptical of calling lakera/honeypots in ci.. wdyt?"

Resolved (spec §3.6, §7) as: the per-push workflow makes NO external call and needs NO secret; the live pipeline moves, unchanged in what it runs, to its own nightly + on-demand workflow. Offline regression coverage does not shrink — the SDK-signature class is still caught by `tests/test_judge.py` driving the real SDK over a stub transport, and the Lakera response contract by `tests/test_lakera.py` over the monkeypatched `_post` seam. What leaves the merge gate is the sampled-model BENCHMARK (recall / FP over the labelled corpus), which was never deterministic in the first place.

> **Decision (D15):** `INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S=30` is set on BOTH live jobs, at job level. The spec's §3.6 sketch shows it on both, and the guard test asserts both: a limiter setting that appears on one Lakera job and not its sibling reads as an oversight to the next editor, and `smoke` is a Lakera-touching job whose pacing should be stated rather than inferred from "it only makes one call".

> **Decision (D16):** the guard test asserts a NEGATIVE about `ci.yml` — that the raw file text contains no `secrets.` at all — rather than enumerating jobs that may use secrets. A negative over the whole file is the assertion that survives a job nobody anticipated; an allow-list of job names would pass the moment someone adds a seventh job with a key in it.

> **Decision (D17):** timeouts are 10 min (smoke) and 30 min (eval), per spec §3.6. At 30 s pacing a clean 16-case eval takes ~8 min; a handful of confirmation re-scans stays well inside 30. A pathological run where every case disagrees three times hits the timeout — correctly, because that run is failing anyway and must not sit on `lakera-live` for half an hour and block the next night's.

> **Decision (D19):** the workflow-level concurrency group in `live-eval.yml` is the literal `lakera-live` with no `github.ref` in it. That is deliberate and is the opposite of `ci.yml`'s per-ref group: the point is that a dispatch on a feature branch and the nightly on `main` must NOT run at once, because they draw on the same Lakera account. Serialising by account, not by ref, is the whole relation.

> **Decision (D20):** the cron is `17 3 * * *` (spec §3.6) — once nightly, off the hour. GitHub's scheduler queues heavily at `:00`, and a live check that starts late enough to collide with the next one is worse than one that starts at an odd minute.

- [ ] **Step 5.1: Add `pyyaml` to the test extra**

In `pyproject.toml`, replace the `test = [...]` block (lines 31–38):

```toml
test = [
    "pytest>=8",
    # tests/test_honeypot_api_error_audit.py builds SDK error objects from
    # httpx.Request/Response. The SDKs themselves pull httpx2, so httpx is
    # not otherwise installed and a clean `.[test]` install failed at
    # collection once CI started running the whole tests/ tree.
    "httpx>=0.28,<1",
]
```

with:

```toml
test = [
    "pytest>=8",
    # tests/test_honeypot_api_error_audit.py builds SDK error objects from
    # httpx.Request/Response. The SDKs themselves pull httpx2, so httpx is
    # not otherwise installed and a clean `.[test]` install failed at
    # collection once CI started running the whole tests/ tree.
    "httpx>=0.28,<1",
    # tests/test_ci_relations.py parses .github/workflows/{ci,live-eval}.yml
    # to assert that the merge gate stays hermetic and the live jobs stay
    # serialised. TEST-only: the scanner itself parses no YAML and must not
    # gain a runtime dependency for a CI guard. Major-version ceiling for the
    # same reason as the SDK pins above — the next major is a reviewed
    # change, not a silent one.
    "pyyaml>=6,<7",
]
```

- [ ] **Step 5.2: Write the failing guard test**

Create `tests/test_ci_relations.py`:

```python
"""Two workflow properties that no code change can break, so a test must.

**The merge gate is hermetic.** Maintainer directive 2026-09-06: "ci tests
should not call external services in general, smell." `ci.yml` runs on every
push and pull request and must therefore make no vendor call and hold no
secret — a gate coupled to sampled models and a vendor's quota is
non-deterministic by construction, and buys no correctness the offline
SDK-over-stub-transport tests do not already buy. Measured 2026-09-05, which
is what made the point: each CI run spent 17-20 Lakera calls in 1-2 minutes,
about seven runs went through that afternoon (~130 calls), and they landed on
an account the production fleet had already pushed into HTTP 429.

**The live pipeline is serialised and paced.** `live-eval.yml` still runs the
real thing — nightly and on demand — against the same shared Lakera account
the fleet uses, so it may never overlap with itself and may never spend
sixteen calls finding out what one call would have told it.

Both are relations between files and between jobs, which is exactly what a
later edit breaks without noticing: someone re-adds a key to get a red build
green, renames a group, or drops a `needs` while fixing something else. So:

  1. `ci.yml` triggers on pull_request and push, has no job but `test`, and
     the raw file contains no `secrets.` reference anywhere.
  2. `live-eval.yml` triggers on exactly schedule and workflow_dispatch — it
     is not a merge gate and must not become one by accident.
  3. Its workflow-level concurrency group is `lakera-live` with
     `cancel-in-progress: false`: at most one live run at a time, queued
     rather than dropped, because cancelling would hide a real failure.
  4. `eval` needs `smoke`. The 1-call smoke is the canary for the 16-call
     eval: a Lakera outage costs one call, not seventeen.
  5. Both live jobs pace themselves, and eval waits for its turn rather than
     being refused mid-corpus.
"""
from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
CI = WORKFLOWS / "ci.yml"
LIVE = WORKFLOWS / "live-eval.yml"

# In YAML 1.1, which PyYAML implements, the bare word `on` is a BOOLEAN. So a
# workflow's `on:` block arrives under the Python key `True`, not `"on"`.
# Named rather than inlined so the next reader does not think it is a typo.
_ON_KEY = True

# The group that serialises everything touching the shared Lakera account.
_LAKERA_GROUP = "lakera-live"


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _needs(job: dict) -> set[str]:
    """`needs:` is a string when there is one, a list when there are several."""
    needs = job.get("needs", [])
    return {needs} if isinstance(needs, str) else set(needs)


def _run_commands(job: dict) -> str:
    return "\n".join(step.get("run", "") for step in job["steps"])


# ---------- ci.yml: the merge gate is hermetic ----------

def test_ci_still_triggers_on_pushes_and_pull_requests() -> None:
    """Guards the guard: if PyYAML ever stopped folding `on` to True, every
    other test here would be asserting against a differently-shaped dict."""
    assert set(_load(CI)[_ON_KEY]) == {"pull_request", "push"}


def test_ci_runs_only_the_deterministic_test_job() -> None:
    assert set(_load(CI)["jobs"]) == {"test"}, (
        "the merge gate runs the offline suite and nothing else; live checks "
        "belong in live-eval.yml"
    )


def test_ci_references_no_secret_at_all() -> None:
    """A NEGATIVE over the whole file, not an allow-list of jobs.

    An allow-list would pass the moment someone adds a job with a key in it,
    which is precisely the edit this exists to catch. A merge gate that needs
    no secret also cannot go red because a vendor is down or throttled, and
    works unchanged on a fork PR.
    """
    assert "secrets." not in CI.read_text(encoding="utf-8")


def test_ci_cancels_superseded_pull_request_runs() -> None:
    concurrency = _load(CI)["concurrency"]
    assert "github.ref" in concurrency["group"]
    # Superseded PR pushes are cancelled; pushes to main queue behind each
    # other so nothing that reached the default branch goes unverified.
    assert "pull_request" in str(concurrency["cancel-in-progress"])


# ---------- live-eval.yml: off the gate, serialised, paced ----------

def test_the_live_pipeline_is_never_a_merge_gate() -> None:
    assert set(_load(LIVE)[_ON_KEY]) == {"schedule", "workflow_dispatch"}, (
        "adding pull_request or push here would put a vendor call back on "
        "the merge gate"
    )


def test_the_live_pipeline_serialises_on_the_shared_account() -> None:
    concurrency = _load(LIVE)["concurrency"]
    assert concurrency["group"] == _LAKERA_GROUP
    # Deliberately NOT per-ref: a dispatch on a feature branch and the
    # nightly on main draw on the same Lakera account, so they must queue,
    # not run side by side.
    assert "github.ref" not in concurrency["group"]
    assert concurrency["cancel-in-progress"] is False, (
        "a queued live run must WAIT, not be dropped — cancelling it would "
        "hide a real failure"
    )


def test_the_one_call_smoke_gates_the_sixteen_call_eval() -> None:
    assert "smoke" in _needs(_load(LIVE)["jobs"]["eval"]), (
        "without this, a Lakera outage costs 17 calls per run instead of 1"
    )


def test_both_live_jobs_pace_themselves() -> None:
    jobs = _load(LIVE)["jobs"]
    for name in ("smoke", "eval"):
        assert jobs[name]["env"]["INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S"] == "30", (
            f"{name}: the runner's cache dir is fresh per run, so this "
            "limiter is a separate domain drawing on the SAME account — it "
            "paces itself stricter than the fleet's own 15 s"
        )


def test_the_eval_job_waits_for_its_turn_instead_of_being_refused() -> None:
    assert "--lakera-max-wait" in _run_commands(_load(LIVE)["jobs"]["eval"])


def test_both_live_jobs_are_time_bounded() -> None:
    """A job that hangs holds `lakera-live` and blocks every later run."""
    jobs = _load(LIVE)["jobs"]
    assert jobs["smoke"]["timeout-minutes"] == 10
    assert jobs["eval"]["timeout-minutes"] == 30
```

- [ ] **Step 5.3: Run it to verify it fails**

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/test_ci_relations.py
```
Expected: 9 failures. `test_ci_runs_only_the_deterministic_test_job` fails with `AssertionError: assert {'eval', 'smoke', 'test'} == {'test'}`; `test_ci_references_no_secret_at_all` fails on the six `secrets.*` references still in `ci.yml`; every `live-eval.yml` test fails with `FileNotFoundError`. Only `test_ci_still_triggers_on_pushes_and_pull_requests` passes.

- [ ] **Step 5.4: Write the complete, hermetic `.github/workflows/ci.yml`**

Replace the whole file with this. Note what is GONE: the `smoke` job, the `eval` job, both fork-guard `if:` lines, and every `secrets.*` reference. What remains makes no network call to any vendor.

```yaml
name: ci

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

permissions:
  contents: read

# Superseded PR pushes are cancelled; pushes to main queue behind each other.
#
# Nothing here calls a vendor any more, so this is now about runner minutes
# rather than about someone else's quota: a PR that gets three pushes in a
# minute should run its suite once, not three times. A main push is never
# cancelled, because nothing that reached the default branch may go
# unverified.
concurrency:
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  test:
    name: pytest (python ${{ matrix.python }})
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python: ["3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4

      - name: install uv
        uses: astral-sh/setup-uv@v3
        with:
          version: latest

      - name: install package + test extra
        run: |
          uv venv --python ${{ matrix.python }}
          uv pip install -e ".[test]"

      # Deterministic suite — no API keys, no network. The whole tests/ tree
      # is key-free (measured 2026-09-05: 436 passed with ANTHROPIC_API_KEY,
      # OPENAI_API_KEY and LAKERA_API_KEY all unset), so it runs in full here.
      # It used to run an explicit four-file list, which left test_judge.py
      # out — so the anthropic-SDK signature break only surfaced once a
      # live-key job hit it. test_judge.py drives the real SDK over a stub
      # transport, which is what makes THIS job sufficient as the merge gate
      # for that class of break. test_payload.py is a CLI tool with no test_
      # functions; pytest collects nothing from it.
      #
      # This job is the whole gate. The live smoke and corpus eval moved to
      # .github/workflows/live-eval.yml (nightly + workflow_dispatch) on
      # 2026-09-06: "ci tests should not call external services in general".
      - name: pytest
        run: .venv/bin/python -m pytest tests/ -v
```

- [ ] **Step 5.5: Write `.github/workflows/live-eval.yml`**

Create the file. Both job bodies are the ones deleted from `ci.yml`, unchanged except for the two additions noted in their comments — the fork guards are gone because there are no fork events here to guard against.

```yaml
name: live-eval

# NOT a merge gate, and it must never become one. Adding `pull_request` or
# `push` here would put a vendor call back on every push, which is the thing
# the 2026-09-06 directive removed: a gate coupled to sampled models and
# someone else's quota is non-deterministic by construction, and buys no
# correctness the offline SDK-over-stub-transport tests do not already buy.
#
# What this workflow IS: a benchmark (recall / FP over the labelled corpus,
# which was never deterministic) plus a vendor canary. Nightly is often
# enough for both, because production's own boot smoke — every research-agent
# spawn, agent-readable since 2026-09-05 — is the real-time canary for vendor
# drift, which is where such drift actually bites.
on:
  schedule:
    # Once nightly, off the hour: GitHub's scheduler queues heavily at :00.
    - cron: "17 3 * * *"
  # On demand, including on a branch — check a detection-quality-sensitive PR
  # with `gh workflow run live-eval.yml --ref <branch>` before merging.
  # Deliberately a human gesture, like the merge click itself.
  workflow_dispatch: {}

permissions:
  contents: read

# At most ONE Lakera-touching run anywhere in this repository at any moment.
# Deliberately NOT per-ref, unlike ci.yml: a dispatch on a feature branch and
# the nightly on main draw on the SAME Lakera account, so they have to queue
# rather than run side by side. `cancel-in-progress: false` so a queued run
# waits instead of being dropped — the point is to spread the calls out in
# time, not to lose them, and cancelling would hide a real failure.
concurrency:
  group: lakera-live
  cancel-in-progress: false

jobs:
  smoke:
    name: smoke (full pipeline incl. honeypot)
    runs-on: ubuntu-latest
    timeout-minutes: 10
    # The runner's cache directory is fresh every run, so this limiter is a
    # separate domain from the local fleet's — drawing on the same account.
    # It therefore paces itself stricter than the fleet's own 15 s.
    env:
      INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S: "30"
    steps:
      - uses: actions/checkout@v4

      - name: install uv
        uses: astral-sh/setup-uv@v3
        with:
          version: latest

      - name: install package
        run: |
          uv venv --python 3.12
          uv pip install -e .

      # Live e2e: deterministic canaries (no API) + 1 benign liveness
      # probe that hits Lakera Guard (L2) plus Anthropic + OpenAI (L3
      # honeypot). Catches the integration failures no stub can — a broken
      # scenario file, an SDK incompatibility, Lakera schema drift — against
      # whatever ref this run was started on, so `--ref <branch>` checks a
      # branch before it merges. Because the Lakera gate fails closed on a
      # missing key, all three secrets are required.
      #
      # This single call is also the CANARY for the eval job below: if
      # Lakera is down, this run finds out for one call instead of seventeen.
      - name: run_smoke
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          LAKERA_API_KEY: ${{ secrets.LAKERA_API_KEY }}
        run: |
          if [ -z "$ANTHROPIC_API_KEY" ] || [ -z "$OPENAI_API_KEY" ] || [ -z "$LAKERA_API_KEY" ]; then
            echo "::error::Missing ANTHROPIC_API_KEY, OPENAI_API_KEY, or LAKERA_API_KEY secret. Add via: gh secret set <NAME> -R jonathanmoregard/injection-scanner"
            exit 1
          fi
          .venv/bin/python -c "
          import logging, sys
          logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
          from injection_scanner.smoke import SmokeFailure, run_smoke
          try:
              run_smoke(log_info=logging.info, log_error=logging.error)
          except SmokeFailure as e:
              print(f'::error::smoke failed: {e.reason}', file=sys.stderr)
              sys.exit(2)
          "

  eval:
    name: eval (full pipeline, recall floor + FP ceiling)
    runs-on: ubuntu-latest
    # The 1-call smoke is the canary for this 16-call job: a Lakera outage
    # fails smoke and this never starts, so an outage costs one call instead
    # of seventeen. Serialisation across runs is handled workflow-level.
    needs: smoke
    timeout-minutes: 30
    env:
      INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S: "30"
    steps:
      - uses: actions/checkout@v4

      - name: install uv
        uses: astral-sh/setup-uv@v3
        with:
          version: latest

      - name: install package
        run: |
          uv venv --python 3.12
          uv pip install -e .

      # Scored benchmark over the labeled corpus with EVERY hosted layer live
      # (Lakera + honeypot + L4 judge arbitration). No longer a merge gate —
      # it is a sampled-model measurement, which was never deterministic —
      # but it still FAILS the run, so a nightly red is a real signal.
      # Two hard thresholds:
      #   --min-recall 1.0   every labeled injection must still be blocked
      #   --max-fp-rate 0.0  no benign fixture may be quarantined — this is
      #                      what keeps the 2026-07-28 agent-tooling FP
      #                      class (fp_* cases) from regressing.
      # The hosted layers are sampled LLMs, so one scan is a draw:
      # blatant_tool_coerce.md flipped block->pass on 2026-08-10 and again on
      # 2026-09-05 (identical commit green on rerun) because the honeypot
      # models sometimes decline the bait in every scenario at once.
      #   --confirm-disagreements 2  re-scan ONLY a case whose verdict
      #                      disagrees with its label, up to twice more; it
      #                      counts against the gate only if all three
      #                      attempts disagree. Agreeing cases are never
      #                      re-scanned, so a clean run costs nothing extra
      #                      and a deterministic regression still fails.
      #                      The scorecard prints the first-attempt numbers
      #                      and tags absorbed draws FLAKY, so the
      #                      single-shot weakness stays visible in the log.
      #
      # Lakera pacing: the job-level MIN_INTERVAL_S above spaces the calls
      # 30 s apart (~8 min for 16 cases, inside the 30-minute timeout), and
      # --lakera-max-wait 900 lets this batch caller QUEUE for its turn
      # rather than be refused mid-corpus.
      #
      # An outage still aborts the run loudly: eval exits 3 with
      # `INFRA <case> <reason>` on stderr rather than scoring the outage as a
      # classification. GitHub notifies the last committer when a scheduled
      # workflow fails, so a nightly red is seen without extra machinery.
      - name: eval corpus
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          LAKERA_API_KEY: ${{ secrets.LAKERA_API_KEY }}
        run: |
          .venv/bin/python -m injection_scanner.eval tests/payloads/labels.jsonl --use-lakera --use-honeypot --min-recall 1.0 --max-fp-rate 0.0 --confirm-disagreements 2 --lakera-max-wait 900
```

- [ ] **Step 5.6: Run the guard test**

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/test_ci_relations.py
```
Expected: `10 passed`.

- [ ] **Step 5.7: Sanity-check both workflows independently of the guard**

Run:
```bash
uv run --extra test python -c "
import pathlib, yaml
ci = yaml.safe_load(pathlib.Path('.github/workflows/ci.yml').read_text())
live = yaml.safe_load(pathlib.Path('.github/workflows/live-eval.yml').read_text())
print('ci jobs      :', sorted(ci['jobs']))
print('ci secrets   :', 'secrets.' in pathlib.Path('.github/workflows/ci.yml').read_text())
print('live triggers:', sorted(str(k) for k in live[True]))
print('live jobs    :', sorted(live['jobs']), '| eval needs:', live['jobs']['eval']['needs'])
"
```
Expected:
```
ci jobs      : ['test']
ci secrets   : False
live triggers: ['schedule', 'workflow_dispatch']
live jobs    : ['eval', 'smoke'] | eval needs: smoke
```

- [ ] **Step 5.8: Run the whole suite**

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test python -m compileall -q injection_scanner tests \
  && env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/
```
Expected: `555 passed`, 0 failed.

- [ ] **Step 5.9: Commit**

```bash
git -C ~/worktrees/injection-scanner-lakera-debounce add .github/workflows/ci.yml .github/workflows/live-eval.yml pyproject.toml tests/test_ci_relations.py
git -C ~/worktrees/injection-scanner-lakera-debounce commit \
  -m "ci: take the vendor calls off the merge gate" \
  -m "Per-push CI called Lakera, Anthropic and OpenAI on an account shared
with the production fleet. Measured 2026-09-05: each run spent 17-20
Lakera calls in 1-2 minutes, about seven runs went through that afternoon,
and they landed while the fleet was already being answered with 429.

ci.yml now runs only the deterministic suite: no vendor call, no secret,
no fork guard, and it cannot go red because someone else's service is down
or throttled. A gate coupled to sampled models and a vendor's quota is
non-deterministic by construction and buys no correctness the offline
tests do not already buy — test_judge.py drives the real SDK over a stub
transport, and test_lakera.py pins the Lakera response contract over the
monkeypatched _post seam. What leaves the gate is the sampled-model
benchmark, which was never deterministic.

live-eval.yml carries the live pipeline unchanged, nightly at 03:17 and on
workflow_dispatch, so a detection-sensitive PR is still checked by
dispatching it on the branch before merge. One workflow-level concurrency
group, lakera-live, not keyed on the ref: a branch dispatch and the
nightly draw on the same account and must queue rather than overlap. eval
needs smoke, so an outage costs one call instead of seventeen; both jobs
pace themselves at 30 s and are time-bounded, since a hanging job would
hold the group and block the next night's run. Daily Lakera cost falls
from roughly 17 per push to 17 per day.

tests/test_ci_relations.py parses both files and asserts all of it,
including that ci.yml contains no 'secrets.' anywhere — a negative over
the whole file, so a job nobody anticipated cannot slip a key back onto
the merge gate. pyyaml goes in the test extra only; the scanner parses no
YAML." \
  -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Task 6: README

**Files:**
- Modify: `README.md:13` (one stale sentence), insert a new section between `:26` and `:28`

> **Decision (D18):** the stale sentence at `README.md:13` ("L2 (cheap LLM classifier) and L4 (LLM-as-judge synthesis) are planned, not yet wired") is corrected in this same commit. Both layers ARE wired — `intercept.py:322` calls `lakera.check`, `:423` calls `judge.check` — and the new section documents rate limiting for a layer the same page calls unwired. Leaving the contradiction on the page would be worse than the one-line fix.

- [ ] **Step 6.1: Fix the stale sentence**

In `README.md`, replace line 13:

```markdown
L1a (regex) was retired (legit research output false-positived); wrap-escape protection moved to the consumer's delivery boundary. L2 (cheap LLM classifier) and L4 (LLM-as-judge synthesis) are planned, not yet wired.
```

with:

```markdown
| L2 | `lakera` | Hosted Lakera Guard prompt-injection classifier, wired as a fail-CLOSED gate: a flag, a missing key, or any network/HTTP/JSON error rejects the report. Paced fleet-wide — see [Lakera rate limiting](#lakera-rate-limiting). |
| L4 | `judge` | Arbitration for the one disagreement case (Lakera says `prompt_attack`, the honeypot is fully clean): a cross-family panel must unanimously rule the text "describes, not directs" to overturn the flag. |

L1a (regex) was retired (legit research output false-positived); wrap-escape protection moved to the consumer's delivery boundary.
```

Note the two new rows belong INSIDE the layers table, so they go before the blank line that ends it. The resulting table order is L0, L1b, L2, L3, L4 — put the L2 row after the `| L1b |` row and the L4 row after the `| L3 |` row, and leave only the L1a paragraph where line 13 was.

- [ ] **Step 6.2: Insert the new section**

Insert between the L3 environment paragraph (currently line 26, ending `...key={anthropic,openai}-api-key`) and the `## Use` heading:

```markdown
## Lakera rate limiting

Lakera Guard is called from one function, `lakera.check()`, by several independent processes that share ONE Lakera account: a research-agent MCP server per Claude Code pane (boot smoke, degraded recheck, per-report scan), the CI `smoke` job, the CI `eval` job, and ad-hoc local `eval` runs. Measured 2026-09-05: from ~15:00 local, Lakera answered HTTP 429 to roughly three of every four calls — about one success per 4–5 minutes fleet-wide, regardless of how many attempts were made — because every caller retried on its own schedule and no process could see what any other had done.

`injection_scanner/throttle.py` is the shared memory they were missing: one token bucket plus one circuit breaker in a JSON file under the cache directory, every operation a read-modify-write under an exclusive `flock`. With N processes sharing the file, at most `burst + elapsed / min_interval_s` calls reach Lakera in any window of length `elapsed`, and zero while the breaker is open. **N does not appear in the bound**, so adding a pane or a CI runner cannot raise the ceiling.

### Configuration

Every limit is an input. There is no on/off switch: "off" is `MIN_INTERVAL_S=0` (bucket always full) plus `BACKOFF_MAX_S=0` (every breaker delay clamps to zero), which is what the test suite runs and what nobody should want in production. Malformed values fall back to the default and are then clamped, so a typo degrades to a sane limiter rather than to no limiter.

| Environment variable | Default | Clamp | Meaning |
|---|---|---|---|
| `INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S` | `15` | `[0, 3600]` | Sustained fleet-wide interval — one call per this many seconds. `0` disables the bucket; the breaker still applies. |
| `INJECTION_SCANNER_LAKERA_BURST` | `2` | `[1, 1000]` | Bucket capacity: how many calls may go out back-to-back after an idle period. |
| `INJECTION_SCANNER_LAKERA_BACKOFF_BASE_S` | `30` | `[0, 3600]` | Breaker delay after the first consecutive throttle that carried no usable `Retry-After`. Doubles per consecutive failure. |
| `INJECTION_SCANNER_LAKERA_BACKOFF_MAX_S` | `600` | `[0, 86400]` | Cap on **every** breaker delay, a server-supplied `Retry-After` included. |
| `INJECTION_SCANNER_LAKERA_LOCK_WAIT_S` | `2` | `[0, 60]` | Bounded wait for the state-file lock before the call is refused. |
| `INJECTION_SCANNER_LAKERA_MAX_WAIT_S` | `0` | `[0, 86400]` | Default wait budget for `check()` when the caller passes none. `0` refuses immediately rather than parking a report. |
| `INJECTION_SCANNER_CACHE_DIR` | `~/.cache/injection-scanner` | — | State directory (`lakera-throttle.json` + `.lock`). Same directory the self-updater uses. |

The defaults are **provisional**. They encode today's best guess — the healthy pre-onset fleet averaged ~0.6 calls/min with zero failures, and a 15 s interval keeps the worst case (six panes plus CI) at ~4 calls/min. They are retuned from a measurement of Lakera's actual published limits by changing environment values, or these defaults in a follow-up commit — never by editing the algorithm.

Batch callers pass a wait budget instead of being refused: `scan(..., lakera_max_wait_s=900)`, `scan_text(..., lakera_max_wait_s=900)`, or `python -m injection_scanner.eval ... --lakera-max-wait 900` (which is already the eval default, because eval is always a batch caller).

### Two new reasons

Both are fixed literals from the closed reason vocabulary, both carry no data, and both are fail-closed exactly like every other `lakera_unavailable:*` — the report is rejected. Neither costs a network round trip.

| Reason | Meaning |
|---|---|
| `lakera_unavailable:throttled` | The fleet's budget is exhausted, or the breaker is open, and the caller's wait budget ran out. |
| `lakera_unavailable:limiter-error` | The limiter itself is unusable — unwritable cache directory, lock wait exceeded, IO error. Fail-closed on purpose: waving calls through when pacing breaks would restore the storm the limiter exists to stop. |

A 429 or 503 from Lakera opens the breaker for the whole fleet; any HTTP 200 closes it, flagged or not, because a 200 means the account is evidently not throttling us. `Retry-After` is server-supplied text: it is parsed into a number inside the limiter, clamped by `BACKOFF_MAX_S`, and the string itself is never stored, logged, or interpolated into a reason.

`python -m injection_scanner.eval` aborts on the first outage rather than scoring it — `INFRA <case-id> <reason>` on stderr, exit code `3` (distinct from `1` for a failed threshold and `2` for usage). `scan_text` fails closed, so a degraded layer agrees with every injection-labelled case; scoring it would report recall earned by an outage.

### CI: a hermetic merge gate, live checks on a schedule

Per-push CI calls no external service. `.github/workflows/ci.yml` runs only the deterministic suite on Python 3.12 and 3.13 — no Lakera, no Anthropic, no OpenAI, no secrets — so a pull request cannot go red because a vendor is down or throttled, and it works unchanged on a fork. Offline coverage does not shrink: `tests/test_judge.py` drives the real Anthropic/OpenAI SDKs over a stub transport (which is what caught the 1.x `temperature` signature break), and `tests/test_lakera.py` pins the Lakera response contract over the monkeypatched `_post` seam.

The live pipeline lives in `.github/workflows/live-eval.yml` and runs **nightly at 03:17 UTC and on demand**, never as a merge gate:

```bash
# check a detection-quality-sensitive PR before merging
gh workflow run live-eval.yml --ref <branch>
```

That dispatch is deliberately a human gesture, like the merge click. What moved off the gate is the sampled-model *benchmark* — recall and FP rate over the labelled corpus — which was never deterministic; **production's own boot smoke, which runs on every research-agent spawn and is agent-readable, remains the real-time canary for vendor drift**, and that is where such drift actually bites.

The relations inside `live-eval.yml` are asserted by `tests/test_ci_relations.py`, so a later edit cannot quietly undo them:

- One workflow-level concurrency group, `lakera-live`, with `cancel-in-progress: false` — at most one live run at a time, queued rather than dropped. Deliberately **not** keyed on the ref: a branch dispatch and the nightly on `main` draw on the same Lakera account, so they must queue rather than overlap.
- `eval` needs `smoke`. The 1-call smoke is the canary for the 16-call eval: a Lakera outage costs one call, not seventeen.
- Both jobs set `INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S=30` — stricter than the fleet's 15 s, because a runner's cache directory is fresh every run, so this limiter is a separate domain drawing on the same account. `eval` also passes `--lakera-max-wait 900`, so it queues for its turn instead of being refused mid-corpus.
- Both are time-bounded (10 and 30 minutes): a hanging job would hold `lakera-live` and block the next night's run.
- The guard test also asserts that `ci.yml` contains no `secrets.` reference anywhere — a negative over the whole file, so a job nobody anticipated cannot put a vendor call back on the merge gate.

Daily Lakera cost from CI falls from roughly 17 calls per push to 17 calls per day.
```

- [ ] **Step 6.3: Check the anchor and the tables render**

Run:
```bash
grep -n 'Lakera rate limiting\|lakera-rate-limiting\|live-eval\|^| L' README.md
```
Expected: the in-table link `[Lakera rate limiting](#lakera-rate-limiting)` on the L2 row, the `## Lakera rate limiting` heading, five layer rows `| L0 |`, `| L1b |`, `| L2 |`, `| L3 |`, `| L4 |`, and the `gh workflow run live-eval.yml --ref <branch>` line.

- [ ] **Step 6.4: Commit**

```bash
git -C ~/worktrees/injection-scanner-lakera-debounce add README.md
git -C ~/worktrees/injection-scanner-lakera-debounce commit \
  -m "docs: document the Lakera limiter, its inputs and the CI relations" \
  -m "A Lakera rate limiting section covering the environment table with
defaults and clamps, the two new fail-closed reasons, how a batch caller
asks to queue instead of being refused, and the CI split: a hermetic merge
gate, live checks nightly and on demand via gh workflow run, and
production's boot smoke as the real-time vendor canary. The defaults are
labelled provisional, with the measurement that would retune them named.

Also corrects a stale sentence: the layers table said L2 and L4 were
planned and not yet wired. Both have been wired for weeks, and the new
section documents rate limiting for a layer the same page called
unwired." \
  -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Task 7: final verification

**Files:** none modified.

- [ ] **Step 7.1: Run the mission verifier**

Run:
```bash
cd ~/worktrees/injection-scanner-lakera-debounce \
  && uv run --extra test python -m compileall -q injection_scanner tests \
  && env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/
```
Expected: `compileall` prints nothing, then a line of the shape `555 passed in <N>s`, exit code 0. The count must be ≥ 443 (the measured baseline) with zero failures; the exact total shifts if a step's parametrisation is adjusted, but **no test may fail and none may be removed**.

- [ ] **Step 7.2: Prove the suite really is key-free and network-free**

Run:
```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY -u LAKERA_API_KEY_FILE -u INJECTION_SCANNER_CACHE_DIR \
  uv run --extra test pytest -q tests/ 2>&1 | tail -3
```
Expected: the same `555 passed`. If a test now reaches the real `~/.cache/injection-scanner`, the autouse fixture in `tests/conftest.py` is not applying — fix the fixture, never the test.

- [ ] **Step 7.3: Confirm nothing outside the repository was touched, and that `tasks` is untracked**

Run:
```bash
git -C ~/worktrees/injection-scanner-lakera-debounce status --short
git -C ~/worktrees/injection-scanner-lakera-debounce log --oneline origin/main..HEAD
```
Expected: `status --short` empty (or showing only ignored artefacts, never `tasks`), and six commits listed — throttle, lakera, intercept, eval, ci, docs.

- [ ] **Step 7.4: Review the whole diff once, with fresh eyes**

Run:
```bash
git -C ~/worktrees/injection-scanner-lakera-debounce diff origin/main...HEAD --stat
```
Expected: exactly these paths, nothing else.

```
 .github/workflows/ci.yml         | modified
 .github/workflows/live-eval.yml  | new
 README.md                        | modified
 injection_scanner/eval.py        | modified
 injection_scanner/intercept.py   | modified
 injection_scanner/lakera.py      | modified
 injection_scanner/throttle.py    | new
 pyproject.toml                   | modified
 tests/conftest.py                | new
 tests/test_ci_relations.py       | new
 tests/test_eval.py               | modified
 tests/test_intercept.py          | modified
 tests/test_lakera.py             | modified
 tests/test_throttle.py           | new
```

- [ ] **Step 7.5: Walk the acceptance criteria against the tests that prove them**

| AC | What it demands | Proved by |
|---|---|---|
| **AC1** | `throttle.py` with `LimiterConfig`, `Decision`, `CrossProcessLimiter` (`from_env`, `acquire(max_wait_s)`, `record_success`, `record_throttled`) per spec §3.1–3.2; `tests/test_throttle.py` covers every §5 bullet incl. the 3-subprocess test; `tests/conftest.py` isolates `INJECTION_SCANNER_CACHE_DIR`. | `tests/test_throttle.py` — config: `test_from_env_uses_the_documented_defaults`, `test_malformed_env_values_fall_back_to_the_default`, `test_env_values_are_clamped_to_their_documented_ranges`, `test_the_cache_dir_env_var_selects_the_state_directory`. Bucket: `test_a_fresh_bucket_allows_the_first_call`, `test_refill_is_fractional_and_never_exceeds_burst`, `test_a_zero_wait_budget_refuses_immediately`, `test_a_wait_budget_shorter_than_the_gap_refuses_without_waiting`, `test_a_positive_wait_budget_sleeps_until_a_token_arrives`, `test_zero_min_interval_disables_the_bucket_but_not_the_breaker`, `test_a_backwards_clock_does_not_mint_tokens`. Breaker: `test_a_numeric_retry_after_is_honoured_and_spends_no_token`, `test_an_http_date_retry_after_is_honoured`, `test_an_unusable_retry_after_falls_back_to_the_base_backoff`, `test_consecutive_failures_double_the_delay_and_cap_it`, `test_a_retry_after_above_the_cap_is_clamped`, `test_record_success_closes_the_breaker_and_resets_the_backoff`, `test_the_breaker_half_opens_and_a_further_throttle_reopens_it_longer`. Durability: `test_an_unusable_state_file_is_a_reset_not_an_error`, `test_an_unusable_state_directory_is_an_error_and_never_raises`, `test_a_lock_held_past_the_wait_budget_is_an_error`, `test_a_zero_lock_wait_budget_is_an_error_when_the_lock_is_held`, `test_the_state_file_is_written_atomically`. Cross-process: `test_the_budget_is_shared_across_processes`. Isolation: `tests/conftest.py::_isolated_limiter_state` (autouse). |
| **AC2** | `lakera.check(text, *, max_wait_s=None)` per §3.3: key first; the two new reasons; 429/503 → `record_throttled(Retry-After)`; 200 → `record_success`; hostile header reaches neither reason nor state file. | `tests/test_lakera.py` — `test_an_empty_bucket_rejects_without_calling_lakera`, `test_a_broken_limiter_rejects_and_never_calls_lakera`, `test_a_call_that_cannot_happen_spends_no_token` (no-key + key-config-error), `test_only_429_and_503_open_the_breaker` (429/503/500/401), `test_a_hostile_retry_after_reaches_neither_the_reason_nor_the_state`, `test_a_flagged_two_hundred_still_closes_the_breaker`, `test_the_max_wait_keyword_reaches_the_limiter`, `test_an_absent_max_wait_falls_back_to_the_environment`, `test_the_raw_retry_after_header_is_handed_to_the_limiter_verbatim`, `test_a_missing_retry_after_header_is_none_not_a_crash`, `test_a_non_http_failure_leaves_the_breaker_alone`, `test_a_rebound_status_code_cannot_decide_to_stop_the_fleet`, `test_scan_text_surfaces_the_throttled_reason_and_fails_closed`. |
| **AC3** | `scan` / `scan_text` accept `lakera_max_wait_s=None` and pass it on. | `tests/test_intercept.py` — `test_lakera_max_wait_s_reaches_the_lakera_layer` (both the value and the `None` default), `test_scan_forwards_lakera_max_wait_s_from_the_disk_entry_point`. |
| **AC4** | `--lakera-max-wait` (default 900) plumbed to `scan_text`; `_is_infra_reason` (head-anchored closed rule); `EvalInfraError`; `INFRA <id> <reason>` on stderr, exit 3, no further scans. | `tests/test_eval.py` — `test_outages_are_recognised_as_infra` (13 cases), `test_classifications_and_junk_are_not_infra` (15 cases incl. `secret_shape:thing_unavailable`), `test_an_infra_verdict_aborts_before_the_next_case`, `test_a_wrapped_honeypot_outage_also_aborts`, `test_a_detection_that_merely_ends_in_the_suffix_still_scores`, `test_a_normal_run_is_unchanged`, `test_evaluate_forwards_the_wait_budget`, `test_the_cli_defaults_the_wait_budget_to_fifteen_minutes`, `test_the_cli_reports_infra_on_stderr_and_exits_three`, `test_an_outage_can_no_longer_earn_recall`. |
| **AC5** | `ci.yml` + `live-eval.yml` per §3.6 (hermetic gate; live checks nightly/dispatch, serialised on `lakera-live`, smoke gating eval, paced, time-bounded); `tests/test_ci_relations.py` guard; `pyyaml` in the `test` extra. | `tests/test_ci_relations.py` — gate: `test_ci_still_triggers_on_pushes_and_pull_requests`, `test_ci_runs_only_the_deterministic_test_job`, `test_ci_references_no_secret_at_all`, `test_ci_cancels_superseded_pull_request_runs`. Live: `test_the_live_pipeline_is_never_a_merge_gate`, `test_the_live_pipeline_serialises_on_the_shared_account`, `test_the_one_call_smoke_gates_the_sixteen_call_eval`, `test_both_live_jobs_pace_themselves`, `test_the_eval_job_waits_for_its_turn_instead_of_being_refused`, `test_both_live_jobs_are_time_bounded`. `pyproject.toml` `[project.optional-dependencies].test` carries `pyyaml>=6,<7`. |
| **AC6** | README "Lakera rate limiting" section per §3.7. | `README.md` — the section added in Task 6: env table, the two new reasons, the CI split (hermetic gate, nightly/`workflow_dispatch` live checks, production's boot smoke as the real-time canary), and the provisional-defaults note. Checked by Step 6.3. |
| **AC7** | Verifier green in the worktree, key-free, no network; every new test deterministic. | Steps 7.1 and 7.2. Determinism by construction: the limiter's clock and sleep are constructor keywords (`tests/test_throttle.py::_Fake`), `lakera._post` is monkeypatched in every Lakera test, `scan_text` is stubbed in every eval test, and the only real subprocesses are the three in `test_the_budget_is_shared_across_processes`, which touch no network. |
| **AC8** | Close-out: `advice-refine-test-loop` to zero BLOCKER/HIGH, push, PR with `--body-file`, `dod-check` DONE. | **Out of this plan's scope** — it is the orchestrating session's step, run after Task 7. Do not start it from inside a task. |

- [ ] **Step 7.6: Commit nothing**

This task changes no files. If `git status --short` is non-empty at the end of Step 7.3, something in Tasks 1–6 was left uncommitted — go back and commit it under the task it belongs to rather than adding a seventh commit here.

---

## Self-review

**1. Spec coverage.** Every section of `docs/superpowers/specs/2026-09-05-lakera-debounce-design.md` maps to a task:

| Spec § | Task |
|---|---|
| §3.1 `CrossProcessLimiter` (bucket, breaker, lock, state file, `acquire` algorithm, `record_*`, error semantics, aggregate guarantee) | Task 1, Step 1.5 |
| §3.2 Configuration table, clamps, no feature flag, provisional defaults | Task 1, Steps 1.3/1.5 (`LimiterConfig.from_env`, the range constants) + Task 6 (the README table) |
| §3.3 `lakera.py` integration (key first, `acquire`, the two reasons, 429/503 → `record_throttled`, 200 → `record_success`) | Task 2 |
| §3.4 `intercept.py` plumbing | Task 3 |
| §3.5 `eval.py` (`--lakera-max-wait`, `_is_infra_reason`, `EvalInfraError`, exit 3) | Task 4 |
| §2 goal 3 (per-push CI makes no external calls; live checks nightly + dispatch, never overlapping, smoke gating eval) | Task 5 |
| §3.6 hermetic `ci.yml` + new `live-eval.yml` | Task 5 |
| §3.7 README | Task 6 |
| §4 Failure semantics table (all 9 rows) | Rows 1–4 → Task 1 tests; rows 5–7 → Task 2 tests; row 8 (clock step) → Task 1 `test_a_backwards_clock_does_not_mint_tokens`; row 9 (hostile `Retry-After`) → Task 1 parametrised header test + Task 2 state-file test; row 10 (eval infra) → Task 4 |
| §5 Testing (every bullet) | Tasks 1–5 as listed in the AC table above |
| §6 Rollout | Out of scope for this repository's PR; steps 2 and 3 belong to research-agent and to the post-measurement retune |
| §7 Decisions taken by discernment, incl. "Live checks leave the merge gate" | Preserved in the module, workflow and README prose; the CI split is Task 5 |

**2. Placeholder scan.** No "TBD", no "similar to Task N", no "add error handling", no "write tests for the above". Every code step carries the full text to write, every run step an exact command and an expected result. The only cross-task reference is the AC table in Step 7.5, which is an index, not an instruction.

**3. Type and name consistency.** Checked across tasks:

- `LimiterConfig(min_interval_s, burst, backoff_base_s, backoff_max_s, lock_wait_s)` — same five fields and same order in the module (Step 1.5), the `_limiter` helper (Step 1.3), `test_an_unusable_state_directory_is_an_error_and_never_raises` (Step 1.9) and `test_a_flagged_two_hundred_still_closes_the_breaker` (Step 2.1).
- `Decision.ALLOWED / THROTTLED / ERROR` — one spelling everywhere.
- `CrossProcessLimiter.state_path` / `.lock_path` / `.config` are properties on the class (Step 1.5) and are the ones the tests read (Steps 1.3, 1.7–1.10).
- `throttle.cache_dir()` and `throttle.default_max_wait_s()` are module-level functions, used by `lakera.check` (Step 2.5) and asserted in Steps 1.3 and 2.1.
- `lakera.check(text, *, max_wait_s=None)` — keyword-only, matching `intercept`'s call (Step 3.3), the spies in Step 2.1 and the stubs in Step 3.4.
- `scan_text(raw, use_honeypot, use_lakera, lakera_max_wait_s)` — the same four names in `intercept` (Step 3.3), in `evaluate`'s call (Step 4.4) and in every eval stub (Steps 4.1).
- `EvalInfraError(case_id, reason)` with attributes `.case_id` / `.reason` — raised in `evaluate` (Step 4.4), read in `_main` (Step 4.5) and asserted in Step 4.1.
- `_is_infra_reason` / `_infra_segments` / `_INFRA_REASON_HEAD_SUFFIX` / `_INFRA_WRAPPER_PREFIXES` / `_INFRA_BARE_REASONS` — identical names and values to `~/Repos/research-agent/mcp_server/server.py:1751-1888`.
- Reason literals appear exactly twice each, once in `lakera.py` and once per assertion: `lakera_unavailable:throttled`, `lakera_unavailable:limiter-error`.
- State-file JSON keys — `schema`, `tokens`, `updated_at`, `open_until`, `failures` — written in `_save` (Step 1.5) and read by `_state` / `_open_for` (Step 1.3) and the Task 2 assertions.

**4. Fixed inline during review.**

- Step 1.7's `test_a_wait_budget_shorter_than_the_gap_refuses_without_waiting` originally asserted `fake.sleeps == [1.0, 1.0, 1.0]`. Traced through `acquire`: with a 10 s gap and a 3 s budget the deadline check fires on the FIRST pass, so no sleep happens at all. Corrected to `== []`, which is also the stronger statement.
- Step 1.9's lock-timeout assertion originally pinned `len(fake.sleeps) == 40`. At an epoch near 1.7e9 the float ulp is ~2.4e-7, so forty additions of 0.05 accumulate enough error to land on either side of the deadline. Replaced with `set(fake.sleeps) == {0.05}` plus `abs(sum(...) - 2.0) < 0.1`, which pins the retry interval and the budget without depending on float luck.
- Task 1 originally had the conftest set only `INJECTION_SCANNER_CACHE_DIR`. Traced the existing suite against the production defaults: `tests/test_lakera.py::test_throttling_is_distinguishable_from_an_expired_key` makes three `check()` calls in one test (the third would be `THROTTLED` at `burst=2`) and its first call raises a 429 (which would open the breaker over the 401 and 503 that follow). Added `MIN_INTERVAL_S=0` and `BACKOFF_MAX_S=0` — the spec's own documented "off" configuration — and made that D1.
- Task 3 originally passed `max_wait_s` conditionally to keep the three one-argument `lakera.check` stubs in `tests/test_intercept.py` working. That hides a real signature change behind a branch and leaves the keyword path untested on the common route. Changed to an unconditional keyword plus explicit stub edits, recorded as D12.
- **Task 5 was rewritten on 2026-09-06** after the maintainer added "ci tests should not call external services in general, smell. Sceptical of calling lakera/honeypots in ci" and spec §3.6 was rewritten to match. The first version paced and serialised the Lakera jobs *inside* `ci.yml`; that is now split into a hermetic `ci.yml` (no vendor call, no secret, no fork guard) plus a new `live-eval.yml` on `schedule` + `workflow_dispatch`. The guard test changed shape with it: `test_every_job_that_touches_lakera_is_in_that_group` — which enumerated jobs holding `LAKERA_API_KEY` — was replaced by `test_ci_references_no_secret_at_all`, a negative over the whole gate file, because the property being defended is now "no vendor on the gate" rather than "every vendor job is grouped". D15, D16, D19 and D20 were rewritten or added; Task 6's CI paragraph and Task 7's AC5/AC6 rows and diff-stat follow. Tasks 1–4 and 7's other rows are untouched: nothing in the limiter, `lakera.py`, `intercept.py` or `eval.py` depends on which workflow calls it.

---

## Known spec / code discrepancies, and how this plan resolves them

1. **`run_eval` / `main` do not exist.** Spec §3.5 and mission AC4 name `run_eval(...)` and `main()`. `injection_scanner/eval.py` defines `evaluate(...)` (line 240) and `_main(argv)` (line 371), and `tests/test_eval.py:16-25` imports those. The plan implements `evaluate` and `_main` (D13). Line numbers also differ: the scan loop is at `:282-313`, not `~270-300`.
2. **`record_success` placement.** §3.1 says "called on any HTTP 200, flagged or not"; §3.3 step 4 lists three named outcomes and omits `bad-response`. The plan calls it once, immediately after `_post` returns — the superset §3.1 describes, with one call site a future parse branch cannot forget (D9).
3. **`min_interval_s=1e6` in §5 is unreachable.** §3.2 clamps the interval to `[0, 3600]`, so the cross-process test's `1e6` is silently 3600. The plan writes `3600` (D7).
4. **§3.4's "no other behaviour change" costs three test edits.** Always passing `max_wait_s=` breaks the one-argument `lakera.check` stubs at `tests/test_intercept.py:210, 263, 283`. Production behaviour is unchanged; the stubs gain `**_kw` (D12).
5. **`acquire`'s error catch is widened.** §3.1 says `OSError`/`ValueError` yield `ERROR`. `intercept.scan_text:323` does not wrap `lakera.check`, so anything else escaping `acquire` would abort the scan rather than reject the report. The plan catches `Exception` — a superset that can only add fail-closed refusals (D3).
6. **The README contradicts itself once the section lands.** `README.md:13` says L2 and L4 are "planned, not yet wired"; both are wired (`intercept.py:322`, `:423`). Corrected in Task 6 (D18).
7. **Spec §3.6 was rewritten mid-plan (2026-09-06).** The version this plan was first written against paced the Lakera jobs inside `ci.yml`; the current one splits them into a hermetic `ci.yml` plus a scheduled `live-eval.yml`. Task 5 implements the CURRENT §3.6. Two details the spec leaves as `...` in its YAML sketch are settled here: the job bodies are the ones deleted from `ci.yml`, verbatim minus the fork guards (there are no fork events on `schedule`/`workflow_dispatch` to guard against), and `INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S` sits at job level on both jobs (D15) rather than on the eval step, which is where the pre-rewrite plan had put it.
