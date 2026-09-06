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
import tempfile
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

    # The numbers Lakera's own published limit implies, not a guess. Community
    # plan: 10,000 requests/month = 13.9/hour = one every 4.3 minutes. 300 s
    # sustained is 12/hour, just under it; burst 10 lets a multi-pane session
    # restore through; the breaker waits MINUTES because recovery from the
    # 2026-09-05 throttle took tens of them. See the constants in throttle.py.
    assert LimiterConfig.from_env() == LimiterConfig(
        min_interval_s=300.0,
        burst=10,
        backoff_base_s=300.0,
        backoff_max_s=3600.0,
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
        min_interval_s=300.0,
        burst=10,
        backoff_base_s=300.0,
        backoff_max_s=3600.0,
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


def test_a_tilde_in_the_cache_dir_is_expanded(monkeypatch):
    """`~` is shell syntax, not path syntax.

    An operator exporting the documented default by hand writes
    `~/.cache/injection-scanner`, and a bare `Path()` would make a literal
    directory NAMED `~` under the cwd — a private budget nobody shares and
    nobody finds.
    """
    monkeypatch.setenv("INJECTION_SCANNER_CACHE_DIR", "~/.cache/injection-scanner")
    assert throttle.cache_dir() == Path.home() / ".cache" / "injection-scanner"


@pytest.mark.parametrize("raw", ["state", "./state", "../state", "~nosuchuser/x"])
def test_a_non_absolute_cache_dir_falls_back_to_the_default(monkeypatch, raw):
    """A relative directory splits the fleet into one budget per cwd.

    That is the failure this whole module exists to prevent, and it would
    happen SILENTLY: every process would find its own full bucket and pace
    itself perfectly against nobody. A path that cannot name the same
    directory from every process is a misconfiguration, and degrades to the
    default exactly as an out-of-range number degrades to its clamp.
    """
    monkeypatch.setenv("INJECTION_SCANNER_CACHE_DIR", raw)
    assert throttle.cache_dir() == Path.home() / ".cache" / "injection-scanner"


def test_a_host_with_no_home_directory_still_gets_a_state_directory(monkeypatch):
    """`cache_dir()` is TOTAL, and `Path.home()` is the part that isn't.

    `Path.home()` raises RuntimeError when `HOME` is unset AND the uid has no
    passwd entry — the ordinary state of a scratch container or anything
    started with `docker run --user 1234`. `cache_dir()` is reached from
    `from_env()`, which `lakera.check` calls outside `acquire`'s own guard, so
    a raise here would abort the scan rather than fail it closed. The fallback
    is absolute (a relative one would give every process its own private
    budget) and per-uid (a shared `/tmp` path would be another user's file).
    """
    monkeypatch.delenv(throttle.ENV_CACHE_DIR, raising=False)
    monkeypatch.delenv("HOME", raising=False)

    def _no_home(*_a, **_kw):
        raise RuntimeError("Could not determine home directory.")

    monkeypatch.setattr(Path, "home", _no_home)

    got = throttle.cache_dir()
    assert got == Path(tempfile.gettempdir()) / f"injection-scanner-{os.getuid()}"
    assert got.is_absolute()


def test_an_unresolvable_tilde_with_no_home_falls_back_rather_than_raising(monkeypatch):
    """The same totality, reached the other way round.

    `~nosuchuser` makes `expanduser()` raise, which degrades to the default
    branch — and on a host with no home directory that branch raises too.
    Neither may escape.
    """
    monkeypatch.setenv(throttle.ENV_CACHE_DIR, "~nosuchuser/x")
    monkeypatch.delenv("HOME", raising=False)

    def _no_home(*_a, **_kw):
        raise RuntimeError("Could not determine home directory.")

    monkeypatch.setattr(Path, "home", _no_home)

    got = throttle.cache_dir()
    assert got == Path(tempfile.gettempdir()) / f"injection-scanner-{os.getuid()}"


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


def test_a_backwards_clock_neither_mints_tokens_nor_confiscates_them(tmp_path):
    """An NTP step or a VM resume must leave the budget exactly as it was.

    `burst >= 2` is what makes this discriminating, and the reason this test
    is written the way it is. With `burst=1` the balance is empty whenever
    the clock moves, so dropping the `max(0.0, ...)` around `elapsed` in
    `_attempt` produced a limiter that re-crossed one token at the very same
    instant as the correct one, and the test passed either way. With a
    PARTLY FULL bucket the two diverge on the first call after the step: a
    negative elapsed subtracts a debt from a balance that was about to be
    spent, and tokens the fleet has already paid for silently vanish.
    """
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=10.0, burst=3)
    assert lim.acquire() is Decision.ALLOWED    # 3.0 -> 2.0

    fake.now -= 100.0                           # ten intervals backwards
    # Confiscates nothing: elapsed clamps to 0, so the balance is still 2.0
    # rather than 2.0 - 10.0. Both remaining tokens are still spendable.
    assert lim.acquire() is Decision.ALLOWED    # 2.0 -> 1.0
    assert lim.acquire() is Decision.ALLOWED    # 1.0 -> 0.0
    assert lim.acquire() is Decision.THROTTLED

    # ...and mints nothing either: measured from the stepped-back instant,
    # one interval buys exactly one token, not the eleven the step spans.
    fake.now += 10.0
    assert lim.acquire() is Decision.ALLOWED
    assert lim.acquire() is Decision.THROTTLED, "one interval buys one token"


# ---------- the circuit breaker ----------

def test_a_numeric_retry_after_is_honoured_and_spends_no_token(tmp_path):
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=10.0, burst=5)
    assert lim.acquire() is Decision.ALLOWED

    lim.record_throttled("30")
    tokens_before = _state(lim)["tokens"]

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


def test_the_breaker_half_opens_with_one_probe_not_a_herd(tmp_path):
    """At the DEFAULT burst, exactly one call goes out when the breaker closes.

    A bucket that refills through the outage is what turns a recovery into a
    stampede: ten tokens are sitting ready the instant `open_until` passes,
    and the fleet answers a server that has only just stopped refusing with
    ten simultaneous calls — the herd that re-trips the breaker and earns the
    next, longer backoff. Two rules prevent it: a throttle caps the bucket at
    a single token, and time spent shut does not refill it.

    Written at `burst=10` on purpose. The earlier version of this test used
    `burst=1`, where the bucket cannot hold a herd in the first place, so it
    demonstrated half-open behaviour that said nothing about the
    configuration anybody actually runs.
    """
    fake = _Fake()
    lim = _limiter(
        tmp_path, fake, min_interval_s=300.0, burst=10,
        backoff_base_s=300.0, backoff_max_s=3600.0,
    )
    assert lim.acquire() is Decision.ALLOWED       # a full bucket: 10 -> 9

    lim.record_throttled(None)                     # shut for 300 s
    assert lim.acquire() is Decision.THROTTLED

    fake.now += 301.0
    assert lim.acquire() is Decision.ALLOWED, "half-open: one probe gets out"
    assert lim.acquire() is Decision.THROTTLED, "...and exactly one, not ten"

    # The probe was refused too: the breaker reopens for longer, and the
    # bucket that probe drained is what paces the next one.
    lim.record_throttled(None)
    assert _open_for(lim, fake) == 600.0
    fake.now += 601.0
    assert lim.acquire() is Decision.THROTTLED, "no tokens banked while shut"
    fake.now += 300.0
    assert lim.acquire() is Decision.ALLOWED, "one interval buys the next probe"


def test_normal_refill_resumes_once_a_success_closes_the_breaker(tmp_path):
    """Suppressing refill while shut is pacing for the outage, not a penalty
    after it. Once a call succeeds the bucket fills at exactly the configured
    rate again, measured from the moment the breaker closed, and climbs all
    the way back to `burst`."""
    fake = _Fake()
    lim = _limiter(
        tmp_path, fake, min_interval_s=300.0, burst=10,
        backoff_base_s=300.0, backoff_max_s=3600.0,
    )
    lim.record_throttled(None)
    assert lim.acquire() is Decision.THROTTLED
    lim.record_success()                           # the probe got through

    assert lim.acquire() is Decision.ALLOWED       # the capped token, spent
    assert lim.acquire() is Decision.THROTTLED
    fake.now += 300.0
    assert lim.acquire() is Decision.ALLOWED, "one interval, one token"
    assert lim.acquire() is Decision.THROTTLED

    fake.now += 3000.0                             # ten intervals: back to full
    for _ in range(10):
        assert lim.acquire() is Decision.ALLOWED
    assert lim.acquire() is Decision.THROTTLED, "and no further than burst"


def test_a_breaker_parked_beyond_the_cap_reopens_on_its_own(tmp_path):
    """`backoff_max_s` has to bound the delays this module OBEYS, not only the
    ones it writes.

    `open_until` is an absolute wall-clock instant, written by whichever
    process saw the 429 and read later by processes that did not exist then.
    A clock that steps BACKWARDS — an NTP correction, a VM resume, a laptop
    waking in another timezone-confused state — leaves that instant sitting
    arbitrarily far in the future, and nothing recovers from it: no call is
    ever made, so no 200 ever arrives, so `record_success` can never fire to
    clear it. The fleet would stay shut until someone deleted the file by
    hand. Clamping on the way IN is what makes the cap self-healing, and it
    is a no-op for every value this module legitimately writes.
    """
    fake = _Fake()
    lim = _limiter(
        tmp_path, fake, min_interval_s=0.0, burst=1, backoff_max_s=600.0
    )
    lim.state_path.parent.mkdir(parents=True, exist_ok=True)
    lim.state_path.write_text(
        json.dumps(
            {
                "schema": 1,
                "tokens": 0.0,
                "updated_at": fake.now,
                "open_until": fake.now + 30 * 86400.0,   # thirty days out
                "failures": 1,
            }
        ),
        encoding="utf-8",
    )

    assert lim.acquire() is Decision.THROTTLED
    fake.now += 599.0
    assert lim.acquire() is Decision.THROTTLED
    fake.now += 2.0
    assert lim.acquire() is Decision.ALLOWED, "capped at backoff_max_s, not 30 d"


def test_a_shorter_retry_after_never_shrinks_an_already_open_breaker(tmp_path):
    """`open_until = max(open_until, now + delay)`, never plain assignment.

    Concurrent callers land out of order: several processes can be in flight
    when Lakera starts refusing, and the one that arrives second may carry a
    much shorter `Retry-After` than the one that arrived first. Assignment
    would let that straggler REOPEN the fleet ten minutes early and walk it
    straight back into the throttle — the breaker may only ever be extended
    by a throttle, and only `record_success` shortens it.
    """
    fake = _Fake()
    lim = _limiter(
        tmp_path, fake, min_interval_s=0.0, burst=1, backoff_max_s=3600.0
    )
    lim.record_throttled("600")
    assert _open_for(lim, fake) == 600.0

    lim.record_throttled("5")
    assert _open_for(lim, fake) == 600.0, "a shorter header must not shrink it"

    fake.now += 100.0
    assert lim.acquire() is Decision.THROTTLED, (
        "still shut at now+100: the 600 s decision stands"
    )


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
        '{"schema": 1, "tokens": 0.0, "updated_at": 0.0, '
        '"open_until": NaN, "failures": 0}',
        '{"schema": 1, "tokens": 0.0, "updated_at": 0.0, '
        '"open_until": Infinity, "failures": 0}',
    ],
    ids=[
        "empty", "truncated", "null", "array", "garbage",
        "foreign-schema", "wrong-type", "nan-tokens",
        "nan-open-until", "inf-open-until",
    ],
)
def test_an_unusable_state_file_is_a_reset_not_an_error(tmp_path, blob):
    """A torn file after a crash must not brick every scanner on the box.

    Every case asserts the WHOLE reset state, not merely that the call went
    through, because each field is discarded for its own reason and a test
    that only watches the `Decision` misses most of them.

    `json.loads` accepts bare `NaN` and `Infinity`, and the two hide from
    arithmetic in opposite directions: `now < NaN` is False, so a NaN breaker
    reads as permanently CLOSED, while `Infinity` reads as one that never
    reopens. Neither is caught by any `min()`/`max()` downstream — only by the
    explicit `math.isfinite` check in `_load` — so the non-finite value is
    placed in `open_until`, where no later clamp can launder it. Putting it in
    `tokens` instead is not a real test of that check: `min(burst, NaN)`
    happens to return `burst`, and the refill rescues the file by accident.

    The foreign-schema case carries an `open_until` far in the future AND
    `failures: 7` on purpose: a breaker this limiter cannot read must be able
    neither to park it nor to hand it a backoff it never earned.
    """
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=10.0, burst=3)
    lim.state_path.parent.mkdir(parents=True, exist_ok=True)
    lim.state_path.write_text(blob, encoding="utf-8")

    assert lim.acquire() is Decision.ALLOWED
    st = _state(lim)
    assert st["schema"] == 1
    # A full bucket less the one call just spent — not the corrupt balance.
    assert st["tokens"] == 2.0
    assert st["open_until"] == 0.0, "a breaker that cannot be read is CLOSED"
    assert st["failures"] == 0


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


def test_the_state_file_is_written_atomically(tmp_path, monkeypatch):
    """`.tmp` + `os.replace`, so no reader ever sees a half-written bucket.

    Asserting only "no leftover `.tmp`" is not a test of atomicity: a plain
    `state_path.write_text(...)` satisfies it perfectly, and that is exactly
    the implementation this test exists to rule out. So the replace itself is
    observed — that it happened at all, that its source is the `.tmp` sibling
    and its destination the state file.
    """
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=10.0, burst=2)

    seen: list[tuple[Path, Path]] = []
    real_replace = os.replace

    def recording_replace(src, dst, *args, **kwargs):
        seen.append((Path(src), Path(dst)))
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(throttle.os, "replace", recording_replace)
    assert lim.acquire() is Decision.ALLOWED

    assert seen, "the state was written without going through os.replace"
    src, dst = seen[-1]
    assert dst == lim.state_path
    assert src == lim.state_path.parent / (lim.state_path.name + ".tmp")
    assert lim.state_path.exists()
    leftovers = list(lim.state_path.parent.glob("*.tmp"))
    assert leftovers == [], f"temp file not replaced: {leftovers}"


def test_a_failed_write_leaves_the_previous_state_intact(tmp_path, monkeypatch):
    """The whole point of the temp file: a write that dies costs the UPDATE,
    never the state that was already on disk.

    Writing in place would truncate the file first and leave a reader — or
    the next process to start — with an empty bucket and a closed breaker,
    which is precisely the fleet-wide amnesia the limiter exists to prevent.
    """
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=10.0, burst=2)
    assert lim.acquire() is Decision.ALLOWED
    before = lim.state_path.read_bytes()

    def failing_replace(src, dst, *args, **kwargs):
        raise OSError("no space left on device")

    monkeypatch.setattr(throttle.os, "replace", failing_replace)

    # Fail-closed rather than raising, and the recorders swallow their own.
    assert lim.acquire() is Decision.ERROR
    lim.record_throttled("30")
    lim.record_success()

    assert lim.state_path.read_bytes() == before, (
        "a failed write must not damage the state that was already there"
    )


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
    try:
        for p in procs:
            out, err = p.communicate(timeout=60)
            assert p.returncode == 0, f"child failed: {err}"
            results.append(int(out.strip()))
    finally:
        # A child wedged on the flock (or on a loaded runner) must not be left
        # behind holding the lock: every later test in this file would then
        # time out too, and the failure would be reported against whichever
        # one ran next rather than against this one.
        for p in procs:
            if p.poll() is None:
                p.kill()
                p.wait()

    assert sum(results) == 2, f"per-child allowances: {results}"
