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
