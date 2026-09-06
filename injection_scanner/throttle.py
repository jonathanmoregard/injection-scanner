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

A 429 or 503 opens the breaker and a 200 closes it — but NOT every 200. At the
default burst the OPENING calls of an outage are in flight together across the
fleet, so a call issued while Lakera was still answering can land after its
peers have already collected their 429s and shut the gate. Letting that
straggler reset the breaker would cancel a decision nine other processes just
made and walk the fleet straight back into the throttle it had correctly
detected. So the state carries `tripped_at`, `record_success` takes the moment
its own call was ISSUED, and a success older than the trip is ignored.
`lakera.check` reads that moment immediately after `acquire` returns, off the
same wall clock this module writes.

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
the PARSED value both when it is WRITTEN and again when state is READ back,
so neither an absurd header nor a wall clock that stepped backwards can park
the fleet for longer than one `backoff_max_s`.

There is NO on/off switch. "Off" is `min_interval_s=0` (bucket always full)
plus `backoff_max_s=0` (every breaker delay clamps to zero); the test suite
runs in exactly that configuration and nobody should want it in production. A
feature flag shipped defaulted-off is the failure mode the
`avoiding-unrequested-feature-flags` rule exists to prevent.

Every limit is an INPUT (`LimiterConfig.from_env`), never a constant fitted to
today's numbers. The defaults follow the ONE limit Lakera publishes (the
Community plan's 10,000 requests per month) and are retuned by changing env
values or these defaults when the dashboard shows a different tier — never by
editing the algorithm.
"""
from __future__ import annotations

import contextlib
import enum
import errno
import fcntl
import json
import math
import os
import stat
import tempfile
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
# Set from measurement on 2026-09-06, not from a guess (full findings in
# ~/.local/state/claude-tasks/research-agent/findings-lakera-limits.md).
#
# Lakera publishes exactly ONE limit: the Community plan's 10,000 requests per
# month. That is 13.9 per hour, one every 4.3 minutes — and it equals the
# trickle measured through the 2026-09-05 throttle ("one success per 4-5
# minutes fleet-wide regardless of attempt count"), which is what identifies
# the monthly quota, rather than some unpublished QPS ceiling, as the thing the
# fleet was hitting. Overnight, 25 calls in 30 minutes were accepted before
# ~40 minutes of 429s, so Lakera's own bucket is roughly 25-50 deep with a slow
# refill.
#
# The defaults sit UNDER that: 300 s sustained is 12 calls/hour against the
# quota's 13.9; a burst of 10 lets one multi-pane session restore through
# without being refused; and the breaker waits MINUTES rather than seconds
# because recovery was observed to take tens of minutes, so a 30 s retry would
# simply re-spend the budget on 429s. For scale: research-agent boot smokes
# alone ran ~632 per day before the liveness cache in smoke.py (~19k/month,
# about twice the entire quota) — spawn frequency, not scan volume, is what
# exhausts this account.
#
# The plan tier is visible only on the Lakera dashboard. On a paid tier every
# knob loosens via env; the algorithm does not change.
#
# Each clamp is a RANGE, so a typo in an environment variable degrades to a
# sane limiter instead of either disabling the bucket or parking the fleet.

DEFAULT_MIN_INTERVAL_S = 300.0
DEFAULT_BURST = 10
DEFAULT_BACKOFF_BASE_S = 300.0
DEFAULT_BACKOFF_MAX_S = 3600.0
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

# A token is a whole call, so anything within this of one IS one.
#
# Refill is an ACCUMULATION under the lock — `tokens += elapsed /
# min_interval_s`, one read-modify-write per poll — so a waiter that naps ten
# times for a tenth of the interval lands on 0.9999999999999999, not 1.0.
# Compared against a bare `>= 1.0` that waiter then computes a residual gap of
# ~1e-15 s and sleeps for it; at today's timestamps one ULP of a float wall
# clock is ~2.4e-7 s, so the nap cannot move the clock and `acquire` spins
# until its budget runs out — measured as a hang under the injected clock in
# tests/test_throttle.py::test_a_positive_wait_budget_sleeps_until_a_token_arrives.
# 1e-9 of a token is 300 ns of budget at the default interval: dust, not a
# call, so this can never mint one. Paired with the `max(0.0, ...)` in
# `_attempt`, which keeps the subtraction from writing a negative balance.
_TOKEN_EPSILON = 1e-9

# `backoff_base_s * 2 ** (failures - 1)` raises OverflowError past ~1024
# consecutive failures. The product is clamped to `backoff_max_s` immediately
# afterwards, so capping the exponent changes no reachable outcome and removes
# the only arithmetic in here that can raise.
_MAX_BACKOFF_DOUBLINGS = 32


def _clamp_float(value: float, bounds: tuple[float, float]) -> float:
    lo, hi = bounds
    return min(max(value, lo), hi)


def env_float(name: str, default: float, bounds: tuple[float, float]) -> float:
    """A float from the environment: malformed -> default, then clamp.

    NaN is turned back explicitly. It parses fine, survives `min`/`max`
    unchanged on CPython, and would then make every comparison in `acquire`
    false — a limiter that neither allows nor refuses.

    PUBLIC because `smoke.py` parses `INJECTION_SCANNER_SMOKE_LIVENESS_TTL_S`
    with it. That knob is not a limiter setting, but it wants exactly this
    contract — "every limit is an input with a range", malformed to the
    default, NaN refused — and one audited implementation of it beats two.
    `_env_int` stays private; nothing outside this module needs it yet.
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

    The DEFAULT is the directory `selfupdate.py` defaults to as well, so an
    operator has one place to look and one place to clear. That is a shared
    default, not a shared setting: `selfupdate.py` takes its directory as a
    parameter and never reads this environment variable, so pointing
    `INJECTION_SCANNER_CACHE_DIR` elsewhere moves the limiter's state alone.

    Two ways an operator's value can fail to name one directory fleet-wide,
    both handled here rather than discovered later:

      * `~` is shell syntax, not path syntax. Unexpanded it becomes a literal
        directory NAMED `~` under whatever the cwd happens to be.
      * a RELATIVE path resolves per process, so every process finds its own
        full bucket and paces itself perfectly against nobody — silently
        recreating the exact failure this module exists to prevent.

    So the value is expanded, and anything still not absolute degrades to the
    default: a misconfigured directory falls back to a sane one, the same way
    an out-of-range number falls back to its clamp.

    TOTAL by contract. `expanduser()` RAISES on a `~user` it cannot resolve,
    and this runs inside `from_env()`, which callers reach outside
    `acquire`'s try/except — an escaping exception there would abort the whole
    scan instead of failing it closed.

    That contract is why the WHOLE body is guarded and not just the
    `expanduser()` call. `Path.home()` raises `RuntimeError` too, whenever
    `HOME` is unset AND the uid has no `/etc/passwd` entry — the ordinary
    state of a scratch container, a `docker run --user 1234`, and some CI
    runners. There is no home directory to name in that case, so the fallback
    is a per-uid directory under the system temp dir: ABSOLUTE, because a
    relative path gives every process its own private budget and silently
    recreates the storm this module exists to stop; and PER-UID, because a
    fixed name under a world-writable `/tmp` would collide with (or be
    unwritable because of) another user's file. It is not durable across
    reboots, which costs one reset bucket — strictly better than a scan that
    aborts. Paired with `lakera.check`, which wraps the `from_env()` +
    `acquire()` pair so even a failure here fails the report closed rather
    than crashing the scan.

    The per-uid NAME does not by itself make the directory private — anyone
    can create it first under a world-writable temp dir — so ownership is
    verified before every use, in `_require_own_directory`.
    """
    try:
        raw = os.environ.get(ENV_CACHE_DIR)
        if raw:
            try:
                path = Path(raw).expanduser()
            except (RuntimeError, OSError, ValueError):
                path = Path(raw)
            if path.is_absolute():
                return path
        return Path.home() / ".cache" / "injection-scanner"
    except Exception:  # noqa: BLE001 — TOTAL by contract; see the docstring
        return Path(tempfile.gettempdir()) / f"injection-scanner-{os.getuid()}"


def default_max_wait_s() -> float:
    """`acquire`'s wait budget when the caller does not name one.

    Default 0: an interactive scan refuses immediately rather than parking a
    report behind the fleet's budget. Batch callers (`eval`) pass their own.
    """
    return env_float(ENV_MAX_WAIT_S, DEFAULT_MAX_WAIT_S, MAX_WAIT_RANGE)


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
    Applied on write and again on read, so it bounds the blast radius of a
    bad header AND of a stored instant a backwards clock left in the
    future — one knob, and no way to be shut for longer than it says."""

    lock_wait_s: float
    """Bounded wait for the flock before `acquire` gives up with `ERROR`."""

    @classmethod
    def from_env(cls) -> "LimiterConfig":
        return cls(
            min_interval_s=env_float(
                ENV_MIN_INTERVAL_S, DEFAULT_MIN_INTERVAL_S, MIN_INTERVAL_RANGE
            ),
            burst=_env_int(ENV_BURST, DEFAULT_BURST, BURST_RANGE),
            backoff_base_s=env_float(
                ENV_BACKOFF_BASE_S, DEFAULT_BACKOFF_BASE_S, BACKOFF_BASE_RANGE
            ),
            backoff_max_s=env_float(
                ENV_BACKOFF_MAX_S, DEFAULT_BACKOFF_MAX_S, BACKOFF_MAX_RANGE
            ),
            lock_wait_s=env_float(
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

    tripped_at: float
    """When the breaker was last opened or extended. `record_success`
    compares the moment ITS call was issued against this, so a straggler
    answered after the trip cannot clear a breaker it predates. 0.0 means
    never tripped, which makes every success on a healthy fleet count."""


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
        # Raises on anything it cannot read (it does not return None on
        # Python >= 3.10), which the surrounding `except` turns into `None`.
        parsed = parsedate_to_datetime(text)
        if parsed.tzinfo is None:
            # HTTP-dates are GMT by definition; a date without a zone is
            # malformed, but reading it as UTC is strictly better than
            # inheriting the local zone of whichever host happens to run this.
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0.0, parsed.timestamp() - now)
    except Exception:  # noqa: BLE001 — TOTAL by contract; see the docstring
        return None


def _require_own_directory(state_dir: Path) -> None:
    """Refuse a state directory this uid does not own.

    `mode=0o700` on `mkdir` applies only when THIS process creates the
    directory; `exist_ok=True` accepts whatever is already at the path. And the
    path is not always private: with no home directory the default falls back
    under the system temp dir, which is world-writable, so another user can get
    there first. Two shapes matter, and `lstat` catches both because it does
    not follow the link:

      * a SYMLINK, which redirects every state write to a directory of their
        choosing;
      * a directory owned by someone else (0777 or otherwise), which they can
        also write.

    Either turns the fleet's shared budget into an object a third party
    controls — they could hold the breaker open and deny the scanner, or keep
    it closed and restore the storm this module exists to stop. It is also the
    one place attacker-influenced state could re-enter the limiter, so the
    answer is to refuse, not to repair.

    Called from `file_lock`, so it guards EVERY user of the cache directory
    rather than the limiter alone. `smoke.py`'s liveness cache needs it just as
    much and for the same reason in the opposite direction: a planted
    `{"ok": true}` there would let a foreign file suppress the fleet's vendor
    probe. Both callers reach this inside a guard that renders a raise as their
    own safe default — the limiter's `ERROR` -> `limiter-error` fail-closed
    reject, the liveness cache's "miss, probe as before".

    Only the FINAL component is checked: a hostile ancestor is beyond what a
    cache path can defend against and belongs to whoever configured
    `INJECTION_SCANNER_CACHE_DIR`.
    """
    info = os.lstat(state_dir)
    if not stat.S_ISDIR(info.st_mode):
        raise NotADirectoryError("cache state path is not a real directory")
    if info.st_uid != os.getuid():
        raise PermissionError("cache state directory belongs to another user")


@contextlib.contextmanager
def file_lock(lock_path: Path, wait_s: float, *, clock=time.time, sleep=time.sleep):
    """Exclusive `flock` over `lock_path`, bounded by `wait_s`.

    The file is opened FRESH for every operation, so the lock also serialises
    threads inside one process: flock is associated with the open file
    description, and each `os.open` makes its own. flock is released by the
    kernel when the holder dies, so there are no stale locks to reap after a
    crash. The parent directory is created `0700` if it is missing, and is then
    refused unless this uid owns it (`_require_own_directory`).

    Two limits on that guarantee, both real and both accepted:

      * the lock lives on an INODE, not on a path. Deleting the lock file while
        a holder still has it open lets the next opener create a fresh inode
        and lock that instead, and the two then run concurrently believing they
        are exclusive. So a wipe of the cache directory is the one window in
        which exclusion is genuinely lost — and it is also the only way two
        processes can collide on the shared `.tmp` name in
        `atomic_write_json`. Clearing the directory is an operator action on
        state that is rebuilt on the next call, so the cost of losing that race
        is one reset bucket.
      * flock is advisory and is EMULATED on some filesystems. Over NFS it is
        mapped onto POSIX locks, and on some overlay and network mounts it
        degrades to a no-op. The cache directory is expected to be local disk;
        a fleet sharing it over NFS gets pacing that is best-effort rather than
        guaranteed.

    `LOCK_NB` plus a retry, rather than a blocking `LOCK_EX`, because the wait
    has to be BOUNDED: a wedged peer must degrade to a caught `TimeoutError`
    (which the limiter renders as a fail-closed reject, and the smoke liveness
    cache renders as a miss) rather than hanging a scan or a boot forever.

    Shared with `smoke.py`'s liveness cache, which keeps a different file in
    the same directory under the same discipline.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _require_own_directory(lock_path.parent)
    deadline = clock() + wait_s
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as e:
                if e.errno not in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                    raise
                if clock() >= deadline:
                    raise TimeoutError("lock wait exceeded") from None
                sleep(_LOCK_RETRY_SLEEP_S)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def atomic_write_json(path: Path, payload: dict) -> None:
    """Write `payload` to `path` via `<path>.tmp` + `os.replace`.

    The replace is atomic, so a reader without the lock — or a process killed
    mid-write — never sees a half-written file. Callers build `payload` by
    NAMING its fields, so a field added to some upstream structure tomorrow is
    invisible here until it is added on purpose.

    There is deliberately NO fsync: what this package keeps in the cache
    directory is a pacing hint (and a liveness hint) rebuilt on the next call,
    not a ledger, and paying a disk flush on every scan to protect it would be
    the wrong trade. The exposure is a power loss, after which the file may be
    torn or empty; every reader in this package treats that as unusable and
    falls back to its own safe default.

    The file is created 0o600 explicitly rather than inheriting whatever umask
    is in force, so it does not depend on this module having been the one to
    create the 0o700 directory around it.

    Shared with `smoke.py`'s liveness cache. Call it inside `file_lock`.
    """
    tmp = path.parent / (path.name + ".tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(payload))
    os.replace(tmp, path)


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

        Note what the `0.0` in the signature is and is not. It is this
        method's own default, NOT the value of
        `INJECTION_SCANNER_LAKERA_MAX_WAIT_S`: nothing here reads that
        variable, and it takes effect only where a caller threads
        `default_max_wait_s()` through — which `lakera.check` does for callers
        that name no budget of their own. Calling `acquire()` bare therefore
        ignores the operator's configured wait, deliberately, so that a
        caller which has not thought about waiting never blocks by accident.

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

    def record_success(self, started_at: float) -> None:
        """Called on any HTTP 200, flagged or not, by the caller that got it.

        A 200 means the account is evidently not throttling us, so the breaker
        closes and the consecutive-failure count resets — provided this call
        can actually vouch for the present. `started_at` is the wall-clock
        instant the call was ISSUED (the caller reads the clock right after
        `acquire` returns `ALLOWED`), and a success that STARTED before the
        breaker tripped is discarded.

        Without that rule one straggler undoes the fleet's whole decision. At
        the default burst ten processes call at once; when Lakera turns, their
        429s arrive and shut the gate while an earlier call is still in
        flight, and its 200 — describing a Lakera that no longer exists —
        would reset `failures` and `open_until` outright. Measured on the
        pre-fix code: seven `record_throttled` calls (failures=7, shut for
        3600 s) followed by one stale `record_success` left failures=0 and the
        gate wide open. Pinned by
        tests/test_throttle.py::test_a_success_issued_before_the_trip_does_not_close_the_breaker
        and its `_after_` twin, which keeps the half-open probe working.

        Swallows its own errors: if the state cannot be written, the next
        `acquire` fails the same way and refuses.
        """
        try:
            # Same coercion `acquire` applies to its budget, and the fallback
            # points the same way: an unusable timestamp reads as the epoch,
            # i.e. older than any trip, so it is DISCARDED rather than allowed
            # to clear a breaker it cannot describe.
            try:
                started_at = float(started_at)
            except (TypeError, ValueError):
                started_at = 0.0
            if not math.isfinite(started_at):
                started_at = 0.0

            with self._locked():
                now = self._clock()
                st = self._load(now)
                if started_at < st.tripped_at:
                    return
                st.failures = 0
                st.open_until = 0.0
                st.tripped_at = 0.0
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
                # The instant the fleet learned it was being refused. Every
                # throttle refreshes it, so a success must have been issued
                # after the MOST RECENT trip to be allowed to clear it — see
                # `record_success`.
                st.tripped_at = now
                # Cap the bucket at a single token, so that what comes out the
                # far side of the outage is a PROBE and not a herd. Without
                # this a full default bucket (ten) is still sitting there when
                # `open_until` passes, and the fleet answers a server that has
                # only just stopped refusing with ten simultaneous calls — the
                # stampede that re-trips the breaker and earns the next,
                # longer backoff. Paired with the refill rule in `_attempt`,
                # which keeps the shut period from converting into tokens.
                st.tokens = min(st.tokens, 1.0)
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
            # Time spent with the breaker OPEN does not refill the bucket, so
            # refill is measured from the later of "last touched" and "the
            # breaker closed". Two things follow, and both are the point:
            # while shut this is zero, so nothing accrues; and once it opens
            # the outage cannot be redeemed retroactively for the tokens it
            # would have earned. Advancing `updated_at` alone is not enough —
            # if no caller happens to arrive during the outage, the whole shut
            # window is still sitting in the gap when the next one does.
            # `max(0.0, ...)` is the separate guard for a clock that stepped
            # BACKWARDS: elapsed goes to zero rather than negative, so a step
            # can delay calls but never mint or confiscate tokens.
            refill_since = max(st.updated_at, st.open_until)
            elapsed = max(0.0, now - refill_since)
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
            elif st.tokens >= 1.0 - _TOKEN_EPSILON:
                # See `_TOKEN_EPSILON`: accumulated refill lands just short of
                # a whole token, and a bare `>= 1.0` turns that dust into an
                # unservable wait.
                st.tokens = max(0.0, st.tokens - 1.0)
                self._save(st)
                return None
            else:
                wait = (1.0 - st.tokens) * self._config.min_interval_s

            self._save(st)
            return wait

    def _locked(self):
        """This limiter's own lock: `file_lock` over `<name>-throttle.lock`,
        bounded by `lock_wait_s` and driven by the INJECTED clock and sleep,
        so the lock-timeout test runs in microseconds and production still
        gets `time.time` / `time.sleep` from the constructor defaults.

        A wedged peer therefore degrades to a `TimeoutError`, which `acquire`
        catches and renders as `ERROR` — a fail-closed reject — rather than
        hanging a scan forever. So does a state directory this uid does not
        own, which `file_lock` refuses before it locks anything.
        """
        return file_lock(
            self._lock_path,
            self._config.lock_wait_s,
            clock=self._clock,
            sleep=self._sleep,
        )

    def _fresh(self, now: float) -> _State:
        return _State(
            tokens=float(self._config.burst),
            updated_at=now,
            open_until=0.0,
            failures=0,
            tripped_at=0.0,
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
            tripped_at = float(obj["tripped_at"])
        except (OSError, ValueError, TypeError, KeyError):
            return self._fresh(now)
        if not all(
            math.isfinite(v) for v in (tokens, updated_at, open_until, tripped_at)
        ):
            return self._fresh(now)
        return _State(
            tokens=min(max(tokens, 0.0), float(self._config.burst)),
            updated_at=updated_at,
            # `backoff_max_s` has to bound the delays this module OBEYS, not
            # merely the ones it writes. `open_until` is an ABSOLUTE instant,
            # written by whichever process saw the 429 and read by processes
            # that did not exist then; a clock stepping BACKWARDS (NTP
            # correction, VM resume) leaves it arbitrarily far in the future
            # with nothing able to recover — no call is made, so no 200
            # arrives, so `record_success` can never fire to clear it, and the
            # fleet stays shut until a human deletes the file. Clamping on the
            # way in makes the cap self-healing, and is a no-op for every
            # value `record_throttled` legitimately stores.
            open_until=min(open_until, now + self._config.backoff_max_s),
            failures=max(failures, 0),
            # A trip cannot have happened in the future. A backwards clock
            # would otherwise leave `tripped_at` ahead of every timestamp any
            # caller can report, so every success would read as stale and the
            # breaker would need a human to clear it. Clamping here is a no-op
            # for every value `record_throttled` legitimately writes, exactly
            # like the `open_until` cap above.
            tripped_at=min(tripped_at, now),
        )

    def _save(self, st: _State) -> None:
        """Persist the bucket + breaker, inside the lock.

        Only the six fields below are written; the payload is built by NAMING
        them, so a field added to `_State` tomorrow is invisible until it is
        added here on purpose. `atomic_write_json` does the tmp + `os.replace`
        (and the 0o600 creation), so no reader ever sees a half-written bucket.

        Its lack of an fsync is the deliberate trade documented there. The
        exposure is a power loss, after which the file may be torn or empty;
        `_load` reads that as unusable and returns `_fresh`, a full bucket with
        the breaker closed. That is the fail-OPEN direction, and it is the
        deliberate choice: a machine that just lost power must come back able
        to scan, and the breaker re-learns within one 429.
        """
        atomic_write_json(
            self._state_path,
            {
                "schema": _SCHEMA,
                "tokens": st.tokens,
                "updated_at": st.updated_at,
                "open_until": st.open_until,
                "failures": st.failures,
                "tripped_at": st.tripped_at,
            },
        )
