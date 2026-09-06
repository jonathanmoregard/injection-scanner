"""The boot-smoke liveness cache (injection_scanner.smoke, spec §3.8).

Key-free and deterministic. `_scan_via_path` is replaced by a stub that COUNTS
Phase 2 probes and answers them with a Verdict of the test's choosing, while
DELEGATING the Phase 1 canary calls to the real function — those touch no
network (`use_honeypot=False, use_lakera=False`) and are the thing several
tests here assert still runs. The TTL clock is injected through
`run_smoke(..., clock=...)`, so no test sleeps and no test waits.

Why the cache exists, measured 2026-09-06: research-agent boot smokes alone ran
~632 per day — one per server spawn, plus one per degraded recheck — about
19,000 a month against Lakera's published Community quota of 10,000, before a
single report is scanned. Spawn frequency, not scan volume, is what exhausts
the account.

What is pinned here:

  * the HIT — a second boot inside the TTL costs zero vendor calls and says so
    in the log; that is the whole point of the file;
  * every unusable-entry shape is a MISS (probe exactly as before), never an
    error and never a pass — a cache in front of a probe must not become a way
    to skip the probe;
  * a FAILING probe records nothing, so an outage can never be cached;
  * Phase 1 runs on every boot regardless, cached or not — it checks THIS
    process's own code, not the fleet's vendors;
  * the entry holds a boolean and a timestamp and nothing else (Invariant 4);
  * `clock` is optional, because research-agent calls `run_smoke(log_info=…,
    log_error=…)` and that call must keep working unchanged.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from injection_scanner import smoke
from injection_scanner.intercept import Verdict

_EPOCH = 1_700_000_000.0

# Phase 1 runs three deterministic canaries, each once through the disk-read
# wrapper `_scan_via_path` (and once through `scan_text`, which the stub below
# does not see). Named so the "Phase 1 always runs" assertions read as
# arithmetic rather than as a magic 3.
_CANARIES_PER_RUN = 3


@dataclass
class _Fake:
    """Simulated wall clock. Nothing sleeps; tests step `now` by hand."""

    now: float = _EPOCH

    def time(self) -> float:
        return self.now


@dataclass
class _Log:
    """Collects the messages `run_smoke` routes through its callbacks."""

    info: list[str] = field(default_factory=list)
    error: list[str] = field(default_factory=list)

    def text(self) -> str:
        return "\n".join(self.info)


def _verdict(ok: bool) -> Verdict:
    """A Verdict shaped exactly as Phase 2 inspects it: `ok`, plus the
    `lakera` and `honeypot` entries in `layers`. `honeypot_api_errors` is left
    at its default — nothing here goes near the audit-only field."""
    if ok:
        return Verdict(
            ok=True,
            reason="pass",
            layers={"lakera": "pass", "honeypot": "pass"},
            sanitize_stats={},
            sanitized_text=smoke._BENIGN_PROBE,
        )
    return Verdict(
        ok=False,
        reason="lakera_unavailable:HTTPError:429",
        layers={"lakera": "unavailable", "honeypot": "skipped"},
        sanitize_stats={},
        sanitized_text="",
    )


class _Probe:
    """Stands in for `smoke._scan_via_path`.

    Phase 2 (`use_honeypot=True`) is COUNTED and answered with `self.verdict`
    — that is the one call in `run_smoke` that would spend Lakera quota and
    hit the honeypot providers. Phase 1 (`use_honeypot=False`) is delegated to
    the real function, which runs the deterministic canaries for real: no
    network, no key, and the only honest way to assert that caching Phase 2
    left Phase 1 alone.
    """

    def __init__(self, real):
        self._real = real
        self.verdict = _verdict(True)
        self.probes = 0
        self.canaries = 0

    def __call__(self, payload, *, use_honeypot, use_lakera=True):
        if not use_honeypot:
            self.canaries += 1
            return self._real(
                payload, use_honeypot=use_honeypot, use_lakera=use_lakera
            )
        self.probes += 1
        return self.verdict


@pytest.fixture
def probe(monkeypatch):
    p = _Probe(smoke._scan_via_path)
    monkeypatch.setattr(smoke, "_scan_via_path", p)
    return p


@pytest.fixture
def cache_file(tmp_path: Path) -> Path:
    """`tests/conftest.py` points `INJECTION_SCANNER_CACHE_DIR` at
    `tmp_path / "cache"` for every test, so this is where an entry lands."""
    return tmp_path / "cache" / "smoke-liveness.json"


@pytest.fixture
def ttl(monkeypatch):
    """The suite runs with the cache OFF (conftest pins the TTL to 0), so a
    test that wants it has to say so. Returns the setter."""

    def _set(seconds) -> None:
        monkeypatch.setenv(
            "INJECTION_SCANNER_SMOKE_LIVENESS_TTL_S", str(seconds)
        )

    return _set


def _run(fake: _Fake, log: _Log) -> None:
    smoke.run_smoke(
        log_info=log.info.append, log_error=log.error.append, clock=fake.time
    )


# ---------- hit, miss, expiry ----------

def test_a_fresh_cache_runs_the_probe_and_records_the_pass(probe, cache_file, ttl):
    ttl(3600)
    fake, log = _Fake(), _Log()
    _run(fake, log)

    assert probe.probes == 1
    assert json.loads(cache_file.read_text(encoding="utf-8")) == {
        "schema": 1,
        "ok": True,
        "at": _EPOCH,
    }


def test_a_second_boot_inside_the_ttl_skips_the_probe(probe, ttl):
    """The property the whole file exists for: a six-pane session restore
    costs ONE Lakera call, not six."""
    ttl(3600)
    fake, log = _Fake(), _Log()
    _run(fake, log)
    assert probe.probes == 1

    fake.now += 120.0
    _run(fake, log)
    assert probe.probes == 1, "a fresh cached pass must not be re-probed"
    assert "liveness probe: cached pass, 120s old" in log.text()

    fake.now += 3400.0                     # 3520 s total, still inside 3600
    _run(fake, log)
    assert probe.probes == 1
    assert "liveness probe: cached pass, 3520s old" in log.text()


def test_an_expired_entry_is_probed_again_and_rewritten(probe, cache_file, ttl):
    ttl(3600)
    fake, log = _Fake(), _Log()
    _run(fake, log)

    fake.now += 3600.1
    _run(fake, log)
    assert probe.probes == 2
    assert json.loads(cache_file.read_text(encoding="utf-8"))["at"] == fake.now


def test_the_ttl_is_an_input_and_a_short_one_is_honoured(probe, ttl):
    ttl(60)
    fake, log = _Fake(), _Log()
    _run(fake, log)

    fake.now += 59.0
    _run(fake, log)
    assert probe.probes == 1

    fake.now += 2.0
    _run(fake, log)
    assert probe.probes == 2


def test_a_ttl_of_zero_disables_the_cache(probe, cache_file, ttl):
    """`0` is the documented off switch: probe every boot, record nothing."""
    ttl(0)
    fake, log = _Fake(), _Log()
    for _ in range(3):
        _run(fake, log)

    assert probe.probes == 3
    assert not cache_file.exists()
    assert "cached pass" not in log.text()


def test_a_malformed_ttl_falls_back_to_the_default(probe, ttl):
    """Same contract as every limiter knob: malformed -> default, then clamp."""
    ttl("about an hour")
    fake, log = _Fake(), _Log()
    _run(fake, log)

    fake.now += 3599.0                     # inside the 3600 s default
    _run(fake, log)
    assert probe.probes == 1


# ---------- a non-passing probe is never cached ----------

def test_a_failing_probe_writes_nothing_and_still_raises(probe, cache_file, ttl):
    """An outage must never be recorded. If it were, one bad boot would
    silence the probe for the whole TTL across the whole fleet."""
    ttl(3600)
    probe.verdict = _verdict(False)
    fake, log = _Fake(), _Log()

    with pytest.raises(smoke.SmokeFailure) as excinfo:
        _run(fake, log)
    assert "ok=False" in excinfo.value.reason
    assert not cache_file.exists()
    assert probe.probes == 1

    # And the next boot probes again rather than inheriting anything.
    probe.verdict = _verdict(True)
    _run(fake, log)
    assert probe.probes == 2


def test_a_degraded_layer_is_not_cached_either(probe, cache_file, ttl):
    """`ok=True` is not enough: Phase 2 also requires BOTH layers to say
    "pass". A verdict that satisfies the first check and fails the second must
    leave the cache empty just the same."""
    ttl(3600)
    probe.verdict = Verdict(
        ok=True,
        reason="pass",
        layers={"lakera": "skipped", "honeypot": "pass"},
        sanitize_stats={},
        sanitized_text=smoke._BENIGN_PROBE,
    )
    fake, log = _Fake(), _Log()

    with pytest.raises(smoke.SmokeFailure) as excinfo:
        _run(fake, log)
    assert "lakera layer not 'pass'" in excinfo.value.reason
    assert not cache_file.exists()


# ---------- every unusable entry is a MISS ----------

@pytest.mark.parametrize(
    "blob",
    [
        "",
        "{",
        "null",
        "[]",
        "not json at all",
        '{"schema": 99, "ok": true, "at": 1700000000.0}',
        '{"schema": 1, "ok": false, "at": 1700000000.0}',
        '{"schema": 1, "ok": "yes", "at": 1700000000.0}',
        '{"schema": 1, "ok": true}',
        '{"schema": 1, "ok": true, "at": "soon"}',
        '{"schema": 1, "ok": true, "at": NaN}',
        '{"schema": 1, "ok": true, "at": 1700009999.0}',
    ],
    ids=[
        "empty", "truncated", "null", "array", "garbage", "foreign-schema",
        "recorded-failure", "ok-not-boolean", "no-timestamp",
        "timestamp-not-a-number", "timestamp-nan", "timestamp-in-the-future",
    ],
)
def test_an_unusable_cache_entry_is_a_miss(probe, cache_file, ttl, blob):
    """Not an error, and above all not a pass. A cache in front of a probe
    must degrade to "run the probe", which is today's behaviour.

    Every blob here carries a timestamp that WOULD be fresh, so each case
    fails for its own stated reason rather than for age. `foreign-schema` is
    an older or newer scanner sharing the cache directory; `recorded-failure`
    and `ok-not-boolean` are the two ways `ok` can be anything but literally
    `true`; `timestamp-in-the-future` is a clock step, and trusting it would
    let an entry outlive its TTL by an arbitrary amount (D25); `timestamp-nan`
    is `json.loads` accepting bare `NaN`, which then makes every comparison
    false.
    """
    ttl(3600)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(blob, encoding="utf-8")

    fake, log = _Fake(), _Log()
    _run(fake, log)

    assert probe.probes == 1, "an entry that cannot be read must be re-probed"
    assert json.loads(cache_file.read_text(encoding="utf-8")) == {
        "schema": 1,
        "ok": True,
        "at": _EPOCH,
    }, "and a pass must overwrite it"


def test_an_unreadable_cache_entry_is_a_miss(probe, cache_file, ttl):
    """A DIRECTORY where the entry should be, so the read itself raises
    rather than returning something unparseable. Root-proof: it fails for
    every uid, unlike a chmod-based fixture.

    §3.8 lists "unreadable" alongside corrupt, and it is the one shape that
    reaches the reader as an exception instead of as bad content. It must
    still be a miss — the boot probes, exactly as before — and the failure to
    record the pass afterwards must not surface as an error either.
    """
    ttl(3600)
    cache_file.mkdir(parents=True)

    fake, log = _Fake(), _Log()
    _run(fake, log)
    _run(fake, log)

    assert probe.probes == 2, "an entry that cannot be read is never a hit"
    assert log.error == []
    assert cache_file.is_dir(), "and nothing clobbered what was there"


def test_an_unwritable_cache_directory_is_not_an_error(
    probe, tmp_path, monkeypatch, ttl
):
    """A regular FILE where the cache directory should be. Root-proof: mkdir
    raises `FileExistsError` for every uid, unlike a chmod-based fixture.

    The boot still succeeds and still probes. Cache failure degrades to
    today's behaviour — never to a refusal to boot, and never to fail-open.
    """
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    monkeypatch.setenv("INJECTION_SCANNER_CACHE_DIR", str(blocked))
    ttl(3600)

    fake, log = _Fake(), _Log()
    _run(fake, log)
    _run(fake, log)

    assert probe.probes == 2, "nothing was recorded, so nothing is cached"
    assert log.error == [], "a cache that cannot be written is not a failure"


def test_a_cache_directory_this_uid_does_not_own_is_a_miss(
    probe, tmp_path, monkeypatch, ttl
):
    """A SYMLINK where the cache directory should be, which is the shape
    `mkdir(exist_ok=True)` accepts and `lstat` catches.

    The liveness entry decides whether the fleet's vendor probe runs at all,
    so a file somebody else can write must never be read as a pass.
    `throttle.file_lock` refuses the directory before it locks anything and
    the refusal lands in the ordinary miss path: probe as before, write
    nothing, log no error.
    """
    real = tmp_path / "real-cache"
    real.mkdir(mode=0o700)
    link = tmp_path / "linked-cache"
    link.symlink_to(real, target_is_directory=True)
    monkeypatch.setenv("INJECTION_SCANNER_CACHE_DIR", str(link))
    ttl(3600)

    fake, log = _Fake(), _Log()
    _run(fake, log)
    _run(fake, log)

    assert probe.probes == 2, "a foreign directory must never yield a hit"
    assert list(real.iterdir()) == [], "and nothing was written through it"
    assert log.error == []


def test_the_cache_entry_carries_only_a_boolean_and_a_timestamp(
    probe, cache_file, ttl
):
    """Invariant 4 made structural: the probe's own text must not be able to
    ride into a file the next process reads."""
    ttl(3600)
    probe.verdict = Verdict(
        ok=True,
        reason="pass",
        layers={"lakera": "pass", "honeypot": "pass"},
        sanitize_stats={"stripped": "SENTINEL-DO-NOT-PERSIST"},
        sanitized_text="SENTINEL-DO-NOT-PERSIST",
    )
    fake, log = _Fake(), _Log()
    _run(fake, log)

    raw = cache_file.read_text(encoding="utf-8")
    assert set(json.loads(raw)) == {"schema", "ok", "at"}
    assert "SENTINEL" not in raw
    assert smoke._BENIGN_PROBE not in raw


# ---------- Phase 1 is never cached ----------

def test_the_phase_one_canaries_run_on_every_boot(probe, ttl):
    """Phase 1 checks THIS process's own code, not the fleet's vendors, so
    caching Phase 2 must not touch it."""
    ttl(3600)
    fake, log = _Fake(), _Log()

    _run(fake, log)
    assert (probe.canaries, probe.probes) == (_CANARIES_PER_RUN, 1)

    _run(fake, log)
    assert (probe.canaries, probe.probes) == (2 * _CANARIES_PER_RUN, 1)


def test_a_broken_canary_still_fails_on_a_cached_boot(probe, monkeypatch, ttl):
    """The cache must not be able to wave a Phase 1 regression through."""
    ttl(3600)
    fake, log = _Fake(), _Log()
    _run(fake, log)
    assert probe.probes == 1

    monkeypatch.setattr(
        smoke,
        "_DETERMINISTIC",
        (
            smoke._Canary(
                "never_blocked", "an entirely benign sentence.", "nothing"
            ),
        ),
    )
    with pytest.raises(smoke.SmokeFailure) as excinfo:
        _run(fake, log)
    assert "expected block" in excinfo.value.reason
    assert probe.probes == 1, "Phase 1 failed before Phase 2 was consulted"


# ---------- the signature production actually calls ----------

def test_the_clock_keyword_is_optional(probe, ttl):
    """research-agent calls `run_smoke(log_info=…, log_error=…)`
    (`mcp_server/server.py`). That call has to keep working unchanged, so
    `clock` must default rather than become required."""
    ttl(0)
    log = _Log()

    smoke.run_smoke(log_info=log.info.append, log_error=log.error.append)
    assert probe.probes == 1

    smoke.run_smoke()
    assert probe.probes == 2
