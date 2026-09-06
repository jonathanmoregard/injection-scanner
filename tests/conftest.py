"""Suite-wide isolation for the on-disk Lakera limiter.

`injection_scanner.throttle` keeps a token bucket and a circuit breaker in a
JSON file under `$INJECTION_SCANNER_CACHE_DIR` (default
`~/.cache/injection-scanner`). Two consequences the test suite has to
neutralise, autouse, for EVERY test rather than per-file:

  1. Without an override, a unit run would read and write the developer's or
     the CI runner's real cache directory — shared state between test
     processes, and a suite that could leave a fleet-wide breaker open.
     `tmp_path` is function-scoped, so each test gets a private directory.

  2. With the production defaults (`burst=10`, `backoff_base_s=300`), tests
     that legitimately call `lakera.check()` more than ten times, or that raise
     a 429 and then expect the NEXT call to report a different HTTP status,
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
