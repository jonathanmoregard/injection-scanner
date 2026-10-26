"""Suite-wide isolation for the on-disk per-vendor L2 limiters.

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
from pytest_socket import disable_socket


_SOCKET_ESCAPE_HATCHES = frozenset(
    {"enable_socket", "socket_enabled", "allow_hosts"}
)


def pytest_configure(config: pytest.Config) -> None:
    """Install one socket embargo before collection and keep it until exit.

    pytest-socket normally swaps the constructor during each test's setup and
    restores it during teardown. That leaves module import, collection, and
    fixture finalizers outside the embargo, and lets imports cache the real
    constructor before a test starts. Its options have already been parsed and
    its configure hook has run by the time this tests/ conftest is registered,
    so remove only its per-test lifecycle hooks and retain its mature guarded
    socket implementation for the whole remaining pytest process.
    """
    if config.getoption("--force-enable-socket"):
        raise pytest.UsageError(
            "network escape hatch forbidden: --force-enable-socket"
        )
    if config.getoption("--allow-hosts") is not None:
        raise pytest.UsageError("network escape hatch forbidden: --allow-hosts")

    socket_plugin = config.pluginmanager.get_plugin("socket")
    if socket_plugin is None:
        raise pytest.UsageError("pytest-socket plugin is required")
    config.pluginmanager.unregister(socket_plugin)
    disable_socket(allow_unix_socket=True)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Reject per-test opt-outs before any test body can execute."""
    for item in items:
        markers = {
            name
            for name in _SOCKET_ESCAPE_HATCHES
            if item.get_closest_marker(name) is not None
        }
        fixtures = _SOCKET_ESCAPE_HATCHES.intersection(item.fixturenames)
        used = sorted(markers | fixtures)
        if used:
            raise pytest.UsageError(
                "network escape hatch forbidden: "
                f"{item.nodeid} uses {', '.join(used)}"
            )

# Every per-vendor environment variable the limiter and the shared transport
# read, minus the cache dir (set below rather than cleared), for every vendor
# in the L2 panel. Listed explicitly so a new knob or vendor has to be added
# here on purpose — a stray value in the developer's shell must never change
# what the suite measures.
_VENDORS = ("LAKERA", "MODEL_ARMOR")
_VENDOR_KNOBS = (
    "MIN_INTERVAL_S",
    "BURST",
    "BACKOFF_BASE_S",
    "BACKOFF_MAX_S",
    "LOCK_WAIT_S",
    "MAX_WAIT_S",
    "TIMEOUT",
    "MAX_RESPONSE_BYTES",
)
_LIMITER_ENV = tuple(
    f"INJECTION_SCANNER_{vendor}_{knob}"
    for vendor in _VENDORS
    for knob in _VENDOR_KNOBS
)


# The panel floor and Model Armor's credential, endpoint ids, size cap and
# monthly budget. Cleared so the suite always measures the documented default
# floor (2) and an unconfigured Model Armor, whatever the developer's shell
# exports.
_PANEL_ENV = (
    "INJECTION_SCANNER_L2_MIN_VERDICTS",
    "MODEL_ARMOR_CREDENTIALS_FILE",
    "MODEL_ARMOR_CREDENTIALS",
    "MODEL_ARMOR_PROJECT",
    "MODEL_ARMOR_LOCATION",
    "MODEL_ARMOR_TEMPLATE",
    "INJECTION_SCANNER_MODEL_ARMOR_MAX_CHARS",
    "INJECTION_SCANNER_MODEL_ARMOR_OVERLAP_CHARS",
    "INJECTION_SCANNER_MODEL_ARMOR_MAX_CHUNKS",
    "INJECTION_SCANNER_MODEL_ARMOR_MONTHLY_TOKENS",
)


@pytest.fixture(autouse=True)
def _isolated_limiter_state(monkeypatch, tmp_path):
    """Private cache directory + the documented "off" budget."""
    for name in _LIMITER_ENV + _PANEL_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("INJECTION_SCANNER_CACHE_DIR", str(tmp_path / "cache"))
    for vendor in _VENDORS:
        monkeypatch.setenv(f"INJECTION_SCANNER_{vendor}_MIN_INTERVAL_S", "0")
        monkeypatch.setenv(f"INJECTION_SCANNER_{vendor}_BACKOFF_MAX_S", "0")
