"""The boot smoke is deterministic readiness: no vendor is ever called.

`run_smoke()` runs the Phase 1 canaries, then asks each layer whether a call
COULD be made — credential resolvable, endpoint trusted, limiter state usable,
SDK importable — and refuses early, naming the layer, when one could not.
Vendor outages are not its business: they surface at the first real scan,
fail-closed and agent-readable.

The suite-wide socket embargo (conftest) already makes any network attempt an
error; the spies below also prove no adapter `check()` and no honeypot/judge
`check()` is reached at all.
"""
from __future__ import annotations

import dataclasses
import os

import pytest

from injection_scanner import honeypot, judge, keyloader, l2, lakera, modelarmor, smoke
from injection_scanner.throttle import BreakerCause, CrossProcessLimiter, Decision

_KEY_ENV = {
    "LAKERA_API_KEY": "lk-test",
    "ANTHROPIC_API_KEY": "sk-ant-test",
    "OPENAI_API_KEY": "sk-openai-test",
}
_FILE_ENV = (
    "LAKERA_API_KEY_FILE",
    "ANTHROPIC_API_KEY_FILE",
    "OPENAI_API_KEY_FILE",
    "LAKERA_GUARD_URL",
)


class _Spy:
    """Stands in for a vendor `check`; records any call and refuses it."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, *_a, **_k):
        self.calls += 1
        raise AssertionError("readiness must not call a vendor")


@pytest.fixture
def spies(monkeypatch):
    out = {}
    for name, module in (
        ("lakera", lakera),
        ("model_armor", modelarmor),
        ("honeypot", honeypot),
        ("judge", judge),
    ):
        spy = _Spy()
        monkeypatch.setattr(module, "check", spy)
        out[name] = spy
    return out


@pytest.fixture
def ready_env(monkeypatch, spies):
    """Every layer ready: keys in env, no keyring, Model Armor declared ready."""
    monkeypatch.setattr(keyloader, "_keyring", lambda _k: None)
    for name in _FILE_ENV:
        monkeypatch.delenv(name, raising=False)
    for name, value in _KEY_ENV.items():
        monkeypatch.setenv(name, value)
    # The Model Armor adapter's own `ready()` arrives with its transport; until
    # then the panel treats it as not implemented (pinned below).
    monkeypatch.setattr(modelarmor, "ready", lambda: None)
    return spies


def _run() -> tuple[list[str], list[str]]:
    info: list[str] = []
    err: list[str] = []
    smoke.run_smoke(log_info=info.append, log_error=err.append)
    return info, err


def _fails() -> str:
    with pytest.raises(smoke.SmokeFailure) as excinfo:
        _run()
    return excinfo.value.reason


def test_all_ready_passes_without_calling_any_vendor(ready_env) -> None:
    info, err = _run()
    assert err == []
    assert any("scanner self-test OK" in line for line in info)
    assert all(spy.calls == 0 for spy in ready_env.values())


@pytest.mark.parametrize(
    "unset, reason, layer_text",
    [
        ("LAKERA_API_KEY", "lakera_unavailable:no-key", "lakera: no API key"),
        ("ANTHROPIC_API_KEY", ":unavailable:no-anthropic-api-key", "honeypot: anthropic model"),
        ("OPENAI_API_KEY", ":unavailable:no-openai-api-key", "honeypot: openai model"),
    ],
)
def test_a_missing_key_names_its_layer(
    ready_env, monkeypatch, unset, reason, layer_text
) -> None:
    monkeypatch.delenv(unset)
    msg = _fails()
    assert reason in msg
    assert f"Failed layer — {layer_text}" in msg
    assert all(spy.calls == 0 for spy in ready_env.values())


def test_a_judge_without_a_key_names_the_judge(ready_env, monkeypatch) -> None:
    """The judges share the honeypot's providers today, so this is reached
    only when the judge's own key resolution disagrees — exactly the drift a
    separate check exists for."""
    monkeypatch.setattr(judge, "_openai_key", lambda: None)
    msg = _fails()
    assert "l2_arbitration:judge_unavailable:" in msg
    assert ":no-openai-api-key" in msg
    assert "Failed layer — judge: openai model" in msg


@pytest.mark.parametrize(
    "file_env, reason",
    [
        ("LAKERA_API_KEY_FILE", "lakera_unavailable:key-config-error"),
        ("ANTHROPIC_API_KEY_FILE", ":unavailable:key-config-error"),
        ("OPENAI_API_KEY_FILE", ":unavailable:key-config-error"),
    ],
)
def test_a_broken_file_mount_is_a_key_config_error(
    ready_env, monkeypatch, tmp_path, file_env, reason
) -> None:
    monkeypatch.setenv(file_env, str(tmp_path / "missing-secret"))
    msg = _fails()
    assert reason in msg
    assert "missing-secret" not in msg


def test_an_untrusted_lakera_endpoint_is_a_url_config_error(ready_env, monkeypatch) -> None:
    monkeypatch.setenv("LAKERA_GUARD_URL", "https://evil.example/v2/guard")
    msg = _fails()
    assert "lakera_unavailable:url-config-error" in msg
    assert "evil.example" not in msg


def test_an_unusable_limiter_directory_is_a_limiter_error(
    ready_env, monkeypatch, tmp_path
) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o777)
    monkeypatch.setenv("INJECTION_SCANNER_CACHE_DIR", str(shared))
    msg = _fails()
    assert "lakera_unavailable:limiter-error" in msg
    assert "Failed layer — lakera: shared limiter unusable" in msg


@pytest.mark.parametrize("cause", list(BreakerCause))
def test_an_open_breaker_is_not_a_readiness_failure(ready_env, monkeypatch, cause) -> None:
    """A breaker is vendor STATE, handled per scan (quota fallback, or a
    fail-closed reject naming the outage). Readiness is about setup, and must
    not spend the token it would take to ask the limiter."""
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_BACKOFF_BASE_S", "300")
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_BACKOFF_MAX_S", "3600")
    limiter = CrossProcessLimiter.from_env("lakera")
    limiter.record_throttled(None, cause=cause)
    _run()
    assert all(spy.calls == 0 for spy in ready_env.values())


def test_readiness_spends_no_limiter_token(ready_env, monkeypatch) -> None:
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S", "3600")
    monkeypatch.setenv("INJECTION_SCANNER_LAKERA_BURST", "1")
    _run()
    _run()
    assert CrossProcessLimiter.from_env("lakera").acquire() is Decision.ALLOWED


# ---------- the panel readiness contract (l2.ready) ----------


def test_an_adapter_without_ready_is_not_ready(ready_env, monkeypatch) -> None:
    """Fail-closed: an adapter that declares no readiness cannot be vouched for."""
    monkeypatch.delattr(modelarmor, "ready")
    msg = _fails()
    assert "model_armor_unavailable:not-implemented" in msg
    assert "Failed layer — model_armor:" in msg


def test_a_vendor_not_ready_is_named(ready_env, monkeypatch) -> None:
    monkeypatch.setattr(
        modelarmor, "ready", lambda: "model_armor_unavailable:key-config-error"
    )
    msg = _fails()
    assert "model_armor_unavailable:key-config-error" in msg
    assert "Failed layer — model_armor:" in msg


def test_a_raising_ready_is_that_vendors_outage(ready_env, monkeypatch) -> None:
    def boom():
        raise RuntimeError("free text that must not surface")

    monkeypatch.setattr(modelarmor, "ready", boom)
    msg = _fails()
    assert "model_armor_unavailable:unhandled:RuntimeError" in msg
    assert "free text" not in msg


@pytest.mark.parametrize(
    "returned", ["lakera_unavailable:no-key", "ready", "pass", 0, ""]
)
def test_a_ready_answer_outside_the_vocabulary_is_bad_result(
    ready_env, monkeypatch, returned
) -> None:
    monkeypatch.setattr(modelarmor, "ready", lambda: returned)
    assert l2.ready() == "model_armor_unavailable:bad-result"


def test_below_floor_one_not_ready_vendor_is_tolerated(ready_env, monkeypatch) -> None:
    """With floor 1 a scan still reaches a verdict through the other vendor,
    so refusing to boot would be a false alarm."""
    monkeypatch.setenv(l2.ENV_MIN_VERDICTS, "1")
    monkeypatch.setattr(modelarmor, "ready", lambda: "model_armor_unavailable:no-key")
    assert l2.ready() is None
    monkeypatch.delenv("LAKERA_API_KEY")
    assert l2.ready() == "lakera_unavailable:no-key"


def test_the_first_not_ready_vendor_is_reported_in_registry_order(
    ready_env, monkeypatch
) -> None:
    monkeypatch.delenv("LAKERA_API_KEY")
    monkeypatch.setattr(modelarmor, "ready", lambda: "model_armor_unavailable:no-key")
    assert l2.ready() == "lakera_unavailable:no-key"


# ---------- Phase 1 is unchanged and still first ----------


def test_a_canary_regression_fails_before_readiness(ready_env, monkeypatch) -> None:
    """Phase 1 checks this process's own code; it must fail on its own terms,
    not be masked by (or mask) a readiness answer."""
    real = smoke._scan_via_path

    def leaky(payload, *, use_honeypot, use_l2=True):
        v = real(payload, use_honeypot=use_honeypot, use_l2=use_l2)
        return dataclasses.replace(v, ok=True)

    monkeypatch.setattr(smoke, "_scan_via_path", leaky)
    monkeypatch.delenv("LAKERA_API_KEY")
    msg = _fails()
    assert "payload passed (expected block)" in msg
    assert "lakera" not in msg


def test_a_readiness_failure_is_also_logged(ready_env, monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY")
    err: list[str] = []
    with pytest.raises(smoke.SmokeFailure):
        smoke.run_smoke(log_info=lambda _m: None, log_error=err.append)
    assert len(err) == 1
    assert err[0].startswith("scanner self-test FAILED: ")
    assert "LAKERA_API_KEY" not in err[0]
