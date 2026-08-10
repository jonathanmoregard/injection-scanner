"""Tests for injection_scanner.keyloader.

Deterministic — no network, no real secrets. Exercises the three-tier
FILE > env > keyring precedence and the fail-loud contract for a
configured-but-broken `*_FILE` path (the botched-agenix-mount case).
"""
from __future__ import annotations

import pytest

from injection_scanner import keyloader
from injection_scanner.keyloader import KeyConfigError, load_key

FILE_ENV = "TEST_KEY_FILE"
ENV_VAR = "TEST_KEY"
KEYRING_KEY = "test-key"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv(FILE_ENV, raising=False)
    monkeypatch.delenv(ENV_VAR, raising=False)


def _kw():
    return dict(file_env=FILE_ENV, env_var=ENV_VAR, keyring_key=KEYRING_KEY)


# ----- FILE tier -----

def test_file_set_and_readable_returns_contents(tmp_path, monkeypatch):
    f = tmp_path / "secret"
    f.write_text("  sk-from-file\n")  # surrounding whitespace is stripped
    monkeypatch.setenv(FILE_ENV, str(f))
    assert load_key(**_kw()) == "sk-from-file"


def test_file_set_but_missing_raises(tmp_path, monkeypatch):
    missing = tmp_path / "does-not-exist"
    monkeypatch.setenv(FILE_ENV, str(missing))
    with pytest.raises(KeyConfigError) as ei:
        load_key(**_kw())
    # message names the file_env and the path
    assert FILE_ENV in str(ei.value)
    assert str(missing) in str(ei.value)


def test_file_set_but_empty_raises(tmp_path, monkeypatch):
    f = tmp_path / "empty"
    f.write_text("   \n\t  ")  # whitespace-only counts as empty
    monkeypatch.setenv(FILE_ENV, str(f))
    with pytest.raises(KeyConfigError):
        load_key(**_kw())


# ----- env tier -----

def test_env_var_used_when_no_file(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "sk-from-env")
    assert load_key(**_kw()) == "sk-from-env"


# ----- keyring tier -----

def test_keyring_used_when_no_file_no_env(monkeypatch):
    class _R:
        stdout = "sk-from-keyring\n"

    monkeypatch.setattr(keyloader.subprocess, "run", lambda *a, **k: _R())
    assert load_key(**_kw()) == "sk-from-keyring"


# ----- precedence -----

def test_file_beats_env_and_keyring(tmp_path, monkeypatch):
    f = tmp_path / "secret"
    f.write_text("sk-from-file")
    monkeypatch.setenv(FILE_ENV, str(f))
    monkeypatch.setenv(ENV_VAR, "sk-from-env")

    class _R:
        stdout = "sk-from-keyring\n"

    monkeypatch.setattr(keyloader.subprocess, "run", lambda *a, **k: _R())
    assert load_key(**_kw()) == "sk-from-file"


def test_env_beats_keyring(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "sk-from-env")

    class _R:
        stdout = "sk-from-keyring\n"

    monkeypatch.setattr(keyloader.subprocess, "run", lambda *a, **k: _R())
    assert load_key(**_kw()) == "sk-from-env"


# ----- nothing configured -----

def test_nothing_configured_returns_none(monkeypatch):
    class _R:
        stdout = ""  # keyring miss

    monkeypatch.setattr(keyloader.subprocess, "run", lambda *a, **k: _R())
    assert load_key(**_kw()) is None


def test_empty_file_env_string_falls_through_to_env(monkeypatch):
    # `*_FILE` set to empty string is treated as "not configured", not a
    # broken mount — falls through to the env tier.
    monkeypatch.setenv(FILE_ENV, "")
    monkeypatch.setenv(ENV_VAR, "sk-from-env")
    assert load_key(**_kw()) == "sk-from-env"
