"""Tests for the self-update mechanism (injection_scanner.selfupdate).

Deterministic — subprocess.run is monkeypatched throughout; no network,
no git, no uv invoked.
"""
from __future__ import annotations

import subprocess

from injection_scanner import selfupdate
from injection_scanner.selfupdate import maybe_update, resolve_remote_sha

SHA_A = "a" * 40
SHA_B = "0123456789abcdef0123456789abcdef01234567"


def _completed(argv, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


def _install_calls(calls):
    return [argv for argv in calls if argv[0] == "uv"]


# ----- resolve_remote_sha -----

def test_resolve_parses_valid_ls_remote(monkeypatch):
    def fake_run(argv, **kw):
        assert argv[:2] == ["git", "ls-remote"]
        return _completed(argv, stdout=f"{SHA_A}\trefs/heads/main\n")

    monkeypatch.setattr(selfupdate.subprocess, "run", fake_run)
    assert resolve_remote_sha() == SHA_A


def test_resolve_passes_repo_and_branch(monkeypatch):
    seen = {}

    def fake_run(argv, **kw):
        seen["argv"] = argv
        return _completed(argv, stdout=f"{SHA_B}\trefs/heads/dev\n")

    monkeypatch.setattr(selfupdate.subprocess, "run", fake_run)
    assert resolve_remote_sha("https://example.com/x.git", "dev") == SHA_B
    assert seen["argv"] == ["git", "ls-remote", "https://example.com/x.git", "dev"]


def test_resolve_garbage_sha_is_none(monkeypatch):
    monkeypatch.setattr(
        selfupdate.subprocess, "run",
        lambda argv, **kw: _completed(argv, stdout="zznot-hex-at-all-zz\trefs/heads/main\n"),
    )
    assert resolve_remote_sha() is None


def test_resolve_short_sha_is_none(monkeypatch):
    monkeypatch.setattr(
        selfupdate.subprocess, "run",
        lambda argv, **kw: _completed(argv, stdout="abc123\trefs/heads/main\n"),
    )
    assert resolve_remote_sha() is None


def test_resolve_empty_output_is_none(monkeypatch):
    monkeypatch.setattr(
        selfupdate.subprocess, "run", lambda argv, **kw: _completed(argv, stdout=""),
    )
    assert resolve_remote_sha() is None


def test_resolve_nonzero_rc_is_none(monkeypatch):
    monkeypatch.setattr(
        selfupdate.subprocess, "run",
        lambda argv, **kw: _completed(argv, returncode=128),
    )
    assert resolve_remote_sha() is None


def test_resolve_timeout_is_none(monkeypatch):
    def fake_run(argv, **kw):
        raise subprocess.TimeoutExpired(argv, 5)

    monkeypatch.setattr(selfupdate.subprocess, "run", fake_run)
    assert resolve_remote_sha() is None


def test_resolve_missing_git_is_none(monkeypatch):
    def fake_run(argv, **kw):
        raise FileNotFoundError("git")

    monkeypatch.setattr(selfupdate.subprocess, "run", fake_run)
    assert resolve_remote_sha() is None


# ----- maybe_update -----

def _run_recorder(monkeypatch, remote_sha, install_rc=0):
    """Route fake subprocess.run: ls-remote resolves to `remote_sha`,
    uv install exits `install_rc`. Returns the recorded argv list."""
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        if argv[0] == "git":
            return _completed(argv, stdout=f"{remote_sha}\trefs/heads/main\n")
        if argv[0] == "uv":
            return _completed(argv, returncode=install_rc, stderr="boom" if install_rc else "")
        raise AssertionError(f"unexpected subprocess: {argv}")

    monkeypatch.setattr(selfupdate.subprocess, "run", fake_run)
    return calls


def test_steady_state_no_install(tmp_path, monkeypatch):
    calls = _run_recorder(monkeypatch, SHA_A)
    (tmp_path / "sha").write_text(SHA_A, encoding="ascii")
    maybe_update(cache_dir=tmp_path)
    assert _install_calls(calls) == []
    # cache untouched
    assert (tmp_path / "sha").read_text(encoding="ascii") == SHA_A


def test_bump_installs_sha_pinned_spec_and_updates_cache(tmp_path, monkeypatch):
    calls = _run_recorder(monkeypatch, SHA_B)
    (tmp_path / "sha").write_text(SHA_A, encoding="ascii")
    maybe_update(cache_dir=tmp_path, venv_python="/some/venv/bin/python")
    installs = _install_calls(calls)
    assert len(installs) == 1
    argv = installs[0]
    # Pinned to the resolved SHA, not a re-resolved branch tip.
    assert argv[-1] == f"injection-scanner @ git+{selfupdate.DEFAULT_REPO}@{SHA_B}"
    assert "--force-reinstall" in argv
    assert "/some/venv/bin/python" in argv
    # Cache updated atomically: final content is the new SHA, no temp left.
    assert (tmp_path / "sha").read_text(encoding="ascii") == SHA_B
    assert not (tmp_path / "sha.tmp").exists()


def test_bump_from_empty_cache_installs(tmp_path, monkeypatch):
    calls = _run_recorder(monkeypatch, SHA_B)
    maybe_update(cache_dir=tmp_path)
    assert len(_install_calls(calls)) == 1
    assert (tmp_path / "sha").read_text(encoding="ascii") == SHA_B


def test_failed_install_keeps_cache_and_does_not_raise(tmp_path, monkeypatch):
    calls = _run_recorder(monkeypatch, SHA_B, install_rc=1)
    (tmp_path / "sha").write_text(SHA_A, encoding="ascii")
    maybe_update(cache_dir=tmp_path)  # must not raise
    assert len(_install_calls(calls)) == 1
    # Cache NOT updated — next boot retries the bump.
    assert (tmp_path / "sha").read_text(encoding="ascii") == SHA_A


def test_offline_is_noop(tmp_path, monkeypatch):
    def fake_run(argv, **kw):
        raise subprocess.TimeoutExpired(argv, 5)

    monkeypatch.setattr(selfupdate.subprocess, "run", fake_run)
    maybe_update(cache_dir=tmp_path)  # must not raise
    assert not (tmp_path / "sha").exists()
