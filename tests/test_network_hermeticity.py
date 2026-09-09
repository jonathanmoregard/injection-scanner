"""Executable proof that pytest cannot open real network endpoints."""
from __future__ import annotations

import socket
import subprocess
import sys
import textwrap
import warnings
from pathlib import Path

import pytest
from pytest_socket import SocketBlockedError


ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "pyproject.toml"


def _run_isolated_pytest(
    tmp_path: Path, source: str, *extra_args: str
) -> subprocess.CompletedProcess[str]:
    """Run one generated test with this project's pytest configuration."""
    case = tmp_path / "test_network_guard_case.py"
    case.write_text(textwrap.dedent(source), encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-c",
            str(PROJECT),
            "-p",
            "tests.conftest",
            *extra_args,
            str(case),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def _assert_child_passed(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr


@pytest.mark.parametrize("family", [socket.AF_INET, socket.AF_INET6])
def test_pytest_blocks_network_sockets(family: socket.AddressFamily) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with pytest.raises(SocketBlockedError):
            socket.socket(family, socket.SOCK_STREAM)


def test_pytest_allows_unix_domain_sockets() -> None:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.close()


def test_a_socket_constructor_cached_during_collection_stays_blocked(
    tmp_path: Path,
) -> None:
    result = _run_isolated_pytest(
        tmp_path,
        """
        import socket

        from pytest_socket import SocketBlockedError

        CACHED_SOCKET = socket.socket

        def test_cached_constructor_is_guarded():
            try:
                sock = CACHED_SOCKET(socket.AF_INET, socket.SOCK_STREAM)
            except SocketBlockedError:
                return
            sock.close()
            raise AssertionError("collection cached the real socket constructor")
        """,
    )
    _assert_child_passed(result)


def test_network_sockets_stay_blocked_during_fixture_finalization(
    tmp_path: Path,
) -> None:
    result = _run_isolated_pytest(
        tmp_path,
        """
        import socket

        import pytest
        from pytest_socket import SocketBlockedError

        @pytest.fixture
        def finalizer_probe():
            yield
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except SocketBlockedError:
                return
            sock.close()
            raise AssertionError("socket guard was removed before finalization")

        def test_guard_lifetime(finalizer_probe):
            pass
        """,
    )
    _assert_child_passed(result)


@pytest.mark.parametrize(
    "escape_arg",
    ["--force-enable-socket", "--allow-hosts=127.0.0.1"],
)
def test_command_line_network_escape_hatches_are_rejected(
    tmp_path: Path, escape_arg: str
) -> None:
    result = _run_isolated_pytest(tmp_path, "def test_noop(): pass", escape_arg)
    assert result.returncode == pytest.ExitCode.USAGE_ERROR, result.stdout + result.stderr
    assert "network escape hatch forbidden" in result.stdout + result.stderr


@pytest.mark.parametrize(
    "escape_source",
    [
        """
        import pytest

        @pytest.mark.enable_socket
        def test_escape():
            pass
        """,
        """
        def test_escape(socket_enabled):
            pass
        """,
        """
        import pytest

        @pytest.mark.allow_hosts(["127.0.0.1"])
        def test_escape():
            pass
        """,
    ],
    ids=["enable-marker", "enabled-fixture", "allow-hosts-marker"],
)
def test_per_test_network_escape_hatches_are_rejected_during_collection(
    tmp_path: Path, escape_source: str
) -> None:
    result = _run_isolated_pytest(tmp_path, escape_source)
    assert result.returncode == pytest.ExitCode.USAGE_ERROR, result.stdout + result.stderr
    assert "network escape hatch forbidden" in result.stdout + result.stderr
