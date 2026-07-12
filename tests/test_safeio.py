"""Tests for attacker-adjacent file I/O (injection_scanner.safeio).

Deterministic — no network, no API keys. Exercises the symlink-swap /
TOCTOU guards and the rejection-audit row shape.
"""
from __future__ import annotations

import errno
import json
import os
import stat

import pytest

from injection_scanner.intercept import Verdict
from injection_scanner.safeio import (
    append_jsonl_via_dirfd,
    atomic_write_excl,
    open_parent_dir,
    write_rejection_audit,
)


# ----- open_parent_dir -----

# O_NOFOLLOW alone yields ELOOP for a symlink; combined with O_DIRECTORY
# some Linux kernels report ENOTDIR instead. Either way the open is
# refused, which is the guarantee under test.
_SYMLINK_REFUSED = (errno.ELOOP, errno.ENOTDIR)


def test_symlinked_parent_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(OSError) as ei:
        open_parent_dir(link / "audit.jsonl")
    assert ei.value.errno in _SYMLINK_REFUSED


def test_regular_parent_opens_and_pins(tmp_path):
    fd = open_parent_dir(tmp_path / "file.txt")
    try:
        assert stat.S_ISDIR(os.fstat(fd).st_mode)
    finally:
        os.close(fd)


# ----- atomic_write_excl -----

def test_atomic_write_excl_writes_new_file(tmp_path):
    target = tmp_path / "out.txt"
    atomic_write_excl(target, "hello")
    assert target.read_text(encoding="utf-8") == "hello"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_atomic_write_excl_refuses_existing(tmp_path):
    target = tmp_path / "out.txt"
    target.write_text("original", encoding="utf-8")
    with pytest.raises(FileExistsError):
        atomic_write_excl(target, "clobber")
    assert target.read_text(encoding="utf-8") == "original"


def test_atomic_write_excl_symlinked_parent_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(OSError) as ei:
        atomic_write_excl(link / "out.txt", "x")
    assert ei.value.errno in _SYMLINK_REFUSED


# ----- append_jsonl_via_dirfd -----

def test_append_creates_0o600(tmp_path):
    target = tmp_path / "log.jsonl"
    append_jsonl_via_dirfd(target, '{"a": 1}\n')
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    append_jsonl_via_dirfd(target, '{"a": 2}\n')
    lines = target.read_text(encoding="utf-8").splitlines()
    assert lines == ['{"a": 1}', '{"a": 2}']


# ----- write_rejection_audit -----

def _verdict(sanitized_text: str) -> Verdict:
    return Verdict(
        ok=False,
        reason="secret_shape:test_shape",
        layers={"secret_shapes": "fail:test_shape"},
        sanitize_stats={"stripped": 0, "text": sanitized_text},
        sanitized_text=sanitized_text,
    )


def test_write_rejection_audit_row_shape(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    content_canary = "CONTENT-CANARY-9f3a1c"
    sanitized_canary = "SANITIZED-CANARY-77bd02"
    verdict = _verdict(sanitized_canary)
    write_rejection_audit(
        audit_path,
        "report-123",
        "why is the sky blue " * 40,  # forces prompt truncation
        verdict,
        f"rejected body with {content_canary} inside",
    )
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    row = json.loads(lines[0])  # valid JSON
    assert row["report_id"] == "report-123"
    assert len(row["prompt"]) == 300
    assert "ts" in row
    # The row's whole job is to carry the rejected bytes for the operator:
    # the content canary MUST be present.
    assert content_canary in row["report_text"]
    # Regression pin: Verdict.to_audit() must not carry the sanitized
    # text — neither as the field itself nor via sanitize_stats["text"].
    assert "sanitized_text" not in row["verdict"]
    assert sanitized_canary not in json.dumps(row["verdict"])
    assert row["verdict"]["reason"] == "secret_shape:test_shape"
    assert row["verdict"]["ok"] is False
    assert row["verdict"]["sanitized_len"] == len(sanitized_canary)


def test_write_rejection_audit_oserror_is_swallowed(tmp_path, capsys):
    # Missing parent directory -> OSError inside append; the function
    # must swallow it, print a generic stderr line, and never echo content.
    audit_path = tmp_path / "missing-dir" / "audit.jsonl"
    body_marker = "REJECTED-BODY-MARKER-xyz"
    write_rejection_audit(audit_path, "report-456", "p", _verdict("s"), body_marker)
    err = capsys.readouterr().err
    assert "report-456" in err
    assert body_marker not in err
    assert not audit_path.exists()
