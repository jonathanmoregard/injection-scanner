"""Attacker-adjacent file I/O primitives.

Consumers of the scanner persist rejected content and audit rows to
directories a same-user attacker (e.g. a prompt-injected agent running
under the same uid) may be able to manipulate. These helpers close the
symlink-swap / TOCTOU window: every write goes through a parent-dir fd
opened with O_NOFOLLOW, so no path component can be swapped for a
symlink between our checks and the write.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def open_parent_dir(path: Path) -> int:
    """Open `path.parent` with O_DIRECTORY | O_NOFOLLOW.

    Refuses to open if the parent is a symlink (ELOOP, or ENOTDIR on
    kernels that report the O_DIRECTORY mismatch first). All writes issued
    relative to the returned dir fd are pinned to that inode — even if an
    attacker later renames or deletes `path.parent` in the filesystem
    namespace, our writes still land on the original directory. Without
    this, a same-user attacker who swaps the audit directory for a
    symlink to a sensitive location mid-call would redirect every
    subsequent audit write to attacker-chosen locations.
    """
    return os.open(
        path.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )


def atomic_write_excl(path: Path, content: str) -> None:
    """Write `content` to `path` atomically, failing if `path` exists.

    Opens the parent dir with O_NOFOLLOW (so a symlinked parent is
    rejected), then creates the file relative to that dir fd with
    O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW. No path component of the
    final write can be swapped between our checks and the write — the
    parent fd pins the inode. Removes any partial file on failure.
    """
    parent_fd = open_parent_dir(path)
    name = path.name
    try:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                fd = -1
                f.write(content)
        except Exception:
            try:
                os.unlink(name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            raise
        finally:
            if fd >= 0:
                os.close(fd)
    finally:
        os.close(parent_fd)


def append_jsonl_via_dirfd(path: Path, line: str) -> None:
    """Append one line to `path`, opening via parent dir fd + O_NOFOLLOW.

    Same parent-dir symlink guard as `atomic_write_excl`, but tailored
    to append-mode for .jsonl audit logs.
    """
    parent_fd = open_parent_dir(path)
    name = path.name
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(line)
    finally:
        os.close(parent_fd)


def write_rejection_audit(
    audit_path: Path,
    report_id: str,
    prompt_label: str,
    verdict,
    content: str,
) -> None:
    """Append a one-line JSON audit record when content is rejected.

    Self-contained diagnostic row: the full suspected-injection bytes are
    written alongside the per-layer verdict so an operator (reading from
    a bare terminal outside any LLM session) can tell what happened from
    the audit log alone. The raw content is harvested directly from the
    scanner's in-memory snapshot — it must NEVER be read back by any LLM.
    Callers should keep `audit_path` in a directory that is deny-listed
    for their agent's file-reading tools.

    The caller owns directory creation: `audit_path.parent` must already
    exist (and its symlink-resistance is enforced by
    `append_jsonl_via_dirfd`). On OSError the failure is reported
    generically to stderr — never including `content`.
    """
    import datetime
    record = {
        "ts": datetime.datetime.now(datetime.UTC).isoformat(),
        "report_id": report_id,
        "prompt": prompt_label[:300],
        "verdict": verdict.to_audit(),
        "report_text": content,
    }
    try:
        append_jsonl_via_dirfd(audit_path, json.dumps(record, default=str) + "\n")
    except OSError as e:
        print(
            f"injection-scanner: audit write failed for {report_id}: "
            f"{type(e).__name__}",
            file=sys.stderr,
        )
