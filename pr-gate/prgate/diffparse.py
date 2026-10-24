"""Parse a git unified diff (as GitHub's `application/vnd.github.diff` returns
it) into per-file changes, and hash a PR's own changes.

Lines are split on "\\n" only. `str.splitlines()` would also split on
U+2028, U+0085 and friends, which would hide exactly the characters the
hidden-Unicode check looks for.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field


class DiffError(ValueError):
    """The input is not a diff this parser understands. Fail closed."""


@dataclass
class FileChange:
    path: str                       # post-image path (pre-image for deletions)
    old_path: str | None = None     # set for renames/copies
    status: str = "modified"        # added | modified | deleted | renamed
    binary: bool = False
    old_mode: str | None = None
    new_mode: str | None = None
    added: list[tuple[int, str]] = field(default_factory=list)  # (new line no, text)
    removed: list[str] = field(default_factory=list)
    # Hunk bodies with "@@" headers dropped: " ctx", "+add", "-del" lines.
    body: list[str] = field(default_factory=list)


_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13,
            '"': 34, "\\": 92}


_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')


def _unquote(s: str) -> str:
    """Undo git's C-style path quoting ("a/sp\\303\\251ce").

    git quotes every path containing `"`, a backslash, a control or a
    non-ASCII byte, so an unquoted path never starts with `"`. Anything that
    does but is not exactly one well-formed quoted UTF-8 string fails closed
    here rather than reaching a file fetch.
    """
    if not s.startswith('"'):
        return s
    if not _QUOTED.fullmatch(s):
        raise DiffError("bad quoted path")
    out = bytearray()
    i, inner = 0, s[1:-1]
    while i < len(inner):
        ch = inner[i]
        if ch != "\\":
            out += ch.encode("utf-8")
            i += 1
            continue
        nxt = inner[i + 1:i + 2]
        if nxt in _ESCAPES:
            out.append(_ESCAPES[nxt])
            i += 2
        elif re.fullmatch(r"[0-7]{3}", inner[i + 1:i + 4]):
            out.append(int(inner[i + 1:i + 4], 8))
            i += 4
        else:
            raise DiffError("bad quoted path")
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        raise DiffError("bad quoted path") from None


def _file_line_path(p: str) -> str:
    """Path from a `--- ` / `+++ ` line. git ends the path with a TAB when
    it contains a space; a TAB inside a path is always quoted as \\t."""
    return p.split("\t", 1)[0]


def _strip_prefix(p: str, prefix: str) -> str:
    p = _unquote(p)
    return p[len(prefix):] if p.startswith(prefix) else p


def _header_paths(rest: str) -> tuple[str, str]:
    """Paths from `diff --git <a> <b>`; refined later by ---/+++/rename lines."""
    if rest.startswith('"'):
        m = re.match(r'^("(?:[^"\\]|\\.)*") (.*)$', rest)
        if not m:
            raise DiffError("bad diff header")
        return _strip_prefix(m.group(1), "a/"), _strip_prefix(m.group(2), "b/")
    if rest.endswith('"'):
        # Unquoted a, quoted b (a rename to a path that needs quoting).
        a, _, b = rest.partition(' "')
        return _strip_prefix(a, "a/"), _strip_prefix('"' + b, "b/")
    # Unquoted: "a/P b/P". Same path both sides is the common case, and the
    # only one where a path containing " b/" is ambiguous.
    half = (len(rest) - 1) // 2
    if len(rest) % 2 == 1 and rest[half] == " " and rest[:half][2:] == rest[half + 1:][2:]:
        return rest[2:half], rest[half + 3:]
    a, sep, b = rest.partition(" b/")
    if not sep:
        raise DiffError("bad diff header")
    return _strip_prefix(a, "a/"), _unquote(b)


def parse(diff: str) -> list[FileChange]:
    files: list[FileChange] = []
    cur: FileChange | None = None
    old_left = new_left = 0
    new_no = 0
    lines = diff.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for line in lines:
        if cur is not None and line.startswith("\\"):
            continue  # "\ No newline at end of file"
        if cur is not None and (old_left > 0 or new_left > 0):
            tag, text = line[:1], line[1:]
            if tag == "+":
                cur.added.append((new_no, text))
                new_no += 1
                new_left -= 1
            elif tag == "-":
                cur.removed.append(text)
                old_left -= 1
            elif tag in (" ", ""):
                new_no += 1
                old_left -= 1
                new_left -= 1
            else:
                raise DiffError("bad hunk line")
            cur.body.append(line)
            continue
        if line.startswith("diff --git "):
            a, b = _header_paths(line[len("diff --git "):])
            cur = FileChange(path=b)
            if a != b:
                cur.old_path = a
                cur.status = "renamed"
            files.append(cur)
            continue
        if cur is None:
            raise DiffError("content before first diff header")
        if line.startswith("@@"):
            m = _HUNK.match(line)
            if not m:
                raise DiffError("bad hunk header")
            old_left = int(m.group(2)) if m.group(2) is not None else 1
            new_left = int(m.group(4)) if m.group(4) is not None else 1
            new_no = int(m.group(3))
        elif line.startswith("new file mode "):
            cur.status, cur.new_mode = "added", line.split()[-1]
        elif line.startswith("deleted file mode "):
            cur.status, cur.old_mode = "deleted", line.split()[-1]
        elif line.startswith("old mode "):
            cur.old_mode = line.split()[-1]
        elif line.startswith("new mode "):
            cur.new_mode = line.split()[-1]
        elif line.startswith(("rename from ", "copy from ")):
            cur.old_path = _unquote(line.split(" ", 2)[2])
            cur.status = "renamed"
        elif line.startswith(("rename to ", "copy to ")):
            cur.path = _unquote(line.split(" ", 2)[2])
        elif line.startswith("--- "):
            p = _file_line_path(line[4:])
            if p != "/dev/null":
                src = _strip_prefix(p, "a/")
                if cur.status == "deleted":
                    cur.path = src
        elif line.startswith("+++ "):
            p = _file_line_path(line[4:])
            if p != "/dev/null":
                cur.path = _strip_prefix(p, "b/")
        elif line.startswith("Binary files ") or line == "GIT binary patch":
            cur.binary = True
        elif line.startswith(("index ", "similarity index ", "dissimilarity index ")):
            pass
        else:
            raise DiffError("unexpected line outside hunk")
    if cur is not None and (old_left > 0 or new_left > 0):
        raise DiffError("truncated hunk")
    if not files:
        if diff.strip():
            raise DiffError("no file headers")
    return files


def own_changes_hash(files: list[FileChange], binary_sha256: dict[str, str]) -> str:
    """Hash of what the PR itself changes, stable across base merges.

    Per file: paths, status, modes, binary content digest, and the hunk
    bodies (context, added and removed lines in order) with the `@@` hunk
    headers dropped, so line offsets that shift when the base gains lines
    elsewhere do not matter. Context lines are kept on purpose: without
    them, moving an added line into a different function leaves the
    added/removed lists identical (see pr-gate/DECISIONS.md).
    """
    h = hashlib.sha256()
    for f in sorted(files, key=lambda f: (f.path, f.old_path or "")):
        record = {
            "path": f.path,
            "old_path": f.old_path,
            "status": f.status,
            "old_mode": f.old_mode,
            "new_mode": f.new_mode,
            "binary": f.binary,
            "binary_sha256": binary_sha256.get(f.path) if f.binary else None,
            "body": f.body,
        }
        h.update(json.dumps(record, ensure_ascii=True, sort_keys=True).encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()
