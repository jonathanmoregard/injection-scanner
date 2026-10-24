"""pr-gate: unified-diff parsing and the own-changes hash."""
from __future__ import annotations

import _prgate  # noqa: F401  (puts pr-gate/ on sys.path)

import pytest

from prgate import diffparse as dp


MODIFY = """\
diff --git a/src/app.py b/src/app.py
index 1111111..2222222 100644
--- a/src/app.py
+++ b/src/app.py
@@ -10,3 +10,4 @@ def main():
     a = 1
-    b = 2
+    b = 3
+    c = 4
     return a
"""

ADD = """\
diff --git a/new.txt b/new.txt
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/new.txt
@@ -0,0 +1,2 @@
+hello
+world
"""

DELETE = """\
diff --git a/old.txt b/old.txt
deleted file mode 100644
index 4444444..0000000
--- a/old.txt
+++ /dev/null
@@ -1 +0,0 @@
-bye
"""

BINARY = """\
diff --git a/img/logo.png b/img/logo.png
new file mode 100644
index 0000000..5555555
Binary files /dev/null and b/img/logo.png differ
"""

RENAME = """\
diff --git a/a/x.py b/b/y.py
similarity index 100%
rename from a/x.py
rename to b/y.py
"""

MODE = """\
diff --git a/run.sh b/run.sh
old mode 100644
new mode 100755
"""


def test_modified_file_added_and_removed_lines_with_new_line_numbers():
    [f] = dp.parse(MODIFY)
    assert f.path == "src/app.py"
    assert f.status == "modified"
    assert f.removed == ["    b = 2"]
    assert f.added == [(11, "    b = 3"), (12, "    c = 4")]
    assert not f.binary


def test_added_file():
    [f] = dp.parse(ADD)
    assert (f.path, f.status, f.new_mode) == ("new.txt", "added", "100644")
    assert f.added == [(1, "hello"), (2, "world")]


def test_deleted_file_keeps_its_path():
    [f] = dp.parse(DELETE)
    assert (f.path, f.status, f.removed) == ("old.txt", "deleted", ["bye"])


def test_binary_file_is_marked():
    [f] = dp.parse(BINARY)
    assert (f.path, f.status, f.binary) == ("img/logo.png", "added", True)


def test_rename_records_both_paths():
    [f] = dp.parse(RENAME)
    assert (f.old_path, f.path, f.status) == ("a/x.py", "b/y.py", "renamed")


def test_mode_change():
    [f] = dp.parse(MODE)
    assert (f.old_mode, f.new_mode) == ("100644", "100755")


def test_multiple_files_in_one_diff():
    files = dp.parse(MODIFY + ADD + DELETE + BINARY)
    assert [f.path for f in files] == ["src/app.py", "new.txt", "old.txt", "img/logo.png"]


def test_content_lines_that_look_like_headers_stay_content():
    # An added line whose text is "++ b/evil" renders as "+++ b/evil" and a
    # removed "-- a/x" as "--- a/x". Hunk line counts keep them content.
    diff = """\
diff --git a/f.md b/f.md
index 1..2 100644
--- a/f.md
+++ b/f.md
@@ -1,2 +1,2 @@
--- a/x
+++ b/evil
 keep
"""
    [f] = dp.parse(diff)
    assert f.path == "f.md"
    assert f.removed == ["-- a/x"]
    assert f.added == [(1, "++ b/evil")]


def test_line_separator_inside_a_line_does_not_split_it():
    diff = (
        "diff --git a/f.js b/f.js\n--- a/f.js\n+++ b/f.js\n"
        "@@ -0,0 +1 @@\n+a\u2028b\x85c\n"
    )
    [f] = dp.parse(diff)
    assert f.added == [(1, "a\u2028b\x85c")]


def test_quoted_paths_are_unquoted():
    diff = (
        'diff --git "a/sp ace\\303\\251.txt" "b/sp ace\\303\\251.txt"\n'
        "new file mode 100644\n--- /dev/null\n"
        '+++ "b/sp ace\\303\\251.txt"\n@@ -0,0 +1 @@\n+x\n'
    )
    [f] = dp.parse(diff)
    assert f.path == "sp aceé.txt"


# Verbatim `git diff` output (git 2.x): a path containing a space gets a
# trailing TAB on its ---/+++ line; non-ASCII and `"` force C-style quoting.
SPACES = (
    "diff --git a/added file.txt b/added file.txt\n"
    "new file mode 100644\nindex 0000000..587be6b\n"
    "--- /dev/null\n+++ b/added file.txt\t\n@@ -0,0 +1 @@\n+x\n"
    "diff --git a/my file.txt b/my other.txt\n"
    "similarity index 66%\nrename from my file.txt\nrename to my other.txt\n"
    "index 422c2b7..de98044 100644\n"
    "--- a/my file.txt\t\n+++ b/my other.txt\t\n@@ -1,2 +1,3 @@\n a\n b\n+c\n"
)

QUOTED = (
    'diff --git a/base.txt "b/caf\\303\\251 2.txt"\n'
    "similarity index 83%\nrename from base.txt\n"
    'rename to "caf\\303\\251 2.txt"\nindex 8a1218a..b414108 100644\n'
    '--- a/base.txt\n+++ "b/caf\\303\\251 2.txt"\t\n@@ -3,3 +3,4 @@\n 3\n 4\n 5\n+6\n'
    'diff --git "a/q\\"uote.txt" "b/q\\"uote.txt"\n'
    "index 7898192..422c2b7 100644\n"
    '--- "a/q\\"uote.txt"\n+++ "b/q\\"uote.txt"\n@@ -1 +1,2 @@\n a\n+b\n'
)


def test_gits_trailing_tab_after_a_path_with_spaces_is_not_part_of_the_path():
    added, renamed = dp.parse(SPACES)
    assert (added.path, added.status) == ("added file.txt", "added")
    assert (renamed.path, renamed.old_path) == ("my other.txt", "my file.txt")


def test_quoted_paths_in_headers_and_file_lines_are_unquoted():
    renamed, quoted = dp.parse(QUOTED)
    assert (renamed.path, renamed.old_path, renamed.status) == ("café 2.txt", "base.txt", "renamed")
    assert renamed.added == [(6, "6")]
    assert (quoted.path, quoted.old_path) == ('q"uote.txt', None)


def test_deleted_file_with_a_space_keeps_its_path():
    diff = ("diff --git a/old file.txt b/old file.txt\ndeleted file mode 100644\n"
            "--- a/old file.txt\t\n+++ /dev/null\n@@ -1 +0,0 @@\n-bye\n")
    [f] = dp.parse(diff)
    assert (f.path, f.status) == ("old file.txt", "deleted")


@pytest.mark.parametrize("line", [
    '+++ "b/unterminated.txt\t',      # opening quote, no closing quote
    '+++ "b/bad\\q.txt"',             # unknown escape
    '+++ "b/\\377.txt"',              # octal bytes that are not UTF-8
    '+++ "b/x.txt"junk',              # text after the closing quote
])
def test_a_path_that_cannot_be_unquoted_fails_closed(line):
    diff = f"diff --git a/x.txt b/x.txt\n--- a/x.txt\n{line}\n@@ -1 +1 @@\n-a\n+b\n"
    with pytest.raises(dp.DiffError):
        dp.parse(diff)


def test_no_newline_marker_is_ignored():
    diff = (
        "diff --git a/f b/f\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a\n"
        "\\ No newline at end of file\n+b\n\\ No newline at end of file\n"
    )
    [f] = dp.parse(diff)
    assert (f.removed, f.added) == (["a"], [(1, "b")])


def test_unparseable_input_raises():
    with pytest.raises(dp.DiffError):
        dp.parse("this is not a diff\n")


# ----- own-changes hash ----------------------------------------------------

def _shift(diff: str, delta: int) -> str:
    """The same change re-diffed after the base gained `delta` lines above it."""
    return diff.replace("@@ -10,3 +10,4 @@", f"@@ -{10 + delta},3 +{10 + delta},4 @@")


def test_hash_ignores_hunk_offsets_from_a_base_merge():
    a = dp.own_changes_hash(dp.parse(MODIFY + ADD), {})
    b = dp.own_changes_hash(dp.parse(_shift(MODIFY, 37) + ADD), {})
    assert a == b


def test_hash_ignores_hunk_header_function_context():
    a = dp.own_changes_hash(dp.parse(MODIFY), {})
    b = dp.own_changes_hash(dp.parse(MODIFY.replace(" def main():", " class X:")), {})
    assert a == b


def test_hash_ignores_file_order_and_index_lines():
    a = dp.own_changes_hash(dp.parse(MODIFY + ADD), {})
    b = dp.own_changes_hash(
        dp.parse(ADD.replace("3333333", "abcdef0") + MODIFY.replace("2222222", "9999999")), {}
    )
    assert a == b


def test_hash_changes_on_an_extra_edit():
    a = dp.own_changes_hash(dp.parse(MODIFY), {})
    b = dp.own_changes_hash(dp.parse(MODIFY.replace("+    c = 4", "+    c = 5")), {})
    assert a != b


def test_hash_changes_when_a_line_moves_to_a_different_context():
    # Same added and removed lines, different surroundings: moving
    # `return True` into another function must not carry a pass over.
    a = dp.own_changes_hash(dp.parse(MODIFY), {})
    b = dp.own_changes_hash(dp.parse(MODIFY.replace("     a = 1", "     z = 9")), {})
    assert a != b


def test_hash_changes_with_binary_content():
    files = dp.parse(BINARY)
    a = dp.own_changes_hash(files, {"img/logo.png": "00" * 32})
    b = dp.own_changes_hash(files, {"img/logo.png": "11" * 32})
    assert a != b


def test_hash_changes_with_mode():
    a = dp.own_changes_hash(dp.parse(MODE), {})
    b = dp.own_changes_hash(dp.parse(MODE.replace("100755", "120000")), {})
    assert a != b


def test_hash_is_hex_sha256():
    h = dp.own_changes_hash(dp.parse(MODIFY), {})
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)
