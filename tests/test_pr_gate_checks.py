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
    ("install.sh", b"#!/bin/sh\n\x00echo hidden\n"),  # a shebang is text, not a magic
    ("README.md", None),                                  # content unknown: fail closed
])
def test_a_text_file_git_treats_as_binary_is_not_overridable(path, data):
    contents = {} if data is None else {path: data}
    [hit] = checks.binaries([fc(path, binary=True)], contents)
    assert (hit.rule, hit.overridable) == ("text-binary", False)
    assert hit.detail == "text file with binary content (e.g. NUL bytes); no reviewer can see it"


@pytest.mark.parametrize("path,data", [
    # An ASCII magic is easy to type at the top of a text file whose NUL
    # byte further down hides it from every reviewer.
    ("src/app.js", b"MZ = 1;\n// \x00 nobody sees this\n"),
    ("notes.md", b"BZh is a heading\n\x00"),
    ("conf.yaml", b"GIF89a: true\n\x00"),
    ("data.json", b"\x1f\x8b\x08\x00"),  # even real binary content: no override
])
def test_a_text_extension_is_text_binary_whatever_its_magic(path, data):
    [hit] = checks.binaries([fc(path, binary=True)], {path: data})
    assert (hit.rule, hit.overridable) == ("text-binary", False)


_NEW_TEXT_EXTS = """tf hcl tfvars mk cmake gradle kts groovy scala swift m mm vue svelte r ex
    exs erl hs ml dart bat cmd psm1 psd1 csv tsv rst adoc tex graphql gql proto env
    properties tpl j2 jinja erb ejs hbs mustache rake gemspec podspec bzl bazel star cue
    dhall jsonc json5 ipynb patch diff""".split()


@pytest.mark.parametrize("ext", _NEW_TEXT_EXTS)
def test_more_text_extensions_are_text_binary(ext):
    path = f"infra/main.{ext}"
    [hit] = checks.binaries([fc(path, binary=True)], {path: b"x = 1\n\x00 hidden\n"})
    assert (hit.rule, hit.overridable) == ("text-binary", False)


@pytest.mark.parametrize("path", [
    "Makefile", "src/GNUmakefile", "Dockerfile", "deploy/Containerfile", "Gemfile",
    "Rakefile", "Vagrantfile", "Jenkinsfile", "Procfile", "Brewfile", "justfile",
    "ios/Podfile", ".gitattributes", ".gitmodules", ".gitignore", ".npmrc", ".yarnrc",
    ".editorconfig", ".envrc", "MAKEFILE", "Dockerfile.dev", "docker/app.dockerfile",
])
def test_known_text_file_names_are_text_binary(path):
    data = b"all:\n\t@echo hi\n\x00 hidden\n"
    [hit] = checks.binaries([fc(path, binary=True)], {path: data})
    assert (hit.rule, hit.overridable) == ("text-binary", False)


@pytest.mark.parametrize("path,data", [
    ("bin/run", b"#!/bin/sh\n\x00echo hidden\n"),        # no extension
    ("bin/run", b"\x7fELF\x02\x01\x01\x00"),             # no extension, whatever it holds
    ("tools/gen.bin", b"#!/usr/bin/env python3\n\x00"),  # a shebang is text
])
def test_extensionless_or_shebang_files_are_text_binary(path, data):
    [hit] = checks.binaries([fc(path, binary=True)], {path: data})
    assert (hit.rule, hit.overridable) == ("text-binary", False)


@pytest.mark.parametrize("path,data", [
    ("logo.png", PNG), ("dist/pkg.zip", b"PK\x03\x04" + b"\x00" * 20),
    ("wheels/a-1.0-py3-none-any.whl", b"PK\x03\x04" + b"\x00" * 20),
    ("fonts/x.woff2", b"wOF2" + b"\x00" * 20), ("blob.dat", b"\x00\x01\x02"),
])
def test_real_binaries_stay_overridable(path, data):
    [hit] = checks.binaries([fc(path, binary=True)], {path: data})
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
    lockfiles = {"uv.lock": checks.Lockfile(b'url = "https://evil.example/pkg.whl"\n', None)}
    hits, _ = checks.run_all(files, {}, ["*"], lockfiles)
    assert rules(hits) == ["hidden-unicode", "lockfile-host"]


def test_parse_exceptions_ignores_blank_lines_and_comments():
    assert checks.parse_exceptions("a/*\n\n  # note\n  b/**  \n") == ["a/*", "b/**"]


# ----- lockfile hosts -------------------------------------------------------
#
# JSON, TOML and YAML lockfiles are parsed whole (head and base) and every
# string in them is checked; requirements*.txt, Gemfile.lock and yarn v1
# lockfiles are checked one added line at a time.

def lock_hits(path, text, base=None):
    """Hits for a lockfile whose head content is `text` (all lines added)."""
    f = fc(path, text.split("\n"))
    lf = checks.Lockfile(text.encode(), None if base is None else base.encode())
    return checks.lockfile_hosts([f], {path: lf})


def line_hits(path, lines):
    """Hits for a line-checked lockfile (no content fetched)."""
    return checks.lockfile_hosts([fc(path, lines)], {})


def doc(path, line):
    """A minimal lockfile of `path`'s format holding one entry line."""
    name = path.rsplit("/", 1)[-1].lower()
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        return '{"packages": {"node_modules/a": {' + line.rstrip(",") + "}}}"
    if name == "flake.lock":
        typ = "" if '"type"' in line else '"type": "github", '
        return '{"nodes": {"a": {"locked": {' + typ + line.rstrip(",") + "}}}}"
    if name == "pnpm-lock.yaml":
        return "lockfileVersion: '9.0'\npackages:\n  a@1.0.0:\n    " + line.strip() + "\n"
    if name == "yarn.lock":
        return "# yarn lockfile v1\n\n\na@^1.0.0:\n  " + line.strip() + "\n"
    if name in ("requirements.txt", "requirements-dev.txt", "gemfile.lock"):
        return line + "\n"
    return '[[package]]\nname = "a"\n' + line + "\n"  # TOML


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
    assert lock_hits(path, doc(path, line)) == []


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
    ("yarn.lock", 'resolved "https://evil.example/a/-/a-1.0.0.tgz#abc"'),
])
def test_foreign_lockfile_hosts_block(path, line):
    # yarn v1 can be reported twice: line by line and as its YAML fallback.
    hits = lock_hits(path, doc(path, line))
    assert hits and {(h.rule, h.overridable) for h in hits} == {("lockfile-host", False)}


@pytest.mark.parametrize("path,line", [
    # The parser decodes string escapes, as the package manager does.
    ("package-lock.json", r'"resolved": "https:\/\/evil.example\/a-1.0.0.tgz",'),
    ("package-lock.json", r'"resolved": "https:\u002f\u002fevil.example/a.tgz",'),
    ("npm-shrinkwrap.json", r'"resolved": "https\u003A//evil.example/a.tgz",'),
    ("package-lock.json", r'"resolved": "https://registry.npmjs.org\u0040evil.example/a.tgz",'),
    ("pnpm-lock.yaml", r'resolution: {tarball: "https:\/\/evil.example\/x.tgz"}'),
    ("pnpm-lock.yaml", r'resolution: {tarball: "https:\x2f\x2fevil.example/x.tgz"}'),
    ("pnpm-lock.yaml", r'resolution: {tarball: "https:\U0000002f\U0000002fevil.example/x.tgz"}'),
    ("uv.lock", r'sdist = { url = "https:\u002f/evil.example/a.tar.gz" }'),
    ("poetry.lock", r'url = "https:\U0000002F\U0000002Fevil.example/x.whl"'),
    # An escape the format does not have: the file does not parse.
    ("package-lock.json", r'"resolved": "https:\q/evil.example/a.tgz",'),
    ("uv.lock", r'url = "https\:\/\/evil.example/x.whl"'),
    # yarn v1 is line-checked: its JSON-style escapes are decoded per line.
    ("yarn.lock", r'resolved "https:\/\/evil.example/a.tgz"'),
])
def test_escaped_lockfile_urls_are_decoded_before_the_host_check(path, line):
    # yarn v1 can be reported twice: line by line and as its YAML fallback.
    hits = lock_hits(path, doc(path, line))
    assert hits and {(h.rule, h.overridable) for h in hits} == {("lockfile-host", False)}


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
    [hit] = lock_hits("package-lock.json", doc("package-lock.json", line))
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
    [hit] = lock_hits("package-lock.json", doc("package-lock.json", line))
    assert (hit.rule, hit.overridable) == ("lockfile-host", False)


def test_mapping_keys_are_checked_too():
    text = '{"packages": {"https://evil.example/a.tgz": {"version": "1.0.0"}}}'
    [hit] = lock_hits("package-lock.json", text)
    assert "evil.example" in hit.detail


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
    assert lock_hits(path, doc(path, line)) == []


@pytest.mark.parametrize("path,line", [
    ("package-lock.json", r'"resolved": "https:\/\/registry.npmjs.org\/a\/-\/a-1.0.0.tgz",'),
    ("uv.lock", r'url = "https:\u002f\u002ffiles.pythonhosted.org/x.whl"'),
    ("package-lock.json", r'"description": "a \"quoted\" word\\path",'),
    ("Cargo.lock", 'source = "git+ssh://git@github.com/org/dep.git#0123abcd"'),
])
def test_escaped_allowlisted_lockfile_urls_still_pass(path, line):
    assert lock_hits(path, doc(path, line)) == []


@pytest.mark.parametrize("path,text", [
    # A backslash-newline continuation joins the next line onto the URL:
    # the parser sees https://registry.npmjs.org.evil.example/p.tgz.
    ("pnpm-lock.yaml", 'packages:\n  a@1.0.0:\n    resolution: {tarball: "https://registry.npmjs.org\\\n'
                       '      .evil.example/p.tgz"}\n'),
    # TOML trims a line-ending backslash and the whitespace after it.
    ("uv.lock", 'url = """https://files.pythonhosted.org\\  \n.evil.example/x.whl"""\n'),
    ("uv.lock", 'url = """https://files.pythonhosted.org\\\n      .evil.example/x.whl"""\n'),
])
def test_a_line_continuation_inside_a_lockfile_string_is_resolved(path, text):
    [hit] = lock_hits(path, text)
    assert (hit.rule, hit.overridable) == ("lockfile-host", False)
    assert "evil.example" in hit.detail


@pytest.mark.parametrize("lines", [
    # pip joins any trailing backslash run, odd or even.
    ["--index-url https://pypi.org\\", ".evil.example/simple"],
    ["--index-url https://pypi.org\\\\", ".evil.example/simple"],
])
def test_a_requirements_line_continuation_is_a_hit(lines):
    hits = line_hits("requirements.txt", lines)
    assert [(h.rule, h.overridable) for h in hits] == [("lockfile-host", False)]
    assert "line 1" in hits[0].detail


@pytest.mark.parametrize("line", [
    # pip-compile's own continuation: whitespace before the backslash.
    "requests==2.32.3 \\",
    "    --hash=sha256:0123abcd \\",
])
def test_pip_compile_continuations_are_not_hits(line):
    assert line_hits("requirements.txt", [line]) == []


_SPLITS = [  # (first part, rest): the consumer strips the newline between them
    ("https://files.pythonhosted.org", ".evil.example/a.whl"),
    ("https://", "evil.example/a.whl"),
    ("https:/", "/evil.example/a.whl"),
    ("https", "://evil.example/a.whl"),
]


@pytest.mark.parametrize("head,rest", _SPLITS)
def test_a_url_split_inside_a_toml_multiline_string_is_a_hit(head, rest):
    # uv.lock: url = '''<head>\n<rest>''' is the URL head+rest to uv.
    text = f"[[package]]\nname = \"a\"\nsdist = {{ url = '''{head}\n{rest}''' }}\n"
    [hit] = lock_hits("uv.lock", text)
    assert (hit.rule, hit.overridable) == ("lockfile-host", False)
    assert "evil.example" in hit.detail


@pytest.mark.parametrize("head,rest", _SPLITS)
def test_a_url_split_inside_a_yaml_block_scalar_is_a_hit(head, rest):
    # YAML strips the block's indentation and keeps the newline.
    head = head.replace("files.pythonhosted.org", "registry.npmjs.org")
    rest = rest.replace(".whl", ".tgz")
    text = (f"packages:\n  a@1.0.0:\n    resolution:\n      tarball: |-\n"
            f"        {head}\n        {rest}\n")
    [hit] = lock_hits("pnpm-lock.yaml", text)
    assert (hit.rule, hit.overridable) == ("lockfile-host", False)
    assert "evil.example" in hit.detail


@pytest.mark.parametrize("path,text", [
    # A blank line inside a block scalar (round 7).
    ("pnpm-lock.yaml", "packages:\n  a@1.0.0:\n    resolution:\n      tarball: |-\n"
                       "        https://registry.npmjs.org\n\n        .evil.example/p.tgz\n"),
    # A double-quoted scalar folding across a blank line, continuation
    # indent trimmed: "https://registry.npmjs.org\n.evil.example/p.tgz".
    ("pnpm-lock.yaml", 'packages:\n  a@1.0.0:\n    resolution:\n      tarball: "https://registry.npmjs.org\n'
                       '\n        .evil.example/p.tgz"\n'),
    # Same, in a yarn Berry (YAML) lockfile.
    ("yarn.lock", '__metadata:\n  version: 8\n\n"a@npm:1.0.0":\n  resolution: "a@npm:1.0.0"\n'
                  '  tarball: "https://registry.yarnpkg.com\n\n    .evil.example/p.tgz"\n'),
    # A yarn v1 file that classic yarn cannot read falls back to YAML there.
    ("yarn.lock", '# yarn lockfile v1\n\n\na@^1.0.0:\n  resolved: "https://registry.yarnpkg.com\n'
                  '\n    .evil.example/p.tgz"\n'),
])
def test_yaml_line_folding_cannot_split_a_url(path, text):
    hits = lock_hits(path, text)
    assert hits and all((h.rule, h.overridable) == ("lockfile-host", False) for h in hits)
    assert any("evil.example" in h.detail for h in hits)


@pytest.mark.parametrize("path,text", [
    ("package-lock.json", '{"packages": {"node_modules/a": {"license": "MIT\\nsecond line"}}}'),
    ("uv.lock", '[[package]]\nname = """a\nb"""\n'),
    ("pnpm-lock.yaml", "packages:\n  a@1.0.0:\n    note: |\n      one\n      two\n"),
    ("package-lock.json", '{"packages": {"node_modules/a": {"license": "MIT\\u0000"}}}'),
])
def test_a_multi_line_string_in_a_parsed_lockfile_is_a_hit(path, text):
    [hit] = lock_hits(path, text)
    assert (hit.rule, hit.overridable) == ("lockfile-host", False)
    assert "multi-line" in hit.detail


@pytest.mark.parametrize("path,text", [
    ("package-lock.json", '{"packages": '),
    ("package-lock.json", '{"a": "https://registry.npmjs.org/a.tgz", "a": "https://evil.example/a.tgz"}'),
    ("uv.lock", "[[package]\n"),
    ("pnpm-lock.yaml", "packages: [\n"),
    ("pnpm-lock.yaml", "a: https://registry.npmjs.org/a.tgz\na: https://evil.example/a.tgz\n"),
    ("pnpm-lock.yaml", "x: &r {tarball: https://registry.npmjs.org/a.tgz}\ny: *r\n"),
    ("pnpm-lock.yaml", "x: !!python/name:os.system\n"),
    ("yarn.lock", "__metadata:\n  version: 8\n x: [\n"),  # Berry (no v1 header)
    ("bun.lock", '{"packages": {"a": ["a@1.0.0", "", {}, "sha512-x"],} // note\n}'),
    ("package-lock.json", "\xff"),
])
def test_a_lockfile_that_does_not_parse_is_a_hit(path, text):
    f = fc(path, ["x"])
    data = text.encode("latin-1") if text == "\xff" else text.encode()
    [hit] = checks.lockfile_hosts([f], {path: checks.Lockfile(data, None)})
    assert (hit.rule, hit.overridable, hit.detail) == ("lockfile-host", False,
                                                       "lockfile does not parse")


def test_a_yarn_v1_lockfile_need_not_parse_as_yaml():
    text = ('# yarn lockfile v1\n\n\nws@^8.17.0:\n  version "8.17.0"\n'
            '  resolved "https://registry.yarnpkg.com/ws/-/ws-8.17.0.tgz#d145"\n'
            '  dependencies:\n    a "^1"\n')
    assert lock_hits("yarn.lock", text) == []


@pytest.mark.parametrize("lf", [checks.Lockfile(None, None), None])
def test_a_lockfile_too_large_to_fetch_is_a_hit(lf):
    lockfiles = {} if lf is None else {"uv.lock": lf}
    [hit] = checks.lockfile_hosts([fc("uv.lock", ["x = 1"])], lockfiles)
    assert (hit.rule, hit.overridable) == ("lockfile-host", False)
    assert "too large" in hit.detail


def test_a_deleted_lockfile_is_not_checked():
    assert checks.lockfile_hosts([fc("uv.lock", status="deleted")], {}) == []


EVIL_PKG = '[[package]]\nname = "{n}"\nsdist = {{ url = "https://evil.example/{n}.tar.gz" }}\n'
GOOD_PKG = '[[package]]\nname = "{n}"\nsdist = {{ url = "https://files.pythonhosted.org/{n}.tar.gz" }}\n'


def test_a_bad_value_already_in_the_base_is_not_a_hit():
    base = EVIL_PKG.format(n="a")
    assert lock_hits("uv.lock", base + GOOD_PKG.format(n="b"), base=base) == []


def test_a_bad_value_new_relative_to_the_base_is_a_hit():
    base = GOOD_PKG.format(n="a")
    [hit] = lock_hits("uv.lock", base + EVIL_PKG.format(n="b"), base=base)
    assert "evil.example" in hit.detail


def test_one_more_copy_of_a_bad_value_already_in_the_base_is_a_hit():
    # Counted, not just present: a second package pointing at the same
    # foreign host is a new value.
    base = EVIL_PKG.format(n="a")
    [hit] = lock_hits("uv.lock", base + EVIL_PKG.format(n="a"), base=base)
    assert "evil.example" in hit.detail


def test_a_base_that_does_not_parse_counts_as_empty():
    [hit] = lock_hits("uv.lock", EVIL_PKG.format(n="a"), base="[[not toml")
    assert "evil.example" in hit.detail


_PACKAGE_LOCK = """{
  "name": "app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {"name": "app", "version": "1.0.0", "dependencies": {"ws": "^8.17.0"}},
    "node_modules/ws": {
      "version": "8.17.0",
      "resolved": "https://registry.npmjs.org/ws/-/ws-8.17.0.tgz",
      "integrity": "sha512-uJq6108EgZMAl20KagGkzCKfMEjxmKvZHG7Tlq0Z6nOky7YF7aq4mOx6xK8TJ/i1LeK4Qus7INktacctDgY8Ow==",
      "license": "MIT",
      "engines": {"node": ">=10.0.0"},
      "peerDependencies": {"bufferutil": "^4.0.1"},
      "peerDependenciesMeta": {"bufferutil": {"optional": true}}
    },
    "node_modules/local": {"resolved": "file:../packages/local", "link": true}
  }
}
"""

_UV_LOCK = """version = 1
requires-python = ">=3.11"

[[package]]
name = "anyio"
version = "4.4.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "idna" },
    { name = "sniffio" },
]
sdist = { url = "https://files.pythonhosted.org/packages/e6/e3/anyio-4.4.0.tar.gz", hash = "sha256:5aadc6a1bbb7cdb0bede386cac5e2940f5e2ff3aa20277e991cf028e0585ce94", size = 173126 }
wheels = [
    { url = "https://files.pythonhosted.org/packages/7b/a2/anyio-4.4.0-py3-none-any.whl", hash = "sha256:c1b2d8f46a8a812513012e1107cb0e68c17159a7a594208005a57dc776e1bdc7", size = 86780 },
]

[package.optional-dependencies]
trio = [
    { name = "trio" },
]

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
"""

_PNPM_LOCK = """lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      ws:
        specifier: ^8.17.0
        version: 8.17.0(bufferutil@4.0.8)
      git:
        specifier: ^0.1.5
        version: 0.1.5

packages:

  ws@8.17.0:
    resolution: {integrity: sha512-uJq6108EgZMAl20KagGkzCKfMEjxmKvZHG7Tlq0Z6nOky7YF7aq4mOx6xK8TJ==}
    engines: {node: '>=10.0.0'}
    peerDependencies:
      bufferutil: ^4.0.1
    peerDependenciesMeta:
      bufferutil:
        optional: true

  tar-pkg@1.0.0:
    resolution: {tarball: https://registry.npmjs.org/tar-pkg/-/tar-pkg-1.0.0.tgz}
    version: 1.0.0

snapshots:

  ws@8.17.0(bufferutil@4.0.8):
    optionalDependencies:
      bufferutil: 4.0.8
"""

_CARGO_LOCK = """# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 3

[[package]]
name = "anyhow"
version = "1.0.86"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "b3d1d046238990b9cf5bcde22a3fb3584ee5cf65fb2765f454ed428c7a0de3da"

[[package]]
name = "dep"
version = "0.1.0"
source = "git+https://github.com/org/dep?branch=main#0123456789abcdef"
dependencies = [
 "anyhow",
 "serde",
]
"""

_POETRY_LOCK = """# This file is automatically @generated by Poetry 1.8.3 and should not be changed by hand.

[[package]]
name = "certifi"
version = "2024.2.2"
description = "Python package for providing Mozilla's CA Bundle."
optional = false
python-versions = ">=3.6"
files = [
    {file = "certifi-2024.2.2-py3-none-any.whl", hash = "sha256:dc383c07b76109f368f6106eee2b593b04a011ea4d55f652c6ca24a754d1cdd1"},
]

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
content-hash = "0123abcd"
"""

_PDM_LOCK = """# This file is @generated by PDM.
# It is not intended for manual editing.

[metadata]
groups = ["default"]
strategy = ["cross_platform", "inherit_metadata"]
lock_version = "4.4.1"
content_hash = "sha256:0123abcd"

[[package]]
name = "certifi"
version = "2024.2.2"
requires_python = ">=3.6"
summary = "Python package for providing Mozilla's CA Bundle."
groups = ["default"]
files = [
    {file = "certifi-2024.2.2-py3-none-any.whl", hash = "sha256:dc383c07b76109f368f6106eee2b593b04a011ea4d55f652c6ca24a754d1cdd1"},
]
"""

_PIPFILE_LOCK = """{
    "_meta": {
        "hash": {"sha256": "0123abcd"},
        "pipfile-spec": 6,
        "requires": {"python_version": "3.11"},
        "sources": [{"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": true}]
    },
    "default": {
        "requests": {
            "hashes": ["sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f"],
            "index": "pypi",
            "markers": "python_version >= '3.7'",
            "version": "==2.31.0"
        }
    },
    "develop": {}
}
"""

_FLAKE_LOCK = """{
  "nodes": {
    "nixpkgs": {
      "locked": {
        "lastModified": 1718530797,
        "narHash": "sha256-pup6cYwtgvzDpvpSCFh1TEUjw2zkNpk8iolbKnyFmmU=",
        "owner": "NixOS",
        "repo": "nixpkgs",
        "rev": "b60ebf54c15553b393d144357375ea956f89e9a9",
        "type": "github"
      },
      "original": {"owner": "NixOS", "ref": "nixos-unstable", "repo": "nixpkgs", "type": "github"}
    },
    "src": {
      "locked": {"lastModified": 1, "narHash": "sha256-x=", "type": "tarball",
                 "url": "https://releases.nixos.org/nixos/24.05/nixexprs.tar.xz"},
      "original": {"type": "tarball", "url": "https://channels.nixos.org/nixos-24.05/nixexprs.tar.xz"}
    },
    "root": {"inputs": {"nixpkgs": "nixpkgs", "src": "src"}}
  },
  "root": "root",
  "version": 7
}
"""

_BUN_LOCK = """{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "app",
      "dependencies": {
        "ws": "^8.17.0",
      },
    },
  },
  "packages": {
    "ws": ["ws@8.17.0", "", { "peerDependencies": { "bufferutil": "^4.0.1" }, "optionalPeers": ["bufferutil"] }, "sha512-uJq6108EgZMAl20KagGkzCKfMEjxmKvZHG7Tlq0Z6nOky7YF7aq4mOx6xK8TJ/i1LeK4Qus7INktacctDgY8Ow=="],
  }
}
"""

_YARN_BERRY = """# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 8
  cacheKey: 10c0

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."
  dependencies:
    ws: "npm:^8.17.0"
  languageName: unknown
  linkType: soft

"ws@npm:^8.17.0":
  version: 8.17.0
  resolution: "ws@npm:8.17.0"
  peerDependencies:
    bufferutil: ^4.0.1
  peerDependenciesMeta:
    bufferutil:
      optional: true
  checksum: 10c0/0123abcd
  languageName: node
  linkType: hard
"""

_YARN_V1 = """# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@scope/pkg@^1.0.0":
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/@scope/pkg/-/pkg-1.0.0.tgz#d145d18eca2ed25aaf791a183903f7be5e295fea"
  integrity sha512-uJq6108EgZMAl20KagGkzCKfMEjxmKvZHG7Tlq0Z6nOky7YF7aq4mOx6xK8TJ/i1LeK4Qus7INktacctDgY8Ow==
  dependencies:
    ws "^8.17.0"

ws@^8.17.0:
  version "8.17.0"
  resolved "https://registry.yarnpkg.com/ws/-/ws-8.17.0.tgz#d145d18eca2ed25aaf791a183903f7be5e295fea"
"""

_GEMFILE_LOCK = """GEM
  remote: https://rubygems.org/
  specs:
    rake (13.2.1)

PLATFORMS
  ruby

DEPENDENCIES
  rake
"""

_REQUIREMENTS = """--index-url https://pypi.org/simple
requests==2.32.3 \\
    --hash=sha256:70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6
"""


@pytest.mark.parametrize("path,text", [
    ("package-lock.json", _PACKAGE_LOCK), ("npm-shrinkwrap.json", _PACKAGE_LOCK),
    ("uv.lock", _UV_LOCK), ("pnpm-lock.yaml", _PNPM_LOCK), ("Cargo.lock", _CARGO_LOCK),
    ("poetry.lock", _POETRY_LOCK), ("pdm.lock", _PDM_LOCK), ("Pipfile.lock", _PIPFILE_LOCK),
    ("flake.lock", _FLAKE_LOCK), ("bun.lock", _BUN_LOCK), ("yarn.lock", _YARN_BERRY),
    ("yarn.lock", _YARN_V1), ("Gemfile.lock", _GEMFILE_LOCK),
    ("requirements.txt", _REQUIREMENTS),
])
def test_realistic_lockfiles_are_not_hits(path, text):
    assert lock_hits(path, text) == []


def test_this_repos_own_uv_lock_is_not_a_hit():
    from pathlib import Path
    text = (Path(__file__).resolve().parent.parent / "uv.lock").read_text(encoding="utf-8")
    assert lock_hits("uv.lock", text) == []


@pytest.mark.parametrize("node", [
    '{"locked": {"type": "gitlab", "owner": "o", "repo": "r"}}',
    '{"original": {"type": "sourcehut", "owner": "o", "repo": "r"}}',
    '{"locked": {"type": "github", "host": "git.evil.example", "owner": "o", "repo": "r"}}',
    '{"locked": {"owner": "o", "repo": "r"}}',
])
def test_flake_inputs_are_checked_on_the_parsed_nodes(node):
    [hit] = lock_hits("flake.lock", '{"nodes": {"x": ' + node + '}, "version": 7}')
    assert "flake" in hit.detail


def test_flake_type_outside_a_node_is_not_a_flake_input():
    assert lock_hits("flake.lock", '{"nodes": {}, "meta": {"type": "gitlab"}}') == []


def test_bun_lock_urls_are_checked():
    text = _BUN_LOCK.replace('"ws@8.17.0", ""', '"ws@8.17.0", "https://evil.example/"')
    [hit] = lock_hits("bun.lock", text)
    assert "evil.example" in hit.detail


def test_requirements_lines_are_not_joined():
    # pip has no multi-line strings: "https://pypi.org" + "requests" is two lines.
    lines = ["--index-url https://pypi.org", "requests==2.32.3"]
    assert line_hits("requirements.txt", lines) == []


def test_non_lockfiles_are_not_host_checked():
    assert line_hits("README.md", ["https://evil.example/"]) == []


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
    hits, _ = checks.run_all(files, {"logo.png": PNG}, [], {}, always_on_only=True)
    assert rules(hits) == ["hidden-unicode"]
    hits, _ = checks.run_all(files, {"logo.png": PNG}, [], {})
    assert rules(hits) == ["binary", "hidden-unicode", "sensitive-path"]


def test_always_on_only_keeps_text_binary():
    files = [fc("logo.png", binary=True), fc("a.js", binary=True)]
    hits, _ = checks.run_all(files, {"logo.png": PNG, "a.js": b"x\x00"}, [], {},
                             always_on_only=True)
    assert rules(hits) == ["text-binary"]
