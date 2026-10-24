"""Deterministic checks. Any hit blocks.

Three of them (hidden Unicode, lockfile hosts, a git-binary file that is
not a known binary type) are ALWAYS-ON: they have no legitimate trigger, so neither the owner
override nor the `exceptions` input can turn them off. The other binary,
submodule and path rules are owner-overridable, and the path rule can be
downgraded per repo to "extra scrutiny".

Everything here is pure: diff (and fetched contents) in, hits out.
Fetching lives in core.py.
"""
from __future__ import annotations

import fnmatch
import json
import re
import shlex
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import unquote

import yaml
from injection_scanner.unicode_sanitize import find_hidden

from .diffparse import FileChange

LONG_LINE = 500


@dataclass(frozen=True)
class Hit:
    rule: str          # hidden-unicode | lockfile-host | text-binary | binary | submodule | sensitive-path | too-large
    path: str          # attacker-chosen: neutralise before display
    detail: str        # may contain attacker-chosen text (hosts): neutralise
    overridable: bool  # cleared by the owner dismissing the gate's block


@dataclass(frozen=True)
class Scrutiny:
    path: str
    reason: str        # closed vocabulary, see the functions below


def _u(cps) -> str:
    return ", ".join(f"U+{cp:04X}" for cp in sorted(set(cps))[:8])


# ----- hidden Unicode ------------------------------------------------------

# Control characters (category Cc) in an added line: a terminal acts on
# them, and an ESC sequence can erase or conceal the line under review. The
# shared "code" profile keeps them for its other callers. Allowed: TAB, form
# feed (page breaks) and a trailing CR (CRLF files).
_CONTROLS = re.compile(r"[\x00-\x08\x0a\x0b\x0d-\x1f\x7f-\x9f]")


def hidden_unicode(files: list[FileChange]) -> list[Hit]:
    hits = []
    for f in files:
        for p in {f.path, f.old_path} - {None}:
            found = find_hidden(p, "code")
            if found:
                hits.append(Hit("hidden-unicode", f.path,
                                f"in the file path: {_u(cp for _, cp in found)}", False))
        for line_no, text in f.added:
            cps = [cp for _, cp in find_hidden(text, "code")]
            cps += [ord(c) for c in _CONTROLS.findall(text.removesuffix("\r"))]
            if cps:
                hits.append(Hit("hidden-unicode", f.path, f"line {line_no}: {_u(cps)}", False))
    return hits


# ----- binaries --------------------------------------------------------------

_MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF87a", "gif"),
    (b"GIF89a", "gif"), (b"\x00\x00\x01\x00", "ico"), (b"wOF2", "woff2"),
    (b"wOFF", "woff"), (b"OTTO", "otf"), (b"\x00\x01\x00\x00", "ttf"),
    (b"%PDF-", "pdf"), (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"),
    (b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"), (b"\xfd7zXZ\x00", "xz"),
    (b"\x28\xb5\x2f\xfd", "zstd"), (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x7fELF", "elf"), (b"MZ", "pe"), (b"\x00asm", "wasm"), (b"#!", "script"),
    (b"\xcf\xfa\xed\xfe", "macho"), (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"), (b"\xfe\xed\xfa\xce", "macho"),
    (b"\xca\xfe\xba\xbe", "macho"),  # fat Mach-O (also Java class files)
]
_EXECUTABLE = frozenset({"elf", "pe", "macho", "wasm", "script"})
_EXT_KIND = {
    "png": "png", "jpg": "jpeg", "jpeg": "jpeg", "gif": "gif", "webp": "webp",
    "ico": "ico", "woff2": "woff2", "woff": "woff", "otf": "otf", "ttf": "ttf",
    "pdf": "pdf", "zip": "zip", "jar": "zip", "whl": "zip", "docx": "zip",
    "xlsx": "zip", "pptx": "zip", "gz": "gzip", "tgz": "gzip", "bz2": "bzip2",
    "xz": "xz", "zst": "zstd", "7z": "7z", "wasm": "wasm",
}


# Known binary types: _EXT_KIND plus common binaries with no magic entry.
# A file git calls binary is overridable only if its extension is one of
# these and its magic does not contradict it. Anything else (a .js or .vbs
# with a NUL byte, UTF-16 text, no extension, a "#!" script) is text-binary:
# git shows no lines of it, so no model, Unicode or lockfile check sees it.
_KNOWN_BINARY = frozenset(_EXT_KIND) | frozenset("""
    bmp tif tiff heic avif icns psd mp3 mp4 m4a wav ogg oga opus flac webm mov avi mkv
    eot tar rar deb rpm dmg iso so dll dylib exe class pyc pyd o a lib db sqlite sqlite3
    mo parquet npy npz pkl pt onnx xls doc ppt odt ods odp key p12 pfx jks keystore der
    bin dat
""".split())
TEXT_BINARY = ("not a known binary type (e.g. text with a NUL byte); git shows none of "
               "it, so no reviewer can see it")


def magic_type(data: bytes) -> str | None:
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    for magic, kind in _MAGIC:
        if data.startswith(magic):
            return kind
    return None


def binaries(files: list[FileChange], contents: dict[str, bytes | None]) -> list[Hit]:
    hits = []
    for f in files:
        if not f.binary or f.status == "deleted":
            continue
        data = contents.get(f.path)
        ext = PurePosixPath(f.path).suffix.lower().lstrip(".")
        kind = None if data is None else magic_type(data)
        # Whatever the extension: "#!" is a script, and an ASCII magic is
        # easy to type at the top of a text file whose NUL byte hides the rest.
        if ext not in _KNOWN_BINARY or kind == "script":
            hits.append(Hit("text-binary", f.path, TEXT_BINARY, False))
            continue
        expected = _EXT_KIND.get(ext)
        mismatch = kind is not None and expected is not None and kind != expected
        if data is None:
            detail = "binary file; content not fetched"
        elif kind is None:
            detail = "binary file; unrecognised content type"
        elif mismatch:
            detail = f"binary file; mismatch: content is {kind}, extension says {expected}"
        else:
            detail = f"binary file; content is {kind}"
        if kind in _EXECUTABLE:
            detail += " (executable)"
        # Content contradicting its extension is not what the owner would
        # be overriding: not clearable either.
        hits.append(Hit("text-binary", f.path, detail, False) if mismatch
                    else Hit("binary", f.path, detail, True))
    return hits


# ----- submodule pointers ----------------------------------------------------

SUBMODULE = ("submodule pointer: its content is not reviewed; check the target "
             "repo/commit before dismissing")


def submodules(files: list[FileChange]) -> list[Hit]:
    """An added or bumped gitlink points at a commit in another repo that no
    reviewer sees (with a .gitmodules URL, any repo). The owner can look at
    that commit, so it is overridable."""
    return [Hit("submodule", f.path, SUBMODULE, True)
            for f in files if f.gitlink and f.status != "deleted"]


# ----- sensitive paths -------------------------------------------------------

_AGENT_FILES = frozenset({"claude.md", "claude.local.md", "agents.md",
                          "agents.override.md", ".mcp.json"})
_AGENT_DIRS = frozenset({".claude", ".codex"})
# Exceptions can never cover these: they define what CI runs, including
# this gate. (.github/actions/ holds local actions that workflows run.)
_NEVER_EXEMPT = (".github/workflows/", ".github/actions/")


def _sensitive_reason(path: str) -> str | None:
    parts = path.split("/")
    if parts[0] == ".github":
        return "github"
    if parts[-1].casefold() in _AGENT_FILES:
        return "agent-instructions"
    if any(p.casefold() in _AGENT_DIRS for p in parts[:-1]):
        return "agent-instructions"
    return None


def parse_exceptions(text: str) -> list[str]:
    out = []
    for line in (text or "").split("\n"):
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _exempt(path: str, exceptions: list[str]) -> bool:
    if path.startswith(_NEVER_EXEMPT):
        return False
    return any(fnmatch.fnmatchcase(path, g) for g in exceptions)


def sensitive_paths(files: list[FileChange], exceptions: list[str]) -> tuple[list[Hit], list[Scrutiny]]:
    hits, scrutiny = [], []
    for f in files:
        for p in dict.fromkeys(x for x in (f.path, f.old_path) if x):
            reason = _sensitive_reason(p)
            if reason is None:
                continue
            if _exempt(p, exceptions):
                scrutiny.append(Scrutiny(p, "exception-path"))
            else:
                detail = ("changes CI configuration" if reason == "github"
                          else "changes agent instructions")
                hits.append(Hit("sensitive-path", p, detail, True))
    return hits, scrutiny


# ----- lockfile hosts --------------------------------------------------------
#
# JSON, TOML and YAML lockfiles are PARSED, head and base, and every string
# in them is checked: re-implementing their string folding line by line
# (block scalars, blank lines, continuations) kept losing. Formats without
# multi-line strings (requirements*.txt, Gemfile.lock, yarn v1) are checked
# one added line at a time.

_NPM = frozenset({"registry.npmjs.org", "registry.yarnpkg.com"})
_PY = frozenset({"pypi.org", "files.pythonhosted.org"})
_LOCKFILES = {
    "package-lock.json": _NPM, "npm-shrinkwrap.json": _NPM, "yarn.lock": _NPM,
    "pnpm-lock.yaml": _NPM, "bun.lock": _NPM,
    "cargo.lock": frozenset({"github.com", "index.crates.io", "static.crates.io"}),
    "uv.lock": _PY, "poetry.lock": _PY, "pipfile.lock": _PY, "pdm.lock": _PY,
    "flake.lock": frozenset({"github.com", "channels.nixos.org", "releases.nixos.org"}),
    "gemfile.lock": frozenset({"rubygems.org"}),
}
_JSON_LOCKS = frozenset({"package-lock.json", "npm-shrinkwrap.json", "pipfile.lock",
                         "flake.lock", "bun.lock"})
_TOML_LOCKS = frozenset({"cargo.lock", "uv.lock", "poetry.lock", "pdm.lock"})
_YAML_LOCKS = frozenset({"pnpm-lock.yaml", "yarn.lock"})
# pip requirement files: requirements*.txt / constraints*.txt, pip-tools'
# requirements*.in / constraints*.in, and any .txt / .in in a directory
# named "requirements" (requirements/base.txt, requirements/dev.in).
_REQUIREMENTS = re.compile(r"^(requirements|constraints)[\w.-]*\.(txt|in)$")
# yarn's own test for its v1 format (Berry's LEGACY_REGEXP).
_YARN_V1 = re.compile(r"(?:#.*\r?\n)*?#\s+yarn\s+lockfile\s+v1\r?\n", re.I)
_OK_SCHEMES = frozenset({"https", "git+https", "registry+https", "sparse+https",
                         "git+ssh", "ssh"})
# A URL is a scheme from a fixed set (http, https, ftp, ws, wss, git, ssh,
# or `<word>+` one of those, like git+https or sparse+https) followed by
# ":" and ANY run of slashes, even none: WHATWG/npm read "https:evil.x" and
# "https:///evil.x" as host evil.x. Any other "scheme://" is a URL too
# (including file://); a bare local `file:../pkg` reference is not.
_SCHEME = re.compile(r"(?<![A-Za-z0-9+./-])([A-Za-z][A-Za-z0-9+.-]*):")
_KNOWN_SCHEME = re.compile(r"(?:\w+\+)?(?:https?|ftp|wss?|git|ssh)", re.I)
_AUTHORITY = re.compile(r"(/*)([^/?#\s\"'`]*)")
_FLAKE_TYPES_OK = frozenset({"github", "git", "tarball", "file", "path", "indirect"})
# No legitimate lockfile string holds a line break, a tab or another control
# character; a URL with one is a different URL to WHATWG/rust-url.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
MULTI_LINE = "multi-line or control-character string"


@dataclass(frozen=True)
class Lockfile:
    """Whole contents of a changed JSON/TOML/YAML lockfile, fetched by core.
    head None: over the fetch cap. base None: not in the base (or too big)."""
    head: bytes | None
    base: bytes | None = None


def _kind(path: str) -> str | None:
    """Which lockfile a path is: its lockfile name, "requirements", or None."""
    name = PurePosixPath(path).name.casefold()
    if name in _LOCKFILES:
        return name
    if _REQUIREMENTS.match(name) or (PurePosixPath(path).parent.name.casefold() == "requirements"
                                     and name.endswith((".txt", ".in"))):
        return "requirements"
    return None


def _allowlist(path: str) -> frozenset[str] | None:
    kind = _kind(path)
    return _PY if kind == "requirements" else _LOCKFILES.get(kind)


def renamed_from_other_kind(f: FileChange) -> bool:
    """Renamed or copied from a path that is not the same kind of lockfile
    (tests/fixtures/lock.json -> package-lock.json): the old file was never
    checked as this lockfile, so nothing in it counts as already known."""
    return f.old_path is not None and _kind(f.old_path) != _kind(f.path)


def parsed_lockfile(f: FileChange) -> bool:
    """A lockfile the check parses whole."""
    return f.status != "deleted" and (PurePosixPath(f.path).name.casefold()
                                      in _JSON_LOCKS | _TOML_LOCKS | _YAML_LOCKS)


def fetched_lockfile(f: FileChange) -> bool:
    """A lockfile core fetches whole: a parsed one, or a line-checked one
    renamed from another kind (a rename shows only the lines it changed)."""
    return parsed_lockfile(f) or (f.status != "deleted" and _allowlist(f.path) is not None
                                  and renamed_from_other_kind(f))


# JSON / TOML / YAML double-quoted string escapes, for the line-checked
# formats: yarn v1 quotes JSON-style, and decoding is conservative for the
# others. Package managers decode these before resolving a URL.
_ESCAPE = re.compile(r"\\(u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|x[0-9A-Fa-f]{2}|.)")
_SIMPLE_ESCAPES = {"/": "/", "\\": "\\", '"': '"', "'": "'", "b": "\b", "f": "\f",
                   "n": "\n", "r": "\r", "t": "\t"}
_SCHEMEISH = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*(?::|\\)")


def _decode_escapes(text: str) -> tuple[str, bool]:
    """(decoded text, whether an escape was left undecoded)."""
    unknown = False

    def one(m: re.Match) -> str:
        nonlocal unknown
        e = m.group(1)
        if len(e) > 1 and int(e[1:], 16) <= 0x10FFFF:
            return chr(int(e[1:], 16))
        if e in _SIMPLE_ESCAPES:
            return _SIMPLE_ESCAPES[e]
        unknown = True
        return m.group(0)

    return _ESCAPE.sub(one, text), unknown


def _urls(text: str):
    """(scheme, authority) pairs. Scheme matches are only "word:", so a junk
    prefix like "x:https://evil.x" can't swallow the real URL after it."""
    for m in _SCHEME.finditer(text):
        slashes, netloc = _AUTHORITY.match(text, m.end()).groups()
        if netloc and (_KNOWN_SCHEME.fullmatch(m.group(1)) or len(slashes) >= 2):
            yield m.group(1), netloc


def _host(netloc: str) -> str:
    host = netloc.rsplit("@", 1)[-1]
    if host.startswith("["):  # IPv6 literal: never in an allowlist
        return host[:host.find("]") + 1].lower() if "]" in host else host.lower()
    return host.split(":", 1)[0].lower().rstrip(".")


def _odd_userinfo(scheme: str, netloc: str) -> bool:
    """Userinfo in a URL authority is a host-confusion vector; the only kind
    lockfiles legitimately carry is ssh's "git@"."""
    if "@" not in netloc:
        return False
    return not (scheme.lower() in ("ssh", "git+ssh") and netloc.count("@") == 1
                and netloc.startswith("git@"))


def _continues(line: str, pip: bool) -> bool:
    """The line ends in a backslash-newline continuation that can glue the
    next line onto a URL ("https://pypi.org\\" + ".evil.x/simple").

    An odd trailing backslash run (an even one is escaped backslashes);
    whitespace after it is ignored. pip joins on ANY trailing backslash run,
    so parity does not matter there, but pip-compile's own "pkg==1.0 \\"
    puts whitespace before it, which cannot glue a URL.
    """
    body = line.rstrip()
    n = len(body) - len(body.rstrip("\\"))
    if not pip:
        return n % 2 == 1
    prev = body[:len(body) - n][-1:]
    return n > 0 and prev != "" and not prev.isspace()


def _bad_urls(text: str, allowed: frozenset[str]) -> list[str]:
    # Parse the way npm/Node (WHATWG URL) does: tab/newline are stripped
    # anywhere and a backslash is a path separator, so
    # "https://evil\@registry.npmjs.org" goes to evil.
    text = re.sub(r"[\t\n\r]", "", text).replace("\\", "/")
    bad = []
    for scheme, netloc in _urls(text):
        host = _host(netloc)
        if scheme.lower() not in _OK_SCHEMES or host not in allowed or _odd_userinfo(scheme, netloc):
            bad.append(f"{scheme.lower()}://{host}")
    return bad


_PIP_COMMENT = re.compile(r"(^|\s+)#.*$")  # pip's COMMENT_RE
_PIP_ATTACHED = re.compile(r"-[icref].")    # pip's short options that take a value


def _pip_options(line: str) -> str | None:
    """The line's options as pip reads them (req_file.py): comment dropped,
    everything from the first token starting with "-" shlex-split, and a
    short option's attached value ("-iURL", which optparse accepts) split
    off. None when shlex cannot split them (pip then refuses the line)."""
    line = _PIP_COMMENT.sub("", line).strip().removesuffix("\\")  # pip joins continuations
    tokens = line.split(" ")
    start = next((i for i, t in enumerate(tokens) if t.startswith("-")), len(tokens))
    try:
        opts = shlex.split(" ".join(tokens[start:]))
    except ValueError:
        return None
    return " ".join(f"{t[:2]} {t[2:]}" if _PIP_ATTACHED.match(t) else t for t in opts)


def _line_hits(f: FileChange, allowed: frozenset[str], lines) -> list[Hit]:
    pip = _kind(f.path) == "requirements"
    yarn = _kind(f.path) == "yarn.lock"
    hits = []
    for line_no, original in lines:
        text, undecoded = _decode_escapes(original)
        bad = []
        if _continues(original, pip):
            bad.append("line continuation")
        if undecoded and _SCHEMEISH.search(text):
            bad.append("undecodable escape near a URL")
        bad += _bad_urls(text, allowed)
        if pip:
            opts = _pip_options(original)
            bad += ["options pip cannot split"] if opts is None else _bad_urls(opts, allowed)
        if yarn:
            bad += _yarn_v1_line_bad(text)
        if bad:
            hits.append(Hit("lockfile-host", f.path,
                            f"line {line_no}: not allowlisted: {', '.join(bad[:4])}", False))
    return hits


def _unique_keys(pairs):
    """JSON object without duplicate keys: parsers disagree on which wins."""
    out = dict(pairs)
    if len(out) != len(pairs):
        raise ValueError("duplicate key")
    return out


class _YamlLoader(getattr(yaml, "CSafeLoader", yaml.SafeLoader)):
    """safe_load, minus duplicate keys (parsers disagree on which wins)."""

    def construct_mapping(self, node, deep=False):
        out = super().construct_mapping(node, deep=deep)
        if len(out) != len(node.value):
            raise yaml.YAMLError("duplicate key")
        return out


# bun.lock is JSON with trailing commas. Strings are skipped whole, so a
# comma inside one stays; anything else non-JSON (a comment) fails to parse.
_TRAILING_COMMA = re.compile(r'"(?:[^"\\\n]|\\.)*"|,(?=[ \t\r\n]*[\]}])')


def _load(name: str, data: bytes):
    """The parsed document. Raises ValueError, RecursionError or YAMLError."""
    text = data.decode("utf-8-sig")
    if name in _TOML_LOCKS:
        return tomllib.loads(text)
    if name in _YAML_LOCKS:
        return yaml.load(text, Loader=_YamlLoader)  # noqa: S506 - a SafeLoader
    if name == "bun.lock":
        text = _TRAILING_COMMA.sub(lambda m: "" if m.group(0) == "," else m.group(0), text)
    return json.loads(text, object_pairs_hook=_unique_keys)


# Package-entry metadata that no npm-family package manager fetches from:
# npm's `funding` (string, {type, url}, or a list of those), `deprecated`
# messages (npm, pnpm) and `license`. Exempt only inside a package entry
# (a mapping with `version` or `resolution`) and only in that shape, so a
# package or dependency NAMED "funding" is still checked.
_METADATA_KEYS = frozenset({"funding", "deprecated", "license"})


def _metadata(entry: dict, key) -> bool:
    if key not in _METADATA_KEYS or not ("version" in entry or "resolution" in entry):
        return False
    v = entry[key]
    return all(isinstance(i, str) or (isinstance(i, dict) and set(i) <= {"type", "url"}
                                      and all(isinstance(x, str) for x in i.values()))
               for i in (v if isinstance(v, list) else [v]))


def _strings(doc, skip_metadata: bool = False):
    """Every string in a parsed document, mapping keys included (minus
    npm-family package metadata if asked). A container reached twice is a
    YAML alias: lockfiles never use them, and expanding them can explode,
    so that does not parse."""
    seen: set[int] = set()
    stack = [doc]
    while stack:
        v = stack.pop()
        if isinstance(v, (dict, list, tuple)):
            if id(v) in seen:
                raise ValueError("alias")
            seen.add(id(v))
            if isinstance(v, dict):
                stack.extend(v.keys())
                stack.extend(x for k, x in v.items()
                             if not (skip_metadata and _metadata(v, k)))
            else:
                stack.extend(v)
        elif isinstance(v, bytes):  # YAML !!binary: a JS consumer stringifies it
            yield v.decode("utf-8", errors="replace")
        elif isinstance(v, str):
            yield v


# npm-family lockfiles also name packages by SPEC, with no URL in sight:
# npm/pacote, yarn, pnpm and bun fetch "github:o/r#sha" or a bare "o/r#sha"
# from that host. So in these files (a) a hosted-git protocol anywhere in a
# string, or a leading "word:" protocol outside a small safe set, is a
# finding; and (b) each fetch slot (npm `resolved`, pnpm `resolution`, the
# bun and Berry "name@spec" entries, yarn v1 `resolved`) must be an https
# URL (whose host the URL check above judges) or a local relative path.
_NPM_LOCKS = frozenset({"package-lock.json", "npm-shrinkwrap.json", "bun.lock",
                        "yarn.lock", "pnpm-lock.yaml"})
_GIT_WORD = r"(?:[A-Za-z0-9.-]+\+)?(?:git|github|gitlab|bitbucket|gist)(?:\+[A-Za-z0-9.-]+)?"
_GIT_SPEC = re.compile(r"(?<![A-Za-z0-9+./-])(" + _GIT_WORD + r"):(?!\s)", re.I)
_SPEC_PREFIX = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*):(?!\s)")
_LOCAL_PROTOCOLS = frozenset({"file", "link", "portal"})
# npm: aliases a registry name; workspace: and catalog: resolve inside the
# repo; patch: wraps another locator that the lockfile also resolves itself.
_SAFE_PROTOCOLS = frozenset({"npm", "workspace", "catalog", "patch"}) | _LOCAL_PROTOCOLS
_VERSION = re.compile(r"[0-9][0-9A-Za-z.+-]*")
NOT_FETCHABLE = "fetch slot that is not an https URL or a local path"


def _local(ref: str) -> bool:
    """A relative local path (yarn may append "#..." or "::params")."""
    path = re.split(r"#|::", ref, maxsplit=1)[0]
    return bool(path) and not path.startswith(("/", "\\", "~")) and ":" not in path


def _https(v) -> bool:
    return isinstance(v, str) and v[:6].lower() == "https:"


def _git_specs(s: str) -> list[str]:
    return [f"hosted-git spec {m.group(1).lower()[:32]}:" for m in _GIT_SPEC.finditer(s)]


def _spec_bad(s: str) -> list[str]:
    """Package-spec findings for one string of an npm-family lockfile."""
    bad = _git_specs(s)
    m = _SPEC_PREFIX.match(s)
    if m:
        word = m.group(1).lower()
        if re.fullmatch(_GIT_WORD, word) or _KNOWN_SCHEME.fullmatch(word):
            pass  # reported above, or a URL for the URL check
        elif word not in _SAFE_PROTOCOLS:
            bad.append(f"package spec protocol {word[:32]}:")
        elif word in _LOCAL_PROTOCOLS and not _local(s[m.end():]):
            bad.append(f"{word}: reference that is not a relative path")
    return bad


def _resolved_bad(v, link=False) -> bool:
    """npm's `resolved` (and pnpm's tarball): an https URL, a `file:`
    relative path, or a bare relative path where npm marks `link: true`."""
    if _https(v):
        return False
    if isinstance(v, str) and v[:5].lower() == "file:" and _local(v[5:]):
        return False
    return not (link is True and isinstance(v, str) and _local(v))


def _spec_slot_bad(ident) -> bool:
    """The spec half of a bun or Berry "name@spec" entry: a version, an
    https URL, or a safe protocol (a local one with a relative path)."""
    at = ident.find("@", 1) if isinstance(ident, str) else -1
    if at < 1:
        return True
    spec = ident[at + 1:]
    if _VERSION.fullmatch(spec) or _https(spec):
        return False
    m = _SPEC_PREFIX.match(spec)
    word = m.group(1).lower() if m else ""
    return word not in _SAFE_PROTOCOLS or (word in _LOCAL_PROTOCOLS
                                           and not _local(spec[m.end():]))


def _pnpm_resolution_bad(res) -> bool:
    if not isinstance(res, dict) or "repo" in res or res.get("type") not in (None, "directory"):
        return True  # a git resolution, or not one pnpm writes
    if "tarball" in res and _resolved_bad(res["tarball"]):
        return True
    return "directory" in res and not (isinstance(res["directory"], str)
                                       and _local(res["directory"]))


def _dicts(v) -> list[dict]:
    return [x for x in v.values() if isinstance(x, dict)] if isinstance(v, dict) else []


def _npm_slots_bad(name: str, doc):
    """One NOT_FETCHABLE per fetch slot that is neither https nor local."""
    if not isinstance(doc, dict):
        return
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        for e in _dicts(doc.get("packages")):
            if "resolved" in e and _resolved_bad(e["resolved"], e.get("link")):
                yield NOT_FETCHABLE
        stack = [doc.get("dependencies")]  # lockfile v1: nested to any depth
        while stack:
            for e in _dicts(stack.pop()):
                if "resolved" in e and _resolved_bad(e["resolved"]):
                    yield NOT_FETCHABLE
                stack.append(e.get("dependencies"))
    elif name == "pnpm-lock.yaml":
        for e in _dicts(doc.get("packages")):
            if "resolution" in e and _pnpm_resolution_bad(e["resolution"]):
                yield NOT_FETCHABLE
    elif name == "bun.lock":
        packages = doc.get("packages")
        for e in packages.values() if isinstance(packages, dict) else ():
            if not isinstance(e, list) or not e:
                continue
            # ["name@1.0.0", "<tarball URL, or empty for the registry>", {...}, "sha512-..."]
            if _spec_slot_bad(e[0]) or (len(e) > 1 and isinstance(e[1], str)
                                        and e[1] and not _https(e[1])):
                yield NOT_FETCHABLE
    elif name == "yarn.lock":
        for e in _dicts(doc):
            if "resolution" in e and _spec_slot_bad(e["resolution"]):  # Berry
                yield NOT_FETCHABLE
            if "resolved" in e and _resolved_bad(e["resolved"]):  # v1 read as YAML
                yield NOT_FETCHABLE


_YARN_V1_RESOLVED = re.compile(r'\s+resolved\s+"?([^"]*)"?\s*$')


def _yarn_v1_line_bad(text: str) -> list[str]:
    bad = _git_specs(text)
    m = _YARN_V1_RESOLVED.match(text)
    if m and _resolved_bad(m.group(1)):
        bad.append(NOT_FETCHABLE)
    return bad


def _flake_bad(doc, allowed: frozenset[str]):
    nodes = doc.get("nodes") if isinstance(doc, dict) else None
    for node in nodes.values() if isinstance(nodes, dict) else ():
        for ref in (node.get("locked"), node.get("original")) if isinstance(node, dict) else ():
            if not isinstance(ref, dict):
                continue
            kind = ref.get("type")
            if not isinstance(kind, str) or kind not in _FLAKE_TYPES_OK:
                yield f"flake input type {kind}"
            host = ref.get("host")
            if host is not None and str(host).lower() not in allowed:
                yield f"flake host {host}"


def _findings(name: str, data: bytes, allowed: frozenset[str]) -> Counter:
    """Bad values in a parsed lockfile, counted. Raises if it does not parse."""
    doc = _load(name, data)
    npm = name in _NPM_LOCKS
    bad: Counter = Counter()
    for s in _strings(doc, skip_metadata=npm):
        if _CONTROL.search(s):
            bad[MULTI_LINE] += 1
        # Berry percent-encodes locators inside locators
        # (npm:1.0.0::__archiveUrl=https%3A%2F%2F...): check both forms.
        for t in dict.fromkeys((s, unquote(s))) if npm else (s,):
            bad.update(_bad_urls(t, allowed))
            if npm:
                bad.update(_spec_bad(t))
    if npm:
        bad.update(_npm_slots_bad(name, doc))
    if name == "flake.lock":
        bad.update(_flake_bad(doc, allowed))
    return bad


_UNPARSED = (ValueError, RecursionError, yaml.YAMLError)


def _parsed_hits(f: FileChange, name: str, allowed: frozenset[str],
                 lf: Lockfile | None, yarn_v1: bool) -> list[Hit]:
    """Only values NEW relative to the base: one already on the default
    branch must not block every later change to the file."""
    if lf is None or lf.head is None:
        return [Hit("lockfile-host", f.path, "lockfile too large to check", False)]
    try:
        head = _findings(name, lf.head, allowed)
    except _UNPARSED:
        # Classic yarn's own format is not YAML; it is checked line by line.
        return [] if yarn_v1 else [Hit("lockfile-host", f.path, "lockfile does not parse", False)]
    base: Counter = Counter()
    if lf.base is not None:
        try:
            base = _findings(name, lf.base, allowed)
        except _UNPARSED:
            base = Counter()  # a base that does not parse has no findings
    new = sorted(head - base)
    if not new:
        return []
    return [Hit("lockfile-host", f.path, f"not allowlisted: {', '.join(new[:4])}", False)]


def _checked_lines(f: FileChange, lf: Lockfile | None):
    """The lines the per-line check reads: the added ones, or every line of
    a file renamed from another kind."""
    if not renamed_from_other_kind(f):
        return f.added
    if lf is None or lf.head is None:
        return None
    return enumerate(lf.head.decode("utf-8", errors="replace").split("\n"), 1)


def lockfile_hosts(files: list[FileChange], lockfiles: dict[str, Lockfile]) -> list[Hit]:
    hits = []
    for f in files:
        allowed = _allowlist(f.path)
        if allowed is None or f.status == "deleted":
            continue
        name = PurePosixPath(f.path).name.casefold()
        lf = lockfiles.get(f.path)
        if not parsed_lockfile(f):
            lines = _checked_lines(f, lf)
            hits += (_line_hits(f, allowed, lines) if lines is not None else
                     [Hit("lockfile-host", f.path, "lockfile too large to check", False)])
            continue
        # yarn.lock with the v1 header is classic yarn's line format, which
        # classic yarn falls back to reading as YAML: check both readings.
        yarn_v1 = (name == "yarn.lock" and lf is not None and lf.head is not None
                   and bool(_YARN_V1.match(lf.head.decode("utf-8", errors="replace"))))
        hits += _parsed_hits(f, name, allowed, lf, yarn_v1)
        if yarn_v1:
            hits += _line_hits(f, allowed, _checked_lines(f, lf))
    return hits


# ----- extra scrutiny (not blocking; listed for the model) -------------------

_INSTALL = re.compile(r"^(install|setup|bootstrap|preinstall|postinstall)([._-].*)?$", re.I)
_MANIFESTS = frozenset({"package.json", "pyproject.toml", "setup.cfg", "cargo.toml",
                        "gemfile", "go.mod", "makefile", "dockerfile", ".gitattributes",
                        ".gitmodules", ".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf"})
_VENDORED_DIRS = frozenset({"dist", "vendor", "vendored", "third_party", "node_modules",
                            "generated", "build"})
# Files a dev tool runs or obeys on its own (direnv, devcontainers, editor
# tasks, git hooks, tool managers, cargo/pnpm/bun config).
_AUTORUN_NAMES = frozenset({".envrc", ".pre-commit-config.yaml", "mise.toml", ".mise.toml",
                            ".tool-versions", ".pnpmfile.cjs", "bunfig.toml", "lefthook.yml"})
_AUTORUN_IN_DIR = frozenset({(".vscode", "tasks.json"), (".vscode", "settings.json"),
                             (".vscode", "launch.json"), (".cargo", "config.toml"),
                             (".cargo", "config")})
_AUTORUN_DIRS = frozenset({".devcontainer", ".husky"})


def _dev_autorun(p: PurePosixPath) -> bool:
    name, parent = p.name.casefold(), p.parent.name.casefold()
    return (name in _AUTORUN_NAMES or (parent, name) in _AUTORUN_IN_DIR
            or any(d.casefold() in _AUTORUN_DIRS for d in p.parts[:-1]))


def scrutiny(files: list[FileChange]) -> list[Scrutiny]:
    out = []
    for f in files:
        if f.status == "deleted":
            continue
        p = PurePosixPath(f.path)
        name = p.name.casefold()
        reasons = []
        if p.suffix == ".nix":
            reasons.append("nix")
        if _allowlist(f.path) is not None:
            reasons.append("lockfile")
        if name == "build.rs":
            reasons.append("build-script")
        if _INSTALL.match(p.name) and p.suffix in ("", ".sh", ".py", ".ps1", ".bash", ".js"):
            reasons.append("install-script")
        if name in _MANIFESTS:
            reasons.append("package-manifest")
        if _dev_autorun(p):
            reasons.append("dev-autorun")
        if ".min." in name or any(part in _VENDORED_DIRS for part in p.parts[:-1]):
            reasons.append("minified-or-vendored")
        if f.new_mode == "120000":
            reasons.append("symlink")
        if f.gitlink:
            reasons.append("submodule")
        if any(len(t) > LONG_LINE for _, t in f.added):
            reasons.append("long-line")
        out.extend(Scrutiny(f.path, r) for r in reasons)
    return out


def run_all(files: list[FileChange], contents: dict[str, bytes | None],
            exceptions: list[str], lockfiles: dict[str, Lockfile], *,
            always_on_only: bool = False
            ) -> tuple[list[Hit], list[Scrutiny]]:
    """All deterministic hits and the extra-scrutiny list.

    `always_on_only` (owner override, carry-over) keeps only the hits no
    override can clear.
    """
    path_hits, exempted = sensitive_paths(files, exceptions)
    hits = (hidden_unicode(files) + lockfile_hosts(files, lockfiles)
            + binaries(files, contents) + submodules(files) + path_hits)
    if always_on_only:
        hits = [h for h in hits if not h.overridable]
    return hits, exempted + scrutiny(files)
