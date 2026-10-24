"""Deterministic checks. Any hit blocks.

Three of them (hidden Unicode, lockfile hosts, a text file git treats as
binary) are ALWAYS-ON: they have no legitimate trigger, so neither the owner
override nor the `exceptions` input can turn them off. The other binary and
path rules are owner-overridable, and the path rule can be downgraded per
repo to "extra scrutiny".

Everything here is pure: diff in, hits out. Fetching lives in core.py.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from injection_scanner.unicode_sanitize import find_hidden

from .diffparse import FileChange

LONG_LINE = 500


@dataclass(frozen=True)
class Hit:
    rule: str          # hidden-unicode | lockfile-host | text-binary | binary | sensitive-path | too-large
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

def hidden_unicode(files: list[FileChange]) -> list[Hit]:
    hits = []
    for f in files:
        for p in {f.path, f.old_path} - {None}:
            found = find_hidden(p, "code")
            if found:
                hits.append(Hit("hidden-unicode", f.path,
                                f"in the file path: {_u(cp for _, cp in found)}", False))
        for line_no, text in f.added:
            found = find_hidden(text, "code")
            if found:
                hits.append(Hit("hidden-unicode", f.path,
                                f"line {line_no}: {_u(cp for _, cp in found)}", False))
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


# Source/text extensions. Git calls such a file binary when it holds e.g. a
# NUL byte; then no added lines reach the model or the Unicode and lockfile
# checks, so nobody can see what it says.
# Such a file is a text-binary hit whatever its content looks like.
_TEXT_EXTS = frozenset("""
    js mjs cjs ts tsx jsx py rb go rs java kt c h cc cpp hpp cs php sh bash zsh fish ps1
    pl lua nix json yaml yml toml ini cfg conf md txt html css scss sql xml svg lock
""".split())
TEXT_BINARY = "text file with binary content (e.g. NUL bytes); no reviewer can see it"


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
        # Whatever its magic: an ASCII one ("MZ", "BZh", "GIF89a") is easy
        # to type at the top of a text file whose NUL byte hides the rest.
        if ext in _TEXT_EXTS:
            hits.append(Hit("text-binary", f.path, TEXT_BINARY, False))
            continue
        expected = _EXT_KIND.get(ext)
        if data is None:
            detail = "binary file; content not fetched"
        elif kind is None:
            detail = "binary file; unrecognised content type"
        elif expected is not None and kind != expected:
            detail = f"binary file; mismatch: content is {kind}, extension says {expected}"
        else:
            detail = f"binary file; content is {kind}"
        if kind in _EXECUTABLE:
            detail += " (executable)"
        hits.append(Hit("binary", f.path, detail, True))
    return hits


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
_REQUIREMENTS = re.compile(r"^(requirements|constraints)[\w.-]*\.txt$")
_OK_SCHEMES = frozenset({"https", "git+https", "registry+https", "sparse+https",
                         "git+ssh", "ssh"})
# A URL is a scheme from a fixed set (http, https, ftp, ws, wss, git, ssh,
# or `<word>+` one of those, like git+https or sparse+https) followed by
# ":" and ANY run of slashes, even none: WHATWG/npm read "https:evil.x" and
# "https:///evil.x" as host evil.x. Any other "scheme://" is a URL too
# (including file://); a bare local `file:../pkg` reference is not.
_SCHEME = re.compile(r"(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]*):")
_KNOWN_SCHEME = re.compile(r"(?:\w+\+)?(?:https?|ftp|wss?|git|ssh)", re.I)
_AUTHORITY = re.compile(r"(/*)([^/?#\s\"'`]*)")
_FLAKE_TYPE = re.compile(r'"type"\s*:\s*"([^"]*)"')
_FLAKE_HOST = re.compile(r'"host"\s*:\s*"([^"]*)"')
_FLAKE_TYPES_OK = frozenset({"github", "git", "tarball", "file", "path", "indirect"})


def _allowlist(path: str) -> frozenset[str] | None:
    name = PurePosixPath(path).name.casefold()
    if name in _LOCKFILES:
        return _LOCKFILES[name]
    if _REQUIREMENTS.match(name):
        return _PY
    return None


# JSON / TOML / YAML double-quoted string escapes. Package managers decode
# these before resolving a URL, so `https:\/\/evil` is a URL to them.
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
    next line onto a URL ("https://registry.npmjs.org\\" + ".evil.x/p.tgz").

    YAML/TOML: an odd trailing backslash run (an even one is escaped
    backslashes); TOML allows whitespace after it. pip joins on ANY trailing
    backslash run, so parity does not matter there, but pip-compile's own
    "pkg==1.0 \\" puts whitespace before it, which cannot glue a URL.
    """
    body = line.rstrip()
    n = len(body) - len(body.rstrip("\\"))
    if not pip:
        return n % 2 == 1
    prev = body[:len(body) - n][-1:]
    return n > 0 and prev != "" and not prev.isspace()


def lockfile_hosts(files: list[FileChange]) -> list[Hit]:
    hits = []
    for f in files:
        allowed = _allowlist(f.path)
        if allowed is None:
            continue
        flake = PurePosixPath(f.path).name == "flake.lock"
        pip = bool(_REQUIREMENTS.match(PurePosixPath(f.path).name.casefold()))
        for line_no, original in f.added:
            text, undecoded = _decode_escapes(original)
            bad = []
            if _continues(original, pip):
                bad.append("line continuation")
            if undecoded and _SCHEMEISH.search(text):
                bad.append("undecodable escape near a URL")
            # Parse the way npm/Node (WHATWG URL) does: tab/newline are
            # stripped anywhere and a backslash is a path separator, so
            # "https://evil\@registry.npmjs.org" goes to evil.
            text = re.sub(r"[\t\n\r]", "", text).replace("\\", "/")
            for scheme, netloc in _urls(text):
                host = _host(netloc)
                if scheme.lower() not in _OK_SCHEMES or host not in allowed or _odd_userinfo(scheme, netloc):
                    bad.append(f"{scheme.lower()}://{host}")
            if flake:
                for kind in _FLAKE_TYPE.findall(text):
                    if kind not in _FLAKE_TYPES_OK:
                        bad.append(f"flake input type {kind}")
                for host in _FLAKE_HOST.findall(text):
                    if host.lower() not in allowed:
                        bad.append(f"flake host {host}")
            if bad:
                hits.append(Hit("lockfile-host", f.path,
                                f"line {line_no}: not allowlisted: {', '.join(bad[:4])}", False))
    return hits


# ----- extra scrutiny (not blocking; listed for the model) -------------------

_INSTALL = re.compile(r"^(install|setup|bootstrap|preinstall|postinstall)([._-].*)?$", re.I)
_MANIFESTS = frozenset({"package.json", "pyproject.toml", "setup.cfg", "cargo.toml",
                        "gemfile", "go.mod", "makefile", "dockerfile", ".gitattributes",
                        ".gitmodules", ".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf"})
_VENDORED_DIRS = frozenset({"dist", "vendor", "vendored", "third_party", "node_modules",
                            "generated", "build"})


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
        if ".min." in name or any(part in _VENDORED_DIRS for part in p.parts[:-1]):
            reasons.append("minified-or-vendored")
        if f.new_mode == "120000":
            reasons.append("symlink")
        if f.new_mode == "160000":
            reasons.append("submodule")
        if any(len(t) > LONG_LINE for _, t in f.added):
            reasons.append("long-line")
        out.extend(Scrutiny(f.path, r) for r in reasons)
    return out


def run_all(files: list[FileChange], contents: dict[str, bytes | None],
            exceptions: list[str], *, always_on_only: bool = False
            ) -> tuple[list[Hit], list[Scrutiny]]:
    """All deterministic hits and the extra-scrutiny list.

    `always_on_only` (owner override, carry-over) keeps only the hits no
    override can clear.
    """
    path_hits, exempted = sensitive_paths(files, exceptions)
    hits = hidden_unicode(files) + lockfile_hosts(files) + binaries(files, contents) + path_hits
    if always_on_only:
        hits = [h for h in hits if not h.overridable]
    return hits, exempted + scrutiny(files)
