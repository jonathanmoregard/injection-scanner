"""
Fail-loud secret loading with a three-tier precedence: FILE > env > keyring.

The FILE tier exists to support the agenix pattern. agenix (and comparable
secret managers such as sops-nix or Kubernetes mounted secrets) does NOT
inject a secret's *value* into a service's environment. Instead it decrypts
the secret to a FILE at a well-known path — e.g.

    config.age.secrets.lakera-api-key.path
      => /run/agenix/lakera-api-key

— and the service reads that file at startup. The conventional wiring is to
pass the path (not the value) into the service environment under a `*_FILE`
variable, e.g. `LAKERA_API_KEY_FILE=/run/agenix/lakera-api-key`.

Design principle (from the maintainer): **all config issues must lead to
loud rejection, never silent degradation.** A `*_FILE` variable that is set
but points at a missing / unreadable / empty file is a *botched mount* — the
operator intended agenix to provide the secret and it didn't arrive. Silently
falling through to the env var or keyring in that case would mask a real
deployment failure. So the fail-loud contract is:

    If a FILE path is CONFIGURED (the `*_FILE` env var is set) it MUST
    resolve to a non-empty, readable file, or `load_key` raises
    KeyConfigError. It never falls through to a lower tier.

The lower tiers are ordinary best-effort lookups: a plain env var, then the
user keyring via `secret-tool`. Keyring *absence* (secret not found) is not a
misconfiguration and yields None. `load_key` returns None only when NO source
is configured at all; the caller decides whether that is fatal (for the
honeypot and the Lakera layer, it is — they reject).
"""
from __future__ import annotations

import os
import pathlib
import subprocess


class KeyConfigError(Exception):
    """Raised on a LOUD misconfiguration — a configured secret source that
    is broken (e.g. a `*_FILE` path that is set but missing / unreadable /
    empty). Never raised for mere absence of a source."""


def _keyring_env() -> dict[str, str]:
    """Ensure secret-tool can reach the user's D-Bus session bus. MCP-server
    subprocesses may not inherit DBUS_SESSION_BUS_ADDRESS; fall back to the
    systemd per-user path."""
    env = dict(os.environ)
    if "DBUS_SESSION_BUS_ADDRESS" not in env:
        bus = f"/run/user/{os.getuid()}/bus"
        if pathlib.Path(bus).exists():
            env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus}"
    if "XDG_RUNTIME_DIR" not in env:
        xdg = f"/run/user/{os.getuid()}"
        if pathlib.Path(xdg).is_dir():
            env["XDG_RUNTIME_DIR"] = xdg
    return env


def _keyring(keyring_key: str) -> str | None:
    """Best-effort keyring lookup. Absence (secret not found) and any
    unexpected secret-tool error both reduce to None — a keyring miss is not
    a misconfiguration, so it must not be loud."""
    try:
        r = subprocess.run(
            ["secret-tool", "lookup", "app", "research-agent", "key", keyring_key],
            capture_output=True, text=True, timeout=3,
            env=_keyring_env(),
        )
        return r.stdout.strip() or None
    except Exception:
        return None


def load_key(*, file_env: str, env_var: str, keyring_key: str) -> str | None:
    """Resolve a secret across three tiers with FAIL-LOUD semantics.

    Precedence:
      1. FILE (agenix pattern): if ``os.environ[file_env]`` is set, a path
         was provided — agenix (or similar) is wired. Read that file. If it
         is missing, unreadable, or empty/whitespace-only, raise
         KeyConfigError naming ``file_env`` and the path. This is a botched
         mount and MUST be loud rather than silently falling through. On
         success, return the stripped file contents.
      2. env: else if ``os.environ[env_var]`` is set and non-empty, return it.
      3. keyring: else look the secret up via ``secret-tool``; return the
         value or None. A keyring miss (or unexpected secret-tool error)
         returns None — absence is not a misconfiguration.

    Returns None only when NO source is configured. The caller decides
    whether that is fatal.
    """
    file_path = os.environ.get(file_env)
    if file_path is not None and file_path != "":
        p = pathlib.Path(file_path)
        try:
            raw = p.read_text(encoding="utf-8")
        except FileNotFoundError as e:
            raise KeyConfigError(
                f"{file_env} is set to {file_path!r} but that file does not "
                f"exist (botched agenix/secret mount)"
            ) from e
        except OSError as e:
            raise KeyConfigError(
                f"{file_env} is set to {file_path!r} but that file could not "
                f"be read: {type(e).__name__} (botched agenix/secret mount)"
            ) from e
        value = raw.strip()
        if not value:
            raise KeyConfigError(
                f"{file_env} is set to {file_path!r} but that file is empty / "
                f"whitespace-only (botched agenix/secret mount)"
            )
        return value

    env_value = os.environ.get(env_var)
    if env_value:
        return env_value

    return _keyring(keyring_key)
