"""Scanner self-update: refresh this package from its git remote at boot.

Consumers (long-lived MCP servers and similar) call `maybe_update()` at
process start so every boot runs the current scanner without a deploy
step. Cheap on the steady state (one `git ls-remote` + a sha-file read),
bounded on the bumped state (one `uv pip install --force-reinstall`).

IMPORT-ORDER CONTRACT (read this before wiring it in):
`maybe_update()` must run BEFORE the consumer imports any other
`injection_scanner` module in the same process. Python caches imported
modules, so anything imported before the update keeps serving the OLD
version for the life of the process — the fresh install only takes
effect for modules imported after it. Call `maybe_update()` first, then
import `injection_scanner.intercept` etc.

uv interplay: a consumer spawned via `uv run` has its environment synced
back to its lockfile before the process starts, so any previous
force-install is undone at spawn. That is fine: `maybe_update()` then
force-installs the resolved SHA again, and that install wins for this
process (given the import-order contract above).

Failure policy: offline, missing tooling, or a failed install all
degrade to "keep installed version, log a warning" — this function is
availability-first and is NOT the correctness gate. The consumer's
fail-closed boot smoke (e.g. `injection_scanner.smoke.run_smoke`) runs
after this and must refuse to serve if the installed scanner — fresh or
stale — cannot pass its canary set.
"""
from __future__ import annotations

import logging
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_REPO = "https://github.com/jonathanmoregard/injection-scanner.git"
DEFAULT_BRANCH = "main"


def _logger(log: logging.Logger | None) -> logging.Logger:
    return log if log is not None else logging.getLogger("injection_scanner.selfupdate")


def resolve_remote_sha(
    repo: str = DEFAULT_REPO,
    branch: str = DEFAULT_BRANCH,
    log: logging.Logger | None = None,
) -> str | None:
    """Return the remote head SHA of `branch` via `git ls-remote`. None on
    offline or network failure — caller treats that as "skip update, keep
    installed version". Times out at 5s so an offline boot doesn't hang
    the consumer's spawn forever."""
    log = _logger(log)
    try:
        r = subprocess.run(
            ["git", "ls-remote", repo, branch],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.warning("scanner update: ls-remote unavailable (%s) — keeping installed version", e)
        return None
    if r.returncode != 0:
        log.warning("scanner update: ls-remote returned %d — keeping installed version", r.returncode)
        return None
    sha = r.stdout.split(maxsplit=1)[0] if r.stdout else ""
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha.lower()):
        log.warning("scanner update: ls-remote produced unparseable SHA %r — keeping installed version", sha[:20])
        return None
    return sha


def maybe_update(
    repo: str = DEFAULT_REPO,
    branch: str = DEFAULT_BRANCH,
    cache_dir: Path | None = None,
    venv_python: Path | str | None = None,
    log: logging.Logger | None = None,
) -> None:
    """Refresh the injection-scanner package from `repo`@`branch` if its
    head has moved since the last successful install on this machine.

    `cache_dir` (default `~/.cache/injection-scanner`) holds the sha
    cache file and the install lock. `venv_python` (default
    `sys.executable`) selects the environment `uv pip install` targets.

    Concurrency: several consumer processes can spawn from parallel tool
    calls. We hold a flock around the install so two concurrent
    --force-reinstall calls can't corrupt site-packages; after acquiring
    the lock we re-read the cache, because a peer may have already
    installed the same SHA.

    Offline / failed install: degrades to "keep installed version, log a
    warning". The consumer still boots — a scanner update must not take
    the service down because the remote is unreachable for 30 seconds.
    This function is NOT the correctness gate: the consumer's fail-closed
    boot smoke runs after it, so a stale scanner still has to pass the
    canary set before the consumer serves.
    """
    import fcntl

    log = _logger(log)
    if cache_dir is None:
        cache_dir = Path.home() / ".cache" / "injection-scanner"
    sha_cache = cache_dir / "sha"
    install_lock = cache_dir / "install.lock"

    t_remote = time.monotonic()
    remote_sha = resolve_remote_sha(repo, branch, log)
    log.info(
        "scanner update: ls-remote took_ms=%d resolved=%s",
        int((time.monotonic() - t_remote) * 1000), remote_sha or "none",
    )
    if remote_sha is None:
        return

    try:
        cached = sha_cache.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        cached = ""

    if cached == remote_sha:
        return  # steady state — fast path

    install_lock.parent.mkdir(parents=True, exist_ok=True)
    with install_lock.open("w") as lf:
        # Block until any concurrent installer finishes. After we
        # acquire, re-read the cache — the other process may have
        # already installed the same SHA, and we should skip.
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            cached = sha_cache.read_text(encoding="ascii").strip()
        except FileNotFoundError:
            cached = ""
        if cached == remote_sha:
            return  # peer installed; nothing more to do

        log.info("scanner update: bumping from %s to %s", cached or "<none>", remote_sha)
        # Force-reinstall pinned to the resolved SHA so we install
        # exactly what we measured — not a re-resolved tip that may
        # have moved between ls-remote and install.
        spec = f"injection-scanner @ git+{repo}@{remote_sha}"
        python = Path(venv_python) if venv_python is not None else Path(sys.executable)
        try:
            r = subprocess.run(
                ["uv", "pip", "install", "--python", str(python),
                 "--no-cache", "--quiet", "--upgrade", "--force-reinstall", spec],
                capture_output=True, text=True, timeout=120,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            log.warning("scanner update: install unavailable (%s) — keeping installed version", e)
            return
        if r.returncode != 0:
            log.error(
                "scanner update: install failed (rc=%d) — keeping installed version. stderr=%s",
                r.returncode, r.stderr.strip()[:500],
            )
            return
        sha_cache.parent.mkdir(parents=True, exist_ok=True)
        tmp = sha_cache.with_suffix(".tmp")
        tmp.write_text(remote_sha, encoding="ascii")
        tmp.replace(sha_cache)
        log.info("scanner update: installed %s", remote_sha)
