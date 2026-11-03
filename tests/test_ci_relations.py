"""GitHub Actions never calls a vendor. A test, because no code change can
break it but a workflow edit can.

Maintainer directives: 2026-09-06 "ci tests should not call external services
in general, smell"; 2026-10-24 "We need to stop hitting lakera from CI, gha
shouldn't ddos third party". Measured 2026-09-05, which is what made the first
point: each CI run spent 17-20 Lakera calls in 1-2 minutes, about seven runs
went through that afternoon, on an account the production fleet had already
pushed into HTTP 429. The nightly/dispatch live-eval workflow that replaced
it still drew on the same shared quota and was deleted on 2026-10-24; the
corpus eval is run locally, by hand (`python -m injection_scanner.eval`).

The guard is a NEGATIVE over every workflow file, not an allow-list of jobs or
files: no `secrets.` reference, and no vendor credential name. Without a
credential no vendor call can succeed — every adapter fails closed on a
missing key before it opens a connection — so a workflow with neither cannot
put load on a vendor, and a workflow added tomorrow is covered on arrival.

  1. `ci.yml` triggers on pull_request and push and has no job but `test`.
  2. No file under `.github/workflows/` contains `secrets.` or a vendor
     credential/env prefix (`LAKERA`, `ANTHROPIC`, `OPENAI`, `MODEL_ARMOR`).
  3. Every pytest run carries the socket embargo.
  4. Superseded PR runs are cancelled; pushes to main are not.
"""
from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "pyproject.toml"
WORKFLOWS = ROOT / ".github" / "workflows"
CI = WORKFLOWS / "ci.yml"

# In YAML 1.1, which PyYAML implements, the bare word `on` is a BOOLEAN. So a
# workflow's `on:` block arrives under the Python key `True`, not `"on"`.
# Named rather than inlined so the next reader does not think it is a typo.
_ON_KEY = True

# Every vendor credential and env prefix the scanner reads. Uppercase only, so
# prose naming a vendor in a comment is fine; an env name is not.
_VENDOR_ENV_TOKENS = ("LAKERA", "ANTHROPIC", "OPENAI", "MODEL_ARMOR")


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _workflow_files() -> list[Path]:
    return sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])


# ---------- ci.yml: the merge gate is hermetic ----------

def test_ci_still_triggers_on_pushes_and_pull_requests() -> None:
    """Guards the guard: if PyYAML ever stopped folding `on` to True, every
    other test here would be asserting against a differently-shaped dict."""
    assert set(_load(CI)[_ON_KEY]) == {"pull_request", "push"}


def test_ci_runs_only_the_deterministic_test_job() -> None:
    assert set(_load(CI)["jobs"]) == {"test"}, (
        "the merge gate runs the offline suite and nothing else"
    )


def test_the_workflow_scan_is_not_vacuous() -> None:
    assert CI in _workflow_files()


# ---------- every workflow: no vendor can be reached ----------

@pytest.mark.parametrize("path", _workflow_files(), ids=lambda p: p.name)
def test_no_workflow_references_a_secret(path: Path) -> None:
    """A workflow that needs no secret also cannot go red because a vendor is
    down or throttled, and works unchanged on a fork PR."""
    assert "secrets." not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("path", _workflow_files(), ids=lambda p: p.name)
def test_no_workflow_names_a_vendor_credential(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    named = [token for token in _VENDOR_ENV_TOKENS if token in text]
    assert named == [], (
        f"{path.name} names {named}: GitHub Actions must not call a scanner "
        "vendor (directive 2026-10-24); run the eval locally"
    )


# ---------- pytest: the network embargo ----------

def test_every_pytest_run_has_the_network_embargo() -> None:
    project = tomllib.loads(PROJECT.read_text(encoding="utf-8"))
    test_deps = project["project"]["optional-dependencies"]["test"]
    assert any(dep.startswith("pytest-socket") for dep in test_deps)
    addopts = project["tool"]["pytest"]["ini_options"]["addopts"].split()
    assert "--disable-socket" in addopts
    assert "--allow-unix-socket" in addopts


def test_ci_cancels_superseded_pull_request_runs() -> None:
    """The WHOLE expression, not just the words in it.

    A substring check for `pull_request` survives flipping `==` to `!=`, and
    that inversion is the dangerous one: it would cancel superseded pushes to
    MAIN — the runs whose whole job is to prove the default branch is still
    good — while letting redundant PR runs stack up. Both halves of the
    condition matter, so both are pinned.
    """
    concurrency = _load(CI)["concurrency"]
    assert "github.ref" in concurrency["group"]
    # Whitespace inside a `${{ }}` expression is insignificant to Actions but
    # significant to `==`, so compare on a normalised form.
    cancel = " ".join(str(concurrency["cancel-in-progress"]).split())
    assert cancel == "${{ github.event_name == 'pull_request' }}", (
        "superseded PR pushes are cancelled; pushes to main queue behind "
        "each other so nothing that reached the default branch goes "
        f"unverified — got {cancel!r}"
    )
