"""Two workflow properties that no code change can break, so a test must.

**The merge gate is hermetic.** Maintainer directive 2026-09-06: "ci tests
should not call external services in general, smell." `ci.yml` runs on every
push and pull request and must therefore make no vendor call and hold no
secret — a gate coupled to sampled models and a vendor's quota is
non-deterministic by construction, and buys no correctness the offline
SDK-over-stub-transport tests do not already buy. Measured 2026-09-05, which
is what made the point: each CI run spent 17-20 Lakera calls in 1-2 minutes,
about seven runs went through that afternoon (~130 calls), and they landed on
an account the production fleet had already pushed into HTTP 429.

**The live pipeline is serialised and paced.** `live-eval.yml` still runs the
real thing — nightly and on demand — against the same shared Lakera account
the fleet uses, so it may never overlap with itself and may never spend
sixteen calls finding out what one call would have told it.

Both are relations between files and between jobs, which is exactly what a
later edit breaks without noticing: someone re-adds a key to get a red build
green, renames a group, or drops a `needs` while fixing something else. So:

  1. `ci.yml` triggers on pull_request and push, has no job but `test`, and
     the raw file contains no `secrets.` reference anywhere.
  2. `live-eval.yml` triggers on exactly schedule and workflow_dispatch — it
     is not a merge gate and must not become one by accident.
  3. Its workflow-level concurrency group is `lakera-live` with
     `cancel-in-progress: false`: at most one live run at a time, queued
     rather than dropped, because cancelling would hide a real failure.
  4. `eval` needs `smoke`. The 1-call smoke is the canary for the 16-call
     eval: a Lakera outage costs one call, not seventeen.
  5. Both live jobs pace themselves, and eval waits for its turn rather than
     being refused mid-corpus.
"""
from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
CI = WORKFLOWS / "ci.yml"
LIVE = WORKFLOWS / "live-eval.yml"

# In YAML 1.1, which PyYAML implements, the bare word `on` is a BOOLEAN. So a
# workflow's `on:` block arrives under the Python key `True`, not `"on"`.
# Named rather than inlined so the next reader does not think it is a typo.
_ON_KEY = True

# The group that serialises everything touching the shared Lakera account.
_LAKERA_GROUP = "lakera-live"


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _needs(job: dict) -> set[str]:
    """`needs:` is a string when there is one, a list when there are several."""
    needs = job.get("needs", [])
    return {needs} if isinstance(needs, str) else set(needs)


def _run_commands(job: dict) -> str:
    return "\n".join(step.get("run", "") for step in job["steps"])


# ---------- ci.yml: the merge gate is hermetic ----------

def test_ci_still_triggers_on_pushes_and_pull_requests() -> None:
    """Guards the guard: if PyYAML ever stopped folding `on` to True, every
    other test here would be asserting against a differently-shaped dict."""
    assert set(_load(CI)[_ON_KEY]) == {"pull_request", "push"}


def test_ci_runs_only_the_deterministic_test_job() -> None:
    assert set(_load(CI)["jobs"]) == {"test"}, (
        "the merge gate runs the offline suite and nothing else; live checks "
        "belong in live-eval.yml"
    )


def test_ci_references_no_secret_at_all() -> None:
    """A NEGATIVE over the whole file, not an allow-list of jobs.

    An allow-list would pass the moment someone adds a job with a key in it,
    which is precisely the edit this exists to catch. A merge gate that needs
    no secret also cannot go red because a vendor is down or throttled, and
    works unchanged on a fork PR.
    """
    assert "secrets." not in CI.read_text(encoding="utf-8")


def test_ci_cancels_superseded_pull_request_runs() -> None:
    concurrency = _load(CI)["concurrency"]
    assert "github.ref" in concurrency["group"]
    # Superseded PR pushes are cancelled; pushes to main queue behind each
    # other so nothing that reached the default branch goes unverified.
    assert "pull_request" in str(concurrency["cancel-in-progress"])


# ---------- live-eval.yml: off the gate, serialised, paced ----------

def test_the_live_pipeline_is_never_a_merge_gate() -> None:
    assert set(_load(LIVE)[_ON_KEY]) == {"schedule", "workflow_dispatch"}, (
        "adding pull_request or push here would put a vendor call back on "
        "the merge gate"
    )


def test_the_live_pipeline_serialises_on_the_shared_account() -> None:
    concurrency = _load(LIVE)["concurrency"]
    assert concurrency["group"] == _LAKERA_GROUP
    # Deliberately NOT per-ref: a dispatch on a feature branch and the
    # nightly on main draw on the same Lakera account, so they must queue,
    # not run side by side.
    assert "github.ref" not in concurrency["group"]
    assert concurrency["cancel-in-progress"] is False, (
        "a queued live run must WAIT, not be dropped — cancelling it would "
        "hide a real failure"
    )


def test_the_one_call_smoke_gates_the_sixteen_call_eval() -> None:
    assert "smoke" in _needs(_load(LIVE)["jobs"]["eval"]), (
        "without this, a Lakera outage costs 17 calls per run instead of 1"
    )


def test_both_live_jobs_pace_themselves() -> None:
    """Both knobs, on both jobs — four cells, asserted one by one.

    The runner's cache directory is fresh every run, so this limiter is a
    separate domain drawing on the SAME account as the fleet: it has to pace
    itself stricter than the fleet's own 300 s sustained interval buys it, and
    it must never be allowed a burst. `BURST` is the one that gets forgotten,
    because a bucket that starts full looks paced until ten calls leave at
    once.
    """
    jobs = _load(LIVE)["jobs"]
    for name in ("smoke", "eval"):
        env = jobs[name].get("env", {})
        assert env.get("INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S") == "60", (
            f"{name}: one Lakera call per minute at most"
        )
        assert env.get("INJECTION_SCANNER_LAKERA_BURST") == "2", (
            f"{name}: a fresh runner bucket must not hand the shared account "
            "the fleet default of ten calls back to back"
        )


def test_the_eval_job_waits_for_its_turn_instead_of_being_refused() -> None:
    """Without a wait budget, a paced eval is REFUSED mid-corpus rather than
    queued, and `--lakera-max-wait` is what turns each refusal into a wait."""
    assert "--lakera-max-wait" in _run_commands(_load(LIVE)["jobs"]["eval"])


def test_both_live_jobs_are_time_bounded() -> None:
    """A job that hangs holds `lakera-live` and blocks every later run."""
    jobs = _load(LIVE)["jobs"]
    assert jobs["smoke"]["timeout-minutes"] == 10
    # 16 cases at 60 s pacing is ~15 min of waiting before any confirmation
    # re-scans, so the eval budget has to be well clear of that.
    assert jobs["eval"]["timeout-minutes"] == 45
