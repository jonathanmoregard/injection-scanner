"""pr-gate: invariants of the composite action, the caller template and the
pinned requirements. These are the properties a careless edit would break
without any unit test noticing."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent / "pr-gate"

MINT = "mint a credential that expires by itself"


def load(name):
    return yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))


def run_mint(tmp_path, **env):
    """Run the mint step's own script. Every case here is refused by a guard
    before the script reaches curl, so this stays offline."""
    import os
    import subprocess
    base = {"RUNNER_TEMP": str(tmp_path), "PATH": os.environ["PATH"],
            "RULE_ID": "r", "ORG_ID": "o", "SERVICE_ACCOUNT_ID": "s", "WORKSPACE_ID": "w",
            "ACTIONS_ID_TOKEN_REQUEST_URL": "", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": ""}
    base.update(env)
    [step] = [s for s in load("action.yml")["runs"]["steps"] if s["name"] == MINT]
    return subprocess.run(["bash", "-c", step["run"]], env=base,
                          capture_output=True, text=True, timeout=30)


def test_action_inputs_and_defaults():
    inputs = load("action.yml")["inputs"]
    assert set(inputs) == {"owner", "model", "effort", "suspicion-threshold", "exceptions",
                           "lockfile-hosts", "marker-key", "federation-rule-id",
                           "organization-id", "service-account-id", "workspace-id"}
    assert inputs["lockfile-hosts"]["default"] == ""
    assert inputs["owner"]["required"] is True
    # Fail-closed starts here: an omitted credential input is a setup error,
    # never a run that quietly reviews nothing.
    for name in ("marker-key", "federation-rule-id", "organization-id",
                 "service-account-id", "workspace-id"):
        assert inputs[name]["required"] is True, name
    assert inputs["model"]["default"] == "claude-opus-5-5"
    assert inputs["effort"]["default"] == "high"
    assert inputs["suspicion-threshold"]["default"] == "25"


def test_the_gate_always_runs_as_github_actions_bot():
    # GATE_LOGIN trusts only github-actions[bot] reviews: a custom token
    # would post reviews the next run can't recognise.
    [gate] = [s for s in load("action.yml")["runs"]["steps"] if s["name"] == "ai-gate"]
    assert gate["env"]["PR_GATE_GITHUB_TOKEN"] == "${{ github.token }}"


def test_no_expression_is_interpolated_into_a_script_body():
    for step in load("action.yml")["runs"]["steps"]:
        assert "${{" not in step.get("run", ""), step.get("name")


def test_action_uses_no_other_actions():
    steps = load("action.yml")["runs"]["steps"]
    assert all("uses" not in s for s in steps)


def test_the_marker_key_reaches_only_the_gate_step():
    steps = load("action.yml")["runs"]["steps"]
    holders = [s["name"] for s in steps
               if "inputs.marker-key" in str(s.get("env", {}))]
    assert holders == ["ai-gate"]


def _mint():
    [step] = [s for s in load("action.yml")["runs"]["steps"]
              if s["name"] == MINT]
    return step


def test_the_marker_key_is_not_the_model_credential():
    """The whole point of federating. The model credential now expires in
    minutes, and a marker signed with it stops verifying on the next run --
    which would silently break pass carry-over, re-runs and owner
    dismissals, all of which re-verify a marker written by an earlier run."""
    gate = [s for s in load("action.yml")["runs"]["steps"] if s["name"] == "ai-gate"][0]
    env = gate["env"]
    assert env["PR_GATE_MARKER_KEY"] == "${{ inputs.marker-key }}"
    # The bearer arrives as a file path, so nothing else can carry the marker
    # key's value and the two can never be the same string again.
    others = [v for k, v in env.items() if k != "PR_GATE_MARKER_KEY"]
    assert "${{ inputs.marker-key }}" not in others


def test_the_credential_never_reaches_a_later_step():
    """A step output is kept by the runner for the whole job and GITHUB_ENV
    puts the value in every later step's environment. The bearer goes to a
    600-mode file instead, so only the step given its path can read it."""
    # Code only: the step's comments name these mechanisms to say it avoids
    # them, and a test that reads prose would pass on a script that used one.
    code = "\n".join(line for line in _mint()["run"].splitlines()
                     if not line.lstrip().startswith("#"))
    for leak in ("GITHUB_ENV", "GITHUB_OUTPUT", "::set-output"):
        assert leak not in code, leak
    assert "chmod 600" in code


def test_the_gate_step_cannot_mint_a_second_credential():
    """Emptied, not absent: the gate process must not be able to ask GitHub
    for another identity token, which would outlive the credential it was
    handed. A variable set to the empty string still occupies its slot."""
    gate = [s for s in load("action.yml")["runs"]["steps"] if s["name"] == "ai-gate"][0]
    assert gate["env"]["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] == ""
    assert gate["env"]["ACTIONS_ID_TOKEN_REQUEST_URL"] == ""


def test_a_repo_without_federation_configured_fails_closed(tmp_path):
    """Never a verdict. An unconfigured repo must redden the check, because a
    gate that cannot reach the model has reviewed nothing."""
    r = run_mint(tmp_path, RULE_ID="", ACTIONS_ID_TOKEN_REQUEST_URL="https://x.test")
    assert r.returncode == 1
    assert "AI_GATE_FEDERATION_RULE_ID" in r.stdout
    assert not (tmp_path / "anthropic-token").exists()


def test_no_identity_token_fails_closed(tmp_path):
    """GitHub issues none when the workflow forgot `id-token: write`."""
    r = run_mint(tmp_path, ACTIONS_ID_TOKEN_REQUEST_URL="")
    assert r.returncode == 1
    assert "id-token" in r.stdout
    assert not (tmp_path / "anthropic-token").exists()


def test_neither_anthropic_credential_variable_shadows_the_bearer():
    """ANTHROPIC_API_KEY and ANTHROPIC_AUTH_TOKEN both take precedence in the
    SDK, and one set to the empty string still occupies its slot."""
    for step in load("action.yml")["runs"]["steps"]:
        assert "ANTHROPIC_API_KEY" not in step.get("env", {}), step["name"]


def test_dependencies_install_hash_pinned_wheels_only():
    install = load("action.yml")["runs"]["steps"][0]["run"]
    for flag in ("--require-hashes", "--no-deps", "--only-binary=:all:", "--isolated"):
        assert flag in install
    assert "requirements.txt" in install


def test_requirements_are_all_pinned_with_hashes():
    text = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    blocks = re.split(r"\n(?=[A-Za-z])", "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")).strip())
    names = []
    for block in blocks:
        head = block.split()[0]
        assert re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+-]+", head), head
        assert "--hash=sha256:" in block, head
        names.append(head.split("==")[0].lower())
    assert "anthropic" in names


# Import name -> distribution name, where they differ.
_DISTS = {"yaml": "pyyaml"}


def test_every_third_party_import_of_the_gate_is_pinned():
    # The tests run on the dev environment; only requirements.txt reaches
    # the runner, so an unpinned import would fail only in the action.
    import ast
    import sys
    text = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    pinned = {m.group(1).lower() for m in re.finditer(r"^([A-Za-z0-9_.-]+)==", text, re.M)}
    imported = set()
    for path in (ROOT / "prgate").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                imported.add(node.module.split(".")[0])
    third_party = imported - set(sys.stdlib_module_names) - {"injection_scanner", "__future__"}
    assert {_DISTS.get(m, m) for m in third_party} <= pinned


def test_caller_template_shape():
    wf = load("caller-example.yml")
    on = wf.get("on", wf.get(True))
    assert on == {"pull_request_target": {"types": ["auto_merge_enabled", "synchronize", "reopened"]}}
    # issues: read is for the timeline endpoint that records who dismissed a review.
    # id-token: write is what makes GitHub sign a statement of this run's
    # identity; without it the exchange has nothing to present and the gate
    # is red on every PR.
    assert wf["permissions"] == {"contents": "read", "pull-requests": "write",
                                 "issues": "read", "id-token": "write"}
    assert wf["concurrency"]["cancel-in-progress"] is False
    [(job_id, job)] = wf["jobs"].items()
    assert job_id == "ai-gate" and job["name"] == "ai-gate"
    assert "if" not in job, "a skipped required job counts as success"
    [step] = job["steps"]
    assert step["uses"].startswith("jonathanmoregard/injection-scanner/pr-gate@")
    assert "checkout" not in str(job)
    assert step["with"]["marker-key"] == "${{ secrets.AI_GATE_MARKER_KEY }}"
    assert step["with"]["owner"]
    # Variables, not secrets: this repo is public and these authorise nothing
    # on their own -- only a run in the configured repo can present a matching
    # identity token.
    assert step["with"]["federation-rule-id"] == "${{ vars.AI_GATE_FEDERATION_RULE_ID }}"
    assert step["with"]["organization-id"] == "${{ vars.AI_GATE_ORGANIZATION_ID }}"
    assert step["with"]["service-account-id"] == "${{ vars.AI_GATE_SERVICE_ACCOUNT_ID }}"
    assert step["with"]["workspace-id"] == "${{ vars.AI_GATE_WORKSPACE_ID }}"
