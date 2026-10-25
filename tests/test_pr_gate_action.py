"""pr-gate: invariants of the composite action, the caller template and the
pinned requirements. These are the properties a careless edit would break
without any unit test noticing."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent / "pr-gate"


def load(name):
    return yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))


def test_action_inputs_and_defaults():
    inputs = load("action.yml")["inputs"]
    assert set(inputs) == {"owner", "model", "effort", "suspicion-threshold", "exceptions",
                           "lockfile-hosts", "anthropic-api-key"}
    assert inputs["lockfile-hosts"]["default"] == ""
    assert inputs["owner"]["required"] is True
    assert inputs["anthropic-api-key"]["required"] is True
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


def test_api_key_reaches_only_the_gate_step():
    steps = load("action.yml")["runs"]["steps"]
    holders = [s["name"] for s in steps
               if "inputs.anthropic-api-key" in str(s.get("env", {}))]
    assert holders == ["ai-gate"]


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
    assert wf["permissions"] == {"contents": "read", "pull-requests": "write", "issues": "read"}
    assert wf["concurrency"]["cancel-in-progress"] is False
    [(job_id, job)] = wf["jobs"].items()
    assert job_id == "ai-gate" and job["name"] == "ai-gate"
    assert "if" not in job, "a skipped required job counts as success"
    [step] = job["steps"]
    assert step["uses"].startswith("jonathanmoregard/injection-scanner/pr-gate@")
    assert "checkout" not in str(job)
    assert step["with"]["anthropic-api-key"] == "${{ secrets.AI_GATE_ANTHROPIC_KEY }}"
    assert step["with"]["owner"]
