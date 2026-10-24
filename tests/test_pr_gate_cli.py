"""pr-gate: the command line — Actions mode wiring and the local dry-run."""
from __future__ import annotations

import _prgate  # noqa: F401

import json

import pytest

from prgate import cli, core
from prgate.llm import Finding, PassResult

HEAD = "d" * 40

CLEAN = """\
diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1 +1 @@
-x = 1
+x = 2
"""
HIDDEN = CLEAN.replace("+x = 2", '+x = "\ufe01\ufe02"')


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


# ----- dry-run ---------------------------------------------------------------------

def test_dry_run_no_llm_clean(tmp_path, capsys):
    code = cli.main(["--dry-run", "--no-llm", "--diff", write(tmp_path, "d.diff", CLEAN)], env={})
    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert out["verdict"] == "pass" and out["llm"] == "skipped"
    assert len(out["own_changes_hash"]) == 64


def test_dry_run_no_llm_reports_hidden_unicode(tmp_path, capsys):
    code = cli.main(["--dry-run", "--no-llm", "--diff", write(tmp_path, "d.diff", HIDDEN)], env={})
    out = json.loads(capsys.readouterr().out)
    assert code == 1 and out["verdict"] == "block"
    assert [h["rule"] for h in out["deterministic"]] == ["hidden-unicode"]


def test_dry_run_with_model_uses_the_configured_model(tmp_path, capsys, monkeypatch):
    seen = {}

    def fake_passes(client, *, model, effort, diff_text, contents, scrutiny, omitted):
        seen.update(model=model, effort=effort, contents=contents)
        return [PassResult("monitor_a", "ok", suspicion=40, analysis="why",
                           findings=[Finding("a.py", "obscure", "medium", "odd", "monitor_a")])]

    monkeypatch.setattr(cli.llm, "run_passes", fake_passes)
    files = tmp_path / "files"
    files.mkdir()
    (files / "a.py").write_text("x = 2\n")
    code = cli.main(["--dry-run", "--diff", write(tmp_path, "d.diff", CLEAN),
                     "--files-dir", str(files), "--model", "claude-fable-5-1",
                     "--effort", "max", "--threshold", "50"],
                    env={"ANTHROPIC_API_KEY": "sk-ant-test"})
    out = json.loads(capsys.readouterr().out)
    assert seen == {"model": "claude-fable-5-1", "effort": "max", "contents": {"a.py": "x = 2\n"}}
    assert code == 1 and out["verdict"] == "block"
    assert out["suspicion"] == 40
    assert out["passes"][0]["analysis"] == "why"
    assert "finding: obscure (medium)" in out["reasons"]


def test_dry_run_without_key_is_a_setup_error(tmp_path, capsys):
    code = cli.main(["--dry-run", "--diff", write(tmp_path, "d.diff", CLEAN)], env={})
    assert code == 2
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err


def test_dry_run_files_dir_cannot_escape(tmp_path, capsys, monkeypatch):
    outside = tmp_path / "secret.txt"
    outside.write_text("SECRET")
    files = tmp_path / "files"
    files.mkdir()
    diff = CLEAN.replace("a.py", "../secret.txt")
    seen = {}

    def fake_passes(client, *, contents, **kw):
        seen["contents"] = contents
        return []

    monkeypatch.setattr(cli.llm, "run_passes", fake_passes)
    cli.main(["--dry-run", "--diff", write(tmp_path, "d.diff", diff), "--files-dir", str(files)],
             env={"ANTHROPIC_API_KEY": "k"})
    assert seen["contents"] == {}


def test_dry_run_exceptions_file(tmp_path, capsys):
    diff = CLEAN.replace("a.py", "CLAUDE.md")
    exc = write(tmp_path, "exc.txt", "CLAUDE.md\n")
    code = cli.main(["--dry-run", "--no-llm", "--diff", write(tmp_path, "d.diff", diff),
                     "--exceptions-file", exc], env={})
    out = json.loads(capsys.readouterr().out)
    assert code == 0 and out["scrutiny"] == [{"path": "CLAUDE.md", "reason": "exception-path"}]


# ----- Actions mode ----------------------------------------------------------------

def actions_env(tmp_path, **over):
    event = {"action": "auto_merge_enabled",
             "pull_request": {"number": 7, "head": {"sha": HEAD}, "base": {"ref": "main"}}}
    p = tmp_path / "event.json"
    p.write_text(json.dumps(event))
    env = {
        "GITHUB_EVENT_NAME": "pull_request_target",
        "GITHUB_EVENT_PATH": str(p),
        "GITHUB_REPOSITORY": "o/r",
        "GITHUB_API_URL": "https://api.github.test",
        "GITHUB_GRAPHQL_URL": "https://api.github.test/graphql",
        "PR_GATE_OWNER": "jonathan",
        "PR_GATE_MODEL": "claude-opus-5-5",
        "PR_GATE_EFFORT": "high",
        "PR_GATE_THRESHOLD": "25",
        "PR_GATE_EXCEPTIONS": ".claude/*\n",
        "PR_GATE_GITHUB_TOKEN": "ghs_x",
        "ANTHROPIC_API_KEY": "sk-ant-x",
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
    }
    env.update(over)
    return env


def test_actions_mode_maps_env_to_config_and_event(tmp_path, capsys, monkeypatch):
    seen = {}

    def fake_run(ev, cfg, gh, review_fn):
        seen.update(ev=ev, cfg=cfg)
        return core.Outcome(0, "passed (full)")

    monkeypatch.setattr(cli.core, "run", fake_run)
    code = cli.main([], env=actions_env(tmp_path))
    assert code == 0
    assert seen["ev"] == core.Event("auto_merge_enabled", 7, HEAD, "main")
    c = seen["cfg"]
    assert (c.owner, c.model, c.effort, c.threshold, c.exceptions) == (
        "jonathan", "claude-opus-5-5", "high", 25, [".claude/*"])
    assert "::notice::" in capsys.readouterr().out
    assert "passed" in (tmp_path / "summary.md").read_text()


def test_actions_mode_refuses_other_events(tmp_path, capsys):
    code = cli.main([], env=actions_env(tmp_path, GITHUB_EVENT_NAME="pull_request"))
    assert code == 1
    assert "pull_request_target" in capsys.readouterr().out


@pytest.mark.parametrize("over", [
    {"PR_GATE_OWNER": ""}, {"PR_GATE_THRESHOLD": "abc"}, {"PR_GATE_EFFORT": "huge"},
    {"PR_GATE_GITHUB_TOKEN": ""},
])
def test_actions_mode_config_errors_fail(tmp_path, capsys, over):
    code = cli.main([], env=actions_env(tmp_path, **over))
    assert code == 1 and "::error::" in capsys.readouterr().out


def test_actions_mode_block_prints_an_error_annotation(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cli.core, "run", lambda *a: core.Outcome(1, "blocked: x"))
    assert cli.main([], env=actions_env(tmp_path)) == 1
    assert "::error::blocked: x" in capsys.readouterr().out


def test_internal_errors_print_only_the_type_name(tmp_path, capsys, monkeypatch):
    def boom(*a):
        raise RuntimeError("SECRET request fragment")

    monkeypatch.setattr(cli.core, "run", boom)
    assert cli.main([], env=actions_env(tmp_path)) == 1
    out = capsys.readouterr()
    assert "RuntimeError" in out.out and "SECRET" not in out.out + out.err


def test_missing_key_surfaces_as_infra_not_a_verdict(tmp_path):
    env = actions_env(tmp_path, ANTHROPIC_API_KEY="")
    review_fn = cli.make_review_fn(env, core.Config("jonathan", "m", "high", 25))
    results = review_fn("diff", {}, [], [])
    assert {(r.status, r.reason) for r in results} == {("infra", "no-key")}


def test_workflow_command_escaping():
    assert cli.escape_command("a%b\nc\rd") == "a%25b%0Ac%0Dd"
