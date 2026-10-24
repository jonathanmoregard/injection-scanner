"""Entry point.

Actions mode (no arguments): reads the pull_request_target event and the
action inputs from the environment, runs the gate, prints one workflow
annotation, exits 0 (pass) or 1 (block / failure).

Dry-run mode (--dry-run): diff file in, verdict JSON out, no GitHub calls.
For calibration against past PRs. Exit 0 pass, 1 block, 2 usage/setup error.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import checks, core, llm, verdict
from .github import GitHub
from .llm import PassResult

PASS_NAMES = ("monitor_a", "monitor_b", "review")


def escape_command(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def make_review_fn(env, cfg: core.Config):
    """The model layer, bound to config. A missing key is a setup failure
    (infra), not a verdict: after fixing the secret, an auto-merge toggle
    reviews."""
    def review_fn(diff_text, contents, scrutiny, omitted) -> list[PassResult]:
        key = (env.get("ANTHROPIC_API_KEY") or "").strip()
        if not key:
            return [PassResult(n, "infra", "no-key") for n in PASS_NAMES]
        client = llm.build_client(key)
        return llm.run_passes(client, model=cfg.model, effort=cfg.effort,
                              diff_text=diff_text, contents=contents,
                              scrutiny=scrutiny, omitted=omitted)
    return review_fn


# ----- Actions mode ------------------------------------------------------------------

def _summary(env, text: str) -> None:
    path = env.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"AI gate: {text}\n")


def _actions(env) -> int:
    def fail(msg: str) -> int:
        print(f"::error::{escape_command(msg)}")
        _summary(env, msg)
        return 1

    if env.get("GITHUB_EVENT_NAME") != "pull_request_target":
        return fail("pr-gate must run on pull_request_target (see caller-example.yml)")
    try:
        with open(env["GITHUB_EVENT_PATH"], encoding="utf-8") as fh:
            payload = json.load(fh)
        pr = payload["pull_request"]
        ev = core.Event(action=str(payload["action"]), number=int(pr["number"]),
                        head_sha=str(pr["head"]["sha"]), base_ref=str(pr["base"]["ref"]),
                        repo=env.get("GITHUB_REPOSITORY", ""),
                        default_branch=str(payload["repository"]["default_branch"]),
                        run_attempt=int(env.get("GITHUB_RUN_ATTEMPT") or ""))
    except (KeyError, TypeError, ValueError, OSError):
        return fail("could not read the pull_request_target event")
    try:
        cfg = core.Config(
            owner=(env.get("PR_GATE_OWNER") or "").strip(),
            model=(env.get("PR_GATE_MODEL") or "").strip(),
            effort=(env.get("PR_GATE_EFFORT") or "").strip(),
            threshold=int((env.get("PR_GATE_THRESHOLD") or "").strip()),
            exceptions=checks.parse_exceptions(env.get("PR_GATE_EXCEPTIONS", "")),
            marker_key=(env.get("ANTHROPIC_API_KEY") or "").strip().encode("utf-8"),
        ).validate()
    except ValueError as e:
        # Messages from Config.validate are gate-written; int() errors are not.
        msg = str(e) if str(e).startswith(("owner", "model", "effort", "suspicion")) \
            else "suspicion-threshold must be an integer 0-100"
        return fail(f"config: {msg}")
    token = (env.get("PR_GATE_GITHUB_TOKEN") or "").strip()
    if not token:
        return fail("config: the workflow token (github.token) is empty")
    try:
        gh = GitHub(token, env.get("GITHUB_REPOSITORY", ""),
                    api_url=env.get("GITHUB_API_URL", "https://api.github.com"),
                    graphql_url=env.get("GITHUB_GRAPHQL_URL", "https://api.github.com/graphql"))
    except ValueError:
        return fail("config: bad GITHUB_REPOSITORY")
    outcome = core.run(ev, cfg, gh, make_review_fn(env, cfg))
    if outcome.exit_code == 0:
        print(f"::notice::{escape_command(outcome.message)}")
        _summary(env, outcome.message)
        return 0
    return fail(outcome.message)


# ----- dry-run --------------------------------------------------------------------------

def _read_local(files_dir: Path | None, path: str) -> bytes | None:
    if files_dir is None:
        return None
    target = (files_dir / path).resolve()
    if files_dir not in target.parents or not target.is_file():
        return None
    return target.read_bytes()


def _dry_run(args, env) -> int:
    cfg = core.Config(owner="dry-run", model=args.model, effort=args.effort,
                      threshold=args.threshold,
                      exceptions=checks.parse_exceptions(
                          Path(args.exceptions_file).read_text(encoding="utf-8")
                          if args.exceptions_file else ""))
    cfg.validate()
    if not args.no_llm and not (env.get("ANTHROPIC_API_KEY") or "").strip():
        print("ANTHROPIC_API_KEY is not set (or pass --no-llm)", file=sys.stderr)
        return 2
    files_dir = Path(args.files_dir).resolve() if args.files_dir else None
    g = core.gather_from(Path(args.diff).read_bytes(),
                         lambda p: _read_local(files_dir, p) or b"")

    def local_contents():
        contents, omitted, left = {}, [], core.CONTENTS_BUDGET
        for f in g.files:
            if f.status == "deleted" or f.binary:
                continue
            data = _read_local(files_dir, f.path)
            if data is None:
                continue
            if len(data) > left:
                omitted.append(f.path)
                continue
            left -= len(data)
            contents[f.path] = data.decode("utf-8", errors="replace")
        return contents, omitted

    review_fn = (lambda *a: []) if args.no_llm else make_review_fn(env, cfg)
    result = core.full_review(g, cfg, review_fn, local_contents)
    llm_state = "skipped" if args.no_llm else (
        "ran" if result.passes else "skipped: diff too large")
    out = {
        "verdict": "block" if result.block else "pass",
        "reasons": result.reasons,
        "infra": result.infra,
        "suspicion": result.suspicion,
        "own_changes_hash": g.own_hash,
        "llm": llm_state,
        "model": cfg.model,
        "effort": cfg.effort,
        "threshold": cfg.threshold,
        "deterministic": [{"rule": h.rule, "path": h.path, "detail": h.detail,
                           "overridable": h.overridable} for h in result.hits],
        "scrutiny": [{"path": s.path, "reason": s.reason} for s in result.scrutiny],
        "passes": [{"name": p.name, "status": p.status, "reason": p.reason,
                    "suspicion": p.suspicion, "declined": p.declined,
                    "analysis": p.analysis,
                    "findings": [{"file": f.file, "category": f.category,
                                  "severity": f.severity, "explanation": f.explanation}
                                 for f in p.findings]} for p in result.passes],
        # Never signed: a dry-run marker must not be trusted by a real gate.
        "review_body": verdict.render_body(result, key=None, repo="", number=0,
                                           head="0" * 40, own_hash=g.own_hash,
                                           threshold=cfg.threshold, model=cfg.model,
                                           effort=cfg.effort, mode="full"),
    }
    print(json.dumps(out, indent=2, ensure_ascii=False))
    if result.infra:
        return 2
    return 1 if result.block else 0


def main(argv=None, env=None) -> int:
    env = os.environ if env is None else env
    p = argparse.ArgumentParser(prog="pr-gate", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dry-run", action="store_true", help="local mode, no GitHub calls")
    p.add_argument("--diff", help="unified diff file (dry-run)")
    p.add_argument("--files-dir", help="directory with post-change file contents (dry-run)")
    p.add_argument("--no-llm", action="store_true", help="deterministic checks only (dry-run)")
    p.add_argument("--model", default="claude-opus-5-5")
    p.add_argument("--effort", default="high", choices=llm.EFFORTS)
    p.add_argument("--threshold", type=int, default=25)
    p.add_argument("--exceptions-file", help="newline-separated path globs (dry-run)")
    args = p.parse_args(argv)
    try:
        if args.dry_run:
            if not args.diff:
                p.error("--dry-run needs --diff")
            return _dry_run(args, env)
        return _actions(env)
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 - never print messages, they can echo data
        print(f"::error::pr-gate internal error ({type(e).__name__})")
        return 2 if args.dry_run else 1
