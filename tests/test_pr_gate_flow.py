"""pr-gate: the end-to-end decision flow (design steps 1-8) against a fake
GitHub layer and a fake model layer. No network."""
from __future__ import annotations

import _prgate  # noqa: F401

import pytest

from prgate import core, verdict
from prgate.github import GitHubError, PullState, Review, TooLarge
from prgate.llm import Finding, PassResult

OWNER = "jonathan"
BOT = "github-actions[bot]"
HEAD = "1" * 40
OLD = "2" * 40

DIFF = """\
diff --git a/src/app.py b/src/app.py
index 1111111..2222222 100644
--- a/src/app.py
+++ b/src/app.py
@@ -10,3 +10,4 @@ def main():
     a = 1
-    b = 2
+    b = 3
+    c = 4
     return a
"""


def shifted(diff, delta=40):
    return diff.replace("@@ -10,3 +10,4 @@", f"@@ -{10 + delta},3 +{10 + delta},4 @@")


class FakeGitHub:
    def __init__(self, diff=DIFF, head=HEAD, enabled_by=OWNER, auto_merge=True,
                 reviews=(), files=None):
        self.state = PullState(head_sha=head, auto_merge=auto_merge, enabled_by=enabled_by)
        self.diff_text = diff
        self._reviews = list(reviews)
        self.files = files or {}
        self.posted: list[tuple[str, str, str]] = []
        self.dismissed: list[int] = []
        self.refuse_request_changes = False
        self.fetched: list[str] = []

    def pull_state(self, number):
        return self.state

    def diff(self, base_ref, head, limit):
        data = self.diff_text.encode()
        if len(data) > limit:
            raise TooLarge("diff")
        return data

    def file_content(self, path, ref, limit):
        self.fetched.append(path)
        data = self.files.get(path, b"x = 1\n")
        if len(data) > limit:
            raise TooLarge("contents")
        return data

    def reviews(self, number):
        return list(self._reviews)

    def post_review(self, number, head, event, body):
        if event == "REQUEST_CHANGES" and self.refuse_request_changes:
            raise GitHubError("post-review", 422)
        self.posted.append((event, head, body))

    def dismiss_review(self, number, review_id, message):
        self.dismissed.append(review_id)


class FakeModel:
    def __init__(self, passes=None):
        self.calls = []
        self.passes = passes if passes is not None else [
            PassResult("monitor_a", "ok", suspicion=3),
            PassResult("monitor_b", "ok", suspicion=4),
            PassResult("review", "ok"),
        ]

    def __call__(self, diff_text, contents, scrutiny, omitted):
        self.calls.append({"diff": diff_text, "contents": contents,
                           "scrutiny": scrutiny, "omitted": omitted})
        return self.passes


def cfg(**kw):
    base = dict(owner=OWNER, model="claude-opus-5-5", effort="high", threshold=25, exceptions=[])
    base.update(kw)
    return core.Config(**base)


def event(action="auto_merge_enabled", head=HEAD):
    return core.Event(action=action, number=7, head_sha=head, base_ref="main")


def run(gh, model=None, action="auto_merge_enabled", **kw):
    model = model if model is not None else FakeModel()
    out = core.run(event(action), cfg(**kw), gh, model)
    return out, model


def gate_review(verdict_, head, own_hash, state=None, rid=100, login=BOT):
    state = state or ("CHANGES_REQUESTED" if verdict_ == "block" else "COMMENTED")
    body = verdict.MARKER.format(verdict=verdict_, head=head, hash=own_hash) + "\n\nbody"
    return Review(id=rid, login=login, state=state, commit_id=head, body=body)


def owner_review(state, commit, rid=200):
    return Review(id=rid, login=OWNER, state=state, commit_id=commit, body="")


def own_hash_of(diff):
    gh = FakeGitHub(diff=diff)
    return core.gather(gh, event()).own_hash


# ----- step 1: owner intent and freshness ---------------------------------------

def test_no_auto_merge_fails_without_review_or_model():
    gh = FakeGitHub(auto_merge=False, enabled_by=None)
    out, model = run(gh)
    assert out.exit_code == 1 and "enable auto-merge" in out.message
    assert gh.posted == [] and model.calls == []


def test_auto_merge_enabled_by_someone_else_fails():
    gh = FakeGitHub(enabled_by="agent-bot[bot]")
    out, model = run(gh)
    assert out.exit_code == 1 and f"enabled by {OWNER}" in out.message
    assert gh.posted == [] and model.calls == []


def test_owner_login_compare_is_case_insensitive():
    out, _ = run(FakeGitHub(enabled_by="Jonathan"))
    assert out.exit_code == 0


def test_stale_head_fails():
    gh = FakeGitHub(head=OLD)
    out, model = run(gh)
    assert out.exit_code == 1 and "stale" in out.message
    assert model.calls == []


def test_unsupported_action_fails():
    out, model = run(FakeGitHub(), action="opened")
    assert out.exit_code == 1 and model.calls == []


# ----- full review ---------------------------------------------------------------

def test_clean_full_review_posts_a_pass_comment_with_hash():
    gh = FakeGitHub()
    out, model = run(gh)
    assert out.exit_code == 0
    [(ev, head, body)] = gh.posted
    assert (ev, head) == ("COMMENT", HEAD)
    assert verdict.parse_marker(body) == ("pass", HEAD, own_hash_of(DIFF))
    assert len(model.calls) == 1


def test_suspicious_review_requests_changes_and_fails():
    gh = FakeGitHub()
    model = FakeModel([PassResult("monitor_a", "ok", suspicion=80)])
    out, _ = run(gh, model)
    assert out.exit_code == 1
    [(ev, _, body)] = gh.posted
    assert ev == "REQUEST_CHANGES" and verdict.parse_marker(body)[0] == "block"


def test_request_changes_refused_falls_back_to_comment():
    gh = FakeGitHub()
    gh.refuse_request_changes = True
    out, _ = run(gh, FakeModel([PassResult("monitor_a", "ok", suspicion=80)]))
    assert out.exit_code == 1
    [(ev, _, body)] = gh.posted
    assert ev == "COMMENT" and verdict.parse_marker(body)[0] == "block"


def test_incomplete_model_answer_blocks_with_a_review():
    gh = FakeGitHub()
    out, _ = run(gh, FakeModel([PassResult("monitor_a", "incomplete", "refusal")]))
    assert out.exit_code == 1 and gh.posted[0][0] == "REQUEST_CHANGES"


def test_infra_failure_fails_without_a_review_so_a_rerun_retries():
    gh = FakeGitHub()
    out, _ = run(gh, FakeModel([PassResult("monitor_a", "ok", suspicion=1),
                                PassResult("review", "infra", "api-timeout")]))
    assert out.exit_code == 1 and gh.posted == []
    assert "api-timeout" in out.message


def test_pass_dismisses_only_the_gates_own_earlier_blocks():
    reviews = [
        gate_review("block", OLD, "0" * 64, rid=1),
        Review(id=2, login=BOT, state="CHANGES_REQUESTED", commit_id=OLD, body="no marker"),
        Review(id=3, login=OWNER, state="CHANGES_REQUESTED", commit_id=OLD, body=""),
        gate_review("pass", OLD, "0" * 64, rid=4),
    ]
    gh = FakeGitHub(reviews=reviews)
    out, _ = run(gh)
    assert out.exit_code == 0 and gh.dismissed == [1]


def test_model_still_runs_when_a_deterministic_check_already_blocks():
    # Otherwise an owner override of a path hit would merge unreviewed code.
    diff = DIFF.replace("src/app.py", ".github/workflows/ci.yml")
    gh = FakeGitHub(diff=diff)
    out, model = run(gh)
    assert out.exit_code == 1 and len(model.calls) == 1
    assert "sensitive-path" in gh.posted[0][2]


def test_diff_too_large_for_the_model_blocks_without_a_model_call(monkeypatch):
    monkeypatch.setattr(core, "DIFF_LLM_CAP", 50)
    gh = FakeGitHub()
    out, model = run(gh)
    assert out.exit_code == 1 and model.calls == []
    assert "too large" in gh.posted[0][2]


def test_diff_beyond_the_hard_cap_fails_without_review(monkeypatch):
    monkeypatch.setattr(core, "DIFF_HARD_CAP", 50)
    gh = FakeGitHub()
    out, model = run(gh)
    assert out.exit_code == 1 and gh.posted == [] and model.calls == []


def test_github_error_fails_closed_without_body():
    class Broken(FakeGitHub):
        def reviews(self, number):
            raise GitHubError("list-reviews", 502)

    out, model = run(Broken())
    assert out.exit_code == 1 and "list-reviews" in out.message and model.calls == []


def test_unparseable_diff_fails_closed():
    out, model = run(FakeGitHub(diff="garbage\n"))
    assert out.exit_code == 1 and model.calls == []


def test_monitor_b_gets_text_contents_but_not_binaries_or_deletions():
    diff = DIFF + (
        "diff --git a/logo.png b/logo.png\nnew file mode 100644\n"
        "Binary files /dev/null and b/logo.png differ\n"
        "diff --git a/gone.py b/gone.py\ndeleted file mode 100644\n--- a/gone.py\n+++ /dev/null\n"
        "@@ -1 +0,0 @@\n-x\n"
    )
    gh = FakeGitHub(diff=diff, files={"logo.png": b"\x89PNG\r\n\x1a\n", "src/app.py": b"a = 1\n"})
    out, model = run(gh)
    contents = model.calls[0]["contents"]
    assert contents == {"src/app.py": "a = 1\n"}
    assert out.exit_code == 1  # the binary blocks


def test_contents_budget_omission_reaches_the_model(monkeypatch):
    monkeypatch.setattr(core, "CONTENTS_BUDGET", 5)
    gh = FakeGitHub(files={"src/app.py": b"0123456789"})
    _, model = run(gh)
    assert model.calls[0]["contents"] == {} and model.calls[0]["omitted"] == ["src/app.py"]


# ----- synchronize: fail, except a pure base merge -------------------------------

def test_synchronize_without_a_previous_pass_fails_without_model_call():
    gh = FakeGitHub()
    out, model = run(gh, action="synchronize")
    assert out.exit_code == 1 and "re-enable auto-merge" in out.message
    assert model.calls == [] and gh.posted == []


def test_synchronize_after_a_base_merge_carries_the_pass_over():
    passed = gate_review("pass", OLD, own_hash_of(DIFF), rid=5)
    gh = FakeGitHub(diff=shifted(DIFF), reviews=[passed])
    out, model = run(gh, action="synchronize")
    assert out.exit_code == 0 and model.calls == []
    [(ev, head, body)] = gh.posted
    assert ev == "COMMENT" and head == HEAD and "carried over" in body
    assert verdict.parse_marker(body) == ("pass", HEAD, own_hash_of(DIFF))


def test_synchronize_with_an_extra_edit_fails():
    passed = gate_review("pass", OLD, own_hash_of(DIFF), rid=5)
    gh = FakeGitHub(diff=shifted(DIFF).replace("+    c = 4", "+    c = 5"), reviews=[passed])
    out, model = run(gh, action="synchronize")
    assert out.exit_code == 1 and model.calls == [] and gh.posted == []


def test_synchronize_ignores_pass_markers_not_written_by_the_gate():
    forged = gate_review("pass", OLD, own_hash_of(DIFF), rid=5, login="agent-bot[bot]")
    gh = FakeGitHub(diff=shifted(DIFF), reviews=[forged])
    out, _ = run(gh, action="synchronize")
    assert out.exit_code == 1


def test_synchronize_uses_the_latest_gate_pass():
    older = gate_review("pass", OLD, own_hash_of(DIFF), rid=5)
    newer = gate_review("pass", OLD, "f" * 64, rid=6)
    gh = FakeGitHub(diff=shifted(DIFF), reviews=[older, newer])
    out, _ = run(gh, action="synchronize")
    assert out.exit_code == 1


def test_carry_over_still_runs_the_always_on_checks():
    # Same own changes can't newly contain hidden Unicode, but the check
    # must not depend on that reasoning.
    diff = DIFF.replace("+    c = 4", '+    c = "\u200b"')
    passed = gate_review("pass", OLD, own_hash_of(diff), rid=5)
    gh = FakeGitHub(diff=shifted(diff), reviews=[passed])
    out, _ = run(gh, action="synchronize")
    assert out.exit_code == 1 and gh.posted[0][0] == "REQUEST_CHANGES"


def test_binary_content_change_breaks_carry_over():
    diff = DIFF + ("diff --git a/logo.png b/logo.png\nnew file mode 100644\n"
                   "Binary files /dev/null and b/logo.png differ\n")
    gh1 = FakeGitHub(diff=diff, files={"logo.png": b"\x89PNG\r\n\x1a\nAAAA"})
    h1 = core.gather(gh1, event()).own_hash
    passed = gate_review("pass", OLD, h1, rid=5)
    gh2 = FakeGitHub(diff=shifted(diff), reviews=[passed], files={"logo.png": b"\x89PNG\r\n\x1a\nBBBB"})
    out, _ = run(gh2, action="synchronize")
    assert out.exit_code == 1 and gh2.posted == []


# ----- override / reroll guard ------------------------------------------------------

def test_owner_approval_after_a_block_passes_without_model_call():
    h = own_hash_of(DIFF)
    gh = FakeGitHub(reviews=[gate_review("block", HEAD, h, rid=1), owner_review("APPROVED", HEAD)])
    out, model = run(gh)
    assert out.exit_code == 0 and model.calls == []
    [(ev, _, body)] = gh.posted
    assert ev == "COMMENT" and "approval" in body.lower()
    assert verdict.parse_marker(body) == ("pass", HEAD, h)
    assert gh.dismissed == [1]


def test_approval_on_an_older_head_does_not_carry():
    gh = FakeGitHub(reviews=[gate_review("block", HEAD, "0" * 64, rid=1), owner_review("APPROVED", OLD)])
    out, model = run(gh)
    assert out.exit_code == 1 and model.calls == [] and gh.posted == []
    assert HEAD in out.message


def test_prior_block_without_approval_stays_blocked_without_model_call():
    gh = FakeGitHub(reviews=[gate_review("block", HEAD, "0" * 64, rid=1)])
    out, model = run(gh)
    assert out.exit_code == 1 and model.calls == [] and gh.posted == []


def test_prior_block_posted_as_comment_fallback_still_counts():
    gh = FakeGitHub(reviews=[gate_review("block", HEAD, "0" * 64, rid=1, state="COMMENTED")])
    out, model = run(gh)
    assert out.exit_code == 1 and model.calls == []


def test_dismissed_prior_block_still_counts():
    gh = FakeGitHub(reviews=[gate_review("block", HEAD, "0" * 64, rid=1, state="DISMISSED")])
    out, model = run(gh)
    assert out.exit_code == 1 and model.calls == []


def test_approval_later_dismissed_does_not_override():
    gh = FakeGitHub(reviews=[gate_review("block", HEAD, "0" * 64, rid=1),
                             owner_review("DISMISSED", HEAD)])
    out, _ = run(gh)
    assert out.exit_code == 1


def test_owner_changes_requested_after_approval_does_not_override():
    gh = FakeGitHub(reviews=[gate_review("block", HEAD, "0" * 64, rid=1),
                             owner_review("APPROVED", HEAD, rid=2),
                             owner_review("CHANGES_REQUESTED", HEAD, rid=3)])
    out, _ = run(gh)
    assert out.exit_code == 1


def test_approval_by_someone_else_does_not_override():
    gh = FakeGitHub(reviews=[gate_review("block", HEAD, "0" * 64, rid=1),
                             Review(id=9, login="agent-bot[bot]", state="APPROVED", commit_id=HEAD, body="")])
    out, _ = run(gh)
    assert out.exit_code == 1


def test_override_clears_path_and_binary_rules():
    diff = DIFF.replace("src/app.py", ".github/workflows/ci.yml")
    gh = FakeGitHub(diff=diff, reviews=[gate_review("block", HEAD, "0" * 64, rid=1),
                                        owner_review("APPROVED", HEAD)])
    out, _ = run(gh)
    assert out.exit_code == 0


def test_override_never_clears_hidden_unicode():
    diff = DIFF.replace("+    c = 4", '+    c = "\ufe01\ufe02"')
    gh = FakeGitHub(diff=diff, reviews=[gate_review("block", HEAD, "0" * 64, rid=1),
                                        owner_review("APPROVED", HEAD)])
    out, model = run(gh)
    assert out.exit_code == 1 and model.calls == []
    assert gh.posted[0][0] == "REQUEST_CHANGES" and "hidden-unicode" in gh.posted[0][2]


def test_override_never_clears_lockfile_hosts():
    diff = ("diff --git a/uv.lock b/uv.lock\n--- a/uv.lock\n+++ b/uv.lock\n@@ -1 +1 @@\n"
            '-x\n+url = "https://evil.example/p.whl"\n')
    gh = FakeGitHub(diff=diff, reviews=[gate_review("block", HEAD, "0" * 64, rid=1),
                                        owner_review("APPROVED", HEAD)])
    out, _ = run(gh)
    assert out.exit_code == 1 and "lockfile-host" in gh.posted[0][2]


def test_owner_approval_without_a_prior_block_still_gets_a_full_review():
    gh = FakeGitHub(reviews=[owner_review("APPROVED", HEAD)])
    _, model = run(gh)
    assert len(model.calls) == 1


def test_auto_merge_toggle_does_not_reroll_a_blocked_head():
    gh = FakeGitHub(reviews=[gate_review("block", HEAD, "0" * 64, rid=1)])
    _, model = run(gh, action="auto_merge_enabled")
    _, model2 = run(gh, action="reopened")
    assert model.calls == [] and model2.calls == []


# ----- config validation -------------------------------------------------------------

@pytest.mark.parametrize("kw", [
    {"owner": ""}, {"owner": "bad login!"}, {"effort": "ultra"},
    {"threshold": -1}, {"threshold": 101}, {"model": " "},
])
def test_bad_config_is_rejected(kw):
    with pytest.raises(ValueError):
        cfg(**kw).validate()
