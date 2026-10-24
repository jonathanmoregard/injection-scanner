"""pr-gate: the stdlib GitHub client, over a fake `urlopen`. No network."""
from __future__ import annotations

import _prgate  # noqa: F401

import io
import json
import urllib.error

import pytest

from prgate.github import GitHub, GitHubError, TimelineEvent, TooLarge

TOKEN = "ghs_SECRETTOKEN"
HEAD = "c" * 40
BASE = "b" * 40


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class FakeOpen:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return Resp(r if isinstance(r, bytes) else json.dumps(r).encode())


def gh(*responses):
    opener = FakeOpen(*responses)
    return GitHub(TOKEN, "owner/repo", api_url="https://api.github.test",
                  graphql_url="https://api.github.test/graphql", urlopen=opener), opener


MERGE = "d" * 40


def merge_commit(oid=MERGE, parents=(BASE, HEAD)):
    return {"oid": oid, "parents": {"nodes": [{"oid": p} for p in parents]}}


def pull(**kw):
    pr = {"headRefOid": HEAD, "baseRefName": "main", "baseRefOid": BASE,
          "autoMergeRequest": {"enabledBy": {"login": "jonathan"}},
          "mergeable": "MERGEABLE", "potentialMergeCommit": merge_commit()}
    pr.update(kw)
    return {"data": {"repository": {"pullRequest": pr}}}


def test_pull_state_reads_the_test_merge_commit_and_its_parents():
    # The same snapshot as head and base: the parents check compares them.
    client, op = gh(pull())
    s = client.pull_state(7)
    assert (s.mergeable, s.merge_sha, s.merge_parents) == ("MERGEABLE", MERGE, (BASE, HEAD))
    query = json.loads(op.requests[0].data)["query"]
    assert "potentialMergeCommit" in query and "mergeable" in query


def test_no_test_merge_commit_yet_reads_as_none():
    client, _ = gh(pull(mergeable="UNKNOWN", potentialMergeCommit=None))
    s = client.pull_state(7)
    assert (s.mergeable, s.merge_sha, s.merge_parents) == ("UNKNOWN", None, ())


@pytest.mark.parametrize("value", [None, "", "mergeable", "DIRTY", 1, True])
def test_an_unrecognised_mergeable_value_reads_as_unknown(value):
    client, _ = gh(pull(mergeable=value))
    assert client.pull_state(7).mergeable == "UNKNOWN"


@pytest.mark.parametrize("commit", [
    merge_commit(oid="main"), merge_commit(oid=None), merge_commit(parents=("main", HEAD)),
    merge_commit(parents=(BASE, None)), {"oid": MERGE}, {"oid": MERGE, "parents": None},
    "x"])
def test_a_malformed_test_merge_commit_fails_closed(commit):
    # Its oid is fetched as content, and its parents decide whether it is
    # the merge of this base and head.
    client, _ = gh(pull(potentialMergeCommit=commit))
    with pytest.raises(GitHubError) as e:
        client.pull_state(7)
    assert e.value.op == "pull-state"


def test_pull_state_from_graphql():
    client, op = gh(pull())
    s = client.pull_state(7)
    assert (s.head_sha, s.auto_merge, s.enabled_by) == (HEAD, True, "jonathan")
    assert (s.base_ref, s.base_oid) == ("main", BASE)
    [req] = op.requests
    assert req.get_method() == "POST" and req.full_url == "https://api.github.test/graphql"
    assert req.get_header("Authorization") == f"Bearer {TOKEN}"
    body = json.loads(req.data)
    assert body["variables"] == {"owner": "owner", "name": "repo", "number": 7}
    assert "enabledBy" in body["query"] and "baseRefOid" in body["query"]


@pytest.mark.parametrize("oid", [None, "main", "b" * 39, "B" * 40, "g" * 40, 40])
def test_a_malformed_base_oid_fails_closed(oid):
    # The compare call uses this oid; a branch name there could resolve to a
    # writer-pushed tag of the same name.
    client, _ = gh(pull(baseRefOid=oid))
    with pytest.raises(GitHubError) as e:
        client.pull_state(7)
    assert e.value.op == "pull-state"


def test_pull_state_without_auto_merge():
    client, _ = gh(pull(autoMergeRequest=None))
    s = client.pull_state(7)
    assert (s.auto_merge, s.enabled_by) == (False, None)


def test_graphql_errors_fail_closed():
    client, _ = gh({"errors": [{"message": "SECRET-DETAIL"}]})
    with pytest.raises(GitHubError) as e:
        client.pull_state(7)
    assert "SECRET" not in str(e.value)


def test_diff_compares_commit_oids():
    client, op = gh(b"diff --git a/x b/x\n")
    assert client.diff(BASE, HEAD, 1000) == b"diff --git a/x b/x\n"
    [req] = op.requests
    assert req.full_url == f"https://api.github.test/repos/owner/repo/compare/{BASE}...{HEAD}"
    assert req.get_header("Accept") == "application/vnd.github.diff"


@pytest.mark.parametrize("base,head", [("main", HEAD), (BASE, "main"), ("b" * 39, HEAD)])
def test_diff_refuses_anything_but_commit_oids(base, head):
    client, op = gh(b"x")
    with pytest.raises(GitHubError):
        client.diff(base, head, 1000)
    assert op.requests == []


def test_diff_over_limit_raises_too_large():
    client, _ = gh(b"x" * 11)
    with pytest.raises(TooLarge):
        client.diff(BASE, HEAD, 10)


def test_diff_406_means_too_large_not_a_retryable_error():
    # GitHub answers 406 when a compare diff exceeds its own file/line limits;
    # a re-run can never clear that, so it must not read as infra.
    err = urllib.error.HTTPError("https://x", 406, "Not Acceptable", {}, io.BytesIO(b""))
    client, _ = gh(err)
    with pytest.raises(TooLarge):
        client.diff(BASE, HEAD, 10)


def test_406_from_other_endpoints_stays_a_github_error():
    err = urllib.error.HTTPError("https://x", 406, "Not Acceptable", {}, io.BytesIO(b""))
    client, _ = gh(err)
    with pytest.raises(GitHubError):
        client.file_content("a.py", HEAD, 10)


def test_file_content_quotes_the_path_and_pins_the_ref():
    client, op = gh(b"data")
    assert client.file_content("dir/sp ace#é.txt", HEAD, 100) == b"data"
    [req] = op.requests
    assert req.full_url == (
        "https://api.github.test/repos/owner/repo/contents/dir/sp%20ace%23%C3%A9.txt"
        f"?ref={HEAD}")
    assert req.get_header("Accept") == "application/vnd.github.raw+json"


def test_reviews_paginate():
    page1 = [{"id": i, "user": {"login": "u"}, "state": "COMMENTED", "commit_id": HEAD, "body": "b"}
             for i in range(100)]
    page2 = [{"id": 100, "user": None, "state": "APPROVED", "commit_id": None, "body": None}]
    client, op = gh(page1, page2)
    reviews = client.reviews(7)
    assert len(reviews) == 101
    assert (reviews[-1].login, reviews[-1].body, reviews[-1].commit_id) == ("", "", None)
    assert "page=2" in op.requests[1].full_url and "per_page=100" in op.requests[1].full_url


def dismissed(review_id, login):
    return {"event": "review_dismissed", "actor": {"login": login},
            "dismissed_review": {"state": "changes_requested", "review_id": review_id,
                                 "dismissal_message": "false alarm"}}


def reviewed(review_id):
    return {"event": "reviewed", "id": review_id, "user": {"login": "github-actions[bot]"},
            "state": "changes_requested", "submitted_at": "2026-10-24T10:00:00Z"}


def test_the_timeline_keeps_order_across_pages_and_only_what_the_override_needs():
    page1 = [{"event": "commented", "actor": {"login": "u"}, "body": "x"}] * 96 + [
        {"event": "committed", "sha": "a" * 40},
        reviewed(5),
        dismissed(5, "jonathan"),
        {"event": "head_ref_force_pushed", "actor": {"login": "w"}}]
    page2 = [{"event": "labeled", "actor": None}, {"event": "head_ref_restored"},
             dismissed(6, "github-actions[bot]"), {"event": "committed"}]
    client, op = gh(page1, page2)
    # `committed` events are dropped: GitHub orders them by the commit's own
    # (writer-chosen) date, so they say nothing about when the head moved.
    assert client.timeline(7) == [
        TimelineEvent("reviewed", 5),
        TimelineEvent("dismissed", 5, "jonathan"), TimelineEvent("rewrite"),
        TimelineEvent("rewrite"), TimelineEvent("dismissed", 6, "github-actions[bot]")]
    first, second = op.requests
    assert first.full_url.startswith("https://api.github.test/repos/owner/repo/issues/7/timeline?")
    assert "page=2" in second.full_url and "per_page=100" in second.full_url


@pytest.mark.parametrize("item", [
    {"event": "review_dismissed", "actor": {"login": "jonathan"}},
    {"event": "review_dismissed", "actor": {"login": "jonathan"},
     "dismissed_review": {"review_id": "five"}},
    {"event": "reviewed"},
    {"event": "reviewed", "id": "5"},
    {"event": "reviewed", "id": None},
    "not an event",
])
def test_a_malformed_timeline_event_fails_closed(item):
    client, _ = gh([item])
    with pytest.raises(GitHubError) as e:
        client.timeline(7)
    assert e.value.op == "timeline"


def test_a_dismissal_without_an_actor_has_an_empty_login():
    client, _ = gh([{"event": "review_dismissed", "actor": None,
                     "dismissed_review": {"review_id": 5}}])
    assert client.timeline(7) == [TimelineEvent("dismissed", 5, "")]


def test_a_timeline_longer_than_the_page_cap_fails_closed():
    client, _ = gh(*([[{"event": "labeled"}] * 100] * 30))
    with pytest.raises(GitHubError):
        client.timeline(7)


def test_post_review_and_dismiss():
    client, op = gh({}, {})
    client.post_review(7, HEAD, "REQUEST_CHANGES", "body")
    client.dismiss_review(7, 55, "superseded")
    post, dismiss = op.requests
    assert post.get_method() == "POST" and post.full_url.endswith("/pulls/7/reviews")
    assert json.loads(post.data) == {"commit_id": HEAD, "event": "REQUEST_CHANGES", "body": "body"}
    assert dismiss.get_method() == "PUT" and dismiss.full_url.endswith("/pulls/7/reviews/55/dismissals")
    assert json.loads(dismiss.data) == {"message": "superseded", "event": "DISMISS"}


def test_http_error_keeps_status_but_never_the_body_or_token():
    err = urllib.error.HTTPError("https://x", 422, "Unprocessable SECRET-REASON", {},
                                 io.BytesIO(b"SECRET-BODY"))
    client, _ = gh(err)
    with pytest.raises(GitHubError) as e:
        client.post_review(7, HEAD, "REQUEST_CHANGES", "b")
    assert e.value.status == 422 and e.value.op == "post-review"
    text = str(e.value) + repr(e.value)
    assert "SECRET" not in text and TOKEN not in text
    assert e.value.__cause__ is None and e.value.__suppress_context__


def test_network_error_has_no_status():
    client, _ = gh(urllib.error.URLError("SECRET-HOST unreachable"))
    with pytest.raises(GitHubError) as e:
        client.reviews(7)
    assert e.value.status is None and "SECRET" not in str(e.value)


def test_out_of_range_status_is_dropped():
    err = urllib.error.HTTPError("https://x", 9999, "x", {}, io.BytesIO(b""))
    client, _ = gh(err)
    with pytest.raises(GitHubError) as e:
        client.reviews(7)
    assert e.value.status is None


def test_bad_repo_slug_is_rejected():
    with pytest.raises(ValueError):
        GitHub(TOKEN, "not a repo", api_url="https://x", graphql_url="https://x/graphql")
