"""pr-gate: the stdlib GitHub client, over a fake `urlopen`. No network."""
from __future__ import annotations

import _prgate  # noqa: F401

import io
import json
import urllib.error

import pytest

from prgate.github import GitHub, GitHubError, TooLarge

TOKEN = "ghs_SECRETTOKEN"
HEAD = "c" * 40


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


def test_pull_state_from_graphql():
    client, op = gh({"data": {"repository": {"pullRequest": {
        "headRefOid": HEAD, "autoMergeRequest": {"enabledBy": {"login": "jonathan"}}}}}})
    s = client.pull_state(7)
    assert (s.head_sha, s.auto_merge, s.enabled_by) == (HEAD, True, "jonathan")
    [req] = op.requests
    assert req.get_method() == "POST" and req.full_url == "https://api.github.test/graphql"
    assert req.get_header("Authorization") == f"Bearer {TOKEN}"
    body = json.loads(req.data)
    assert body["variables"] == {"owner": "owner", "name": "repo", "number": 7}
    assert "enabledBy" in body["query"]


def test_pull_state_without_auto_merge():
    client, _ = gh({"data": {"repository": {"pullRequest": {
        "headRefOid": HEAD, "autoMergeRequest": None}}}})
    s = client.pull_state(7)
    assert (s.auto_merge, s.enabled_by) == (False, None)


def test_graphql_errors_fail_closed():
    client, _ = gh({"errors": [{"message": "SECRET-DETAIL"}]})
    with pytest.raises(GitHubError) as e:
        client.pull_state(7)
    assert "SECRET" not in str(e.value)


def test_diff_request():
    client, op = gh(b"diff --git a/x b/x\n")
    assert client.diff("release/1.0", HEAD, 1000) == b"diff --git a/x b/x\n"
    [req] = op.requests
    assert req.full_url == f"https://api.github.test/repos/owner/repo/compare/release/1.0...{HEAD}"
    assert req.get_header("Accept") == "application/vnd.github.diff"


def test_diff_over_limit_raises_too_large():
    client, _ = gh(b"x" * 11)
    with pytest.raises(TooLarge):
        client.diff("main", HEAD, 10)


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
