"""The few GitHub API calls the gate needs, over stdlib urllib.

Errors carry an operation name and a range-checked HTTP status only. HTTP
error bodies and exception messages are dropped: they can echo request
content, and the token must never reach a log.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

TIMEOUT_S = 60
JSON_LIMIT = 20_000_000
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA = re.compile(r"^[0-9a-f]{40}$")

_PULL_QUERY = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      headRefOid
      baseRefName
      baseRefOid
      autoMergeRequest { enabledBy { login } }
      mergeable
      potentialMergeCommit { oid parents(first: 3) { nodes { oid } } }
    }
  }
}
"""


class GitHubError(Exception):
    def __init__(self, op: str, status: int | None = None):
        if not (isinstance(status, int) and 100 <= status <= 599):
            status = None
        self.op, self.status = op, status
        super().__init__(f"github {op} failed" + (f" (HTTP {status})" if status else ""))


class TooLarge(Exception):
    pass


@dataclass(frozen=True)
class PullState:
    head_sha: str
    auto_merge: bool
    enabled_by: str | None
    base_ref: str      # live base branch name, for the default-branch check
    base_oid: str      # live base commit; the diff is taken against this, never a name
    # GitHub's test merge of head into base: what a merge or squash lands.
    # It lags a push or a base move; the parents say which pair it merged.
    mergeable: str = "UNKNOWN"         # MERGEABLE | CONFLICTING | UNKNOWN
    merge_sha: str | None = None
    merge_parents: tuple[str, ...] = ()


@dataclass(frozen=True)
class Review:
    id: int
    login: str
    state: str
    commit_id: str | None
    body: str


@dataclass(frozen=True)
class TimelineEvent:
    """One PR timeline event the owner-override rule reads:
      reviewed   a review was submitted (review_id)
      dismissed  a review was dismissed (review_id, actor; "" if omitted)
      rewrite    the head was force-pushed or the head branch restored
    `committed` events are left out: GitHub places them by the commit's own
    (writer-chosen) date, not by when it was pushed.
    """
    kind: str
    review_id: int | None = None
    actor: str = ""


_REWRITES = ("head_ref_force_pushed", "head_ref_restored")
_MERGEABLE = ("MERGEABLE", "CONFLICTING")


def _oid(v) -> str:
    if not (isinstance(v, str) and _SHA.match(v)):
        raise TypeError
    return v


def _int(v) -> int:
    if type(v) is not int:
        raise TypeError
    return v


class GitHub:
    def __init__(self, token: str, repo: str, *, api_url: str, graphql_url: str,
                 urlopen=urllib.request.urlopen):
        if not _REPO.match(repo or ""):
            raise ValueError("bad repository slug")
        self._token = token
        self._owner, self._name = repo.split("/")
        self._api = api_url.rstrip("/") + f"/repos/{self._owner}/{self._name}"
        self._graphql = graphql_url
        self._urlopen = urlopen

    def _request(self, op: str, method: str, url: str, *, body=None,
                 accept: str = "application/vnd.github+json", limit: int = JSON_LIMIT) -> bytes:
        req = urllib.request.Request(
            url, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": accept,
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "pr-gate",
                **({"Content-Type": "application/json"} if body is not None else {}),
            },
        )
        try:
            with self._urlopen(req, timeout=TIMEOUT_S) as resp:
                data = resp.read(limit + 1)
        except urllib.error.HTTPError as e:
            status = e.code
            e.close()
            raise GitHubError(op, status) from None
        except (urllib.error.URLError, OSError, ValueError):
            raise GitHubError(op) from None
        if len(data) > limit:
            raise TooLarge(op)
        return data

    def _json(self, op: str, method: str, url: str, body=None):
        data = self._request(op, method, url, body=body)
        try:
            return json.loads(data) if data else {}
        except ValueError:
            raise GitHubError(op) from None

    def pull_state(self, number: int) -> PullState:
        data = self._json("pull-state", "POST", self._graphql, {
            "query": _PULL_QUERY,
            "variables": {"owner": self._owner, "name": self._name, "number": number},
        })
        try:
            if data.get("errors"):
                raise GitHubError("pull-state")
            pr = data["data"]["repository"]["pullRequest"]
            amr = pr["autoMergeRequest"]
            enabled_by = (amr.get("enabledBy") or {}).get("login") if amr else None
            merge_sha, parents = None, ()
            merge = pr["potentialMergeCommit"]   # null until GitHub has computed it
            if merge is not None:
                merge_sha = _oid(merge["oid"])
                parents = tuple(_oid(p["oid"]) for p in merge["parents"]["nodes"])
            mergeable = pr["mergeable"]
            return PullState(head_sha=pr["headRefOid"], auto_merge=amr is not None,
                             enabled_by=enabled_by, base_ref=str(pr["baseRefName"] or ""),
                             base_oid=_oid(pr["baseRefOid"]),
                             mergeable=mergeable if mergeable in _MERGEABLE else "UNKNOWN",
                             merge_sha=merge_sha, merge_parents=parents)
        except (KeyError, TypeError, AttributeError):
            raise GitHubError("pull-state") from None

    def diff(self, base_oid: str, ref: str, limit: int) -> bytes:
        """base_oid...ref. Commit oids only: a branch name could resolve to
        a writer-pushed tag of the same name."""
        if not (_SHA.match(base_oid or "") and _SHA.match(ref or "")):
            raise GitHubError("diff")
        url = f"{self._api}/compare/{base_oid}...{ref}"
        try:
            return self._request("diff", "GET", url, accept="application/vnd.github.diff",
                                 limit=limit)
        except GitHubError as e:
            # 406: the diff exceeds GitHub's own limits (~300 files / 20k
            # lines). A re-run cannot fix that.
            if e.status == 406:
                raise TooLarge("diff") from None
            raise

    def file_content(self, path: str, ref: str, limit: int) -> bytes:
        url = (f"{self._api}/contents/{urllib.parse.quote(path, safe='/')}"
               f"?ref={urllib.parse.quote(ref, safe='')}")
        return self._request("file-content", "GET", url,
                             accept="application/vnd.github.raw+json", limit=limit)

    def reviews(self, number: int) -> list[Review]:
        out: list[Review] = []
        for page in range(1, 31):
            items = self._json("list-reviews", "GET",
                               f"{self._api}/pulls/{number}/reviews?per_page=100&page={page}")
            if not isinstance(items, list):
                raise GitHubError("list-reviews")
            try:
                for it in items:
                    out.append(Review(
                        id=int(it["id"]),
                        login=str((it.get("user") or {}).get("login") or ""),
                        state=str(it.get("state") or ""),
                        commit_id=it.get("commit_id"),
                        body=str(it.get("body") or ""),
                    ))
            except (KeyError, TypeError, ValueError, AttributeError):
                raise GitHubError("list-reviews") from None
            if len(items) < 100:
                return out
        raise GitHubError("list-reviews")

    def timeline(self, number: int) -> list[TimelineEvent]:
        """The PR timeline's review, dismissal and head-moving events, in
        GitHub's order. A relevant event without its fields fails closed."""
        out: list[TimelineEvent] = []
        for page in range(1, 31):
            items = self._json("timeline", "GET",
                               f"{self._api}/issues/{number}/timeline?per_page=100&page={page}")
            if not isinstance(items, list):
                raise GitHubError("timeline")
            try:
                for it in items:
                    kind = it["event"]
                    if kind == "reviewed":
                        out.append(TimelineEvent("reviewed", _int(it["id"])))
                    elif kind == "review_dismissed":
                        out.append(TimelineEvent(
                            "dismissed", _int(it["dismissed_review"]["review_id"]),
                            str((it.get("actor") or {}).get("login") or "")))
                    elif kind in _REWRITES:
                        out.append(TimelineEvent("rewrite"))
            except (KeyError, TypeError, AttributeError):
                raise GitHubError("timeline") from None
            if len(items) < 100:
                return out
        raise GitHubError("timeline")

    def post_review(self, number: int, head: str, event: str, body: str) -> None:
        self._json("post-review", "POST", f"{self._api}/pulls/{number}/reviews",
                   {"commit_id": head, "event": event, "body": body})

    def dismiss_review(self, number: int, review_id: int, message: str) -> None:
        self._json("dismiss-review", "PUT",
                   f"{self._api}/pulls/{number}/reviews/{review_id}/dismissals",
                   {"message": message, "event": "DISMISS"})
