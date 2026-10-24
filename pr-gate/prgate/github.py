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

_PULL_QUERY = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      headRefOid
      autoMergeRequest { enabledBy { login } }
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


@dataclass(frozen=True)
class Review:
    id: int
    login: str
    state: str
    commit_id: str | None
    body: str


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
            return PullState(head_sha=pr["headRefOid"], auto_merge=amr is not None,
                             enabled_by=enabled_by)
        except (KeyError, TypeError, AttributeError):
            raise GitHubError("pull-state") from None

    def diff(self, base_ref: str, head: str, limit: int) -> bytes:
        url = f"{self._api}/compare/{urllib.parse.quote(base_ref, safe='/')}...{head}"
        return self._request("diff", "GET", url, accept="application/vnd.github.diff",
                             limit=limit)

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

    def post_review(self, number: int, head: str, event: str, body: str) -> None:
        self._json("post-review", "POST", f"{self._api}/pulls/{number}/reviews",
                   {"commit_id": head, "event": event, "body": body})

    def dismiss_review(self, number: int, review_id: int, message: str) -> None:
        self._json("dismiss-review", "PUT",
                   f"{self._api}/pulls/{number}/reviews/{review_id}/dismissals",
                   {"message": message, "event": "DISMISS"})
