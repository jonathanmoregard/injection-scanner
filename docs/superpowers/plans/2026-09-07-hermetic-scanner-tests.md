# Hermetic Scanner Tests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (default) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every local and CI pytest run reject real network endpoints by construction, replace existing loopback tests with in-process transport doubles, and repair the limiter state-read fail-open found during review.

**Architecture:** Configure the mature `pytest-socket` plugin in project-level pytest options so the embargo cannot be omitted by a different invocation. Keep HTTP coverage at the existing `lakera._OPENER` seam with complete response/opener doubles. Narrow limiter reset behavior to absent or malformed state; propagate real I/O failures to the existing fail-closed `Decision.ERROR` boundary.

**Tech Stack:** Python 3.12+, pytest, pytest-socket, stdlib urllib/pathlib/tomllib.

---

## File map

- Modify `pyproject.toml`: test-only dependency and mandatory pytest socket options.
- Create `tests/test_network_hermeticity.py`: executable proof that IPv4/IPv6 sockets are blocked and Unix sockets remain permitted.
- Modify `tests/test_ci_relations.py`: guard the project-level embargo configuration.
- Modify `tests/test_lakera.py`: replace four loopback-server tests with in-process transport doubles.
- Modify `injection_scanner/lakera.py`: pin the credentialed destination,
  disable ambient proxies, and strictly validate injection decisions.
- Modify `injection_scanner/intercept.py`: remove the stale legacy fallback
  response-contract comment.
- Modify `tests/test_throttle.py`: regression for unreadable state.
- Modify `injection_scanner/throttle.py`: distinguish missing state from read I/O failure.
- Modify `README.md`: accurate hermetic-test, directory-mode, and parsed-200 documentation.

### Task 1: Enforce the socket embargo in every pytest invocation

**Files:**
- Modify: `pyproject.toml`
- Create: `tests/test_network_hermeticity.py`
- Modify: `tests/test_ci_relations.py`

- [ ] **Step 1: Write the failing sentinel test**

Create `tests/test_network_hermeticity.py`:

```python
"""Executable proof that pytest cannot open real network endpoints."""
from __future__ import annotations

import socket

import pytest
from pytest_socket import SocketBlockedError


@pytest.mark.parametrize("family", [socket.AF_INET, socket.AF_INET6])
def test_pytest_blocks_network_sockets(family: socket.AddressFamily) -> None:
    with pytest.raises(SocketBlockedError):
        socket.socket(family, socket.SOCK_STREAM)


def test_pytest_allows_unix_domain_sockets() -> None:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.close()
```

Append a project-configuration guard to `tests/test_ci_relations.py`:

```python
import tomllib

PROJECT = ROOT / "pyproject.toml"


def test_every_pytest_run_has_the_network_embargo() -> None:
    project = tomllib.loads(PROJECT.read_text(encoding="utf-8"))
    test_deps = project["project"]["optional-dependencies"]["test"]
    assert any(dep.startswith("pytest-socket") for dep in test_deps)
    addopts = project["tool"]["pytest"]["ini_options"]["addopts"].split()
    assert "--disable-socket" in addopts
    assert "--allow-unix-socket" in addopts
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```bash
uv run --extra test pytest -q tests/test_network_hermeticity.py tests/test_ci_relations.py
```

Expected: collection fails because `pytest_socket` is absent, or the
configuration guard fails because the dependency/options are absent. No
network call is made.

- [ ] **Step 3: Add the test-only plugin and mandatory options**

In `pyproject.toml`, append to `[project.optional-dependencies].test`:

```toml
    "pytest-socket>=0.7,<1",
```

Add:

```toml
[tool.pytest.ini_options]
addopts = "--disable-socket --allow-unix-socket"
```

No test gets an `enable_socket` or `socket_enabled` escape hatch.

In `tests/conftest.py`, add a `pytest_configure` hook that rejects
`--force-enable-socket` and `--allow-hosts`, unregisters pytest-socket's
per-test lifecycle plugin after option parsing, and calls
`disable_socket(allow_unix_socket=True)` once. Add a collection hook that
rejects the `enable_socket`, `socket_enabled`, and `allow_hosts`
marker/fixture escape mechanisms.

Extend `tests/test_network_hermeticity.py` with isolated subprocess pytest
cases proving a constructor cached during collection remains guarded, fixture
finalizers remain guarded, and every CLI/per-test escape mechanism exits with
a usage error. The RED run against stock pytest-socket must fail without ever
connecting or binding: constructor creation alone is enough to discriminate
the lifecycle gap.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run:

```bash
uv run --extra test pytest -q tests/test_network_hermeticity.py tests/test_ci_relations.py
```

Expected: all tests pass; IPv4/IPv6 socket construction raises
`SocketBlockedError` in bodies, collection-cached call sites, and finalizers;
escape mechanisms are usage errors; an unbound Unix-domain socket can be
created.

- [ ] **Step 5: Run the fastest file checks**

Run:

```bash
python -m compileall -q tests/conftest.py tests/test_network_hermeticity.py tests/test_ci_relations.py
git diff --check -- pyproject.toml tests/conftest.py tests/test_network_hermeticity.py tests/test_ci_relations.py
```

Expected: exit 0.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml tests/conftest.py tests/test_network_hermeticity.py tests/test_ci_relations.py
git commit -m "test: forbid network endpoints under pytest"
```

### Task 2: Replace real loopback endpoints with transport doubles

**Files:**
- Modify: `tests/test_lakera.py`

- [ ] **Step 1: Verify the embargo catches the current tests**

Run:

```bash
uv run --extra test pytest -q \
  tests/test_lakera.py::test_a_redirect_is_an_outage_and_never_forwards_the_key \
  tests/test_lakera.py::test_a_two_hundred_still_parses_through_the_same_opener \
  tests/test_lakera.py::test_a_response_one_byte_over_the_cap_is_an_outage \
  tests/test_lakera.py::test_a_response_at_the_cap_still_parses
```

Expected: all four error with `SocketBlockedError` while constructing the
loopback server. This is the RED proof that the existing tests violate the new
invariant.

- [ ] **Step 2: Add complete in-process response/opener doubles**

Remove `threading`, `BaseHTTPRequestHandler`, `ThreadingHTTPServer`, the
global probe state, and the `loopback` fixture. Add:

```python
class _Response:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.read_limits: list[int] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> bool:
        return False

    def read(self, limit: int) -> bytes:
        self.read_limits.append(limit)
        return self.body[:limit]


class _Opener:
    def __init__(self, outcome: _Response | BaseException) -> None:
        self.outcome = outcome
        self.calls: list[tuple[object, float]] = []

    def open(self, request, *, timeout: float):
        self.calls.append((request, timeout))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def _hermetic_post(monkeypatch, outcome, *, timeout: float = 5.0):
    opener = _Opener(outcome)
    monkeypatch.setattr(lakera, "_OPENER", opener)
    result = None
    error = None
    try:
        result = lakera._post(
            "https://api.lakera.invalid/v2/guard",
            b"{}",
            {
                "Authorization": f"Bearer {_KEY_MARKER}",
                "Content-Type": "application/json",
            },
            timeout,
        )
    except BaseException as exc:  # returned to the assertion, never swallowed
        error = exc
    return result, error, opener
```

Keep the doubles test-only. Do not add test hooks to production.

- [ ] **Step 3: Rewrite the redirect and response-size tests**

Use a realistic `HTTPError` outcome for the 302 test and assert:

```python
error = HTTPError(
    "https://api.lakera.invalid/v2/guard",
    302,
    "Found",
    {"Location": "https://attacker.invalid/elsewhere"},
    None,
)
result, raised, opener = _hermetic_post(monkeypatch, error)
assert result is None
assert raised is error
assert lakera._transport_reason(raised) == "lakera_unavailable:HTTPError:302"
assert len(opener.calls) == 1
request, _ = opener.calls[0]
assert request.get_header("Authorization") == f"Bearer {_KEY_MARKER}"
assert lakera._NoRedirect().redirect_request(
    request, None, 302, "Found", {}, "https://attacker.invalid/elsewhere"
) is None
```

For 200 and cap-boundary tests, pass `_Response(body)`, assert the parsed
production result, and assert `response.read_limits == [cap + 1]`. The
one-byte-over case must raise exactly `lakera.ResponseTooLarge`.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run:

```bash
uv run --extra test pytest -q tests/test_lakera.py
```

Expected: all Lakera tests pass under the project-wide socket embargo.

- [ ] **Step 5: Check and commit**

```bash
python -m compileall -q tests/test_lakera.py
git diff --check -- tests/test_lakera.py
git add tests/test_lakera.py
git commit -m "test: replace loopback endpoints with transport doubles"
```

### Task 3: Pin the credentialed endpoint and validate responses strictly

**Files:**
- Modify: `tests/test_lakera.py`
- Modify: `injection_scanner/lakera.py`
- Modify: `injection_scanner/intercept.py` (comment only)

- [ ] **Step 1: Write failing endpoint tests**

Add table-driven tests that accept the default endpoint and its normalized
HTTPS/default-port spelling, and reject before token acquisition:

```python
@pytest.mark.parametrize(
    "url",
    [
        "https://attacker.invalid/v2/guard",
        "https://api.lakera.ai.evil.invalid/v2/guard",
        "https://user@api.lakera.ai/v2/guard",
        "https://api.lakera.ai:444/v2/guard",
        "https://api.lakera.ai:/v2/guard",
        "https://api.lakera.ai:0443/v2/guard",
        "https://api.lakera.ai/other",
        "https://api.lakera.ai/v2/guard?next=evil",
        "https://api.lakera.ai/v2/guard#fragment",
        "https://api.lakera.ai/v2/guard?",
        "https://api.lakera.ai/v2/guard#",
        "https://api.lakera.ai:bad/v2/guard",
        "https://api.lakera.ai:65536/v2/guard",
        "https://user:password@api.lakera.ai/v2/guard",
        "https://api%2elakera.ai/v2/guard",
        "https://api.lakera.ai/v2%2fguard",
        " https://api.lakera.ai/v2/guard",
        "\x1fhttps://api.lakera.ai/v2/guard",
        "https://api.lakera.ai/v2/guard\n",
        "https://api.lakera.\tai/v2/guard",
        "https://api.lakera.ai\\@attacker.invalid/v2/guard",
    ],
)
def test_only_the_canonical_lakera_endpoint_can_receive_the_key(
    monkeypatch, url
) -> None:
    _with_key(monkeypatch)
    monkeypatch.setenv("LAKERA_GUARD_URL", url)
    _post_must_not_run(monkeypatch)
    result = lakera.check("anything")
    assert result.ok is False
    assert result.reason == "lakera_unavailable:url-config-error"
```

Add an accepted-spelling table for the default URL, uppercase scheme/host, and
explicit port 443. Install a limiter spy in the rejection table and assert no
token acquisition occurs.

Add a production `_build_opener()` factory. In a test, set `HTTPS_PROXY` and
`ALL_PROXY`, construct an opener, and assert the handler chain contains
`_NoRedirect` but no `ProxyHandler`. CPython does not retain an empty
`ProxyHandler({})`; without the explicit empty handler, ambient proxies create
a populated handler, so absence is the discriminating assertion.

- [ ] **Step 2: Write failing response-schema tests**

Parametrize malformed responses:

```python
@pytest.mark.parametrize(
    "data",
    [
        {"flagged": True, "breakdown": []},
        {"flagged": False, "breakdown": []},
        {"flagged": False, "breakdown": [
            {"detector_type": "prompt_attack", "detected": "false"}
        ]},
        {"flagged": False, "breakdown": [
            {"detector_type": "prompt_attack", "detected": False},
            {"detector_type": "prompt_attack", "detected": False},
        ]},
        {"flagged": False, "breakdown": [
            {"detector_type": "prompt_attack", "detected": True}
        ]},
        {"flagged": "false", "breakdown": [
            {"detector_type": "prompt_attack", "detected": False}
        ]},
    ],
)
def test_malformed_or_contradictory_decisions_fail_closed(
    monkeypatch, data
) -> None:
    _with_key(monkeypatch)
    monkeypatch.setattr(lakera, "_post", lambda *_a, **_kw: data)
    result = lakera.check("anything")
    assert result.ok is False
    assert result.reason == "lakera_unavailable:bad-response"
```

Add a positive test proving a detected non-prompt detector name never appears
in `categories`.

Extend malformed-shape coverage to non-boolean `flagged`/`detected` values,
missing or wrongly typed fields, malformed entries after a valid prompt entry,
conflicting duplicate prompt entries, and a breakdown containing only
non-prompt detectors. Add a liveness regression proving a parsed HTTP 200 with
an invalid schema still records success before returning `bad-response`.

At the raw transport seam, add a duplicate-key JSON regression, including a
nested duplicate. Use `object_pairs_hook` to reject last-value-wins ambiguity
and map that dedicated content-free failure to `bad-response` in `check`.

- [ ] **Step 3: Run the new tests and verify RED**

Run the exact new node IDs with:

```bash
uv run --extra test pytest -q tests/test_lakera.py -k \
  "canonical_lakera_endpoint or ambient_proxies or malformed_or_contradictory or never_exposes"
```

Expected: endpoint-host and malformed-response cases fail against the current
HTTPS-only/lenient parser.

- [ ] **Step 4: Implement destination validation and proxy isolation**

Replace `_is_https` with `_is_trusted_endpoint`:

```python
def _is_trusted_endpoint(url: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(url)
        return (
            parsed.scheme.lower() == "https"
            and parsed.hostname == "api.lakera.ai"
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and parsed.path == "/v2/guard"
            and not parsed.query
            and not parsed.fragment
        )
    except (TypeError, ValueError):
        return False
```

Build the opener with:

```python
_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _NoRedirect(),
)
```

Keep validation before limiter acquisition and header construction.

- [ ] **Step 5: Implement strict prompt-attack parsing**

After confirming `data` is a dictionary, require a boolean `flagged`, a list
`breakdown`, well-formed entries, and exactly one prompt-attack entry. Return
`bad-response` for invalid shapes. Return only:

```python
if prompt_detected:
    if flagged is not True:
        return LakeraResult(ok=False, reason="lakera_unavailable:bad-response")
    return LakeraResult(
        ok=False,
        flagged=True,
        categories=["prompt_attack"],
        reason="lakera:prompt_attack",
    )
return LakeraResult(ok=True, reason="pass")
```

Do not expose any upstream detector name other than the fixed literal.

- [ ] **Step 6: Run, check, and commit**

```bash
uv run --extra test pytest -q tests/test_lakera.py
python -m compileall -q injection_scanner/lakera.py injection_scanner/intercept.py tests/test_lakera.py
git diff --check -- injection_scanner/lakera.py injection_scanner/intercept.py tests/test_lakera.py
git add injection_scanner/lakera.py injection_scanner/intercept.py tests/test_lakera.py
git commit -m "fix: pin and validate the Lakera boundary"
```

### Task 4: Make limiter state read failures fail closed

**Files:**
- Modify: `tests/test_throttle.py`
- Modify: `injection_scanner/throttle.py`

- [ ] **Step 1: Write the failing regression test**

Add beside the durability tests:

```python
def test_a_state_file_read_error_refuses_instead_of_resetting(
    tmp_path, monkeypatch
) -> None:
    fake = _Fake()
    lim = _limiter(tmp_path, fake, min_interval_s=10.0, burst=3)
    lim.record_throttled("600")
    real_read_text = Path.read_text

    def unreadable(path: Path, *args, **kwargs):
        if path == lim.state_path:
            raise PermissionError("simulated unreadable limiter state")
        return real_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", unreadable)
    assert lim.acquire() is Decision.ERROR
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```bash
uv run --extra test pytest -q \
  tests/test_throttle.py::test_a_state_file_read_error_refuses_instead_of_resetting
```

Expected: FAIL because current `_load` catches `PermissionError`, creates a
fresh full bucket, and returns `Decision.ALLOWED`.

- [ ] **Step 3: Narrow reset behavior**

In `CrossProcessLimiter._load`, replace the broad handler with:

```python
        except FileNotFoundError:
            return self._fresh(now)
        except (ValueError, TypeError, KeyError):
            return self._fresh(now)
```

Update the docstring to state that a missing file or malformed contents reset,
while a read I/O failure propagates to `acquire` and becomes
`Decision.ERROR`.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run:

```bash
uv run --extra test pytest -q tests/test_throttle.py
```

Expected: all throttle tests pass, including the new unreadable-state case.

- [ ] **Step 5: Check and commit**

```bash
python -m compileall -q injection_scanner/throttle.py tests/test_throttle.py
git diff --check -- injection_scanner/throttle.py tests/test_throttle.py
git add injection_scanner/throttle.py tests/test_throttle.py
git commit -m "fix: fail closed on limiter state read errors"
```

### Task 5: Align documentation and run the complete hermetic verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Correct the cache-directory statement**

Replace “a directory this uid owns is trusted whatever its permissions” with:

```markdown
The directory must be owned by this uid and must not grant group or world
write unless it carries the sticky bit. Sharing one cache directory between
accounts is unsupported by design.
```

- [ ] **Step 2: Clarify breaker success and test hermeticity**

State that a **parsed** HTTP 200 from a call issued after the latest trip
closes the breaker. In the CI section state that `pytest-socket`, loaded from
project-level `addopts`, blocks IPv4/IPv6 sockets for both local and CI
pytest runs; HTTP clients are tested through in-process transports.

- [ ] **Step 3: Check the documentation**

```bash
rg -n "whatever its permissions|real loopback|hermetic|parsed HTTP 200" README.md
git diff --check -- README.md
```

Expected: the obsolete statement is absent, and the replacement documentation
is present.

- [ ] **Step 4: Run complete verification with keys absent**

```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY \
  uv run --extra test pytest -q tests/
python -m compileall -q injection_scanner tests
git diff --check
git status --short
```

Expected: the full suite passes; compileall and diff check exit 0; status shows
only the intended README change before commit. No smoke/eval workflow or
endpoint is contacted.

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: document hermetic scanner tests"
```

- [ ] **Step 6: Review the complete branch**

```bash
git diff --stat 7167fa2ecb8c8e7017776a6f93e2b78b3e4247b2..HEAD
git status --short --branch
```

Expected: a clean feature branch containing the original limiter work plus
the hermeticity and fail-closed corrections.
