# Hermetic scanner tests

Date: 2026-09-07. Status: approved by the maintainer (“do sota”).

## Problem

The scanner suite says it is key-free and network-free, but four Lakera tests
start a real loopback HTTP server and send requests through the production
opener. Nothing prevents a future test from reaching a public endpoint when a
developer or CI runner happens to have credentials and network access.
Hermeticity is therefore an intention, not an enforced invariant.

The same review found a separate fail-closed defect in the new limiter:
permission and other I/O failures while reading the state file are classified
as corrupt state and reset to a fresh full bucket. Only a missing or
syntactically corrupt state file may reset; an unreadable state file must
refuse the call.

## Requirements

1. Every pytest run blocks IPv4 and IPv6 socket access by default, locally and
   in CI, before a connection or listening endpoint is opened.
2. The embargo is project configuration, not a command-line convention. A
   developer invoking plain `pytest` receives the same protection as CI.
3. If the embargo plugin is absent, pytest fails during option parsing rather
   than running unprotected.
4. Tests that exercise HTTP behavior use explicit in-process transports or
   response doubles. No test receives an allow-network marker.
5. A sentinel regression test proves the embargo is active.
6. Unix-domain sockets remain available; they do not reach network endpoints
   and may be needed by local test infrastructure.
7. CI continues to run the entire deterministic test tree. Live smoke and
   sampled evaluation remain separate operational workflows, not tests.
8. Limiter state-file read I/O errors return `Decision.ERROR`; missing,
   malformed, non-finite, or foreign-schema state still resets safely.
9. The scanner remains fail-closed, and no secret or scanned bytes appear in
   errors, logs, state, or test output.
10. The Lakera bearer key can be sent only to the canonical Guard v2 HTTPS
    endpoint. A configured URL cannot select another host, port, path, query,
    fragment, or userinfo, and the client does not inherit ambient proxies.
11. A response can pass only when it has a boolean top-level `flagged`, a
    well-formed breakdown, and exactly one boolean `prompt_attack` decision.
    Missing, duplicate, malformed, or contradictory injection decisions fail
    closed. Detector names other than the fixed `prompt_attack` literal never
    leave the scanner as categories.

## Design

### Pytest network embargo

Add `pytest-socket` to the test-only dependency group and configure:

```toml
[tool.pytest.ini_options]
addopts = "--disable-socket --allow-unix-socket"
```

`--disable-socket` is parsed before tests run and patches socket creation for
the entire pytest process. Keeping it in project configuration makes plain
`pytest`, `python -m pytest`, local `uv run`, and the existing CI command
equivalent. `--allow-unix-socket` retains non-network local IPC.

No test may opt out with `enable_socket` or `socket_enabled`. The CI
relations test will parse `pyproject.toml` and assert the dependency and both
options remain present. This makes removal of the embargo an ordinary test
failure.

A sentinel test attempts to create an IPv4 socket and asserts
`pytest_socket.SocketBlockedError`. It is not the primary enforcement; it is
an executable assertion that the configured enforcement is loaded.

### Hermetic HTTP behavior tests

Delete the loopback `ThreadingHTTPServer` fixture. Replace it with small
test-only response and opener doubles at the transport seam already owned by
`lakera._OPENER`.

The doubles reproduce the complete behavior each test consumes:

- a context-managed response whose `read(limit)` records the requested cap
  and returns bounded bytes;
- an opener whose `open(request, timeout)` records the request and either
  returns that response or raises a realistic `urllib.error.HTTPError`;
- direct coverage of `_NoRedirect.redirect_request`, proving redirects are
  rejected without creating a server.

Assertions remain about production behavior: response-size enforcement,
timeout propagation, authorization headers, and fail-closed redirect results.
They do not assert merely that a mock was called.

### Limiter fail-closed correction

Change `CrossProcessLimiter._load` so `FileNotFoundError` creates fresh
state, while other `OSError` values propagate to `acquire`. The existing
top-level exception boundary converts them to `Decision.ERROR`, which
`lakera.check` already maps to
`lakera_unavailable:limiter-error`.

Add a regression test that writes an open-breaker state and makes the state
path unreadable through a deterministic patched `Path.read_text`. It must
first fail by returning `ALLOWED`, then pass by returning `ERROR`. Avoid
mode-bit tests because they are unreliable when tests run as root.

### Credentialed endpoint and response validation

`LAKERA_GUARD_URL` remains an operator input for compatibility, but it may
name only the canonical service: HTTPS, host `api.lakera.ai`, path
`/v2/guard`, default port, no userinfo, query, or fragment. Scheme and host
normalization follow URL rules; a different destination returns the fixed
`lakera_unavailable:url-config-error` before a token is spent or the key is
attached.

Build the urllib opener with `ProxyHandler({})` and the existing no-redirect
handler. This makes the credential's network destination depend only on the
validated URL, not on `HTTPS_PROXY`, `ALL_PROXY`, or desktop proxy state.

Response parsing validates the decision as a schema, not as a collection of
optional hints:

- `flagged` is a real boolean;
- `breakdown` is a list of dictionaries whose `detector_type` is a string
  and `detected` is a real boolean;
- exactly one entry has `detector_type == "prompt_attack"`;
- `prompt_attack: true` requires `flagged: true`;
- a false prompt-attack result may coexist with top-level `flagged: true`,
  because moderation/PII detectors are intentionally not gate decisions.

The only returned category is the fixed literal `prompt_attack` on that
detector's positive result. Other detector names are neither trusted as output
nor needed for the gate. Any invalid shape returns the fixed fail-closed
`lakera_unavailable:bad-response`.

### Documentation consistency

Update the README to match the implemented cache-directory mode policy.
Clarify that a parsed HTTP 200 closes the breaker. A malformed JSON response
continues to fail closed and does not make a liveness claim.

## Verification

Run, with provider keys removed from the environment:

```bash
uv run --extra test pytest -q tests/test_network_hermeticity.py
uv run --extra test pytest -q tests/test_lakera.py tests/test_throttle.py tests/test_ci_relations.py
python -m compileall -q injection_scanner tests
uv run --extra test pytest -q tests/
```

The full suite must pass with the socket embargo active. No live smoke,
scheduled workflow, public endpoint, or loopback server is invoked.

## Non-goals

- Blocking network for the separate `live-eval` workflow; its purpose is to
  probe vendors explicitly.
- Adding production network feature flags.
- Building an OS-specific test launcher or requiring containers locally.
- Weakening scanner availability checks to make tests pass.
