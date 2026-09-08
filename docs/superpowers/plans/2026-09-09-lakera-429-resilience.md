# Lakera 429 Resilience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (default) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep research delivery usable during Lakera quota throttling while requiring strict honeypot success and unanimous cross-family benign arbitration.

**Architecture:** Integrate the reviewed cross-process limiter and smoke liveness cache from `feat/lakera-debounce` onto strict scanner main. Preserve breaker cause in a closed on-disk enum so only quota states reach the existing L3/L4 fail-closed fallback. Teach smoke to accept only a fully verified quota fallback, then pin the exact scanner commit from research-agent.

**Tech Stack:** Python 3.12/3.13, pytest, `fcntl.flock`, JSON state, uv, GitHub Actions.

---

## File map

- `injection_scanner/throttle.py`: shared token bucket, breaker cause, closed admission decisions.
- `injection_scanner/lakera.py`: map HTTP 429/503 into typed breaker causes and fixed safe reasons.
- `injection_scanner/intercept.py`: exact quota classification and strict honeypot-plus-judge fallback.
- `injection_scanner/smoke.py`: production-stack liveness definition and cache/log behavior.
- `tests/test_throttle.py`: persisted cause and non-downgrade properties.
- `tests/test_lakera.py`: decision-to-reason and HTTP-to-cause mapping.
- `tests/test_intercept.py`: quota fallback allow/reject matrix.
- `tests/test_smoke_liveness.py`: healthy quota fallback and cache behavior.
- `mcp_server/server.py` in research-agent: closed diagnosis vocabulary for new limiter reasons.
- `tests/test_infra_reason_visibility.py` in research-agent: no-leak diagnosis regressions.
- `uv.lock` in research-agent: exact scanner commit pin.

### Task 1: Integrate reviewed budget-control branch with strict main

**Files:** Existing files from `feat/lakera-debounce`; strict `honeypot.py` and strict tests remain from current main.

- [ ] **Step 1: Merge without committing**

```bash
git merge --no-ff --no-commit feat/lakera-debounce
```

Expected: PR #15 files enter index. If conflicts occur, keep current main's strict honeypot request protocol and PR #15's limiter/liveness/CI files.

- [ ] **Step 2: Verify strict protocol survived integration**

```bash
rg -n 'strict=True|parallel_tool_calls=False|tool_choice="required"|additionalProperties' injection_scanner/honeypot.py tests/test_honeypot_tool_args.py
```

Expected: strict schema, required first tool turn, disabled parallel calls, and malformed-argument tests all remain.

- [ ] **Step 3: Run integration-focused tests before commit**

```bash
uv run --extra test pytest -q tests/test_throttle.py tests/test_lakera.py tests/test_smoke_liveness.py tests/test_ci_relations.py tests/test_honeypot_tool_args.py tests/test_honeypot_scan_surface.py
```

Expected: all pass with no network.

- [ ] **Step 4: Commit integration**

```bash
git commit -m "feat: integrate Lakera budget controls"
```

### Task 2: Preserve breaker cause across processes

**Files:** Modify `injection_scanner/throttle.py`, `injection_scanner/lakera.py`, `tests/test_throttle.py`, `tests/test_lakera.py`.

- [ ] **Step 1: Write failing throttle tests**

Add tests equivalent to:

```python
from injection_scanner.throttle import BreakerCause, Decision


def test_service_breaker_remains_distinct_from_quota(tmp_path):
    fake = _Fake()
    lim = _limiter(tmp_path, fake)
    assert lim.acquire() is Decision.ALLOWED
    lim.record_throttled(None, cause=BreakerCause.SERVICE)
    assert lim.acquire() is Decision.SERVICE_UNAVAILABLE
    assert _state(lim)["breaker_cause"] == "service"


def test_quota_signal_cannot_downgrade_open_service_breaker(tmp_path):
    fake = _Fake()
    lim = _limiter(tmp_path, fake)
    lim.record_throttled("30", cause=BreakerCause.SERVICE)
    lim.record_throttled("5", cause=BreakerCause.QUOTA)
    assert lim.acquire() is Decision.SERVICE_UNAVAILABLE
    assert _state(lim)["breaker_cause"] == "service"


def test_foreign_schema_resets_breaker_cause(tmp_path):
    fake = _Fake()
    lim = _limiter(tmp_path, fake)
    lim.state_path.parent.mkdir(parents=True)
    lim.state_path.write_text('{"schema":1}', encoding="utf-8")
    assert lim.acquire() is Decision.ALLOWED
    assert _state(lim)["schema"] == 2
```

- [ ] **Step 2: Verify RED**

```bash
uv run --extra test pytest -q tests/test_throttle.py -k 'service_breaker or foreign_schema'
```

Expected: import/member/signature assertions fail because breaker cause does not exist.

- [ ] **Step 3: Implement closed cause and decision**

Implement this shape, preserving existing guards and explicit comparisons:

```python
_SCHEMA = 2


class BreakerCause(enum.Enum):
    QUOTA = "quota"
    SERVICE = "service"


class Decision(enum.Enum):
    ALLOWED = "allowed"
    THROTTLED = "throttled"
    SERVICE_UNAVAILABLE = "service-unavailable"
    ERROR = "error"


@dataclass
class _State:
    tokens: float
    updated_at: float
    open_until: float
    failures: int
    tripped_at: float
    breaker_cause: BreakerCause | None
```

`record_throttled(..., cause=BreakerCause.QUOTA)` stores only enum values. While an unexpired service breaker exists, later quota records keep `SERVICE`. `_attempt` returns both wait and cause; `acquire` returns `SERVICE_UNAVAILABLE` only when wait exhaustion came from an open service breaker. Bucket exhaustion remains `THROTTLED`. `_save` writes `breaker_cause.value` or `None`; `_load` accepts only `None`, `quota`, or `service`, else resets fresh.

- [ ] **Step 4: Write failing Lakera mapping tests**

Extend `_SpyLimiter.record_throttled` to capture cause, then assert:

```python
assert _http_failure(429).recorded_cause is BreakerCause.QUOTA
assert _http_failure(503).recorded_cause is BreakerCause.SERVICE

spy = _SpyLimiter(Decision.SERVICE_UNAVAILABLE)
result = _check_with_spy(monkeypatch, spy)
assert result.reason == "lakera_unavailable:service-unavailable"
assert spy.post_calls == 0
```

- [ ] **Step 5: Verify RED, implement mapping, verify GREEN**

```bash
uv run --extra test pytest -q tests/test_lakera.py -k 'service or 429 or 503 or throttle'
```

Use bounded integer status only:

```python
cause = BreakerCause.QUOTA if code == 429 else BreakerCause.SERVICE
limiter.record_throttled(_retry_after(exc), cause=cause)
```

Map `Decision.SERVICE_UNAVAILABLE` to the fixed literal `lakera_unavailable:service-unavailable`.

- [ ] **Step 6: Run component tests and commit**

```bash
uv run --extra test pytest -q tests/test_throttle.py tests/test_lakera.py
git add injection_scanner/throttle.py injection_scanner/lakera.py tests/test_throttle.py tests/test_lakera.py
git commit -m "fix: retain Lakera breaker cause"
```

### Task 3: Add exact quota-only L3/L4 fallback

**Files:** Modify `injection_scanner/intercept.py`, `tests/test_intercept.py`.

- [ ] **Step 1: Write failing fallback tests**

Add a helper whose signature preserves PR #15's wait keyword:

```python
def _lakera_failure(reason):
    from injection_scanner.lakera import LakeraResult

    def fail(_text, *, max_wait_s=None):
        return LakeraResult(ok=False, reason=reason)

    return fail
```

Parameterize `lakera_unavailable:HTTPError:429` and `lakera_unavailable:throttled`; patch strict honeypot clean and judge unanimous benign; assert verdict passes and both layer values remain. Add negative tests proving `service-unavailable`, `HTTPError:503`, `no-key`, and `limiter-error` reject before honeypot/judge. Add tests proving quota fallback rejects on honeypot failure, judge attack, judge outage, and `use_honeypot=False`.

- [ ] **Step 2: Verify RED**

```bash
uv run --extra test pytest -q tests/test_intercept.py -k 'quota or service_unavailable'
```

Expected: quota cases reject before honeypot.

- [ ] **Step 3: Implement exact classification and reuse arbitration**

```python
_LAKERA_QUOTA_REASONS = frozenset({
    "lakera_unavailable:HTTPError:429",
    "lakera_unavailable:throttled",
})


def is_lakera_quota_degraded(reason: object) -> bool:
    return isinstance(reason, str) and reason in _LAKERA_QUOTA_REASONS
```

Defer when reason is `lakera:prompt_attack` or `is_lakera_quota_degraded(reason)`, but only with honeypot enabled. Reuse current honeypot and judge code without weakening any result checks. Keep `lakera_arbitration:*` on judge rejection; `layers["lakera"]` distinguishes positive versus quota paths.

- [ ] **Step 4: Verify GREEN and strict tests**

```bash
uv run --extra test pytest -q tests/test_intercept.py tests/test_honeypot_tool_args.py tests/test_honeypot_scan_surface.py tests/test_judge.py
```

- [ ] **Step 5: Commit**

```bash
git add injection_scanner/intercept.py tests/test_intercept.py
git commit -m "fix: scan through Lakera quota exhaustion"
```

### Task 4: Make boot health reflect viable strict fallback

**Files:** Modify `injection_scanner/smoke.py`, `tests/test_smoke_liveness.py`.

- [ ] **Step 1: Write failing smoke tests**

Construct an `ok=True` verdict with `lakera_unavailable:throttled`, honeypot `pass`, and judge `benign-unanimous`. Assert `run_smoke` succeeds, records cache, and logs `quota fallback`. Parameterize missing/wrong honeypot and judge layer values; assert `SmokeFailure` and no cache write. Assert cache-hit line makes no claim that named vendors were freshly contacted.

- [ ] **Step 2: Verify RED**

```bash
uv run --extra test pytest -q tests/test_smoke_liveness.py -k 'quota or cache_hit'
```

Expected: quota verdict fails the current `lakera == "pass"` assertion.

- [ ] **Step 3: Implement liveness predicate**

Accept either:

```python
full_live = lk == "pass" and hp == "pass"
quota_live = (
    is_lakera_quota_degraded(lk)
    and hp == "pass"
    and v.layers.get("judge") == "benign-unanimous"
)
```

Require `v.ok` first. Cache only `full_live or quota_live`. Emit distinct full-live versus quota-fallback lines; make cache-hit line claim only scanner-stack liveness.

- [ ] **Step 4: Verify GREEN and commit**

```bash
uv run --extra test pytest -q tests/test_smoke_liveness.py
git add injection_scanner/smoke.py tests/test_smoke_liveness.py
git commit -m "fix: accept verified quota fallback at boot"
```

### Task 5: Verify and publish injection-scanner

**Files:** All scanner changes plus spec/plan.

- [ ] **Step 1: Run syntax and full hermetic suite**

```bash
uv run --extra test python -m compileall -q injection_scanner tests
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u LAKERA_API_KEY uv run --extra test pytest -q tests/
```

Expected: exit 0, no network.

- [ ] **Step 2: Inspect diff and preserve untracked note**

```bash
git status --short
git diff --check origin/main...HEAD
git log --oneline --decorate origin/main..HEAD
```

Expected: `pending_for_human.md` remains untracked and absent from every commit.

- [ ] **Step 3: Push and open PR**

```bash
git push -u origin fix/lakera-429-resilience
gh pr create --repo jonathanmoregard/injection-scanner --base main --head fix/lakera-429-resilience --title "fix: keep scanning through Lakera quota exhaustion" --body-file /tmp/injection-scanner-lakera-429-pr.md
```

### Task 6: Pin scanner and extend closed diagnosis in research-agent

**Files:** Modify `mcp_server/server.py`, `tests/test_infra_reason_visibility.py`, `uv.lock` on a new session-owned research-agent branch from `origin/main`.

- [ ] **Step 1: Create branch and write failing diagnosis tests**

```bash
git fetch origin main
git switch -c fix/lakera-429-resilience origin/main
```

Assert exact fixed reasons map to exact closed conditions:

```python
assert _infra_diagnosis("lakera_unavailable:throttled")["condition"] == "throttled"
assert _infra_diagnosis("lakera_unavailable:limiter-error")["condition"] == "limiter_error"
assert _infra_diagnosis("lakera_unavailable:service-unavailable")["condition"] == "service_unavailable"
```

- [ ] **Step 2: Verify RED, implement enums, verify GREEN**

```bash
uv run --with pytest pytest -q tests/test_infra_reason_visibility.py
```

Add only closed enum members and literal token mappings; never pass reason fragments through.

- [ ] **Step 3: Pin exact scanner commit**

Update only injection-scanner's git SHA in `uv.lock`, then sync:

```bash
uv lock --upgrade-package injection-scanner
uv sync
```

- [ ] **Step 4: Verify targeted and full suites**

```bash
uv run --with pytest pytest -q tests/test_infra_reason_visibility.py tests/test_scanner_health_gate.py tests/test_lazy_boot_warmup.py tests/test_artifact_gate.py
uv run --with pytest pytest -q
```

Expected: only documented pre-existing memguard failure may remain. Compare against fresh branch baseline before attributing it.

- [ ] **Step 5: Commit, push, open PR**

```bash
git add mcp_server/server.py tests/test_infra_reason_visibility.py uv.lock
git commit -m "fix: deploy Lakera quota-resilient scanner"
git push -u origin fix/lakera-429-resilience
gh pr create --repo jonathanmoregard/research-agent --base main --head fix/lakera-429-resilience --title "fix: deploy Lakera quota-resilient scanner" --body-file /tmp/research-agent-lakera-429-pr.md
```

### Task 7: Deploy without merge and prove both reports

**Files:** Runtime `.venv`, supplied `/tmp` dispatcher/prompts/output directory.

- [ ] **Step 1: Verify installed scanner identity and offline smoke contracts**

```bash
uv run python -c 'import injection_scanner, pathlib; print(pathlib.Path(injection_scanner.__file__).resolve())'
uv run --with pytest pytest -q tests/test_scanner_health_gate.py tests/test_lazy_boot_warmup.py
```

- [ ] **Step 2: Run supplied dispatcher under a new transient service**

Use a fresh output directory and log. Remove the dispatcher's artificial 900-second sleeps because scanner now owns shared pacing and quota fallback. Keep prompts byte-identical.

- [ ] **Step 3: Monitor to terminal state**

Poll service plus log at intervals under 60 seconds. On completion, read only returned clean report files and index; do not read isolation-zone reject artifacts.

- [ ] **Step 4: Verify acceptance**

Both index entries must have `status` accepted by the dispatcher, non-null existing `report_path`, and no scanner-infra reject. Run fresh full tests again before completion claim.

- [ ] **Step 5: Report PR states from live queries**

Query both PRs with `.state`, checks, and URLs. Do not merge.
