# injection-scanner

Layered prompt-injection / secret-exfil scanner. Extracted from `research-agent` so multiple agents can share a single hardening pipeline.

## Layers

| Order | Layer | Purpose |
|------|-------|---------|
| L0 | `unicode_sanitize` | Strip covert channels (zero-width, bidi, tag-block), NFKC normalize, flag anomalous density. |
| L1b | `secret_shapes` | High-precision API key / JWT / PEM patterns. |
| L2 | `lakera` | Hosted Lakera Guard prompt-injection classifier, wired fail-closed. Exact quota pressure may defer to L3/L4; every other failure rejects. Paced fleet-wide — see [Lakera rate limiting](#lakera-rate-limiting). |
| L3 | `honeypot` | Run the report past a 3-model judge ensemble (`claude-haiku-4-5`, `gpt-4o-mini`, `gpt-4.1-nano`) across six canary scenarios — two scenarios per model. If any judge gets coerced into calling a bait tool, echoing a canary via a legitimate tool argument, or surfacing one in freeform text, the report is rejected. |
| L4 | `judge` | Arbitration when Lakera says `prompt_attack` or reports exact quota pressure and the honeypot is fully clean: a cross-family panel must unanimously rule the text "describes, not directs" before delivery. |

L1a (regex) was retired (legit research output false-positived); wrap-escape protection moved to the consumer's delivery boundary.

## Install

```bash
pip install -e ~/Repos/injection-scanner
```

L3 honeypot environment requirements (fail-closed if any are missing):

- `ANTHROPIC_API_KEY` — required (2 of 6 scenarios run on `claude-haiku-4-5`).
- `OPENAI_API_KEY` — required (4 of 6 scenarios run on `gpt-4o-mini` / `gpt-4.1-nano`).

A missing key surfaces as `honeypot_unavailable:<scenario>:unavailable:no-<provider>-api-key+skipped=N/6` in the Verdict. Per the fail-closed contract, that quarantines every report until the key is restored. Keys may live in env OR in the local secret store under `app=research-agent, key={anthropic,openai}-api-key`.

## Lakera rate limiting

Lakera Guard is called from one function, `lakera.check()`, by several independent processes that share ONE Lakera account. Measured 2026-09-05: from ~15:00 local, Lakera answered HTTP 429 to roughly three of every four calls — about one success per 4–5 minutes fleet-wide, regardless of how many attempts were made — because every caller retried on its own schedule and no process could see what any other had done.

### The relations

| Caller | Lakera calls per event | What paces it |
|---|---|---|
| research-agent boot smoke (one MCP server per Claude Code pane) | 1 per spawn, 0 while a cached pass is fresh | liveness cache, then the shared limiter |
| research-agent degraded recheck | same as a boot smoke — it calls `run_smoke()` too | same |
| research-agent per-report scan | 1 per `research()` / `retry_research()` | the shared limiter; refuses immediately unless the caller passes a wait budget |
| CI `smoke` job (`live-eval.yml`) | 1 per run — nightly, or on dispatch | runner-local limiter at 60 s / burst 2, inside the `lakera-live` concurrency group |
| CI `eval` job (`live-eval.yml`) | 16, plus up to 2 re-scans per disagreeing case | same, plus `--lakera-max-wait 1800` and `needs: smoke` |
| per-push CI (`ci.yml`) | 0 | hermetic — no vendor call, no secret |
| ad-hoc local `eval` runs | 16+ | the shared limiter, `--lakera-max-wait` default 900 |

`injection_scanner/throttle.py` is the shared memory they were missing: one token bucket plus one circuit breaker in a JSON file under the cache directory, every operation a read-modify-write under an exclusive `flock`. With N processes sharing the file, at most `burst + elapsed / min_interval_s` calls reach Lakera in any window of length `elapsed`, and zero while the breaker is open. **N does not appear in the bound**, so adding a pane or a CI runner cannot raise the ceiling.

### Configuration

Every limit is an input. There is no on/off switch: "off" is `MIN_INTERVAL_S=0` (bucket always full) plus `BACKOFF_MAX_S=0` (every breaker delay clamps to zero), which is what the test suite runs and what nobody should want in production. Malformed values fall back to the default and are then clamped, so a typo degrades to a sane limiter rather than to no limiter.

| Environment variable | Default | Clamp | Meaning |
|---|---|---|---|
| `INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S` | `300` | `[0, 3600]` | Sustained fleet-wide interval — one call per this many seconds. `0` disables the bucket; the breaker still applies. |
| `INJECTION_SCANNER_LAKERA_BURST` | `10` | `[1, 1000]` | Bucket capacity: how many calls may go out back-to-back after an idle period. |
| `INJECTION_SCANNER_LAKERA_BACKOFF_BASE_S` | `300` | `[0, 3600]` | Breaker delay after the first consecutive throttle that carried no usable `Retry-After`. Doubles per consecutive failure. |
| `INJECTION_SCANNER_LAKERA_BACKOFF_MAX_S` | `3600` | `[0, 86400]` | Cap on **every** breaker delay, a server-supplied `Retry-After` included. |
| `INJECTION_SCANNER_LAKERA_LOCK_WAIT_S` | `2` | `[0, 60]` | Bounded wait for the state-file lock before the call is refused. Also bounds the liveness cache's lock. |
| `INJECTION_SCANNER_LAKERA_MAX_WAIT_S` | `0` | `[0, 86400]` | Default wait budget for `check()` when the caller passes none. `0` refuses immediately rather than parking a report. |
| `INJECTION_SCANNER_LAKERA_MAX_RESPONSE_BYTES` | `1048576` | `[4096, 67108864]` | How much of a Guard response body is read. A larger one is an outage (`lakera_unavailable:ResponseTooLarge`), not an OOM: the timeout bounds how long a call takes, this bounds how much it can return. |
| `INJECTION_SCANNER_SMOKE_LIVENESS_TTL_S` | `3600` | `[0, 86400]` | How long one passing boot-smoke liveness probe is trusted fleet-wide (see below). `0` disables the cache. |
| `INJECTION_SCANNER_CACHE_DIR` | `~/.cache/injection-scanner` | — | State directory (`lakera-throttle.json` + `.lock`, `smoke-liveness.json` + `.lock`). Same directory the self-updater defaults to. |

**What the defaults rest on (measured 2026-09-06).** Lakera publishes exactly one limit: the Community plan's **10,000 requests per month** — 13.9 per hour, one every 4.3 minutes. That equals the trickle measured through the 2026-09-05 throttle (one success per 4–5 minutes fleet-wide, regardless of how many attempts were made), which is what identifies the monthly quota rather than some unpublished QPS ceiling as the thing the fleet was hitting. Overnight, 25 calls in 30 minutes were accepted before ~40 minutes of 429s, so Lakera's own bucket is roughly 25–50 deep with a slow refill. The defaults sit under that: 12 calls/hour sustained, a burst of 10 so one multi-pane session restore passes, and a breaker that waits minutes rather than seconds because recovery was observed to take tens of them. The plan tier is visible only on the Lakera dashboard; on a paid tier every knob loosens via environment, and the algorithm does not change.

Batch callers pass a wait budget instead of being refused: `scan(..., lakera_max_wait_s=900)`, `scan_text(..., lakera_max_wait_s=900)`, or `python -m injection_scanner.eval ... --lakera-max-wait 900` (which is already the eval default, because eval is always a batch caller).

**The cache directory is a shared, single-uid resource.** `INJECTION_SCANNER_CACHE_DIR` must name an ABSOLUTE path — `~` is shell syntax, and a relative path resolves per process, so every process would find its own full bucket and pace itself against nobody. A value that is not absolute after expansion falls back to the default, the same way an out-of-range number falls back to its clamp. If `HOME` cannot be resolved at all (a scratch container, `docker run --user 1234`, some CI runners), the fallback is `<tempdir>/injection-scanner-<uid>` — absolute and per-uid, not durable across reboots, which costs one reset bucket.

The final directory component is checked with `lstat` before every use. It must be a real directory owned by the current uid; symlinks and foreign owners are refused. A same-owner directory is also refused when it grants group or world write unless it has the sticky bit. Sticky world-writable directories are allowed because other unprivileged users cannot rename or unlink entries they do not own; the directory owner or a privileged process still can. A refusal makes the limiter fail closed with `lakera_unavailable:limiter-error` and the liveness cache read as a miss. This covers both hostile pre-creation under a shared temp directory and ordinary `sudo -E` ownership accidents. **Sharing one cache directory between accounts is unsupported by design.**

### The boot-smoke liveness cache

`run_smoke()` has two phases: deterministic canaries that touch no network, and one live probe that calls Lakera and the honeypot providers. Measured 2026-09-06, research-agent boot smokes alone ran **~632 per day** — one per server spawn, plus one per degraded recheck — about 19,000 a month against a 10,000-a-month quota, before a single report is scanned. Spawn frequency, not scan volume, is what exhausts the account, and one Claude Code session restore spawns six panes at once. The limiter bounds the RATE; only this reduces the DEMAND.

So a healthy scanner-stack probe is recorded in `smoke-liveness.json` and trusted fleet-wide for `INJECTION_SCANNER_SMOKE_LIVENESS_TTL_S` seconds: the second and every later spawn inside the TTL costs zero vendor calls. Healthy means either a full Lakera + honeypot pass, or exact quota pressure followed by a full strict honeypot pass and unanimous benign judge result. There is deliberately no single-flight, so panes that boot simultaneously — before the first probe has finished and recorded — all miss and all probe, a burst the limiter is there to bound. Recovery after an outage works the same way: degraded rechecks call `run_smoke()` too, so once one pane's recheck passes and records, every other pane's next recheck is served from the cache.

It is a cache in front of a probe, not a gate:

- Phase 1 always runs. It checks the installed scanner's own code, not the fleet's vendors.
- A missing, corrupt, foreign-schema, unreadable or future-dated entry is a **miss** — the probe runs exactly as it did before. So is a cache directory that fails the ownership/mode policy above. An unwritable cache directory means the pass is simply not recorded. Nothing here can turn into fail-open.
- A **failing** probe records nothing and raises as it always did, so one bad boot cannot silence the probe fleet-wide.
- The file holds `{"schema": 1, "ok": true, "at": <epoch>}` — a boolean about the scanner stack and a timestamp, no reason string and no report bytes.
- `0` disables it.

**To force a fresh scanner-stack probe**, delete `smoke-liveness.json` from the cache directory, or set `INJECTION_SCANNER_SMOKE_LIVENESS_TTL_S=0`.

What a stale cached pass can hide is an outage that began within the TTL. The server then boots "healthy" and the first real scan fails closed with the agent-readable infra reason: fail-closed and visibility are both preserved, and only the moment of discovery moves from spawn to first use. The sharper edge is that the hidden condition need not be temporal at all — a PANE-LOCAL fault, this process missing `LAKERA_API_KEY` or `ANTHROPIC_API_KEY` or running an older install, is papered over by a healthier peer's pass, because what is cached is a claim about the vendors and the reader cannot tell it apart from a claim about itself. Scans still fail closed (`lakera_unavailable:no-key` on the first one); what is lost is the boot banner that used to name the fault before any work arrived. `TTL=0` restores that per-boot diagnosis for an operator who wants it.

### Quota fallback and fixed reasons

These are fixed literals from a closed vocabulary and carry no data. `HTTPError:429` and local `throttled` are the only outcomes eligible for degraded arbitration: they still reject unless all strict honeypot scenarios pass and the cross-family judge returns `benign-unanimous`. Disabling the honeypot keeps them as hard rejections. Every other `lakera_unavailable:*` remains a hard rejection.

| Reason | Meaning |
|---|---|
| `lakera_unavailable:HTTPError:429` | Lakera directly refused the request for quota/rate pressure. |
| `lakera_unavailable:throttled` | The fleet's local budget is exhausted, or a quota breaker is open, and the caller's wait budget ran out. |
| `lakera_unavailable:service-unavailable` | A 503-opened service breaker suppressed the call. This is never quota fallback. |
| `lakera_unavailable:limiter-error` | The limiter itself is unusable — unwritable, symlinked, foreign-owned or unsafely writable cache directory; lock wait exceeded; or IO error. Fail-closed on purpose: waving calls through when pacing breaks would restore the storm the limiter exists to stop. |

A 429 or 503 from Lakera opens the breaker for the whole fleet and caps the bucket at a single token, so what comes out the far side of an outage is a probe rather than a herd. The breaker persists a closed cause (`quota` or `service`); a later in-flight 429 cannot downgrade an open service breaker. A successfully JSON-decoded HTTP 200 records success and closes it even when the result is flagged or the decoded value later fails the strict response-schema check: transport liveness and content acceptance are separate claims. Malformed JSON and transport/HTTP failures make no success claim. Success still counts only when that call was ISSUED after the breaker last opened. At a burst of 10 the opening calls of an outage are in flight together, and letting a straggler's 200 reset a decision nine peers had already made would walk the fleet straight back into the throttle it had correctly detected. `Retry-After` is server-supplied text: it is parsed into a number inside the limiter, clamped by `BACKOFF_MAX_S`, and the string itself is never stored, logged, or interpolated into a reason.

The key can be sent only to the canonical Guard destination, `https://api.lakera.ai/v2/guard` (case-normalized scheme/host and an explicit `:443` are accepted); alternate schemes, hosts, credentials, ports, paths, queries, fragments and ambiguous spellings fail closed before a limiter token is spent. The opener ignores ambient proxy settings and never follows redirects, so a 3xx is an outage rather than a second credential-bearing request. A usable verdict must be an object with boolean `flagged`, a `breakdown` list whose entries have string `detector_type` and boolean `detected`, and exactly one `prompt_attack` decision; duplicate keys and malformed required structure fail closed, while unknown extra top-level or entry fields and non-prompt detector types are allowed.

`python -m injection_scanner.eval` aborts on the first outage rather than scoring it — `INFRA <case_id> <reason>` on stderr, exit code `3` (distinct from `1` for a failed threshold and `2` for usage). `scan_text` fails closed, so a degraded layer agrees with every injection-labelled case; scoring it would report recall earned by an outage.

### CI: a hermetic merge gate, live checks on a schedule

Per-push CI calls no external service. `.github/workflows/ci.yml` runs only the deterministic suite on Python 3.12 and 3.13 — no Lakera, no Anthropic, no OpenAI, no secrets — so a pull request cannot go red because a vendor is down or throttled, and it works unchanged on a fork. Pytest installs a project-wide socket embargo before collection and keeps it through fixture finalizers: IPv4 and IPv6 sockets are forbidden, Unix sockets remain available, and command-line, marker and fixture escape hatches are rejected. Offline coverage does not shrink: `tests/test_judge.py` drives the real Anthropic/OpenAI SDKs over a stub transport (which is what caught the 1.x `temperature` signature break), while `tests/test_lakera.py` exercises request construction, proxy/redirect policy, bounded reads, JSON decoding and the strict response contract using only in-process `_post`, transport and `OpenerDirector` doubles — never loopback or a real endpoint.

The live evaluation is an operational/scheduled workflow, not part of pytest or the merge gate. It lives in `.github/workflows/live-eval.yml` and runs **nightly at 03:17 UTC and on demand**:

```bash
# check a detection-quality-sensitive PR before merging
gh workflow run live-eval.yml --ref <branch>
```

That dispatch is deliberately a human gesture, like the merge click. What moved off the gate is the sampled-model *benchmark* — recall and FP rate over the labelled corpus — which was never deterministic; **production's boot smoke — a live vendor probe at most once per liveness TTL, plus every real report scan — remains the day-to-day canary for vendor drift, and CI's nightly is the benchmark**. Both are agent-readable, and production is where such drift actually bites.

The relations inside `live-eval.yml` are asserted by `tests/test_ci_relations.py`, so a later edit cannot quietly undo them:

- One workflow-level concurrency group, `lakera-live`, with `cancel-in-progress: false` — at most one live run at a time, queued rather than dropped. Deliberately **not** keyed on the ref: a branch dispatch and the nightly on `main` draw on the same Lakera account, so they must queue rather than overlap.
- `eval` needs `smoke`. The 1-call smoke is the canary for the 16-call eval: a Lakera outage costs one call, not seventeen.
- Both jobs set `INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S=60` **and** `INJECTION_SCANNER_LAKERA_BURST=2`. A runner's cache directory is fresh every run, so its limiter is a separate domain drawing on the same account: it has to pace itself, and it must never be allowed the fleet's burst of 10 — a bucket that starts full looks paced until ten calls leave at once. `eval` also passes `--lakera-max-wait 1800`, so it queues for its turn instead of being refused mid-corpus.
- Both are time-bounded (10 and 45 minutes): 16 cases at 60 s pacing is ~15 minutes of waiting before any confirmation re-scans, and a hanging job would hold `lakera-live` and block the next night's run.
- The guard test also asserts that `ci.yml` contains no `secrets.` reference anywhere — a negative over the whole file, so a job nobody anticipated cannot put a vendor call back on the merge gate.

Daily Lakera cost from CI falls from roughly 17 calls per push to 17 calls per day.

## Use

```python
from injection_scanner.intercept import scan, scan_text, Verdict

verdict = scan(Path("report.md"))           # disk path
verdict = scan_text(raw_text)               # in-memory bytes
if verdict.ok:
    deliver(verdict.sanitized_text)
else:
    quarantine(verdict.reason, verdict.to_audit())
```

`scan(use_honeypot=False)` skips the API-paying L3 layer for unit tests only.

## Test

```bash
pytest tests/
```

## Consumers

- `~/Repos/research-agent` — MCP server's `deliver_report` path.
- `~/.claude/dev-container/bin/claude-cl-sync` — sandbox→host sync gate.
