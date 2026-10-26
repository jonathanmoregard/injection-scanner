# injection-scanner

Layered prompt-injection / secret-exfil scanner. Extracted from `research-agent` so multiple agents can share a single hardening pipeline.

## Layers

| Order | Layer | Purpose |
|------|-------|---------|
| L0 | `unicode_sanitize` | Strip covert channels (zero-width, bidi, tag-block), NFKC normalize, flag anomalous density. |
| L1b | `secret_shapes` | High-precision API key / JWT / PEM patterns. |
| L2 | `l2` panel: `lakera`, `model_armor` | Hosted prompt-injection classifiers (Lakera Guard, Google Model Armor), run concurrently, wired fail-closed against a verdict floor — see [L2 panel](#l2-panel). Each vendor is paced fleet-wide — see [Lakera rate limiting](#lakera-rate-limiting). |
| L3 | `honeypot` | Run the report past a 3-model judge ensemble (`claude-haiku-4-5`, `gpt-4o-mini`, `gpt-4.1-mini`) across six canary scenarios — two scenarios per model. If any judge gets coerced into calling a bait tool, echoing a canary via a legitimate tool argument, or surfacing one in freeform text, the report is rejected. |
| L4 | `judge` | Arbitration when the L2 panel is `flagged` or `degraded-quota` and the honeypot is fully clean: a cross-family panel must unanimously rule the text "describes, not directs" before delivery. |

L1a (regex) was retired (legit research output false-positived); wrap-escape protection moved to the consumer's delivery boundary.

## Install

```bash
pip install -e ~/Repos/injection-scanner
```

L3 honeypot environment requirements (fail-closed if any are missing):

- `ANTHROPIC_API_KEY` — required (2 of 6 scenarios run on `claude-haiku-4-5`).
- `OPENAI_API_KEY` — required (4 of 6 scenarios run on `gpt-4o-mini` / `gpt-4.1-mini`).

A missing key surfaces as `honeypot_unavailable:<scenario>:unavailable:no-<provider>-api-key+skipped=N/6` in the Verdict. Per the fail-closed contract, that quarantines every report until the key is restored. Keys may live in env OR in the local secret store under `app=research-agent, key={anthropic,openai}-api-key`.

## L2 panel

`l2.run()` sends the text to every vendor in the registry, in fixed order `lakera`, `model_armor`, **concurrently**: wall time is the slowest vendor's wait, not the sum. Each vendor answers a verdict (`pass`, `<vendor>:prompt_attack`) or a shortfall (`<vendor>_unavailable:<condition>`). The floor is `INJECTION_SCANNER_L2_MIN_VERDICTS` (default `2`, clamped to `[1, number of vendors]`).

| Outcome (`layers["l2"]`) | When | What `scan_text` does |
|---|---|---|
| `pass` | verdicts ≥ floor, none flagged | continue to L3 |
| `flagged` | verdicts ≥ floor, any `prompt_attack` | honeypot on: L3 + strict L4 arbitration; off: reject with the first flag |
| `degraded-quota` | verdicts < floor, every shortfall quota-class | honeypot on: L3 + strict L4 arbitration; off: reject with the first shortfall |
| `unavailable` | verdicts < floor, any other shortfall | reject with the first non-quota shortfall (registry order) |

Quota-class is exact membership in `<vendor>_unavailable:HTTPError:429` and `<vendor>_unavailable:throttled` for that vendor — no prefix matching. Unparseable or unexpected results are shortfalls, never passes. `layers["lakera"]` and `layers["model_armor"]` carry each vendor's reason; `layers["l2"]` is the closed summary, e.g. `pass verdicts=2/2 floor=2` or `degraded-quota verdicts=1/2 floor=2`, readable with `intercept.l2_outcome(verdict)`. An exception inside an adapter becomes `<vendor>_unavailable:unhandled:<ExcType>`; a result outside the vendor's own vocabulary becomes `<vendor>_unavailable:bad-result`. `l2_max_wait_s` applies to each vendor, concurrently.

| Reason | Meaning |
|---|---|
| `model_armor:prompt_attack` | Model Armor flagged the text. |
| `model_armor_unavailable:no-key` | No service-account key (`MODEL_ARMOR_CREDENTIALS_FILE`, `MODEL_ARMOR_CREDENTIALS`, keyring `model-armor-sa-key`). |
| `model_armor_unavailable:key-config-error` | The key file is unreadable, or the key is not a `service_account` JSON with `token_uri` exactly `https://oauth2.googleapis.com/token` and an RSA `private_key`. |
| `model_armor_unavailable:url-config-error` | `MODEL_ARMOR_PROJECT`, `MODEL_ARMOR_LOCATION` or `MODEL_ARMOR_TEMPLATE` missing or not a valid id. |
| `model_armor_unavailable:too-large` | Text needs more than `INJECTION_SCANNER_MODEL_ARMOR_MAX_CHUNKS` windows; not sent. |
| `model_armor_unavailable:token-error` / `token-error:<status>` | The OAuth token exchange failed: network error or malformed token response / HTTP status (a 3xx included — redirects are refused). Hard. |
| `model_armor_unavailable:throttled` | As for every vendor, plus: the monthly token budget is spent. Quota-class. |
| `model_armor_unavailable:limiter-error` | As for every vendor, plus: the monthly budget ledger is unusable. Hard. |
| `model_armor_unavailable:skipped` | The prompt-injection filter reported `EXECUTION_SKIPPED`. Hard. |
| `model_armor_unavailable:partial-invocation` | `invocationResult` was `PARTIAL` or `FAILURE`. Hard. |
| `model_armor_unavailable:bad-response` | Any other response shape. |
| `<vendor>_unavailable:bad-result` | An adapter returned something outside its closed vocabulary. |
| `l2_unavailable:unhandled:<ExcType>` | The panel machinery itself failed. |
| `l2_arbitration:attack:<judge>` | L4 arbitration after `flagged` / `degraded-quota`: a judge voted attack. A judgement. |
| `l2_arbitration:judge_unavailable:<judge>:<signal>` / `l2_arbitration:judge_unavailable:panel-incomplete` | L4 arbitration could not get every judge's verdict. An outage (the `<layer>_unavailable` head under the `l2_arbitration` wrapper). |

### Model Armor

`modelarmor.check()` calls Google Cloud Model Armor's `sanitizeUserPrompt` and reads only the `pi_and_jailbreak` filter: `MATCH_FOUND` is `model_armor:prompt_attack`, `NO_MATCH_FOUND` is `pass`, anything else is a shortfall (see the reasons above). The whole text goes in one request; the filter accepts 65,536 tokens.

| Setting | Meaning |
|---|---|
| `MODEL_ARMOR_CREDENTIALS_FILE` | Path to a service-account JSON key (agenix pattern). Also `MODEL_ARMOR_CREDENTIALS` (the JSON itself) or the keyring entry `app=research-agent, key=model-armor-sa-key`; same FILE > env > keyring precedence as every key. |
| `MODEL_ARMOR_PROJECT` | GCP project id (`[a-z][a-z0-9-]{4,28}[a-z0-9]`). |
| `MODEL_ARMOR_LOCATION` | Region (`europe-west4`) or multi-region (`eu`, `us`). |
| `MODEL_ARMOR_TEMPLATE` | Template id (`[A-Za-z0-9_-]{1,63}`). |
| `INJECTION_SCANNER_MODEL_ARMOR_MAX_CHARS` | Default `240000`, clamp `[1000, 262144]`. Characters per request; longer text is scanned as overlapping windows. |
| `INJECTION_SCANNER_MODEL_ARMOR_OVERLAP_CHARS` | Default `10000`, clamp `[500, 131072]`, never more than half of `MAX_CHARS`. Characters shared by consecutive windows. |
| `INJECTION_SCANNER_MODEL_ARMOR_MAX_CHUNKS` | Default `8`, clamp `[1, 64]`. Windows per text; a text needing more is `too-large` and never sent. |
| `INJECTION_SCANNER_MODEL_ARMOR_MONTHLY_TOKENS` | Default `20000000`, clamp `[0, 100000000]`. Fleet-wide monthly token budget, a runaway guard (at most ~$1.80/month past the free tier); `0` refuses every call. |

The endpoint is built from the three ids, never read from the environment: `https://modelarmor.<location>.rep.googleapis.com/v1/projects/<project>/locations/<location>/templates/<template>:sanitizeUserPrompt`, then checked against that exact destination before the token is attached. `modelarmor.ready()` runs the same credential and endpoint checks with no network call and returns the reason a scan would get (`no-key`, `key-config-error`, `url-config-error`), or `None`.

**The template** should enable the prompt-injection and jailbreak filter only, at confidence `MEDIUM_AND_ABOVE`, with template logging off so report text is not written to Cloud Logging. Results of any other filter are ignored; the always-on CSAM filter is expected in the response and does not matter.

**Auth.** The service account needs `roles/modelarmor.user` on the project. The scanner signs an RS256 JWT with the key (`cryptography`) and trades it at `https://oauth2.googleapis.com/token` for an access token, through the same hardened opener as every vendor call (pinned URL, no redirects, no proxy, capped read, strict 200). The exchange happens only after the limiter has admitted the scan, immediately before the request is sent, so a token is never chosen and then left to expire in the queue; it spends no extra limiter token. The token is cached in process until 5 minutes before it expires, keyed by the service account, and dropped on a 401. A token-endpoint 429 is reported as `model_armor_unavailable:HTTPError:429` (quota-class, like a 429 from Model Armor) and a 503 as `token-error:503`; both open Model Armor's fleet breaker exactly as they would from Model Armor itself, so later scans stop at the limiter instead of retrying the token endpoint. Every other token failure is `token-error`, hard.

**Budget.** The free tier is 2M tokens a month and Google bills past it rather than refusing, so the scanner keeps its own ledger: `model_armor-budget.json` in the cache directory, `flock`ed and shared fleet-wide, reset on the UTC calendar month. Each call reserves Google's estimate (non-whitespace characters / 4, rounded up) after the limiter admits it and before it is sent, under the ledger lock, so concurrent callers cannot overshoot and a throttled call spends nothing. The reservation is kept only when Model Armor answers with a decoded HTTP 200 (the call Google bills, whatever the verdict) and released for every other outcome — network error, timeout, any non-200 status, an oversize or undecodable body — so a dead endpoint cannot drain the month. A timeout may still have been billed, so the ledger can under-count by those calls. The default (20M) is set well past the 2M free tier on purpose: the fleet scans about 1.5M tokens a month, so a free-tier cap would refuse scans in a heavy month, and with a panel floor of 2 that refuses every report. Past 2M Google bills $0.10 per 1M tokens. A spent budget is `throttled` (quota-class). A torn or foreign ledger is `limiter-error` rather than a silent reset, which would re-mint a month of billable calls; delete `model_armor-budget.json` to start the month over.

**One ledger per GCP project.** The ledger is per cache directory, not per project. Every process that calls Model Armor on one GCP project must share one `INJECTION_SCANNER_CACHE_DIR` (and so run as one uid, see below); otherwise each directory admits its own full monthly allowance and Google bills the overlap.

## Lakera rate limiting

Lakera Guard is called from one function, `lakera.check()`, by several independent processes that share ONE Lakera account. Measured 2026-09-05: from ~15:00 local, Lakera answered HTTP 429 to roughly three of every four calls — about one success per 4–5 minutes fleet-wide, regardless of how many attempts were made — because every caller retried on its own schedule and no process could see what any other had done.

### The relations

| Caller | Lakera calls per event | What paces it |
|---|---|---|
| research-agent boot readiness (one MCP server per Claude Code pane) | 0 — no vendor call | nothing to pace |
| research-agent degraded recheck | same as boot readiness — 0 | same |
| research-agent per-report scan | 1 per vendor per `research()` / `retry_research()` | each vendor's shared limiter; refuses immediately unless the caller passes a wait budget |
| CI (`ci.yml`) | 0 | hermetic — no vendor call, no secret |
| local `eval` runs (by hand) | 16+ per vendor | each vendor's shared limiter, `--l2-max-wait` default 900 |

`injection_scanner/throttle.py` is the shared memory they were missing: one token bucket plus one circuit breaker in a JSON file under the cache directory, every operation a read-modify-write under an exclusive `flock`. With N processes sharing the file, at most `burst + elapsed / min_interval_s` calls reach Lakera in any window of length `elapsed`, and zero while the breaker is open. **N does not appear in the bound**, so adding a pane or a CI runner cannot raise the ceiling.

### Configuration

Every limit is an input. There is no on/off switch: "off" is `MIN_INTERVAL_S=0` (bucket always full) plus `BACKOFF_MAX_S=0` (every breaker delay clamps to zero), which is what the test suite runs and what nobody should want in production. Malformed values fall back to the default and are then clamped, so a typo degrades to a sane limiter rather than to no limiter.

| Environment variable | Default | Clamp | Meaning |
|---|---|---|---|
| `INJECTION_SCANNER_LAKERA_MIN_INTERVAL_S` | `300` | `[0, 3600]` | Sustained fleet-wide interval — one call per this many seconds. `0` disables the bucket; the breaker still applies. |
| `INJECTION_SCANNER_LAKERA_BURST` | `10` | `[1, 1000]` | Bucket capacity: how many calls may go out back-to-back after an idle period. |
| `INJECTION_SCANNER_LAKERA_BACKOFF_BASE_S` | `300` | `[0, 3600]` | Breaker delay after the first consecutive throttle that carried no usable `Retry-After`. Doubles per consecutive failure. |
| `INJECTION_SCANNER_LAKERA_BACKOFF_MAX_S` | `3600` | `[0, 86400]` | Cap on **every** breaker delay, a server-supplied `Retry-After` included. |
| `INJECTION_SCANNER_LAKERA_LOCK_WAIT_S` | `2` | `[0, 60]` | Bounded wait for the state-file lock before the call is refused. Also bounds the budget ledger's lock. |
| `INJECTION_SCANNER_LAKERA_MAX_WAIT_S` | `0` | `[0, 86400]` | Default wait budget for `check()` when the caller passes none. `0` refuses immediately rather than parking a report. |
| `INJECTION_SCANNER_LAKERA_MAX_RESPONSE_BYTES` | `1048576` | `[4096, 67108864]` | How much of a Guard response body is read. A larger one is an outage (`lakera_unavailable:ResponseTooLarge`), not an OOM: the timeout bounds how long a call takes, this bounds how much it can return. |
| `INJECTION_SCANNER_CACHE_DIR` | `~/.cache/injection-scanner` | — | State directory (`<vendor>-throttle.json` + `.lock` per vendor, and `model_armor-budget.json` + `.lock`). |

**What the defaults rest on (measured 2026-09-06).** Lakera publishes exactly one limit: the Community plan's **10,000 requests per month** — 13.9 per hour, one every 4.3 minutes. That equals the trickle measured through the 2026-09-05 throttle (one success per 4–5 minutes fleet-wide, regardless of how many attempts were made), which is what identifies the monthly quota rather than some unpublished QPS ceiling as the thing the fleet was hitting. Overnight, 25 calls in 30 minutes were accepted before ~40 minutes of 429s, so Lakera's own bucket is roughly 25–50 deep with a slow refill. The defaults sit under that: 12 calls/hour sustained, a burst of 10 so one multi-pane session restore passes, and a breaker that waits minutes rather than seconds because recovery was observed to take tens of them. The plan tier is visible only on the Lakera dashboard; on a paid tier every knob loosens via environment, and the algorithm does not change.

Every vendor has the same knobs under its own prefix — `INJECTION_SCANNER_MODEL_ARMOR_MIN_INTERVAL_S` and so on, plus `_TIMEOUT` — with the same defaults and clamps, and its own state file (`model_armor-throttle.json`). One vendor's 429 opens only that vendor's breaker.

Batch callers pass a wait budget instead of being refused: `scan(..., l2_max_wait_s=900)`, `scan_text(..., l2_max_wait_s=900)`, or `python -m injection_scanner.eval ... --l2-max-wait 900` (which is already the eval default, because eval is always a batch caller). The budget applies to each vendor.

**The cache directory is a shared, single-uid resource.** `INJECTION_SCANNER_CACHE_DIR` must name an ABSOLUTE path — `~` is shell syntax, and a relative path resolves per process, so every process would find its own full bucket and pace itself against nobody. A value that is not absolute after expansion falls back to the default, the same way an out-of-range number falls back to its clamp. If `HOME` cannot be resolved at all (a scratch container, `docker run --user 1234`, some CI runners), the fallback is `<tempdir>/injection-scanner-<uid>` — absolute and per-uid, not durable across reboots, which costs one reset bucket.

The final directory component is checked with `lstat` before every use. It must be a real directory owned by the current uid; symlinks and foreign owners are refused. A same-owner directory is also refused when it grants group or world write unless it has the sticky bit. Sticky world-writable directories are allowed because other unprivileged users cannot rename or unlink entries they do not own; the directory owner or a privileged process still can. A refusal makes the limiter fail closed with `lakera_unavailable:limiter-error`. This covers both hostile pre-creation under a shared temp directory and ordinary `sudo -E` ownership accidents. **Sharing one cache directory between accounts is unsupported by design.**

### Prompt size: one request per text, measured past 8k tokens

`lakera.check()` sends the whole text in one request. Lakera's Community plan lists an 8k-token maximum prompt and does not document what happens above it, so it was measured on 2026-10-24 (two calls, production key and project policy):

| # | Text | Result |
|---|---|---|
| 1 | ~49k chars (~12k tokens) of benign prose, one obvious injection at ~10k tokens | HTTP 200, `lakera:prompt_attack` (flagged) |
| 2 | Same text, injection replaced by a benign sentence | HTTP 200, `pass` |

Guard therefore screens content after the 8k mark, at least up to ~12k tokens, and no chunking is done. Larger texts (the biggest research reports reach ~95k characters, ~24k tokens) are unmeasured; re-run the same two-call probe at that size before relying on it.

`modelarmor.check()` sends a text of up to `MAX_CHARS` (240,000) characters in one request, under the filter's 65,536-token limit. A longer text is split into windows of `MAX_CHARS` that overlap by `OVERLAP_CHARS` (10,000), so any injection no longer than the overlap lies whole inside at least one window. Windows are sent in order, each a request and a budget reservation of its own; the first flagged or unavailable window is the answer and later windows are not sent, and the text passes only when every window passed.

### The boot smoke: deterministic readiness

`run_smoke()` makes **no network call and no vendor call**. It runs the deterministic canaries (one per detector class, through both `scan_text` and `scan(Path)`), then asks each remote layer whether a call *could* be made, and raises `SmokeFailure` naming the first layer that could not (`readiness check failed (<reason>). Failed layer — <diagnose.describe(reason)>.`):

| Layer | Checked | Reasons |
|---|---|---|
| L2 panel (`l2.ready()`) | per vendor: credential resolvable, endpoint/config valid (adapter `ready()`), limiter directory usable (owned, mode-safe, lockable, writable, state readable); passes while ready vendors ≥ the floor | `<vendor>_unavailable:no-key` / `key-config-error` / `url-config-error` / `limiter-error` / `not-implemented` (adapter has no `ready()`) |
| L3 honeypot (`honeypot.ready()`) | each scenario's SDK importable and key resolvable | `honeypot_unavailable:<scenario>:unavailable:<signal>` |
| L4 judge (`judge.ready()`) | each judge's SDK importable and key resolvable | `l2_arbitration:judge_unavailable:<judge>:<signal>` |

An open breaker, quota or service, is **not** a readiness failure: it is vendor state, not setup, and reading it through the limiter would spend a token. The scan path handles it (quota fallback, or a fail-closed reject naming the outage).

Why no live probe: in research-agent the smoke is a serving gate, run on every server spawn and degraded recheck. A live probe there spent vendor quota on boots alone (measured 2026-09-06: ~632 a day against Lakera's 10,000 a month) and needed a fleet-wide liveness cache that could hide a pane-local fault behind a peer's pass. Its value was refusing early on setup errors; readiness keeps that without a call. A vendor outage surfaces at the first real scan instead: fail-closed, with the same agent-readable reason.

Adapter contract: a panel adapter may define `ready() -> str | None`, returning `None` when a call could be sent, else the closed `<vendor>_unavailable:<condition>` reason its `check` would return before sending; no network. An exception is `<vendor>_unavailable:unhandled:<ExcType>`, an answer outside the vendor's namespace `<vendor>_unavailable:bad-result`.

### Quota fallback and fixed reasons

These are fixed literals from a closed vocabulary and carry no data. `HTTPError:429` and local `throttled` are the only quota-class shortfalls: a panel short of its floor only through them is `degraded-quota` (see [L2 panel](#l2-panel)), which still rejects unless all strict honeypot scenarios pass and the cross-family judge returns `benign-unanimous`. Disabling the honeypot keeps it a hard rejection. Every other `lakera_unavailable:*` below the floor is a hard rejection. The same conditions exist for every vendor under its own prefix.

| Reason | Meaning |
|---|---|
| `lakera_unavailable:HTTPError:429` | Lakera directly refused the request for quota/rate pressure. |
| `lakera_unavailable:throttled` | The fleet's local budget is exhausted, or a quota breaker is open, and the caller's wait budget ran out. |
| `lakera_unavailable:service-unavailable` | A 503-opened service breaker suppressed the call. This is never quota fallback. |
| `lakera_unavailable:limiter-error` | The limiter itself is unusable — unwritable, symlinked, foreign-owned or unsafely writable cache directory; lock wait exceeded; or IO error. Fail-closed on purpose: waving calls through when pacing breaks would restore the storm the limiter exists to stop. |

A 429 or 503 from Lakera opens the breaker for the whole fleet and caps the bucket at a single token, so what comes out the far side of an outage is a probe rather than a herd. The breaker persists a closed cause (`quota` or `service`); a later in-flight 429 cannot downgrade an open service breaker. A successfully JSON-decoded HTTP 200 records success and closes it even when the result is flagged or the decoded value later fails the strict response-schema check: transport liveness and content acceptance are separate claims. Malformed JSON and transport/HTTP failures make no success claim. Success still counts only when that call was ISSUED after the breaker last opened. At a burst of 10 the opening calls of an outage are in flight together, and letting a straggler's 200 reset a decision nine peers had already made would walk the fleet straight back into the throttle it had correctly detected. `Retry-After` is server-supplied text: it is parsed into a number inside the limiter, clamped by `BACKOFF_MAX_S`, and the string itself is never stored, logged, or interpolated into a reason.

The key can be sent only to the canonical Guard destination, `https://api.lakera.ai/v2/guard` (case-normalized scheme/host and an explicit `:443` are accepted); alternate schemes, hosts, credentials, ports, paths, queries, fragments and ambiguous spellings fail closed before a limiter token is spent. The opener ignores ambient proxy settings and never follows redirects, so a 3xx is an outage rather than a second credential-bearing request. A usable verdict must be an object with boolean `flagged`, a `breakdown` list whose entries have string `detector_type` and boolean `detected`, and exactly one `prompt_attack` decision; duplicate keys and malformed required structure fail closed, while unknown extra top-level or entry fields and non-prompt detector types are allowed.

`python -m injection_scanner.eval` aborts on the first outage rather than scoring it — `INFRA <case_id> <reason>` on stderr, exit code `3` (distinct from `1` for a failed threshold and `2` for usage). `scan_text` fails closed, so a degraded layer agrees with every injection-labelled case; scoring it would report recall earned by an outage.

### CI: hermetic, and no workflow calls a vendor

GitHub Actions makes no external call. `.github/workflows/ci.yml` runs only the deterministic suite on Python 3.12 and 3.13 — no Lakera, no Model Armor, no Anthropic, no OpenAI, no secrets — so a pull request cannot go red because a vendor is down or throttled, and it works unchanged on a fork. Pytest installs a project-wide socket embargo before collection and keeps it through fixture finalizers: IPv4 and IPv6 sockets are forbidden, Unix sockets remain available, and command-line, marker and fixture escape hatches are rejected. Offline coverage does not shrink: `tests/test_judge.py` drives the real Anthropic/OpenAI SDKs over a stub transport (which is what caught the 1.x `temperature` signature break), while `tests/test_lakera.py` exercises request construction, proxy/redirect policy, bounded reads, JSON decoding and the strict response contract using only in-process `vendor_http._post`, transport and `OpenerDirector` doubles — never loopback or a real endpoint.

There is no scheduled or dispatched live workflow. The nightly `live-eval.yml` was deleted on 2026-10-24 ("gha shouldn't ddos third party"): it drew on the same vendor quota as the production fleet. `tests/test_ci_relations.py` asserts, as a negative over every file in `.github/workflows/`, that none references `secrets.` or names a vendor credential (`LAKERA`, `ANTHROPIC`, `OPENAI`, `MODEL_ARMOR`); without a credential every adapter fails closed before opening a connection, so a new workflow cannot put load on a vendor either.

The corpus eval — recall and FP rate over the labelled corpus, which was never deterministic — is an operator command, run locally, by hand, paced by the shared limiter (`--l2-max-wait` defaults to 900 s), when a detection-quality-sensitive change needs it:

```bash
python -m injection_scanner.eval tests/payloads/labels.jsonl --use-l2 --use-honeypot \
  --min-recall 1.0 --max-fp-rate 0.0 --confirm-disagreements 2
```

Day to day, vendor drift surfaces at the first real scan in production, fail-closed and agent-readable.

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
