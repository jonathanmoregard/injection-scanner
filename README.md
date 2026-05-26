# injection-scanner

Layered prompt-injection / secret-exfil scanner. Extracted from `research-agent` so multiple agents can share a single hardening pipeline.

## Layers

| Order | Layer | Purpose |
|------|-------|---------|
| L0 | `unicode_sanitize` | Strip covert channels (zero-width, bidi, tag-block), NFKC normalize, flag anomalous density. |
| L1b | `secret_shapes` | High-precision API key / JWT / PEM patterns. |
| L3 | `honeypot` | Run the report past a multi-provider judge ensemble (Anthropic Haiku + OpenAI gpt-4o-mini + gpt-4.1-nano) across six canary scenarios. If any judge gets coerced into calling a bait tool, echoing a canary via a legitimate tool argument, or surfacing one in freeform text, the report is rejected. |

L1a (regex) was retired (legit research output false-positived); wrap-escape protection moved to the consumer's delivery boundary. L2 (cheap LLM classifier) and L4 (LLM-as-judge synthesis) are planned, not yet wired.

## Install

```bash
pip install -e ~/Repos/injection-scanner
```

L3 honeypot environment requirements (fail-closed if any are missing):

- `ANTHROPIC_API_KEY` — required (2 of 6 scenarios run on `claude-haiku-4-5`).
- `OPENAI_API_KEY` — required (4 of 6 scenarios run on `gpt-4o-mini` / `gpt-4.1-nano`).

A missing key surfaces as `honeypot_unavailable:<scenario>:unavailable:no-<provider>-api-key+skipped=N/6` in the Verdict. Per the fail-closed contract, that quarantines every report until the key is restored. Keys may live in env OR in the local secret store under `app=research-agent, key={anthropic,openai}-api-key`.

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
