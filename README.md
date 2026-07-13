# injection-scanner

Layered prompt-injection / secret-exfil scanner. Extracted from `research-agent` so multiple agents can share a single hardening pipeline.

## Layers

| Order | Layer | Purpose |
|------|-------|---------|
| L0 | `unicode_sanitize` | Strip covert channels (zero-width, bidi, tag-block), NFKC normalize, flag anomalous density. |
| L1b | `secret_shapes` | High-precision API key / JWT / PEM patterns. |
| L3 | `honeypot` | Tempt a downstream Haiku with trap tools; if the report coerces a tool call, fail. |

L2 (LLM classifier) and L4 (LLM-as-judge) are planned, not yet wired.

## Install

```bash
pip install -e ~/Repos/injection-scanner
```

Requires `ANTHROPIC_API_KEY` for the L3 honeypot layer (degrades to `skipped:<why>` if missing).

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
