# 001 — Encoded-form detection in L1b (secret_shapes)

**Status:** proposal
**Source:** SOTA-vs-setup review of `repo-check` Phase C honeypot
(2026-04-28). Cross-ref: `repo-check/proposals/001`.

## Gap

`L1b/secret_shapes` currently matches the literal shape of API
keys / JWTs / PEMs. A scanned report containing
`base64(SECRET_VALUE)` or `hex(SECRET_VALUE)` does not trigger.

`L1a/regex` similarly tests literal patterns (role-swap,
system-tag, exfil URL). An exfil URL with the credential
URL-encoded into a query param trips the URL part but the
`secret_shapes` part of the credential value is invisible because
it's encoded.

## Why it matters

Imprompter (Liang et al., 2024) and follow-up adversarial-suffix
work demonstrate routine encoding of payloads to slip past
substring scanners. Once `injection-scanner` is the shared
hardening pipeline, encoded forms are the obvious bypass.

## Proposal

Add an encoded-form layer (call it `L1c/encoded_secrets`) that
runs **after** L1b. For each secret-shape match found by L1b, also
test these representations of the input text:

- `base64.b64decode(s, validate=True)` — recursive, depth ≤ 3
- `bytes.fromhex(s)` — recursive
- `urllib.parse.unquote(s)` — recursive
- `s[::-1]` (reversed)
- `re.sub(r'\s+', '', s)` (whitespace-stripped)

Any decoded form that *itself* matches an L1b shape pattern
counts as a secret hit. The scanner reports both the literal
position and the encoding chain (`base64→jwt`, `hex→pem`, etc.)
so operators can tell what the payload was hiding.

## Effort

~80 lines (implementation + 5 encoding handlers + recursion guard
+ tests). No deps beyond stdlib.

## Risk if skipped

Any caller using `injection-scanner` as a defense gate (including
`repo-check` Phase C, but also `research-agent`) misses the
encoded-payload case. False-clean verdict on motivated attacker.
