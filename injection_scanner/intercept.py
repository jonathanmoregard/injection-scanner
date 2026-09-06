"""
Intercept orchestrator: runs the layered shim and produces a single verdict.

Order (each layer can short-circuit):
  L0  unicode_sanitize      — strip covert channels, NFKC normalize, flag anomaly
  L1b secret_shapes         — high-precision API-key / JWT / PEM patterns
  L2  lakera                — hosted Lakera Guard prompt-injection classifier.
                              GATE, fail-CLOSED: a missing key or ANY error
                              (network/HTTP/JSON/timeout/broken config) rejects
                              loudly, exactly like the honeypot. Never silently
                              degrades to "pass".
  L3  honeypot              — fan the report out to a 3-model judge ensemble
                              (claude-haiku-4-5, gpt-4o-mini, gpt-4.1-nano)
                              across 6 canary scenarios; if any judge gets
                              coerced into a bait-tool call or canary echo, fail
  L4  judge                 — arbitration, ONLY for the disagreement case
                              lakera:prompt_attack + honeypot fully clean:
                              a cross-family panel must unanimously rule the
                              text "describes, not directs" to overturn the
                              flag; any attack vote, outage, or malformed
                              verdict quarantines (fail-closed). Closes the
                              measured FP class (benign research prose about
                              agent tooling / injection attacks) without
                              widening any attack path.

Caller passes the cleaned path and receives a Verdict the server can use
both to decide to deliver and to build an audit record. Those two uses sit
at different trust levels: `verdict.ok` / `verdict.reason` / `verdict.layers`
are scanner-synthesized and safe to render anywhere, while
`verdict.to_audit()` is cleared for the quarantine audit file and nothing
else. See `Verdict.to_audit` before routing it anywhere new.

Honeypot runs by default. The `use_honeypot` bool parameter on `scan` /
`scan_text` toggles it — production callers leave it at its `True` default;
unit tests pass `use_honeypot=False` so they don't pay the API call.

L1a regex was removed: the previous role-swap / instruction-override /
wrap-escape rules false-positived on legitimate research output that
quoted prompt-injection examples (security tooling docs, AI-safety
posts, the scanner's own README). Wrap-escape protection now lives at
the consumer's delivery boundary — research-agent encodes dangerous
tag chars on the report body before wrapping it. That's structurally
zero-FP and survives any future tag rename.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path

from injection_scanner import decode, judge, lakera, secret_shapes, unicode_sanitize
from injection_scanner.containment import QuarantineFieldsCoerced, QuarantineOnly
from injection_scanner.honeypot import check as honeypot_check

# `QuarantineOnly` is defined in `injection_scanner.containment`, not here.
# It has to be importable by `honeypot.py` — the layer that first touches
# provider bytes — so the payload can be wrapped at the point of
# construction rather than here, several hops later. Re-exported under the
# original name because that is where consumers already import it from; see
# the containment module docstring for what the holder does and does not
# guarantee.
__all__ = ["QuarantineOnly", "Verdict", "scan", "scan_text"]


# ---------- to_audit() allow-lists ----------
#
# `to_audit()` used to build with `asdict(self)` and then pop the known-bad
# keys. That is a deny-list: ANY field added to `Verdict` later would flow
# straight into a record billed as publishable, silently, with no diff on
# `to_audit()` to catch a reviewer's eye. These allow-lists invert it — a
# name absent from both tuples is dropped, so a new field fails closed and
# has to be classified deliberately before it appears in the record.
#
# Scanner-synthesized, fixed vocabulary, no report- or provider-derived
# bytes. Copied through as-is.
_AUDIT_SAFE_FIELDS = ("ok", "reason", "layers")

# Fields typed `QuarantineOnly`; unwrapped into the record because the
# quarantine audit file is the one surface cleared to carry them.
_AUDIT_QUARANTINE_ONLY_FIELDS = ("honeypot_api_errors",)

# `sanitize_stats` gets the same inversion one level down: previously a
# `k != "text"` deny-list, now an explicit roster of the numeric/bool
# counters from `unicode_sanitize.SanitizeResult`. `text` (the full
# sanitized report body) is excluded by construction rather than by
# remembering to pop it, and a future stat is dropped until it is added
# here on purpose.
_AUDIT_SANITIZE_STAT_KEYS = (
    "stripped", "bidi_hits", "tag_hits", "zw_hits", "fmt_hits", "nfkc_changed",
)

# Deliberately in NO list, recorded here so the omission reads as a decision
# rather than an oversight: `sanitized_text` is the report body itself; only
# its length reaches the record, as `sanitized_len`.


@dataclass
class Verdict(QuarantineFieldsCoerced):
    # Every assignment to a name in here — by the generated `__init__`, by
    # `dataclasses.replace`, or by a caller writing to the attribute later —
    # is wrapped in the holder first. Without it the annotation on
    # `honeypot_api_errors` below is a promise only this package keeps:
    # `Verdict(..., honeypot_api_errors={"A": provider_body})` put a bare
    # dict on a public object and the next `repr(v)` spilled it. See
    # `containment.QuarantineFieldsCoerced`.
    _QUARANTINE_FIELDS = {"honeypot_api_errors": QuarantineOnly}

    ok: bool                       # True  -> deliver
    reason: str                    # short code e.g. "pass" / "secret_shape:aws_access_key"
    layers: dict[str, str]         # per-layer outcome for audit
    sanitize_stats: dict           # unicode_sanitize stats
    sanitized_text: str            # cleaned text the server should deliver
    # UNTRUSTED / audit-file-only, and typed to say so: honeypot scenario
    # name -> structured provider API-error detail (see
    # honeypot._error_detail). Empty unless a honeypot probe hit a provider
    # error. Deliberately kept OUT of `reason` and `layers`, which stay
    # type-name-only so no provider-echoed request fragment can ride them
    # back into a caller's context.
    #
    # The `QuarantineOnly` wrapper is the trust boundary made visible: every
    # other field on this dataclass is scanner-synthesized and safe to render
    # anywhere, this one is not, and the annotation is what tells a new
    # consumer which is which. See the class docstring above.
    honeypot_api_errors: QuarantineOnly = field(default_factory=QuarantineOnly)

    def to_audit(self) -> dict:
        """Build the QUARANTINE-FILE-ONLY audit record.

        ONE legal destination: a quarantine audit file, written by
        `safeio.write_rejection_audit` into a directory that the consuming
        agent's file-reading tools are deny-listed from. That file already
        carries the full rejected report bytes, which is exactly why this
        record is cleared to sit next to them.

        NOT safe to: print, log, return from a tool call, embed in an error
        message, attach to a trace/metric/OTel tag, render into a chat
        transcript, or hand to any "operator context" that an LLM can read
        back. An operator here may be an interactive model session, so
        "an operator will see it" is not a safety argument.

        The reason is `honeypot_api_errors`. Provider error bodies echo
        request fragments (`messages.0.content: ...`) that originate in
        attacker-controlled report text, so the record carries laundered
        report bytes even though it carries no report field. They are
        capped, control-stripped and `unicode_sanitize`d
        (see `honeypot._error_detail`) — that bounds the blast radius, it
        does not make them trusted.

        What is excluded, by construction rather than by pop: the report
        body in either form. `sanitized_text` never appears (only
        `sanitized_len`), and `sanitize_stats` is filtered to its numeric
        counters, so `sanitize_stats["text"]` cannot ride along. Anyone
        needing the raw bytes reads the quarantined file directly, from a
        terminal, outside any session.

        Construction is an allow-list (`_AUDIT_SAFE_FIELDS` /
        `_AUDIT_QUARANTINE_ONLY_FIELDS`). A `Verdict` field named in
        neither is dropped: new fields fail closed and must be classified
        before they can reach this record.
        """
        d: dict = {}

        # Allow-list, not `asdict()` minus pops: an unclassified field is
        # simply never reached.
        for name in _AUDIT_SAFE_FIELDS:
            value = getattr(self, name)
            # Shallow-copy the containers so the record can't alias — and
            # later mutate — live Verdict state.
            d[name] = dict(value) if isinstance(value, dict) else value

        stats = self.sanitize_stats
        d["sanitize_stats"] = (
            {k: stats[k] for k in _AUDIT_SANITIZE_STAT_KEYS if k in stats}
            if isinstance(stats, dict)
            else {}
        )

        # The report body never appears; only its length.
        d["sanitized_len"] = len(self.sanitized_text)

        # The one sanctioned unwrap of a QuarantineOnly payload, reached
        # only for fields explicitly classified as such.
        for name in _AUDIT_QUARANTINE_ONLY_FIELDS:
            d[name] = getattr(self, name).reveal_for_quarantine_record()

        return d


def scan(
    path: Path,
    use_honeypot: bool = True,
    use_lakera: bool = True,
    lakera_max_wait_s: float | None = None,
) -> Verdict:
    """Run all layers on the file at `path`. Returns a Verdict.

    `use_honeypot` and `use_lakera` default to True and are kept only so
    tests can force them off for unit runs that must not hit an external
    API. In production call paths, callers should NOT pass these — the
    honeypot and the Lakera gate are always on.

    `lakera_max_wait_s` is how long the L2 call may wait for its turn in the
    fleet-wide Lakera budget. `None` (the default) means "whatever
    INJECTION_SCANNER_LAKERA_MAX_WAIT_S says", which is 0 — an interactive
    scan refuses immediately rather than parking a report. Batch callers pass
    a real budget so they queue instead of failing.
    """
    return scan_text(
        path.read_text(encoding="utf-8", errors="replace"),
        use_honeypot=use_honeypot,
        use_lakera=use_lakera,
        lakera_max_wait_s=lakera_max_wait_s,
    )


def scan_text(
    raw: str,
    use_honeypot: bool = True,
    use_lakera: bool = True,
    lakera_max_wait_s: float | None = None,
) -> Verdict:
    """Run all layers on pre-read `raw` text. Returns a Verdict.

    Separate entry point so callers that need symlink/TOCTOU-safe reads can
    load the content into memory themselves (e.g. `os.open(..., O_NOFOLLOW)`)
    and scan the same bytes they've already snapshotted — no second disk
    read that could race against a file swap.

    Each scanner layer is wrapped in a try/except per honeypot-manufacturing
    Invariant 3: any exception inside a layer must reduce to *reject*, not
    propagate. The exception *type name* lands in the reason — never
    `str(e)`, which can echo input bytes back to the caller.

    `lakera_max_wait_s` is passed straight to `lakera.check`; nothing here
    interprets it. See `scan` for what it means.
    """
    layers: dict[str, str] = {}
    # Audit-only provider diagnostics from L3; stays empty unless a honeypot
    # probe hit a provider API error. Populated after the honeypot runs and
    # threaded into every Verdict reachable from that point onwards. THIS
    # LOCAL is a QuarantineOnly from its first binding and is never rebound
    # to a bare dict, so no code path in this function can render the payload
    # by accident — and the same now holds upstream: `honeypot.py` wraps at
    # the point of construction, so `HoneypotResult.api_error_details` is
    # already a QuarantineOnly and this local is simply that same holder.
    # There is no longer a window in which the payload is a bare dict on a
    # public object.
    hp_api_errors = QuarantineOnly()

    # L0
    try:
        san = unicode_sanitize.sanitize(raw)
    except Exception as e:
        layers["unicode_sanitize"] = f"unhandled:{type(e).__name__}"
        return Verdict(
            ok=False,
            reason=f"unicode_sanitize_unavailable:unhandled:{type(e).__name__}",
            layers=layers,
            sanitize_stats={},
            sanitized_text="",
        )
    layers["unicode_sanitize"] = (
        f"stripped={san.stripped} bidi={san.bidi_hits} "
        f"tag={san.tag_hits} zw={san.zw_hits} fmt={san.fmt_hits} "
        f"nfkc_changed={san.nfkc_changed}"
    )
    if unicode_sanitize.is_anomalous(san, len(raw)):
        return Verdict(
            ok=False,
            reason=f"unicode_anomaly:stripped={san.stripped}/{len(raw)}",
            layers=layers,
            sanitize_stats=asdict(san),
            sanitized_text=san.text,
        )

    # L1a-decode — decode candidate encoded blobs and rescan the *decoded*
    # text for secret shapes. Closes the encoding-bypass hole where a
    # base64/hex/rot13-encoded credential is opaque to L0 and L1b but a
    # downstream model would decode and act on it. Deterministic and
    # low-FP: we only fail on decoded content that carries a secret shape;
    # decoded prose-injection is left to the planned L2 classifier. As with
    # the audit-leak rule, the verdict reason carries only the encoding and
    # the detector name — never the decoded bytes or the secret snippet.
    #
    # Blanket try/except per Invariant 3, like every sibling layer. This block
    # was the one without one, and it is not a layer that can be trusted to
    # stay quiet: `find_encoded_blobs` runs candidate decoders over
    # attacker-shaped bytes, and `secret_shapes.scan` then runs regexes over
    # whatever those decoders produced — the deepest point in the scanner where
    # a crafted input meets code that has to guess at a format. An exception
    # here escaped `scan_text` outright, which is worse than any rejection: it
    # aborts the scan rather than failing it closed, and it breaks `run_smoke`'s
    # contract of raising nothing but `SmokeFailure`.
    #
    # The reason carries the exception TYPE name only, never `str(e)` — this is
    # precisely the layer whose exceptions are most likely to embed the decoded
    # bytes that caused them (Invariant 4). `decode` is already a layer name
    # research-agent's closed vocabulary knows and `_unavailable` is the infra
    # head suffix, so `eval._is_infra_reason` and the downstream diagnosis
    # classify this as the outage it is with no new vocabulary crossing the
    # boundary.
    #
    # The guard covers the decode WORK and nothing else: `layers` and the
    # detection return are built after it, so a rejecting Verdict can never be
    # swallowed by the except that exists to reject.
    encoded_hit: tuple[str, str] | None = None
    try:
        blobs = decode.find_encoded_blobs(san.text)
        encodings = sorted({b.encoding for b in blobs})
        for blob in blobs:
            decoded_hits = secret_shapes.scan(blob.decoded)
            if decoded_hits:
                encoded_hit = (blob.encoding, decoded_hits[0].name)
                break
    except Exception as e:
        layers["decode"] = f"unhandled:{type(e).__name__}"
        return Verdict(
            ok=False,
            reason=f"decode_unavailable:{type(e).__name__}",
            layers=layers,
            sanitize_stats=asdict(san),
            sanitized_text=san.text,
        )
    layers["decode"] = f"blobs={len(blobs)} encodings={','.join(encodings)}"
    if encoded_hit is not None:
        return Verdict(
            ok=False,
            reason=f"encoded_secret:{encoded_hit[0]}:{encoded_hit[1]}",
            layers=layers,
            sanitize_stats=asdict(san),
            sanitized_text=san.text,
        )

    # L1b — secret-shape scan.
    try:
        hits = secret_shapes.scan(san.text)
    except Exception as e:
        layers["secret_shapes"] = f"unhandled:{type(e).__name__}"
        return Verdict(
            ok=False,
            reason=f"secret_shapes_unavailable:unhandled:{type(e).__name__}",
            layers=layers,
            sanitize_stats=asdict(san),
            sanitized_text=san.text,
        )
    layers["secret_shapes"] = "pass" if not hits else f"fail:{hits[0].name}"
    if hits:
        # Reason carries the matched rule NAME only — never the matched
        # snippet bytes. The 40-char snippet was attacker-controllable
        # (the bytes of a planted credential-shape that triggered the
        # rule); echoing it into `reason` flowed it back to the calling
        # LLM's context, violating honeypot-manufacturing Invariant 4
        # ("the caught bytes never return"). The full matched snippet
        # is available off-path in the operator-only secret_shapes log,
        # not in the caller-visible Verdict.
        return Verdict(
            ok=False,
            reason=f"secret_shape:{hits[0].name}",
            layers=layers,
            sanitize_stats=asdict(san),
            sanitized_text=san.text,
        )

    # L2 lakera — hosted Lakera Guard classifier, wired as a fail-CLOSED GATE.
    #
    # Unlike an additive skip, this layer REJECTS on anything that isn't a
    # clean pass: a flagged classification, a missing key, a broken `*_FILE`
    # mount, or any network/HTTP/JSON/timeout error. lakera.check already
    # collapses every one of those to ok=False with a flat reason (detector
    # name / category label / exception type / bounded HTTP status only —
    # never input bytes; see lakera._transport_reason), so
    # the `if not res.ok` branch below quarantines both real detections and
    # degraded-coverage outages. Silent degradation of a detection layer is
    # exactly the failure operators must hear about.
    #
    # The `use_lakera=False` path is used by unit tests / deterministic
    # measurement runs that must not depend on a live key or hit the network.
    lakera_deferred = False
    if use_lakera:
        res = lakera.check(san.text, max_wait_s=lakera_max_wait_s)
        layers["lakera"] = res.reason
        if not res.ok:
            if res.reason == "lakera:prompt_attack" and use_honeypot:
                # DEFER, don't deliver: a definite prompt_attack
                # classification with the behavioral honeypot available
                # downstream enters L4 arbitration instead of rejecting
                # unilaterally. Measured 2026-07-28: the unilateral gate
                # false-positived on benign research prose ABOUT agent
                # tooling and injection attacks (4/9 fp_* corpus cases,
                # honeypot clean on all 9), quarantining legitimate
                # research-agent reports. The report is still rejected
                # unless the honeypot comes back fully clean AND the
                # cross-family judge panel unanimously rules "describes,
                # not directs" (see judge.py).
                #
                # Everything else stays a hard reject: every
                # lakera_unavailable:* outage (fail-closed unchanged) and
                # the no-breakdown `lakera:flagged` fallback (unknown
                # detector mix — conservative). With the honeypot off
                # (lakera-only measurement runs) there is no corroborating
                # signal, so the flag also stays a hard reject.
                lakera_deferred = True
            else:
                return Verdict(
                    ok=False,
                    reason=res.reason,
                    layers=layers,
                    sanitize_stats=asdict(san),
                    sanitized_text=san.text,
                )
    else:
        layers["lakera"] = "disabled (test-only)"

    # L3 honeypot. Always runs in production.
    #
    # Fail-closed on degraded honeypot: honeypot_check returns ok=False
    # with reason="honeypot_unavailable:<scenario>:<why>" when the SDK
    # is missing, the API key is unset/revoked, or the provider is
    # unreachable. The `if not hp.ok` branch below catches both
    # triggered (real attack signal) and unavailable (degraded coverage)
    # outcomes. An outage quarantines real reports until the honeypot
    # is back — that's intentional, since silently lowered detection is
    # the exact failure mode operators must hear about. Diagnose via
    # `layers.honeypot` in the audit record.
    #
    # The `use_honeypot=False` path is used by unit tests that must not
    # hit the Anthropic API.
    if use_honeypot:
        # Blanket try/except per honeypot-manufacturing Invariant 3:
        # any exception raised inside a scanner layer must reduce to
        # *reject*, not propagate up and short-circuit downstream gates.
        # honeypot._run_all already converts per-scenario coroutine
        # raises to Skipped results; this catches the residual
        # possibility (import-time errors, scheduling failures, etc.)
        # so the scan boundary is fail-closed end-to-end. Only the
        # exception type name lands in the reason — `str(e)` on SDK
        # exceptions can echo the prompt body we sent.
        try:
            hp = honeypot_check(san.text)
        except Exception as e:
            layers["honeypot"] = f"unhandled:{type(e).__name__}"
            return Verdict(
                ok=False,
                reason=f"honeypot_unavailable:unhandled:{type(e).__name__}",
                layers=layers,
                sanitize_stats=asdict(san),
                sanitized_text=san.text,
            )
        layers["honeypot"] = hp.reason
        # `layers` stays content-free: `s.signal` carries library labels,
        # exception type names and a bounded HTTP status code (three ASCII
        # digits at most — see honeypot._api_error_signal), never provider
        # body text. The structured error body travels separately, on
        # `hp_api_errors` -> `Verdict.honeypot_api_errors` -> to_audit().
        for s in hp.per_scenario:
            layers[f"honeypot.{s.scenario}"] = f"{s.verdict}:{s.signal}"
        # Already a QuarantineOnly (wrapped in honeypot._run_all). Passed
        # through as-is: unwrapping to re-wrap here would recreate the bare
        # dict this channel is built to avoid. The holder exposes no
        # mutation API, so sharing the object between HoneypotResult and
        # Verdict cannot let one alias mutate the other.
        hp_api_errors = hp.api_error_details
        if not hp.ok:
            return Verdict(
                ok=False,
                reason=f"honeypot:{hp.reason}",
                layers=layers,
                sanitize_stats=asdict(san),
                sanitized_text=san.text,
                honeypot_api_errors=hp_api_errors,
            )

        # L4 judge — arbitration of the Lakera-flag / honeypot-clean
        # disagreement. Reached ONLY when L2 said prompt_attack and every
        # honeypot scenario came back Left_Alone. Fail-closed like every
        # other layer: a judge outage, a malformed verdict, or a single
        # "attack" vote all quarantine. Only a unanimous cross-family
        # "benign" overturns the flag.
        if lakera_deferred:
            try:
                jr = judge.check(san.text)
            except Exception as e:
                layers["judge"] = f"unhandled:{type(e).__name__}"
                return Verdict(
                    ok=False,
                    reason=f"judge_unavailable:unhandled:{type(e).__name__}",
                    layers=layers,
                    sanitize_stats=asdict(san),
                    sanitized_text=san.text,
                    honeypot_api_errors=hp_api_errors,
                )
            layers["judge"] = jr.reason
            for v in jr.votes:
                layers[f"judge.{v.judge}"] = f"{v.vote}:{v.signal}"
            if not jr.ok:
                return Verdict(
                    ok=False,
                    reason=f"lakera_arbitration:{jr.reason}",
                    layers=layers,
                    sanitize_stats=asdict(san),
                    sanitized_text=san.text,
                    honeypot_api_errors=hp_api_errors,
                )
    else:
        layers["honeypot"] = "disabled (test-only)"

    return Verdict(
        ok=True,
        reason="pass",
        layers=layers,
        sanitize_stats=asdict(san),
        sanitized_text=san.text,
        honeypot_api_errors=hp_api_errors,
    )
