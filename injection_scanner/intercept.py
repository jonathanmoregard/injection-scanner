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

Caller passes the cleaned path and receives a Verdict dict the server can
use both to decide to deliver and to attach audit metadata.

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

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path

from injection_scanner import decode, judge, lakera, secret_shapes, unicode_sanitize
from injection_scanner.honeypot import check as honeypot_check


class QuarantineOnly:
    """Opaque holder for values that may embed attacker-controlled bytes.

    A `Verdict` mixes two trust classes. Most fields (`ok`, `reason`,
    `layers`) are synthesized by the scanner from a fixed vocabulary and
    are safe anywhere. A few carry text that ultimately originates in the
    scanned report — directly, or laundered through a provider error body
    that echoes request fragments back at us.

    A plain `dict[str, str]` annotation makes those two classes look
    identical at the call site, so a new consumer cannot tell which is
    which without reading honeypot.py. This type is the marker: any field
    annotated `QuarantineOnly` is cleared for the quarantine audit file
    and nothing else.

    It is also a guard, not just a label:

      * `repr` / `str` redact, so `print(verdict)`, an f-string, a log
        line, or a pytest assertion diff cannot spill the contents — and
        unlike `field(repr=False)`, that holds even after the value has
        been pulled off the dataclass into a local.
      * `json.dumps(..., default=str)` — the exact call the audit writer
        uses — serializes the redaction, not the payload. A structure
        that reaches a JSON encoder by some path other than
        `Verdict.to_audit()` fails closed.
      * It is deliberately NOT a Mapping: no `__iter__`, no `__getitem__`,
        no `.items()`. Reading the payload requires naming
        `reveal_for_quarantine_record()`, which is unpleasant enough to
        read in a diff that it cannot happen by reflex.
      * It is deliberately NOT a dataclass, so `dataclasses.asdict()` on
        a containing dataclass cannot flatten it back into raw strings.
    """

    __slots__ = ("_values",)

    def __init__(self, values: Mapping[str, str] | None = None) -> None:
        self._values: dict[str, str] = dict(values) if values else {}

    def reveal_for_quarantine_record(self) -> dict[str, str]:
        """Return the raw mapping. ONE legal destination.

        That destination is the quarantine audit file written by
        `safeio.write_rejection_audit` — a file in a directory the
        consuming agent's file-reading tools are deny-listed from, which
        already carries the full report bytes. Anywhere an LLM can read
        the result back is a leak, not a diagnostic.
        """
        return dict(self._values)

    def __repr__(self) -> str:
        n = len(self._values)
        return f"QuarantineOnly(<{n} entr{'y' if n == 1 else 'ies'} redacted>)"

    __str__ = __repr__

    def __bool__(self) -> bool:
        return bool(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, QuarantineOnly):
            return self._values == other._values
        return NotImplemented

    __hash__ = None  # type: ignore[assignment]  # mutable payload


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
class Verdict:
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
        """Return an audit record safe to persist to disk or forward to an
        operator context. Never includes any report text — the whole point
        of a quarantine is that the bytes stay out of any interactive
        session. Callers needing the raw bytes must read the quarantined
        file directly outside the session.

        `honeypot_api_errors` IS included: it is capped, sanitized,
        structured-body-derived provider diagnostics, and the quarantine
        audit record is the one surface cleared to carry it.
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


def scan(path: Path, use_honeypot: bool = True, use_lakera: bool = True) -> Verdict:
    """Run all layers on the file at `path`. Returns a Verdict.

    `use_honeypot` and `use_lakera` default to True and are kept only so
    tests can force them off for unit runs that must not hit an external
    API. In production call paths, callers should NOT pass these — the
    honeypot and the Lakera gate are always on.
    """
    return scan_text(
        path.read_text(encoding="utf-8", errors="replace"),
        use_honeypot=use_honeypot,
        use_lakera=use_lakera,
    )


def scan_text(raw: str, use_honeypot: bool = True, use_lakera: bool = True) -> Verdict:
    """Run all layers on pre-read `raw` text. Returns a Verdict.

    Separate entry point so callers that need symlink/TOCTOU-safe reads can
    load the content into memory themselves (e.g. `os.open(..., O_NOFOLLOW)`)
    and scan the same bytes they've already snapshotted — no second disk
    read that could race against a file swap.

    Each scanner layer is wrapped in a try/except per honeypot-manufacturing
    Invariant 3: any exception inside a layer must reduce to *reject*, not
    propagate. The exception *type name* lands in the reason — never
    `str(e)`, which can echo input bytes back to the caller.
    """
    layers: dict[str, str] = {}
    # Audit-only provider diagnostics from L3; stays empty unless a honeypot
    # probe hit a provider API error. Populated after the honeypot runs and
    # threaded into every Verdict reachable from that point onwards. Held in
    # the QuarantineOnly wrapper from the moment it exists, so there is no
    # window in which it is a bare dict that could be logged by accident.
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
    blobs = decode.find_encoded_blobs(san.text)
    encodings = sorted({b.encoding for b in blobs})
    layers["decode"] = f"blobs={len(blobs)} encodings={','.join(encodings)}"
    for blob in blobs:
        decoded_hits = secret_shapes.scan(blob.decoded)
        if decoded_hits:
            return Verdict(
                ok=False,
                reason=f"encoded_secret:{blob.encoding}:{decoded_hits[0].name}",
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
    # name / category label / exception type only — never input bytes), so
    # the `if not res.ok` branch below quarantines both real detections and
    # degraded-coverage outages. Silent degradation of a detection layer is
    # exactly the failure operators must hear about.
    #
    # The `use_lakera=False` path is used by unit tests / deterministic
    # measurement runs that must not depend on a live key or hit the network.
    lakera_deferred = False
    if use_lakera:
        res = lakera.check(san.text)
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
        # `layers` stays type-name-only: `s.signal` never carries provider
        # body text. The structured error body travels separately, on
        # `hp_api_errors` -> `Verdict.honeypot_api_errors` -> to_audit().
        for s in hp.per_scenario:
            layers[f"honeypot.{s.scenario}"] = f"{s.verdict}:{s.signal}"
        hp_api_errors = QuarantineOnly(hp.api_error_details)
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
