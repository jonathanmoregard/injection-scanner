"""
Scored evaluation harness.

Turns "is the scanner getting more SOTA?" into a MEASURABLE number. Runs the
real `scan_text` over a labeled corpus and produces a confusion-matrix
scorecard treating "block" as the positive class.

This is an honest scorecard: with the honeypot off, the deterministic layers
(unicode_sanitize + secret_shapes + decode) cannot catch prose-only
injections. Those show up as false negatives — the coverage gap the planned
L2 LLM classifier is meant to close. We do NOT fudge labels to make the score
look better; a fixture whose nature is "injection" is labeled "block" even if
today's layers miss it.

CLI:
    python -m injection_scanner.eval <corpus.jsonl>
    python -m injection_scanner.eval <corpus.jsonl> --min-recall 0.8

Exit codes:
    0  measured (the default: a run with no threshold flag is not a gate)
    1  a threshold failed — --min-recall / --max-fp-rate, so CI can hold a
       floor and a ceiling
    2  usage error
    3  a scanner OUTAGE — see `_is_infra_reason`. An outage is not a
       measurement, so nothing is scored and no scorecard is printed; the
       diagnosis goes to stderr as `INFRA <case_id> <reason>`.

With the hosted layers live, one scan is a sample from an LLM. Pass
--confirm-disagreements N to re-scan only the cases whose verdict disagrees
with their label; the gate then uses the confirmed verdict and the scorecard
still prints the first-attempt numbers. See `evaluate` for the measured
history behind it.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass, field
from pathlib import Path

from injection_scanner.intercept import scan_text

# Label vocabulary.
BLOCK = "block"
PASS = "pass"
_VALID = {BLOCK, PASS}


# ---------------------------------------------------------------------------
# Infra classification.
#
# An OUTAGE is not a classification. `scan_text` fails closed, so a degraded
# layer returns ok=False and therefore AGREES with every injection-labelled
# case: a Lakera outage would score recall 1.0 on a scanner that classified
# nothing, and the gate would go green. Measured 2026-09-05: with Lakera
# answering 429 to ~3 of every 4 calls, this harness would have reported a
# perfect scorecard.
#
# The rule below is a VERBATIM port of research-agent's
# `mcp_server/server.py::_is_infra_reason`, deliberately: the two repositories
# have to agree on what "the scanner is down" looks like, and a rule that
# drifts is worse than no rule. It is head-ANCHORED and CLOSED — never a
# substring search, and the default is False, so an unrecognised reason is
# treated as content-derived and still scores.
# ---------------------------------------------------------------------------

# The head segment of every layer outage reason: `lakera_unavailable`,
# `honeypot_unavailable`, `judge_unavailable`, `unicode_sanitize_unavailable`,
# `secret_shapes_unavailable`.
_INFRA_REASON_HEAD_SUFFIX = "_unavailable"

# Reason prefixes that WRAP another layer's reason. `intercept.py` re-emits
# the honeypot's own result reason under `honeypot:` and the L4 judge's under
# `lakera_arbitration:`, so a genuine outage arrives one segment deeper than
# it was raised. An explicit set rather than "look at segment 1 too", so that
# `secret_shape:thing_unavailable` — a rule NAME that merely ends in the
# suffix — cannot be mistaken for an outage. Pinned by
# `tests/test_eval.py::test_a_detection_that_merely_ends_in_the_suffix_still_scores`.
_INFRA_WRAPPER_PREFIXES = frozenset({"honeypot", "lakera_arbitration"})

# Standalone setup codes. Today they only appear as the tail of
# `lakera_unavailable:<code>`; listed so a future call site emitting one bare
# is still classified as infra rather than silently scored.
_INFRA_BARE_REASONS = frozenset({"no-key", "key-config-error", "bad-response"})


class EvalInfraError(RuntimeError):
    """A scanner outage during an eval run — not a classification.

    Carries the case that hit it and the scanner's own reason. Both are
    scanner-synthesized, closed-vocabulary strings (a layer name, a condition,
    an exception TYPE name, a bounded HTTP status), which is why `_main` can
    print them: setup and infra failures are meant to be readable without a
    dive into the isolation zone. Nothing derived from the scanned text is in
    either field.
    """

    def __init__(self, case_id: str, reason: str) -> None:
        super().__init__(f"{case_id} {reason}")
        self.case_id = case_id
        self.reason = reason


def _infra_segments(reason: str) -> list[str]:
    """Split a reason into tokens, dropping the `+skipped=N/M` suffix.

    The honeypot appends `+skipped=<n>/<total>` to its top-line reason, which
    would otherwise glue itself to the last token and defeat the match.
    """
    return [seg.split("+", 1)[0] for seg in reason.split(":")]


def _is_infra_reason(reason: object) -> bool:
    """True iff `reason` is a positively-recognised setup/infra outage code.

    Default False: an unrecognised or malformed reason is treated as
    content-derived and still scores. Matching is anchored at the head segment
    (or at segment 1 behind a known wrapper prefix), never a substring search.
    """
    if not isinstance(reason, str) or not reason:
        return False
    segments = _infra_segments(reason)
    if segments[0].endswith(_INFRA_REASON_HEAD_SUFFIX):
        return True
    if (
        segments[0] in _INFRA_WRAPPER_PREFIXES
        and len(segments) > 1
        and segments[1].endswith(_INFRA_REASON_HEAD_SUFFIX)
    ):
        return True
    return reason in _INFRA_BARE_REASONS


@dataclass
class EvalCase:
    id: str
    text: str
    expected: str  # "block" or "pass"

    def __post_init__(self) -> None:
        if self.expected not in _VALID:
            raise ValueError(
                f"case {self.id!r}: expected must be one of {sorted(_VALID)}, "
                f"got {self.expected!r}"
            )


@dataclass
class CaseRow:
    id: str
    expected: str
    predicted: str
    reason: str
    # How many scans this case cost, and what the FIRST one said. They differ
    # from 1 / `predicted` only when disagreement confirmation re-scanned the
    # case (see `evaluate`). Kept on the row so the scorecard can report the
    # single-shot outcome next to the confirmed one instead of hiding it.
    attempts: int = 1
    first_predicted: str | None = None

    def __post_init__(self) -> None:
        if self.first_predicted is None:
            self.first_predicted = self.predicted

    @property
    def correct(self) -> bool:
        return self.expected == self.predicted

    @property
    def flaky(self) -> bool:
        """Matched its label only on a re-scan: a sampled layer disagreed first."""
        return self.correct and self.first_predicted != self.predicted


@dataclass
class EvalResult:
    """Alias-style result wrapper for a single case (id/expected/predicted/reason)."""

    case: EvalCase
    predicted: str
    reason: str

    @property
    def correct(self) -> bool:
        return self.case.expected == self.predicted


@dataclass
class Scorecard:
    tp: int = 0
    fn: int = 0
    fp: int = 0
    tn: int = 0
    rows: list[CaseRow] = field(default_factory=list)
    # The confirmation budget this card was scored under (0 = single shot).
    confirm_disagreements: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fn + self.fp + self.tn

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    @property
    def fp_rate(self) -> float:
        """False-alarm rate over the negatives (expected pass)."""
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    @property
    def false_negatives(self) -> list[str]:
        """Ids the scanner MISSED — expected block but predicted pass.

        This is the actionable coverage gap.
        """
        return [r.id for r in self.rows if r.expected == BLOCK and r.predicted == PASS]

    @property
    def false_positives(self) -> list[str]:
        """Ids falsely blocked — expected pass but predicted block."""
        return [r.id for r in self.rows if r.expected == PASS and r.predicted == BLOCK]

    @property
    def flaky(self) -> list[str]:
        """Ids that matched their label only after a re-scan.

        These are the sampled-layer draws the gate absorbed. A non-empty list
        is the measured single-shot weakness, and belongs in the report even
        though the confirmed verdict was right.
        """
        return [r.id for r in self.rows if r.flaky]

    # Single-shot metrics, from what the FIRST scan of each case said. These
    # are what production experiences — one scan per report — so they are
    # reported alongside the confirmed metrics whenever confirmation is on.
    @property
    def first_attempt_recall(self) -> float:
        pos = [r for r in self.rows if r.expected == BLOCK]
        hits = sum(1 for r in pos if r.first_predicted == BLOCK)
        return hits / len(pos) if pos else 0.0

    @property
    def first_attempt_fp_rate(self) -> float:
        neg = [r for r in self.rows if r.expected == PASS]
        alarms = sum(1 for r in neg if r.first_predicted == BLOCK)
        return alarms / len(neg) if neg else 0.0

    def format(self) -> str:
        lines: list[str] = []
        lines.append("=" * 72)
        lines.append("SCANNER EVALUATION SCORECARD")
        lines.append("=" * 72)
        lines.append(
            f"cases={self.total}  "
            f"precision={self.precision:.3f}  "
            f"recall={self.recall:.3f}  "
            f"F1={self.f1:.3f}  "
            f"accuracy={self.accuracy:.3f}  "
            f"FP-rate={self.fp_rate:.3f}"
        )
        lines.append(
            f"confusion: TP={self.tp} FN={self.fn} FP={self.fp} TN={self.tn}  "
            f"(positive class = {BLOCK!r})"
        )
        if self.confirm_disagreements:
            rescanned = sum(1 for r in self.rows if r.attempts > 1)
            lines.append(
                f"confirm-disagreements={self.confirm_disagreements}: "
                f"first-attempt recall={self.first_attempt_recall:.3f}  "
                f"FP-rate={self.first_attempt_fp_rate:.3f}  "
                f"(re-scanned {rescanned} case(s))"
            )
        lines.append("-" * 72)
        max_attempts = self.confirm_disagreements + 1
        for r in self.rows:
            tag = "FLAKY" if r.flaky else ("PASS" if r.correct else "FAIL")
            note = ""
            if r.flaky:
                note = (
                    f"  [matched its label on attempt {r.attempts} of "
                    f"{max_attempts}; first said {r.first_predicted}]"
                )
            elif not r.correct and r.attempts > 1:
                note = f"  [disagreed on all {r.attempts} attempts]"
            lines.append(
                f"{tag:<5} {r.id:<24}  {r.expected}->{r.predicted:<5}  {r.reason}{note}"
            )
        lines.append("-" * 72)
        fns = self.false_negatives
        lines.append(f"FALSE NEGATIVES (missed blocks — coverage gap): {len(fns)}")
        if fns:
            for fid in fns:
                lines.append(f"  MISS  {fid}")
        else:
            lines.append("  (none)")
        fps = self.false_positives
        if fps:
            lines.append(f"FALSE POSITIVES (false alarms): {len(fps)}")
            for fid in fps:
                lines.append(f"  ALARM {fid}")
        flaky = self.flaky
        if flaky:
            lines.append(
                f"FLAKY (label matched only on re-scan — a sampled layer "
                f"disagreed first): {len(flaky)}"
            )
            for fid in flaky:
                lines.append(f"  FLAKY {fid}")
        lines.append("=" * 72)
        return "\n".join(lines)


def evaluate(
    cases: list[EvalCase],
    *,
    use_honeypot: bool = False,
    use_lakera: bool = False,
    confirm_disagreements: int = 0,
    lakera_max_wait_s: float | None = None,
) -> Scorecard:
    """Run scan_text over each case and score against expected labels.

    "block" is the positive class:
      TP = expected block & blocked
      FN = expected block & passed  (a MISS — the coverage gap)
      FP = expected pass  & blocked (a false alarm)
      TN = expected pass  & passed

    `use_lakera` defaults to False: the Lakera gate fails CLOSED without a
    live key, so leaving it on would block every case in a keyless CI run.
    Deterministic-layer measurement runs it off; pass True (with a key set)
    to score the hosted layer end-to-end.

    `confirm_disagreements=N` re-scans a case whose verdict disagrees with
    its label, up to N more times, and counts the disagreement only if every
    attempt disagrees. A case that agrees on its first scan is never
    re-scanned, so a clean run costs exactly one scan per case.

    Why it exists (2026-09-05): the hosted layers are sampled LLMs, so with
    them live a single scan is a draw. CI's gate saw blatant_tool_coerce.md
    flip block->pass on 2026-08-10 and again on 2026-09-05 — the honeypot
    models occasionally decline the bait in every scenario at once — and
    the identical commit went green on rerun. Confirmation makes a
    stochastic miss have to repeat N+1 times before it fails the gate,
    while a deterministic regression (a layer that is actually broken)
    disagrees on every attempt and fails exactly as before. The first-scan
    outcome is kept on each row and reported by `Scorecard.format` as the
    single-shot numbers, because one scan per report is what production
    gets: the weakness is surfaced, not absorbed.

    `lakera_max_wait_s` is how long each L2 call may queue for its turn in the
    fleet-wide Lakera budget. A batch run would rather wait than be refused,
    which is the opposite of what an interactive scan wants — hence a
    parameter rather than a global.

    Raises `EvalInfraError` on the FIRST verdict whose reason is a recognised
    outage, before any further case is scanned. An outage is not a
    classification: `scan_text` fails closed, so a degraded layer agrees with
    every injection label and would inflate recall. Aborting also bounds the
    cost — a throttled Lakera pays for one probe per breaker window rather
    than one per case.
    """
    if confirm_disagreements < 0:
        raise ValueError(
            f"confirm_disagreements must be >= 0, got {confirm_disagreements}"
        )
    card = Scorecard(confirm_disagreements=confirm_disagreements)
    for case in cases:
        attempts = 0
        first_predicted: str | None = None
        while True:
            attempts += 1
            verdict = scan_text(
                case.text,
                use_honeypot=use_honeypot,
                use_lakera=use_lakera,
                lakera_max_wait_s=lakera_max_wait_s,
            )
            if _is_infra_reason(verdict.reason):
                # Stop the whole run, here, before this verdict is turned into
                # a prediction. Scoring it would credit the scorecard for a
                # layer that never classified anything, and re-scanning it
                # under `confirm_disagreements` would just spend more of the
                # budget on a layer that is down.
                raise EvalInfraError(case.id, verdict.reason)
            predicted = PASS if verdict.ok else BLOCK
            if first_predicted is None:
                first_predicted = predicted
            if predicted == case.expected or attempts > confirm_disagreements:
                break
        card.rows.append(
            CaseRow(
                id=case.id,
                expected=case.expected,
                predicted=predicted,
                reason=verdict.reason,
                attempts=attempts,
                first_predicted=first_predicted,
            )
        )
        if case.expected == BLOCK and predicted == BLOCK:
            card.tp += 1
        elif case.expected == BLOCK and predicted == PASS:
            card.fn += 1
        elif case.expected == PASS and predicted == BLOCK:
            card.fp += 1
        else:
            card.tn += 1
    return card


def load_jsonl(path: str | Path) -> list[EvalCase]:
    """Load a JSONL corpus.

    Each line: {"id": ..., "text": ..., "expected": "block"|"pass"}.
    Blank lines are skipped so external datasets (PINT / NotInject / BIPIA /
    deepset) can be dropped in with minimal massaging.
    """
    cases: list[EvalCase] = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
            try:
                cases.append(
                    EvalCase(id=obj["id"], text=obj["text"], expected=obj["expected"])
                )
            except KeyError as exc:
                raise ValueError(
                    f"{path}:{lineno}: missing required field {exc}"
                ) from exc
    return cases


def load_corpus_dir(directory: str | Path) -> list[EvalCase]:
    """Load a corpus from a directory containing a `labels.jsonl` file.

    The labels file gives one line per case. If a line omits `text`, the text
    is read from `<directory>/<id>` (the fixture file), letting a corpus store
    labels separately from the raw fixtures on disk.
    """
    directory = Path(directory)
    labels_path = directory / "labels.jsonl"
    if not labels_path.exists():
        raise FileNotFoundError(f"no labels.jsonl in {directory}")
    cases: list[EvalCase] = []
    with open(labels_path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            text = obj.get("text")
            if text is None:
                text = (directory / obj["id"]).read_text(encoding="utf-8")
            cases.append(
                EvalCase(id=obj["id"], text=text, expected=obj["expected"])
            )
    return cases


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m injection_scanner.eval",
        description="Score the scanner against a labeled corpus.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "exit codes:\n"
            "  0  measured (a run with no threshold flag is not a gate)\n"
            "  1  a threshold failed (--min-recall / --max-fp-rate)\n"
            "  2  usage error\n"
            "  3  a scanner OUTAGE: a layer was down, so nothing was\n"
            "     measured. No scorecard is printed; the diagnosis goes to\n"
            "     stderr as `INFRA <case_id> <reason>`.\n"
        ),
    )
    parser.add_argument("corpus", help="path to a JSONL corpus file")
    parser.add_argument(
        "--use-honeypot",
        action="store_true",
        help="enable the honeypot layer (costs an API call per case)",
    )
    parser.add_argument(
        "--use-lakera",
        action="store_true",
        help="enable the Lakera Guard gate (requires LAKERA_API_KEY; fails "
        "closed without one, blocking every case)",
    )
    parser.add_argument(
        "--min-recall",
        type=float,
        default=None,
        metavar="X",
        help="exit 1 if recall < X (lets CI enforce a floor). "
        "Omit to always exit 0 (pure measurement).",
    )
    parser.add_argument(
        "--max-fp-rate",
        type=float,
        default=None,
        metavar="X",
        help="exit 1 if FP-rate > X (lets CI enforce a false-alarm ceiling "
        "over the expected-pass cases). Omit to always exit 0.",
    )
    parser.add_argument(
        "--confirm-disagreements",
        type=int,
        default=0,
        metavar="N",
        help="re-scan a case whose verdict disagrees with its label up to N "
        "more times and count the disagreement only if every attempt "
        "disagrees (absorbs sampled-layer draws; a deterministic regression "
        "still fails). Agreeing cases are never re-scanned. The scorecard "
        "reports the first-attempt numbers alongside. Default 0: single shot.",
    )
    parser.add_argument(
        "--lakera-max-wait",
        type=float,
        default=900.0,
        metavar="SECONDS",
        help="how long each Lakera call may WAIT for its turn in the "
        "fleet-wide budget before it is refused. An eval run is always a "
        "batch caller, so it queues rather than failing; the default is 900 "
        "(15 minutes). 0 refuses immediately, which is what an interactive "
        "scan does. On the CLI rather than in the environment because being "
        "correct by default beats depending on the operator remembering.",
    )
    args = parser.parse_args(argv)
    if not math.isfinite(args.lakera_max_wait) or args.lakera_max_wait < 0:
        # A typo must not be able to disguise itself as an outage. The limiter
        # clamps a negative or non-finite budget to 0.0 — refuse immediately —
        # so under fleet contention the first case would come back
        # `lakera_unavailable:throttled` and the run would exit 3 reporting a
        # scanner outage that was really a mistyped flag. `evaluate` already
        # rejects `confirm_disagreements < 0`; this is the same treatment, and
        # exit 2 keeps a usage error out of the outage channel.
        parser.error(
            f"--lakera-max-wait must be a finite number of seconds >= 0, got "
            f"{args.lakera_max_wait!r}"
        )

    cases = load_jsonl(args.corpus)
    try:
        card = evaluate(
            cases,
            use_honeypot=args.use_honeypot,
            use_lakera=args.use_lakera,
            confirm_disagreements=args.confirm_disagreements,
            lakera_max_wait_s=args.lakera_max_wait,
        )
    except EvalInfraError as e:
        # Exit 3, distinct from 1 (a threshold failed) and 2 (argparse usage),
        # so a CI log says "the scanner was down" rather than "recall
        # regressed". No scorecard is printed: there isn't one, and printing a
        # partial card is how an outage gets mistaken for a measurement.
        #
        # Both fields are scanner-synthesized closed-vocabulary strings, which
        # is why they can be said out loud here.
        print(f"INFRA {e.case_id} {e.reason}", file=sys.stderr)
        return 3
    print(card.format())

    failed = False
    if args.min_recall is not None and card.recall < args.min_recall:
        print(
            f"\nRECALL FLOOR FAILED: recall={card.recall:.3f} "
            f"< --min-recall={args.min_recall:.3f}",
            file=sys.stderr,
        )
        failed = True
    if args.max_fp_rate is not None and card.fp_rate > args.max_fp_rate:
        print(
            f"\nFP-RATE CEILING FAILED: fp_rate={card.fp_rate:.3f} "
            f"> --max-fp-rate={args.max_fp_rate:.3f}",
            file=sys.stderr,
        )
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_main())
