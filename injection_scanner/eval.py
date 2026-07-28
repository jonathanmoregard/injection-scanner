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

Always exits 0 (measurement, not a gate) UNLESS --min-recall is passed, in
which case it exits 1 when recall falls below the floor (lets CI enforce it).
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from injection_scanner.intercept import scan_text

# Label vocabulary.
BLOCK = "block"
PASS = "pass"
_VALID = {BLOCK, PASS}


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

    @property
    def correct(self) -> bool:
        return self.expected == self.predicted


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
        lines.append("-" * 72)
        for r in self.rows:
            tag = "PASS" if r.correct else "FAIL"
            lines.append(
                f"{tag}  {r.id:<24}  {r.expected}->{r.predicted:<5}  {r.reason}"
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
        lines.append("=" * 72)
        return "\n".join(lines)


def evaluate(
    cases: list[EvalCase], *, use_honeypot: bool = False, use_lakera: bool = False
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
    """
    card = Scorecard()
    for case in cases:
        verdict = scan_text(case.text, use_honeypot=use_honeypot, use_lakera=use_lakera)
        predicted = PASS if verdict.ok else BLOCK
        card.rows.append(
            CaseRow(
                id=case.id,
                expected=case.expected,
                predicted=predicted,
                reason=verdict.reason,
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
    args = parser.parse_args(argv)

    cases = load_jsonl(args.corpus)
    card = evaluate(cases, use_honeypot=args.use_honeypot, use_lakera=args.use_lakera)
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
