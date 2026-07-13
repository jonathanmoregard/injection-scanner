"""
Tests for the scored evaluation harness (injection_scanner.eval).

CI-safe: every case runs with use_honeypot=False, so there is NO Anthropic
API call. The point is to lock in today's deterministic-layer behavior AND to
document the known coverage gap (prose-only injections the honeypot-off path
cannot catch yet) as an executable assertion. When the planned L2 classifier
lands, the false-negative assertions below should start failing — that's the
signal the gap has closed, and they should be tightened at that point.
"""
from __future__ import annotations

from pathlib import Path

from injection_scanner.eval import (
    BLOCK,
    PASS,
    EvalCase,
    Scorecard,
    evaluate,
    load_corpus_dir,
    load_jsonl,
)

PAYLOADS = Path(__file__).parent / "payloads"
LABELS = PAYLOADS / "labels.jsonl"

# Fixtures that hit a DETERMINISTIC layer with the honeypot off.
DETERMINISTIC_BLOCKS = {"secret_leak.md", "unicode_smuggle.md"}
# Prose-only injections: no secret shape, no unicode anomaly. The deterministic
# layers cannot catch these — they are the coverage gap for L2.
PROSE_INJECTIONS = {
    "aggressive_injection.md",
    "blatant_tool_coerce.md",
    "canary_extract.md",
    "naive_injection.md",
    "sneaky_injection.md",
}


def _card() -> Scorecard:
    cases = load_jsonl(LABELS)
    return evaluate(cases, use_honeypot=False)


def test_harness_runs_over_seed_corpus() -> None:
    cases = load_jsonl(LABELS)
    # 8 fixtures: 1 benign + 7 malicious.
    assert len(cases) == 8
    card = evaluate(cases, use_honeypot=False)
    assert card.total == 8
    assert card.tp + card.fn + card.fp + card.tn == 8


def test_deterministic_fixtures_are_caught() -> None:
    """secret_leak and unicode_smuggle must block with the honeypot off."""
    card = _card()
    by_id = {r.id: r for r in card.rows}
    for fid in DETERMINISTIC_BLOCKS:
        assert by_id[fid].predicted == BLOCK, (
            f"{fid} should be caught deterministically, "
            f"got reason={by_id[fid].reason!r}"
        )
    # Reasons should name the specific deterministic detector, not the honeypot.
    assert by_id["secret_leak.md"].reason.startswith("secret_shape")
    assert by_id["unicode_smuggle.md"].reason.startswith("unicode_anomaly")


def test_benign_does_not_false_positive() -> None:
    card = _card()
    by_id = {r.id: r for r in card.rows}
    assert by_id["benign.md"].predicted == PASS
    assert card.false_positives == []
    assert card.fp == 0


def test_prose_injections_are_the_known_gap() -> None:
    """Honeypot off, prose-only injections CANNOT be caught yet.

    We assert they show up as false negatives rather than asserting they block.
    This documents the gap; when L2 lands, this test should be revisited.
    """
    card = _card()
    fns = set(card.false_negatives)
    assert fns == PROSE_INJECTIONS, (
        "expected exactly the prose injections to be missed with honeypot off; "
        f"got {sorted(fns)}"
    )


def test_confusion_matrix_and_metrics() -> None:
    card = _card()
    # 2 deterministic blocks caught, 5 prose blocks missed, 1 benign passes.
    assert card.tp == 2
    assert card.fn == 5
    assert card.fp == 0
    assert card.tn == 1
    # Precision is perfect (no false alarms); recall is the honest low number.
    assert card.precision == 1.0
    assert abs(card.recall - 2 / 7) < 1e-9


def test_load_jsonl_round_trips_inline_corpus(tmp_path: Path) -> None:
    corpus = tmp_path / "mini.jsonl"
    corpus.write_text(
        '{"id": "a", "text": "hello world", "expected": "pass"}\n'
        "\n"  # blank line should be skipped
        '{"id": "b", "text": "leak sk-ant-oat01-x", "expected": "block"}\n',
        encoding="utf-8",
    )
    cases = load_jsonl(corpus)
    assert len(cases) == 2
    assert cases[0] == EvalCase(id="a", text="hello world", expected="pass")
    assert cases[1].id == "b"
    assert cases[1].expected == BLOCK


def test_load_corpus_dir_reads_labels_file() -> None:
    cases = load_corpus_dir(PAYLOADS)
    assert len(cases) == 8
    assert {c.id for c in cases} == {
        "benign.md",
        *DETERMINISTIC_BLOCKS,
        *PROSE_INJECTIONS,
    }
