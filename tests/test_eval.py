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
from types import SimpleNamespace

from injection_scanner.eval import (
    BLOCK,
    PASS,
    EvalCase,
    Scorecard,
    _main,
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
    # 16 fixtures: 7 malicious + 1 benign + 8 benign-hard fp_* cases
    # (2026-07-28 agent-tooling false-positive corpus).
    assert len(cases) == 16
    card = evaluate(cases, use_honeypot=False)
    assert card.total == 16
    assert card.tp + card.fn + card.fp + card.tn == 16


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
    # 2 deterministic blocks caught, 5 prose blocks missed, 9 benign pass
    # (benign.md + the 8 fp_* benign-hard agent-tooling cases).
    assert card.tp == 2
    assert card.fn == 5
    assert card.fp == 0
    assert card.tn == 9
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
    assert len(cases) == 16
    fp_cases = {c.id for c in cases if c.id.startswith("fp_")}
    assert len(fp_cases) == 8
    assert all(c.expected == PASS for c in cases if c.id.startswith("fp_"))
    assert {c.id for c in cases if not c.id.startswith("fp_")} == {
        "benign.md",
        *DETERMINISTIC_BLOCKS,
        *PROSE_INJECTIONS,
    }


# ---------------------------------------------------------------------------
# Disagreement confirmation (added 2026-09-05).
#
# The hosted layers are sampled LLMs, so a single scan is a draw. CI's eval
# saw blatant_tool_coerce.md flip block->pass on 2026-08-10 and again on
# 2026-09-05 — the same commit went green on rerun — because the honeypot
# models occasionally decline the bait in every scenario at once.
#
# `confirm_disagreements=N` re-scans ONLY a case whose verdict disagrees with
# its label, up to N more times. A stochastic miss therefore has to repeat
# N+1 times in a row to count, while a deterministic regression still
# disagrees on every attempt and still fails. Nothing is re-scanned on a
# clean run, so the gate costs nothing when nothing is wrong. The
# first-attempt numbers stay on the scorecard: the single-shot weakness is
# reported, not hidden.
# ---------------------------------------------------------------------------


def _scripted_scan(monkeypatch, script: dict[str, list[bool]]) -> dict[str, int]:
    """Replace scan_text with a stub replaying a per-text sequence of `ok`.

    The last value in a sequence repeats once it is exhausted. Returns the
    live call counter so a test can assert how many scans each case cost.
    """
    calls: dict[str, int] = {}

    def fake(raw: str, *, use_honeypot: bool = False, use_lakera: bool = False):
        seq = script[raw]
        i = calls.get(raw, 0)
        calls[raw] = i + 1
        ok = seq[min(i, len(seq) - 1)]
        return SimpleNamespace(ok=ok, reason="pass" if ok else f"stub:attempt{i + 1}")

    monkeypatch.setattr("injection_scanner.eval.scan_text", fake)
    return calls


def test_default_is_single_shot(monkeypatch) -> None:
    """With no confirmation configured the harness is byte-for-byte the old one."""
    calls = _scripted_scan(monkeypatch, {"inj": [True, False]})
    card = evaluate([EvalCase(id="inj", text="inj", expected=BLOCK)])
    assert (card.tp, card.fn) == (0, 1)
    assert calls["inj"] == 1
    assert card.rows[0].attempts == 1
    assert card.rows[0].first_predicted == PASS
    assert card.flaky == []
    assert "FLAKY" not in card.format()
    assert "first-attempt" not in card.format()


def test_stochastic_miss_is_caught_on_rescan_and_named_flaky(monkeypatch) -> None:
    calls = _scripted_scan(monkeypatch, {"inj": [True, False]})
    card = evaluate(
        [EvalCase(id="inj", text="inj", expected=BLOCK)], confirm_disagreements=1
    )
    assert (card.tp, card.fn) == (1, 0)
    assert calls["inj"] == 2
    row = card.rows[0]
    assert row.attempts == 2
    assert row.first_predicted == PASS
    assert row.predicted == BLOCK
    assert row.reason == "stub:attempt2"
    assert card.flaky == ["inj"]
    # The confirmed number gates; the first-attempt number is still reported.
    assert card.recall == 1.0
    assert card.first_attempt_recall == 0.0
    out = card.format()
    assert "FLAKY inj" in out
    assert "matched its label on attempt 2 of 2" in out
    assert "first-attempt recall=0.000" in out


def test_deterministic_miss_still_fails_and_says_so(monkeypatch) -> None:
    calls = _scripted_scan(monkeypatch, {"inj": [True]})
    card = evaluate(
        [EvalCase(id="inj", text="inj", expected=BLOCK)], confirm_disagreements=2
    )
    assert (card.tp, card.fn) == (0, 1)
    assert calls["inj"] == 3
    assert card.rows[0].attempts == 3
    assert card.flaky == []
    out = card.format()
    assert "FAIL  inj" in out
    assert "disagreed on all 3 attempts" in out


def test_agreeing_verdict_is_never_rescanned(monkeypatch) -> None:
    calls = _scripted_scan(monkeypatch, {"inj": [False], "ok": [True]})
    card = evaluate(
        [
            EvalCase(id="inj", text="inj", expected=BLOCK),
            EvalCase(id="ok", text="ok", expected=PASS),
        ],
        confirm_disagreements=3,
    )
    assert calls == {"inj": 1, "ok": 1}
    assert (card.tp, card.tn) == (1, 1)
    assert card.flaky == []


def test_false_alarm_direction_is_symmetric(monkeypatch) -> None:
    _scripted_scan(monkeypatch, {"ok": [False, True]})
    card = evaluate(
        [EvalCase(id="ok", text="ok", expected=PASS)], confirm_disagreements=1
    )
    assert (card.tn, card.fp) == (1, 0)
    assert card.flaky == ["ok"]
    assert card.fp_rate == 0.0
    assert card.first_attempt_fp_rate == 1.0


def test_negative_confirmation_is_rejected() -> None:
    try:
        evaluate([], confirm_disagreements=-1)
    except ValueError:
        return
    raise AssertionError("confirm_disagreements=-1 must raise")


def test_cli_gates_on_the_confirmed_verdict(monkeypatch, tmp_path: Path) -> None:
    corpus = tmp_path / "c.jsonl"
    corpus.write_text(
        '{"id": "inj", "text": "inj", "expected": "block"}\n', encoding="utf-8"
    )
    _scripted_scan(monkeypatch, {"inj": [True, False]})
    assert _main([str(corpus), "--min-recall", "1.0"]) == 1
    _scripted_scan(monkeypatch, {"inj": [True, False]})
    assert _main([str(corpus), "--min-recall", "1.0", "--confirm-disagreements", "1"]) == 0
    # A deterministic miss is not rescued by confirmation.
    _scripted_scan(monkeypatch, {"inj": [True]})
    assert _main([str(corpus), "--min-recall", "1.0", "--confirm-disagreements", "2"]) == 1
