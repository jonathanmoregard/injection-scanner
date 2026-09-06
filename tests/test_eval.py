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

import pytest

from injection_scanner.eval import (
    BLOCK,
    PASS,
    EvalCase,
    EvalInfraError,
    Scorecard,
    _is_infra_reason,
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


def _stub_scan_text(monkeypatch, verdict) -> list[dict]:
    """Replace `scan_text` with a stub and return its live call log.

    THE ONLY place in this file that spells out `scan_text`'s keyword list.
    The stub must accept every keyword the real function takes — a stub that
    swallowed `**kwargs` would keep passing while the real call site broke —
    and one copy of the signature means the next keyword is one edit, not
    four, with no copy left silently behind.

    `verdict(raw, attempt)` decides what each call returns; `attempt` is the
    0-based attempt index for that text. Each log entry records the text and
    every keyword the call carried, so a test can assert what EVERY attempt
    did, not just the first.
    """
    log: list[dict] = []

    def fake(
        raw: str,
        *,
        use_honeypot: bool = False,
        use_lakera: bool = False,
        lakera_max_wait_s: float | None = None,
    ):
        attempt = sum(1 for entry in log if entry["raw"] == raw)
        log.append(
            {
                "raw": raw,
                "use_honeypot": use_honeypot,
                "use_lakera": use_lakera,
                "lakera_max_wait_s": lakera_max_wait_s,
            }
        )
        return verdict(raw, attempt)

    monkeypatch.setattr("injection_scanner.eval.scan_text", fake)
    return log


def _scripted_scan(monkeypatch, script: dict[str, list[bool]]) -> dict[str, int]:
    """Stub `scan_text` with a per-text sequence of `ok`.

    The last value in a sequence repeats once it is exhausted. Returns the
    live call counter so a test can assert how many scans each case cost.
    """
    calls: dict[str, int] = {}

    def verdict(raw: str, attempt: int):
        seq = script[raw]
        calls[raw] = attempt + 1
        ok = seq[min(attempt, len(seq) - 1)]
        return SimpleNamespace(
            ok=ok, reason="pass" if ok else f"stub:attempt{attempt + 1}"
        )

    _stub_scan_text(monkeypatch, verdict)
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


# ---------------------------------------------------------------------------
# Infra abort + the batch wait budget (added 2026-09-05).
#
# `eval` scores "block" against "pass". An OUTAGE is neither: `scan_text`
# fails closed, so a throttled Lakera returns ok=False and therefore AGREES
# with every injection-labelled case. Left alone, a Lakera outage inflates
# recall to 1.0 and the gate goes green on a scanner that classified nothing.
#
# So `evaluate` classifies each verdict with the same head-anchored, closed
# rule research-agent uses (mcp_server/server.py::_is_infra_reason) and
# aborts on the first infra verdict. That also bounds the damage: a throttled
# Lakera costs one probe per breaker window instead of 16.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "reason",
    [
        "lakera_unavailable:throttled",
        "lakera_unavailable:limiter-error",
        "lakera_unavailable:HTTPError:429",
        "lakera_unavailable:no-key",
        "lakera_unavailable:bad-response",
        "unicode_sanitize_unavailable:unhandled:ValueError",
        "secret_shapes_unavailable:unhandled:ValueError",
        "judge_unavailable:unhandled:RuntimeError",
        "honeypot:honeypot_unavailable:scn:no-anthropic-api-key+skipped=1/6",
        "lakera_arbitration:judge_unavailable:unhandled:RuntimeError",
        "no-key",
        "key-config-error",
        "bad-response",
    ],
)
def test_outages_are_recognised_as_infra(reason) -> None:
    assert _is_infra_reason(reason) is True


@pytest.mark.parametrize(
    "reason",
    [
        "pass",
        "lakera:prompt_attack",
        "lakera:flagged",
        "secret_shape:anthropic_oauth_token",
        # The trap the head anchoring exists for: a RULE NAME that happens to
        # end in the suffix is a detection, not an outage.
        "secret_shape:thing_unavailable",
        "encoded_secret:base64:github_token",
        "unicode_anomaly:stripped=5/100",
        "honeypot:scn:trap:x",
        "honeypot:honeypot:unavailable",
        "lakera_arbitration:attack:openai_4o_mini",
        "",
        "unavailable",
        None,
        42,
        pytest.param(["lakera_unavailable:throttled"], id="list-not-str"),
    ],
)
def test_classifications_and_junk_are_not_infra(reason) -> None:
    assert _is_infra_reason(reason) is False


def _reason_scan(monkeypatch, script: dict[str, list[str]]) -> list[dict]:
    """Stub `scan_text` with a per-text SEQUENCE of reasons.

    The last reason repeats once the sequence is exhausted; a case that is
    scanned once takes a one-element sequence. Returns the live call log —
    see `_stub_scan_text` for what each entry holds.
    """

    def verdict(raw: str, attempt: int):
        seq = script[raw]
        reason = seq[min(attempt, len(seq) - 1)]
        return SimpleNamespace(ok=(reason == "pass"), reason=reason)

    return _stub_scan_text(monkeypatch, verdict)


def test_an_infra_verdict_aborts_before_the_next_case(monkeypatch) -> None:
    log = _reason_scan(
        monkeypatch,
        {"a": ["pass"], "b": ["lakera_unavailable:throttled"], "c": ["pass"]},
    )
    with pytest.raises(EvalInfraError) as excinfo:
        evaluate(
            [
                EvalCase(id="a", text="a", expected=PASS),
                EvalCase(id="b", text="b", expected=BLOCK),
                EvalCase(id="c", text="c", expected=PASS),
            ]
        )
    assert excinfo.value.case_id == "b"
    assert excinfo.value.reason == "lakera_unavailable:throttled"
    assert [e["raw"] for e in log] == ["a", "b"], (
        "no case after the outage may be scanned"
    )


def test_a_wrapped_honeypot_outage_also_aborts(monkeypatch) -> None:
    _reason_scan(
        monkeypatch,
        {"a": ["honeypot:honeypot_unavailable:scn:no-openai-api-key+skipped=2/6"]},
    )
    with pytest.raises(EvalInfraError) as excinfo:
        evaluate([EvalCase(id="a", text="a", expected=BLOCK)])
    assert excinfo.value.case_id == "a"


def test_an_outage_on_a_rescan_aborts_too(monkeypatch) -> None:
    """The abort is per ATTEMPT, not per case.

    With confirmation on, a case whose verdict disagrees with its label is
    scanned again — and the re-scan is exactly where a throttled Lakera turns
    up, because the first attempt is what spent the last token. Classifying
    only the first attempt would score the outage AND keep re-scanning
    through it, spending the budget on a layer that is down.
    """
    log = _reason_scan(
        monkeypatch,
        {
            "ok": ["lakera:prompt_attack", "lakera_unavailable:throttled", "pass"],
            "next": ["pass"],
        },
    )
    with pytest.raises(EvalInfraError) as excinfo:
        evaluate(
            [
                EvalCase(id="ok", text="ok", expected=PASS),
                EvalCase(id="next", text="next", expected=PASS),
            ],
            confirm_disagreements=2,
            lakera_max_wait_s=120.0,
        )
    assert excinfo.value.case_id == "ok"
    assert excinfo.value.reason == "lakera_unavailable:throttled"
    assert [e["raw"] for e in log] == ["ok", "ok"], (
        "the third attempt and the next case must never be scanned"
    )
    assert [e["lakera_max_wait_s"] for e in log] == [120.0, 120.0], (
        "every attempt, not just the first, must carry the wait budget"
    )


def test_a_detection_that_merely_ends_in_the_suffix_still_scores(monkeypatch) -> None:
    _reason_scan(monkeypatch, {"a": ["secret_shape:thing_unavailable"]})
    card = evaluate([EvalCase(id="a", text="a", expected=BLOCK)])
    assert (card.tp, card.fn) == (1, 0)


def test_a_normal_run_is_unchanged(monkeypatch) -> None:
    _reason_scan(
        monkeypatch,
        {
            "a": ["pass"],
            "b": ["secret_shape:github_token"],
            "c": ["lakera:prompt_attack"],
        },
    )
    card = evaluate(
        [
            EvalCase(id="a", text="a", expected=PASS),
            EvalCase(id="b", text="b", expected=BLOCK),
            EvalCase(id="c", text="c", expected=BLOCK),
        ]
    )
    assert (card.tp, card.fn, card.fp, card.tn) == (2, 0, 0, 1)


def test_evaluate_forwards_the_wait_budget(monkeypatch) -> None:
    log = _reason_scan(monkeypatch, {"a": ["pass"]})
    evaluate([EvalCase(id="a", text="a", expected=PASS)], lakera_max_wait_s=900.0)
    assert log == [
        {
            "raw": "a",
            "use_honeypot": False,
            "use_lakera": False,
            "lakera_max_wait_s": 900.0,
        }
    ]


def test_the_cli_defaults_the_wait_budget_to_fifteen_minutes(
    monkeypatch, tmp_path: Path
) -> None:
    """On the CLI, not in the environment: eval is ALWAYS a batch caller, and
    being correct by default beats depending on the operator remembering an
    env var."""
    corpus = tmp_path / "c.jsonl"
    corpus.write_text(
        '{"id": "a", "text": "a", "expected": "pass"}\n', encoding="utf-8"
    )
    log = _reason_scan(monkeypatch, {"a": ["pass"]})
    assert _main([str(corpus)]) == 0
    assert log[0]["lakera_max_wait_s"] == 900.0

    log.clear()
    assert _main([str(corpus), "--lakera-max-wait", "5"]) == 0
    assert log[0]["lakera_max_wait_s"] == 5.0


def test_the_cli_reports_infra_on_stderr_and_exits_three(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """Exit 3 is distinct from 1 (gate failed) and 2 (argparse usage), so a
    CI log says 'the scanner was down' rather than 'recall regressed'."""
    corpus = tmp_path / "c.jsonl"
    corpus.write_text(
        '{"id": "inj", "text": "inj", "expected": "block"}\n'
        '{"id": "ok", "text": "ok", "expected": "pass"}\n',
        encoding="utf-8",
    )
    log = _reason_scan(
        monkeypatch, {"inj": ["lakera_unavailable:throttled"], "ok": ["pass"]}
    )
    assert _main([str(corpus), "--min-recall", "1.0"]) == 3
    captured = capsys.readouterr()
    assert captured.out == "", (
        "no scorecard on stdout: there isn't one, and a partial card is how "
        "an outage gets mistaken for a measurement"
    )
    # The exact line and nothing else: a CI log reading this must not have to
    # guess which of several lines is the diagnosis.
    assert captured.err.strip() == "INFRA inj lakera_unavailable:throttled"
    assert [e["raw"] for e in log] == ["inj"], (
        "the second case must never be scanned"
    )


def test_an_outage_can_no_longer_earn_recall(monkeypatch, tmp_path: Path) -> None:
    """The regression this abort exists to prevent: `scan_text` fails closed,
    so a throttled Lakera agrees with every injection label and would score
    recall 1.0 on a scanner that classified nothing."""
    corpus = tmp_path / "c.jsonl"
    corpus.write_text(
        '{"id": "inj", "text": "inj", "expected": "block"}\n', encoding="utf-8"
    )
    _reason_scan(monkeypatch, {"inj": ["lakera_unavailable:throttled"]})
    assert _main([str(corpus), "--min-recall", "1.0"]) != 0


@pytest.mark.parametrize(
    "flag",
    [
        pytest.param(["--lakera-max-wait", "-5"], id="negative"),
        pytest.param(["--lakera-max-wait", "-0.001"], id="barely-negative"),
        pytest.param(["--lakera-max-wait", "nan"], id="nan"),
        pytest.param(["--lakera-max-wait", "inf"], id="inf"),
        # `-inf` only reaches the guard in the `=` form: a bare `-inf` looks
        # like an option to argparse and is rejected one step earlier.
        pytest.param(["--lakera-max-wait=-inf"], id="negative-inf"),
    ],
)
def test_a_nonsense_wait_budget_is_a_usage_error(
    monkeypatch, tmp_path: Path, capsys, flag: list[str]
) -> None:
    """A typo must not be able to disguise itself as an outage.

    `acquire` clamps a negative or non-finite budget to 0.0 — refuse
    immediately — so under fleet contention the first case would come back
    `lakera_unavailable:throttled` and the run would exit 3 reporting a
    scanner outage that was really a mistyped flag. `evaluate` already
    rejects `confirm_disagreements < 0`; this is the same treatment on the
    same kind of input, and exit 2 keeps a usage error out of the outage
    channel.
    """
    corpus = tmp_path / "c.jsonl"
    corpus.write_text(
        '{"id": "a", "text": "a", "expected": "pass"}\n', encoding="utf-8"
    )
    log = _reason_scan(monkeypatch, {"a": ["pass"]})
    with pytest.raises(SystemExit) as excinfo:
        _main([str(corpus), *flag])
    assert excinfo.value.code == 2
    assert "--lakera-max-wait" in capsys.readouterr().err
    assert log == [], "a rejected budget must not scan anything"


@pytest.mark.parametrize("good, expected", [("0", 0.0), ("900", 900.0)])
def test_a_sane_wait_budget_is_accepted(
    monkeypatch, tmp_path: Path, good: str, expected: float
) -> None:
    """0 is legal — it is exactly what an interactive scan does."""
    corpus = tmp_path / "c.jsonl"
    corpus.write_text(
        '{"id": "a", "text": "a", "expected": "pass"}\n', encoding="utf-8"
    )
    log = _reason_scan(monkeypatch, {"a": ["pass"]})
    assert _main([str(corpus), "--lakera-max-wait", good]) == 0
    assert log[0]["lakera_max_wait_s"] == expected


# ---------------------------------------------------------------------------
# Usage errors leave through the usage-error exit (added 2026-09-06).
#
# The epilog promises four exhaustive exit codes: 0 measured, 1 a threshold
# failed, 2 usage, 3 an outage. Three inputs escaped that promise by raising
# out of `_main` uncaught, and Python renders an uncaught exception as exit 1
# — the code CI reads as "recall regressed". A missing corpus, a corrupt one,
# and `--confirm-disagreements -1` therefore all reported a scoring failure
# and printed a traceback over the operator's terminal.
#
# The corpus is an ARGUMENT, so a bad one is a usage error like any other:
# `parser.error` names the cause, argparse exits 2, and no traceback is
# printed. Nothing is scanned in any of these cases.
# ---------------------------------------------------------------------------


def _usage_error(monkeypatch, argv: list[str], capsys) -> str:
    """Run `_main(argv)`, assert exit 2, return what argparse said on stderr."""
    log = _reason_scan(monkeypatch, {})
    with pytest.raises(SystemExit) as excinfo:
        _main(argv)
    assert excinfo.value.code == 2
    assert log == [], "a rejected run must not scan anything"
    return capsys.readouterr().err


def test_a_missing_corpus_is_a_usage_error_not_a_threshold_failure(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    err = _usage_error(monkeypatch, [str(tmp_path / "nope.jsonl")], capsys)
    assert "corpus" in err
    assert "Traceback" not in err


def test_an_unreadable_corpus_is_a_usage_error(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """A DIRECTORY where a file was named: an OSError, not a FileNotFoundError,
    so catching the narrower type alone would still traceback."""
    err = _usage_error(monkeypatch, [str(tmp_path)], capsys)
    assert "corpus" in err


@pytest.mark.parametrize(
    "line, id",
    [
        pytest.param("{not json at all}\n", "invalid-json", id="invalid-json"),
        pytest.param('{"id": "a", "text": "a"}\n', "missing-field", id="missing-field"),
        pytest.param(
            '{"id": "a", "text": "a", "expected": "maybe"}\n', "bad-label",
            id="bad-label",
        ),
        pytest.param("[1, 2, 3]\n", "not-an-object", id="not-an-object"),
    ],
)
def test_a_malformed_corpus_row_is_a_usage_error(
    monkeypatch, tmp_path: Path, capsys, line: str, id: str
) -> None:
    corpus = tmp_path / "c.jsonl"
    corpus.write_text(line, encoding="utf-8")
    err = _usage_error(monkeypatch, [str(corpus)], capsys)
    assert "corpus" in err
    assert "Traceback" not in err


def test_a_negative_confirmation_budget_is_a_usage_error(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """`evaluate` raises ValueError on this; escaping `_main` it became exit 1.
    Rejected at parse time now, the same treatment `--lakera-max-wait` gets."""
    corpus = tmp_path / "c.jsonl"
    corpus.write_text(
        '{"id": "a", "text": "a", "expected": "pass"}\n', encoding="utf-8"
    )
    err = _usage_error(
        monkeypatch, [str(corpus), "--confirm-disagreements", "-1"], capsys
    )
    assert "--confirm-disagreements" in err


def test_a_valid_run_still_exits_zero(monkeypatch, tmp_path: Path) -> None:
    """The control: none of the above narrows what a good run does."""
    corpus = tmp_path / "c.jsonl"
    corpus.write_text(
        '{"id": "a", "text": "a", "expected": "pass"}\n', encoding="utf-8"
    )
    _reason_scan(monkeypatch, {"a": ["pass"]})
    assert _main([str(corpus)]) == 0
    _reason_scan(monkeypatch, {"a": ["pass"]})
    assert _main([str(corpus), "--confirm-disagreements", "0"]) == 0
