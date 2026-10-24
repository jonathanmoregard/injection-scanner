"""The cross-process monthly spend budget (injection_scanner.throttle.MonthlyBudget).

A vendor with a free monthly allowance and no server-side cap (Model Armor:
2M tokens a month, then billed) needs a ledger the whole fleet shares. Every
property here is one the fleet relies on: a reservation is all-or-nothing,
a released one gives its amount back to the month it came from, the month
resets on the UTC calendar boundary and only forwards, concurrent callers
never overspend, and a ledger that cannot be trusted refuses rather than
re-minting a month of spend.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime

import pytest

from injection_scanner.throttle import Decision, MonthlyBudget


def _at(text: str) -> float:
    return datetime.fromisoformat(text).replace(tzinfo=UTC).timestamp()


class _Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _budget(tmp_path, limit: int, clock=None) -> MonthlyBudget:
    return MonthlyBudget(
        tmp_path / "state",
        "vendor_x",
        limit,
        clock=clock or _Clock(_at("2026-10-15T12:00:00")),
    )


def test_charges_are_allowed_up_to_the_limit_and_refused_beyond(tmp_path):
    budget = _budget(tmp_path, 100)

    assert budget.reserve(60).decision is Decision.ALLOWED
    assert budget.reserve(40).decision is Decision.ALLOWED
    assert budget.reserve(1).decision is Decision.THROTTLED


def test_a_refused_charge_spends_nothing(tmp_path):
    """All-or-nothing: a large text that does not fit must not eat the
    remainder a smaller one could still use."""
    budget = _budget(tmp_path, 100)

    assert budget.reserve(70).decision is Decision.ALLOWED
    assert budget.reserve(50).decision is Decision.THROTTLED
    assert budget.reserve(30).decision is Decision.ALLOWED


def test_the_ledger_is_shared_through_the_state_directory(tmp_path):
    clock = _Clock(_at("2026-10-15T12:00:00"))
    assert _budget(tmp_path, 100, clock).reserve(100).decision is Decision.ALLOWED
    assert _budget(tmp_path, 100, clock).reserve(1).decision is Decision.THROTTLED


def test_the_budget_resets_on_the_utc_calendar_month(tmp_path):
    clock = _Clock(_at("2026-10-31T23:59:59"))
    budget = _budget(tmp_path, 100, clock)
    assert budget.reserve(100).decision is Decision.ALLOWED
    assert budget.reserve(1).decision is Decision.THROTTLED

    clock.now = _at("2026-11-01T00:00:00")

    assert budget.reserve(100).decision is Decision.ALLOWED
    assert budget.reserve(1).decision is Decision.THROTTLED


def test_a_clock_stepping_back_a_month_does_not_mint_a_fresh_budget(tmp_path):
    clock = _Clock(_at("2026-11-01T00:00:05"))
    budget = _budget(tmp_path, 100, clock)
    assert budget.reserve(100).decision is Decision.ALLOWED

    clock.now = _at("2026-10-31T23:59:58")

    assert budget.reserve(1).decision is Decision.THROTTLED


def test_a_zero_limit_refuses_every_charge(tmp_path):
    assert _budget(tmp_path, 0).reserve(1).decision is Decision.THROTTLED


def test_concurrent_chargers_never_overspend(tmp_path):
    clock = _Clock(_at("2026-10-15T12:00:00"))
    outcomes: list[Decision] = []
    guard = threading.Lock()

    def worker() -> None:
        budget = _budget(tmp_path, 50, clock)
        for _ in range(10):
            decision = budget.reserve(1).decision
            with guard:
                outcomes.append(decision)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert outcomes.count(Decision.ALLOWED) == 50
    assert outcomes.count(Decision.THROTTLED) == 30
    assert _budget(tmp_path, 50, clock).reserve(1).decision is Decision.THROTTLED


def test_concurrent_processes_never_overspend(tmp_path):
    """flock is per open file description, so threads prove the lock within
    one process; forked children prove it across processes."""
    clock = _Clock(_at("2026-10-15T12:00:00"))
    pids = []
    for _ in range(4):
        pid = os.fork()
        if pid == 0:  # child: charge, exit with the count allowed
            allowed = sum(
                _budget(tmp_path, 30, clock).reserve(1).decision is Decision.ALLOWED
                for _ in range(10)
            )
            os._exit(allowed)
        pids.append(pid)

    total = 0
    for pid in pids:
        _, status = os.waitpid(pid, 0)
        total += os.waitstatus_to_exitcode(status)

    assert total == 30


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "",
        json.dumps({"schema": 99, "month": "2026-10", "used": 0}),
        json.dumps({"schema": 1, "month": "October", "used": 0}),
        json.dumps({"schema": 1, "month": "2026-10", "used": -1}),
        json.dumps({"schema": 1, "month": "2026-10", "used": True}),
        json.dumps({"schema": 1, "month": "2026-10"}),
    ],
    ids=["garbage", "empty", "foreign-schema", "bad-month", "negative", "bool", "missing"],
)
def test_an_untrustworthy_ledger_refuses_rather_than_resetting(tmp_path, content):
    """Unlike the pacing state, this is a spend ledger: resetting it would
    re-mint a month of billable calls. The operator deletes the file."""
    budget = _budget(tmp_path, 100)
    assert budget.reserve(1).decision is Decision.ALLOWED
    budget.state_path.write_text(content, encoding="utf-8")

    assert budget.reserve(1).decision is Decision.ERROR


def test_a_missing_ledger_starts_the_month_empty(tmp_path):
    budget = _budget(tmp_path, 100)
    assert not budget.state_path.exists()
    assert budget.reserve(100).decision is Decision.ALLOWED
    saved = json.loads(budget.state_path.read_text(encoding="utf-8"))
    assert saved == {"schema": 1, "month": "2026-10", "used": 100}


def test_an_unsafely_writable_state_directory_refuses(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o777)

    assert _budget(tmp_path, 100).reserve(1).decision is Decision.ERROR


@pytest.mark.parametrize("amount", [-1, 1.5, True, "3"])
def test_a_nonsense_amount_is_an_error_not_a_free_call(tmp_path, amount):
    assert _budget(tmp_path, 100).reserve(amount).decision is Decision.ERROR


def test_the_name_must_be_a_lower_case_identifier(tmp_path):
    budget = MonthlyBudget(tmp_path, "../escape", 100)
    assert budget.reserve(1).decision is Decision.ERROR
    assert not (tmp_path.parent / "escape-budget.json").exists()


# ----- release: a reservation the vendor did not bill goes back -----


def _used(budget: MonthlyBudget) -> int:
    return json.loads(budget.state_path.read_text(encoding="utf-8"))["used"]


def test_a_released_reservation_gives_its_amount_back(tmp_path):
    budget = _budget(tmp_path, 100)
    held = budget.reserve(70)
    assert held.decision is Decision.ALLOWED
    assert budget.reserve(50).decision is Decision.THROTTLED

    held.release()

    assert _used(budget) == 0
    assert budget.reserve(100).decision is Decision.ALLOWED


def test_release_is_idempotent(tmp_path):
    budget = _budget(tmp_path, 100)
    assert budget.reserve(30).decision is Decision.ALLOWED
    held = budget.reserve(20)
    held.release()
    held.release()
    assert _used(budget) == 30


@pytest.mark.parametrize("limit", [0, 5])
def test_releasing_a_refused_reservation_gives_nothing_back(tmp_path, limit):
    budget = _budget(tmp_path, limit)
    if limit:
        assert budget.reserve(limit).decision is Decision.ALLOWED
    refused = budget.reserve(10)
    assert refused.decision is Decision.THROTTLED
    refused.release()
    assert budget.reserve(1).decision is Decision.THROTTLED


def test_a_release_after_the_month_turned_leaves_the_new_month_alone(tmp_path):
    clock = _Clock(_at("2026-10-31T23:59:00"))
    budget = _budget(tmp_path, 100, clock)
    held = budget.reserve(60)
    clock.now = _at("2026-11-01T00:01:00")
    assert budget.reserve(30).decision is Decision.ALLOWED

    held.release()

    assert _used(budget) == 30


def test_a_release_on_an_unusable_ledger_never_raises_and_keeps_the_charge(tmp_path):
    """Fails closed: a release that cannot be recorded over-counts."""
    budget = _budget(tmp_path, 100)
    held = budget.reserve(10)
    budget.state_path.write_text("torn", encoding="utf-8")
    held.release()
    assert budget.state_path.read_text(encoding="utf-8") == "torn"


def test_concurrent_reserve_and_release_never_exceed_the_limit(tmp_path):
    """Every caller reserves, then half release: the ledger never admits more
    than the limit at once, and ends at exactly what was kept."""
    clock = _Clock(_at("2026-10-15T12:00:00"))
    held: list = []
    guard = threading.Lock()

    def worker() -> None:
        budget = _budget(tmp_path, 40, clock)
        for _ in range(10):
            r = budget.reserve(1)
            with guard:
                held.append(r)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    allowed = [r for r in held if r.decision is Decision.ALLOWED]
    assert len(allowed) == 40

    releasers = [threading.Thread(target=r.release) for r in allowed[:25]]
    for t in releasers:
        t.start()
    for t in releasers:
        t.join()
    assert _used(_budget(tmp_path, 40, clock)) == 15
