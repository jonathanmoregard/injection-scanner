"""The L2 vendor panel (injection_scanner.l2).

Hermetic: every test hands `l2.run` its own adapter stand-ins through the
`checks` parameter, so no vendor module, key or socket is involved.

Pinned here:
  * the decision table — every combination of pass / flag / quota / hard
    outage for two vendors, at floor 1 and floor 2;
  * the floor input (default 2, clamped to [1, number of vendors]);
  * Invariant 3: an exception inside an adapter is a fail-closed outage of
    that vendor, never an escape;
  * concurrency: vendors run at the same time (wall time = max, not sum);
  * closed vocabulary: an adapter result outside its own namespace cannot
    carry its reason through.
"""
from __future__ import annotations

import threading

import pytest

from injection_scanner import l2
from injection_scanner.l2 import Outcome
from injection_scanner.vendor_http import VendorResult


def _result(vendor: str, state: str) -> VendorResult:
    if state == "P":
        return VendorResult(ok=True, reason="pass")
    if state == "F":
        return VendorResult(ok=False, flagged=True, reason=f"{vendor}:prompt_attack")
    if state == "Q":
        return VendorResult(ok=False, reason=f"{vendor}_unavailable:HTTPError:429")
    if state == "T":
        return VendorResult(ok=False, reason=f"{vendor}_unavailable:throttled")
    if state == "H":
        return VendorResult(ok=False, reason=f"{vendor}_unavailable:no-key")
    raise AssertionError(state)


def _checks(lakera_state: str, armor_state: str) -> dict:
    return {
        "lakera": lambda _t, **_kw: _result("lakera", lakera_state),
        "model_armor": lambda _t, **_kw: _result("model_armor", armor_state),
    }


_L = {
    "F": "lakera:prompt_attack",
    "Q": "lakera_unavailable:HTTPError:429",
    "H": "lakera_unavailable:no-key",
}
_M = {
    "F": "model_armor:prompt_attack",
    "Q": "model_armor_unavailable:HTTPError:429",
    "H": "model_armor_unavailable:no-key",
}

# (lakera, model_armor, floor) -> (outcome, reason, verdicts)
_TABLE = [
    # ----- floor 2: both vendors must answer -----
    ("P", "P", 2, Outcome.PASS, "pass", 2),
    ("P", "F", 2, Outcome.FLAGGED, _M["F"], 2),
    ("F", "P", 2, Outcome.FLAGGED, _L["F"], 2),
    ("F", "F", 2, Outcome.FLAGGED, _L["F"], 2),
    ("P", "Q", 2, Outcome.DEGRADED_QUOTA, _M["Q"], 1),
    ("Q", "P", 2, Outcome.DEGRADED_QUOTA, _L["Q"], 1),
    ("F", "Q", 2, Outcome.DEGRADED_QUOTA, _M["Q"], 1),
    ("Q", "F", 2, Outcome.DEGRADED_QUOTA, _L["Q"], 1),
    ("Q", "Q", 2, Outcome.DEGRADED_QUOTA, _L["Q"], 0),
    ("P", "H", 2, Outcome.UNAVAILABLE, _M["H"], 1),
    ("H", "P", 2, Outcome.UNAVAILABLE, _L["H"], 1),
    ("F", "H", 2, Outcome.UNAVAILABLE, _M["H"], 1),
    ("H", "F", 2, Outcome.UNAVAILABLE, _L["H"], 1),
    ("Q", "H", 2, Outcome.UNAVAILABLE, _M["H"], 0),
    ("H", "Q", 2, Outcome.UNAVAILABLE, _L["H"], 0),
    ("H", "H", 2, Outcome.UNAVAILABLE, _L["H"], 0),
    # ----- floor 1: one verdict is enough -----
    ("P", "P", 1, Outcome.PASS, "pass", 2),
    ("P", "F", 1, Outcome.FLAGGED, _M["F"], 2),
    ("F", "P", 1, Outcome.FLAGGED, _L["F"], 2),
    ("F", "F", 1, Outcome.FLAGGED, _L["F"], 2),
    ("P", "Q", 1, Outcome.PASS, "pass", 1),
    ("Q", "P", 1, Outcome.PASS, "pass", 1),
    ("F", "Q", 1, Outcome.FLAGGED, _L["F"], 1),
    ("Q", "F", 1, Outcome.FLAGGED, _M["F"], 1),
    ("Q", "Q", 1, Outcome.DEGRADED_QUOTA, _L["Q"], 0),
    ("P", "H", 1, Outcome.PASS, "pass", 1),
    ("H", "P", 1, Outcome.PASS, "pass", 1),
    ("F", "H", 1, Outcome.FLAGGED, _L["F"], 1),
    ("H", "F", 1, Outcome.FLAGGED, _M["F"], 1),
    ("Q", "H", 1, Outcome.UNAVAILABLE, _M["H"], 0),
    ("H", "Q", 1, Outcome.UNAVAILABLE, _L["H"], 0),
    ("H", "H", 1, Outcome.UNAVAILABLE, _L["H"], 0),
]


@pytest.mark.parametrize(
    "lakera_state,armor_state,floor,outcome,reason,verdicts",
    _TABLE,
    ids=[f"{a}{b}-floor{f}" for a, b, f, *_ in _TABLE],
)
def test_the_decision_table(
    monkeypatch, lakera_state, armor_state, floor, outcome, reason, verdicts
):
    monkeypatch.setenv("INJECTION_SCANNER_L2_MIN_VERDICTS", str(floor))
    res = l2.run("text", checks=_checks(lakera_state, armor_state))
    assert res.outcome is outcome
    assert res.reason == reason
    assert res.verdicts == verdicts
    assert res.floor == floor
    assert res.results == {
        "lakera": _result("lakera", lakera_state),
        "model_armor": _result("model_armor", armor_state),
    }


def test_local_throttling_is_quota_class_too(monkeypatch):
    res = l2.run("text", checks=_checks("T", "P"))
    assert res.outcome is Outcome.DEGRADED_QUOTA
    assert res.reason == "lakera_unavailable:throttled"


@pytest.mark.parametrize(
    "reason",
    [
        "lakera_unavailable:HTTPError:503",
        "lakera_unavailable:HTTPError:429-extra",
        "lakera_unavailable:HTTPError:4290",
        "lakera_unavailable:service-unavailable",
        "lakera_unavailable:limiter-error",
        "model_armor_unavailable:HTTPError:429",
    ],
)
def test_quota_class_is_exact_membership_for_the_vendor_itself(reason):
    """No prefix matching, and one vendor cannot borrow another's
    quota reason to reach the narrower degraded path."""
    checks = {
        "lakera": lambda _t, **_kw: VendorResult(ok=False, reason=reason),
        "model_armor": lambda _t, **_kw: VendorResult(ok=True, reason="pass"),
    }
    res = l2.run("text", checks=checks)
    assert res.outcome is Outcome.UNAVAILABLE


def test_the_summary_is_a_closed_one_liner(monkeypatch):
    assert l2.run("t", checks=_checks("P", "P")).summary == (
        "pass verdicts=2/2 floor=2"
    )
    assert l2.run("t", checks=_checks("P", "Q")).summary == (
        "degraded-quota verdicts=1/2 floor=2"
    )
    assert l2.run("t", checks=_checks("F", "P")).summary == (
        "flagged verdicts=2/2 floor=2"
    )
    assert l2.run("t", checks=_checks("H", "P")).summary == (
        "unavailable verdicts=1/2 floor=2"
    )


@pytest.mark.parametrize(
    "raw,floor",
    [(None, 2), ("1", 1), ("2", 2), ("5", 2), ("0", 1), ("-3", 1), ("x", 2)],
)
def test_the_floor_is_an_input_clamped_to_the_panel(monkeypatch, raw, floor):
    if raw is None:
        monkeypatch.delenv("INJECTION_SCANNER_L2_MIN_VERDICTS", raising=False)
    else:
        monkeypatch.setenv("INJECTION_SCANNER_L2_MIN_VERDICTS", raw)
    assert l2.run("t", checks=_checks("P", "P")).floor == floor


def test_the_default_floor_clamps_to_a_one_vendor_panel(monkeypatch):
    monkeypatch.delenv("INJECTION_SCANNER_L2_MIN_VERDICTS", raising=False)
    res = l2.run(
        "t", checks={"lakera": lambda _t, **_kw: VendorResult(ok=True, reason="pass")}
    )
    assert res.floor == 1
    assert res.outcome is Outcome.PASS


def test_the_production_registry_order_is_fixed():
    assert l2.VENDORS == ("lakera", "model_armor")


def test_an_exception_inside_an_adapter_is_that_vendors_outage():
    """Invariant 3: a raise reduces to reject, never escapes the scan. Only
    the exception TYPE name crosses; its message is dropped."""

    def _boom(_t, **_kw):
        raise RuntimeError("SECRET_MESSAGE_MARKER")

    checks = {
        "lakera": lambda _t, **_kw: VendorResult(ok=True, reason="pass"),
        "model_armor": _boom,
    }
    res = l2.run("text", checks=checks)
    assert res.outcome is Outcome.UNAVAILABLE
    assert res.reason == "model_armor_unavailable:unhandled:RuntimeError"
    assert res.results["model_armor"] == VendorResult(
        ok=False, reason="model_armor_unavailable:unhandled:RuntimeError"
    )


@pytest.mark.parametrize(
    "bad",
    [
        None,
        VendorResult(ok=True, reason="pass", flagged=True),
        VendorResult(ok=False, reason="pass"),
        VendorResult(ok=True, reason="lakera:prompt_attack"),
        VendorResult(ok=False, flagged=True, reason="lakera:prompt_attack"),
        VendorResult(ok=False, reason="lakera_unavailable:no-key"),
        VendorResult(ok=False, reason="free text from somewhere"),
    ],
    ids=[
        "none",
        "pass-but-flagged",
        "pass-reason-not-ok",
        "ok-with-flag-reason",
        "another-vendors-flag",
        "another-vendors-outage",
        "free-text",
    ],
)
def test_a_result_outside_the_vendors_own_vocabulary_is_a_bad_result(bad):
    checks = {
        "lakera": lambda _t, **_kw: VendorResult(ok=True, reason="pass"),
        "model_armor": lambda _t, **_kw: bad,
    }
    res = l2.run("text", checks=checks)
    assert res.outcome is Outcome.UNAVAILABLE
    assert res.reason == "model_armor_unavailable:bad-result"


def test_vendors_run_concurrently():
    """Each stand-in blocks until BOTH have started. Run one after the other,
    the first would wait out the barrier and fail closed."""
    barrier = threading.Barrier(2, timeout=5)

    def _waits_for_peer(_t, **_kw):
        barrier.wait()
        return VendorResult(ok=True, reason="pass")

    res = l2.run(
        "text", checks={"lakera": _waits_for_peer, "model_armor": _waits_for_peer}
    )
    assert res.outcome is Outcome.PASS


def test_the_wait_budget_reaches_every_vendor():
    seen: dict[str, object] = {}

    def _spy(name):
        def check(text, *, max_wait_s=None):
            seen[name] = (text, max_wait_s)
            return VendorResult(ok=True, reason="pass")

        return check

    l2.run("the text", max_wait_s=120.0, checks={"lakera": _spy("lakera"),
                                                 "model_armor": _spy("model_armor")})
    assert seen == {
        "lakera": ("the text", 120.0),
        "model_armor": ("the text", 120.0),
    }


@pytest.mark.parametrize(
    "summary,outcome",
    [
        ("pass verdicts=2/2 floor=2", Outcome.PASS),
        ("degraded-quota verdicts=1/2 floor=2", Outcome.DEGRADED_QUOTA),
        ("flagged verdicts=2/2 floor=2", Outcome.FLAGGED),
        ("unavailable verdicts=0/2 floor=2", Outcome.UNAVAILABLE),
        ("passed verdicts=2/2 floor=2", None),
        ("disabled (test-only)", None),
        ("", None),
        (None, None),
        (42, None),
    ],
)
def test_outcome_of_reads_only_the_closed_summary(summary, outcome):
    assert l2.outcome_of(summary) is outcome
