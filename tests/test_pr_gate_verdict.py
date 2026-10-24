"""pr-gate: verdict thresholds and the review body."""
from __future__ import annotations

import _prgate  # noqa: F401

import pytest

from prgate import verdict as v
from prgate.checks import Hit, Scrutiny
from prgate.llm import Finding, PassResult

HEAD = "a" * 40
HASH = "b" * 64


def ok(name="monitor_a", suspicion=0, findings=()):
    return PassResult(name, "ok", suspicion=suspicion, findings=list(findings))


def finding(category, severity, explanation="x", file="a.py", source="monitor_a"):
    return Finding(file, category, severity, explanation, source)


def decide(hits=(), passes=(), threshold=25):
    return v.decide(list(hits), [], list(passes), threshold)


# ----- thresholds -------------------------------------------------------------

def test_clean_run_passes():
    r = decide(passes=[ok("monitor_a", 3), ok("monitor_b", 5), ok("review", None)])
    assert not r.block and r.suspicion == 5


@pytest.mark.parametrize("s,block", [(24, False), (25, True), (90, True)])
def test_max_suspicion_against_threshold(s, block):
    r = decide(passes=[ok("monitor_a", 0), ok("monitor_b", s)])
    assert r.block is block


@pytest.mark.parametrize("category,severity,block", [
    ("malicious", "low", False), ("malicious", "medium", True), ("malicious", "high", True),
    ("obscure", "low", False), ("obscure", "medium", True),
    ("security", "medium", False), ("security", "high", True),
    ("bug", "high", False),
])
def test_finding_rules(category, severity, block):
    r = decide(passes=[ok(findings=[finding(category, severity)])])
    assert r.block is block


def test_any_deterministic_hit_blocks():
    r = decide(hits=[Hit("binary", "x.png", "binary file", True)], passes=[ok()])
    assert r.block
    assert any("binary" in reason for reason in r.reasons)


@pytest.mark.parametrize("reason", ["refusal", "max_tokens", "bad-json", "bad-schema", "no-text"])
def test_incomplete_pass_blocks(reason):
    r = decide(passes=[ok(), PassResult("monitor_b", "incomplete", reason)])
    assert r.block and not r.infra
    assert any("did not complete" in x and reason in x for x in r.reasons)


def test_declined_pass_blocks_even_if_the_fallback_found_nothing():
    p = ok("monitor_a", 0)
    p.declined = True
    r = decide(passes=[p])
    assert r.block
    assert any("declined" in x for x in r.reasons)


def test_infra_failure_is_flagged_separately():
    r = decide(passes=[ok(), PassResult("review", "infra", "api-timeout")])
    assert r.infra == ["review: api-timeout"]


def test_no_passes_and_no_hits_passes():
    # The owner-override and carry-over runs make no model call.
    assert not decide().block


# ----- neutralise ----------------------------------------------------------------

@pytest.mark.parametrize("raw,absent", [
    ("ping @alice now", "@alice"),
    ("see #12", "#12"),
    ("see owner/repo#12", "#12"),
    ("see GH-12", "GH-12"),
    ("[click](https://evil.example/x)", "]("),
    ("go https://evil.example/x", "https://"),
    ("go www.evil.example", "www.evil"),
    ("<img src=x onerror=alert(1)>", "<img"),
    ("```\nbreak out", "```"),
    ("line1\nline2", "\n"),
    ("tick `code`", "`"),
])
def test_neutralise_removes_active_markup(raw, absent):
    assert absent not in v.neutralise(raw)


def test_neutralise_makes_hidden_characters_visible():
    assert v.neutralise("a\u200bb") == "a<U+200B>b".replace("<", "&lt;").replace(">", "&gt;")


def test_neutralise_truncates():
    out = v.neutralise("x" * 5000, limit=100)
    assert len(out) <= 101 and out.endswith("…")


def test_neutralise_keeps_ordinary_text_readable():
    assert v.neutralise("Uses eval() on user input in parse_args.") == \
        "Uses eval() on user input in parse_args."


# ----- review body ------------------------------------------------------------------

KEY = b"sk-ant-k"
REPO = "o/r"
MAC = "c" * 64


def _body(result, mode="full", key=KEY):
    return v.render_body(result, key=key, repo=REPO, number=7, head=HEAD, own_hash=HASH,
                         threshold=25, model="claude-opus-5-5", effort="high", mode=mode)


def test_body_starts_with_a_verifiable_marker():
    body = _body(decide(passes=[ok()]))
    assert v.verify_marker(body, KEY, repo=REPO, number=7) == ("pass", HEAD, HASH)


def test_block_marker():
    body = _body(decide(passes=[ok(suspicion=99)]))
    assert v.verify_marker(body, KEY, repo=REPO, number=7) == ("block", HEAD, HASH)


def test_repo_in_the_mac_is_case_insensitive_like_github():
    body = _body(decide())
    assert v.verify_marker(body, KEY, repo="O/R", number=7) == ("pass", HEAD, HASH)


def test_marker_does_not_verify_under_another_key_or_pr():
    body = _body(decide())
    assert v.verify_marker(body, b"other", repo=REPO, number=7) is None
    assert v.verify_marker(body, KEY, repo=REPO, number=8) is None
    assert v.verify_marker(body, KEY, repo="o/other", number=7) is None
    assert v.verify_marker(body, b"", repo=REPO, number=7) is None


def test_without_a_key_the_marker_is_unsigned_and_never_verifies():
    body = _body(decide(), key=None)
    assert f"mac={v.UNSIGNED}" in body
    assert v.parse_marker(body) is None
    assert v.verify_marker(body, KEY, repo=REPO, number=7) is None


def test_body_never_contains_the_key():
    assert KEY.decode() not in _body(decide(passes=[ok(suspicion=99)]))


@pytest.mark.parametrize("field", ["verdict", "repo", "number", "head", "own_hash"])
def test_every_marker_field_is_in_the_mac(field):
    base = dict(verdict="pass", repo=REPO, number=7, head=HEAD, own_hash=HASH)
    changed = dict(base, **{field: {"verdict": "block", "repo": "o/x", "number": 8,
                                    "head": "e" * 40, "own_hash": "e" * 64}[field]})
    assert v.marker_mac(KEY, **base) != v.marker_mac(KEY, **changed)


@pytest.mark.parametrize("body", [
    "", "hello", f"x <!-- pr-gate:v2 verdict=pass head={HEAD} hash={HASH} mac={MAC} -->",
    f"<!-- pr-gate:v2 verdict=maybe head={HEAD} hash={HASH} mac={MAC} -->",
    f"<!-- pr-gate:v2 verdict=pass head={HEAD[:-1]} hash={HASH} mac={MAC} -->",
    f"<!-- pr-gate:v2 verdict=pass head={HEAD} hash={HASH} mac={MAC[:-1]} -->",
    f"<!-- pr-gate:v1 verdict=pass head={HEAD} hash={HASH} -->",
    None,
])
def test_parse_marker_rejects_anything_else(body):
    assert v.parse_marker(body) is None


def test_body_neutralises_model_text_and_paths():
    f = finding("malicious", "high",
                explanation="@alice see #3 and [x](https://e.example)", file="@bob/#4.py")
    r = decide(hits=[Hit("sensitive-path", ".github/@carol", "changes CI configuration", True)],
               passes=[ok(findings=[f])])
    body = _body(r)
    for bad in ("@alice", "#3", "](", "https://", "@bob", "#4", "@carol"):
        assert bad not in body


def test_body_lists_findings_by_severity_and_omits_analysis():
    p = ok(findings=[finding("bug", "low", "LOW-ONE"), finding("security", "high", "HIGH-ONE")])
    p.analysis = "SECRET-ANALYSIS"
    body = _body(decide(passes=[p]))
    assert body.index("HIGH-ONE") < body.index("LOW-ONE")
    assert "SECRET-ANALYSIS" not in body


def test_block_body_says_how_to_clear_it():
    body = _body(decide(passes=[ok(suspicion=80)]))
    assert "dismisses this review" in body.lower() and "re-run" in body.lower()
    assert "approve" not in body.lower()


def test_body_reports_deterministic_hits_and_suspicion():
    r = decide(hits=[Hit("hidden-unicode", "a.js", "line 3: U+FE01", False)],
               passes=[ok("monitor_a", 7), ok("monitor_b", 30)])
    body = _body(r)
    assert "hidden-unicode" in body and "U+FE01" in body
    assert "30" in body and "25" in body


def test_body_is_bounded():
    many = [finding("bug", "low", "y" * 900) for _ in range(500)]
    body = _body(decide(passes=[ok(findings=many)]))
    assert len(body) <= v.MAX_BODY


def test_override_and_carry_over_modes_are_named():
    assert "dismissed the gate's block" in _body(decide(), mode="owner-override").lower()
    assert "carried over" in _body(decide(), mode="carry-over").lower()


def test_scrutiny_is_listed():
    r = v.decide([], [Scrutiny("flake.nix", "nix")], [ok()], 25)
    assert "flake.nix" in _body(r)
