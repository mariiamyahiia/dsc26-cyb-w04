import hashlib
from datetime import date

import pytest

from triage.core import (Finding, Group, apply_suppressions, dedupe, diff_baseline, fingerprint,
                         gate, load_suppressions)

TODAY = date(2026, 11, 3)


def F(tool="bandit", rule="B608", path="invoicing/db.py", line=13, sev="high", cwe=89, code="cur.execute(x)"):
    return Finding(tool, rule, path, line, sev, cwe, "m", code)


def entry(**kw):
    e = {"fingerprint": "a" * 64, "reason": "a clear and checkable reason", "by": "b03-cyber-pod",
         "expires": "2026-11-20"}
    e.update(kw)
    return e


def test_valid_entry_is_accepted():
    valid, invalid = load_suppressions([entry()])
    assert len(valid) == 1 and invalid == []
    assert valid[0].expires == date(2026, 11, 20) and valid[0].by == "b03-cyber-pod"


@pytest.mark.parametrize("bad", [
    entry(reason="short"),
    entry(reason="           "),
    entry(by=""),
    entry(by="   "),
    entry(fingerprint="A" * 64),
    entry(fingerprint="a" * 63),
    entry(fingerprint="a" * 65),
    entry(fingerprint=None),
    entry(expires="not-a-date"),
    entry(expires="2026-13-45"),
    entry(expires=20261120),
    "not a dict",
])
def test_invalid_entries_are_collected_not_raised(bad):
    valid, invalid = load_suppressions([entry(), bad])
    assert len(valid) == 1 and len(invalid) == 1 and invalid[0] == bad


def test_missing_keys_are_invalid():
    for key in ("fingerprint", "reason", "by", "expires"):
        e = entry()
        del e[key]
        assert load_suppressions([e])[0] == []


def sup_for(f, expires):
    return load_suppressions([entry(fingerprint=fingerprint(f), expires=expires)])[0]


def test_expiry_boundaries():
    f = F()
    groups = dedupe([f])
    for expires, hidden in [("2026-11-02", False), ("2026-11-03", True), ("2026-11-04", True)]:
        active, suppressed = apply_suppressions(groups, sup_for(f, expires), TODAY)
        assert (len(suppressed) == 1) == hidden and (len(active) == 1) != hidden


def test_one_suppressed_member_hides_the_merged_group():
    bandit, semgrep = F("bandit", "B608", sev="medium"), F("semgrep", "diwan.sql", sev="high")
    groups = dedupe([bandit, semgrep])
    assert len(groups) == 1
    active, suppressed = apply_suppressions(groups, sup_for(bandit, "2026-12-01"), TODAY)
    assert active == [] and suppressed == groups


def test_active_and_suppressed_keep_input_order():
    fs = [F(rule="R1", cwe=1, line=1), F(rule="R2", cwe=2, line=2), F(rule="R3", cwe=3, line=3)]
    groups = dedupe(fs)
    sups = sup_for(fs[1], "2026-12-01")
    active, suppressed = apply_suppressions(groups, sups, TODAY)
    assert active == [g for g in groups if g.line != 2] and [g.line for g in suppressed] == [2]


def test_baseline_new_existing_fixed():
    old, brand_new = F(rule="R1", cwe=1, code="old()"), F(rule="R2", cwe=2, code="brand_new()")
    moved_old = F(rule="R1", cwe=1, code="old()", line=99)          # same code, line moved
    groups = dedupe([moved_old, brand_new])
    baseline = {fingerprint(old), "b" * 64, "a" * 64}
    new, existing, fixed = diff_baseline(groups, baseline)
    assert [g.findings[0].code for g in new] == ["brand_new()"]
    assert [g.findings[0].line for g in existing] == [99]
    assert fixed == ["a" * 64, "b" * 64]


def test_empty_baseline_means_everything_is_new():
    groups = dedupe([F()])
    assert diff_baseline(groups, set()) == (groups, [], [])


def G(sev):
    return Group(key="k", path="p", line=1, severity=sev)


@pytest.mark.parametrize("fail_on, severities, passes", [
    ("low", ["low"], False), ("low", ["info"], True),
    ("medium", ["low"], True), ("medium", ["medium"], False),
    ("high", ["medium"], True), ("high", ["low", "high"], False),
    ("critical", ["high"], True), ("critical", ["high", "critical"], False),
    ("high", [], True), ("info", ["info"], False),
])
def test_gate_thresholds(fail_on, severities, passes):
    assert gate([G(s) for s in severities], fail_on) is passes