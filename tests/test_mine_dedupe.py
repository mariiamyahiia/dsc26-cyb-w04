import random

from triage.core import Finding, dedupe, issue_key


def F(tool="bandit", rule="B608", path="invoicing/db.py", line=13, sev="medium", cwe=89, code="x"):
    return Finding(tool, rule, path, line, sev, cwe, "m", code)


def test_issue_key_order_of_preference():
    eq = {"bandit:B324": "weak-hash"}
    assert issue_key(F(rule="B324", cwe=327), eq) == "weak-hash"
    assert issue_key(F(rule="B608", cwe=89), eq) == "CWE-89"
    assert issue_key(F(rule="B999", cwe=None), eq) == "bandit:B999"
    assert issue_key(F(rule="B999", cwe=None), {}) == "bandit:B999"


def test_same_issue_from_two_tools_is_one_group():
    groups = dedupe([F("semgrep", "diwan.sql", sev="high"), F("bandit", "B608", sev="medium")])
    assert len(groups) == 1
    g = groups[0]
    assert g.tools == ["bandit", "semgrep"] and g.severity == "high" and g.key == "CWE-89"
    assert len(g.fingerprints) == 2 and g.line == 13 and g.path == "invoicing/db.py"


def test_different_problems_on_one_line_stay_apart():
    groups = dedupe([F(rule="B501", cwe=295), F(rule="B113", cwe=400)])
    assert len(groups) == 2


def test_equivalence_table_merges_different_cwes():
    eq = {"semgrep:diwan.unsafe-yaml-load": "unsafe-yaml", "bandit:B506": "unsafe-yaml"}
    groups = dedupe([F("semgrep", "diwan.unsafe-yaml-load", cwe=502), F("bandit", "B506", cwe=20)], eq)
    assert len(groups) == 1 and groups[0].key == "unsafe-yaml"


def test_different_line_or_path_is_not_merged():
    assert len(dedupe([F(line=13), F(tool="semgrep", rule="r", line=14)])) == 2
    assert len(dedupe([F(path="a.py"), F(tool="semgrep", rule="r", path="b.py")])) == 2


def test_order_is_severity_then_path_then_line_then_key():
    findings = [
        F(rule="a", path="b.py", line=1, sev="low", cwe=1),
        F(rule="b", path="a.py", line=9, sev="high", cwe=2),
        F(rule="c", path="a.py", line=2, sev="high", cwe=3),
        F(rule="d", path="a.py", line=2, sev="high", cwe=2),
        F(rule="e", path="a.py", line=1, sev="critical", cwe=4),
    ]
    got = [(g.severity, g.path, g.line, g.key) for g in dedupe(findings)]
    assert got == [("critical", "a.py", 1, "CWE-4"), ("high", "a.py", 2, "CWE-2"),
                   ("high", "a.py", 2, "CWE-3"), ("high", "a.py", 9, "CWE-2"),
                   ("low", "b.py", 1, "CWE-1")]


def test_output_does_not_depend_on_input_order_and_nothing_is_lost():
    findings = [F("semgrep", "s1", sev="high"), F("bandit", "B608"), F("bandit", "B113", cwe=400),
                F(rule="B2", path="x.py", line=3, cwe=None), F("semgrep", "s2", path="x.py", line=3, cwe=None)]
    expected = dedupe(findings)
    rng = random.Random(7)
    for _ in range(20):
        shuffled = findings[:]
        rng.shuffle(shuffled)
        got = dedupe(shuffled)
        assert got == expected
        assert [g.fingerprints for g in got] == [g.fingerprints for g in expected]
    assert sum(len(g.findings) for g in expected) == len(findings)