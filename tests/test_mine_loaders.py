import json

import pytest

from triage.core import load_bandit, load_semgrep_sarif

P = "diwan_invoicing"


def write(tmp_path, name, data):
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def sarif_rule(rule_id="r1", score=None, default_level=None, tags=None):
    rule = {"id": rule_id, "properties": {}}
    if score is not None:
        rule["properties"]["security-severity"] = score
    if tags is not None:
        rule["properties"]["tags"] = tags
    if default_level is not None:
        rule["defaultConfiguration"] = {"level": default_level}
    return rule


def sarif_result(rule_id="r1", level=None, uri="invoicing/db.py", line=13, snippet="cur.execute(x)\n"):
    region = {"startLine": line}
    if snippet is not None:
        region["snippet"] = {"text": snippet}
    result = {
        "ruleId": rule_id,
        "message": {"text": "msg"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}],
    }
    if level is not None:
        result["level"] = level
    return result


def load_one(tmp_path, rule, result):
    data = {"version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Semgrep OSS", "rules": [rule]}}, "results": [result]}]}
    return load_semgrep_sarif(write(tmp_path, "s.sarif", data), P)[0]


@pytest.mark.parametrize("score, expected", [
    ("9.0", "critical"), ("9.5", "critical"), (10, "critical"),
    ("7.0", "high"), ("8.8", "high"), (8.8, "high"),
    ("4.0", "medium"), ("3.9", "low"), ("0.1", "low"),
])
def test_security_severity_score_wins_over_level(tmp_path, score, expected):
    f = load_one(tmp_path, sarif_rule(score=score), sarif_result(level="note"))
    assert f.severity == expected


@pytest.mark.parametrize("score", ["0.0", "abc", 11, "11", "", None])
def test_unusable_scores_fall_back_to_the_level(tmp_path, score):
    f = load_one(tmp_path, sarif_rule(score=score), sarif_result(level="error"))
    assert f.severity == "high"


def test_result_level_overrides_the_rule_default(tmp_path):
    f = load_one(tmp_path, sarif_rule(default_level="error"), sarif_result(level="note"))
    assert f.severity == "low"


@pytest.mark.parametrize("default, expected", [("error", "high"), ("warning", "medium"), ("note", "low"), ("none", "info")])
def test_rule_default_level_is_used(tmp_path, default, expected):
    assert load_one(tmp_path, sarif_rule(default_level=default), sarif_result()).severity == expected


def test_no_level_anywhere_means_warning(tmp_path):
    assert load_one(tmp_path, sarif_rule(), sarif_result()).severity == "medium"


def test_cwe_tags(tmp_path):
    assert load_one(tmp_path, sarif_rule(tags=["security"]), sarif_result()).cwe is None
    assert load_one(tmp_path, sarif_rule(), sarif_result()).cwe is None
    tags = ["external", "CWE-78: OS Command Injection", "CWE-89: SQL Injection"]
    assert load_one(tmp_path, sarif_rule(tags=tags), sarif_result()).cwe == 78


def test_two_runs_and_per_run_rule_join(tmp_path):
    def run(score):
        return {"tool": {"driver": {"rules": [sarif_rule(score=score)]}}, "results": [sarif_result()]}
    data = {"runs": [run("9.5"), run("4.0")]}
    found = load_semgrep_sarif(write(tmp_path, "s.sarif", data), P)
    assert [f.severity for f in found] == ["critical", "medium"]


def test_snippet_first_line_and_path_are_normalised(tmp_path):
    uri = "file:///home/runner/work/diwan_invoicing/diwan_invoicing/invoicing/db.py"
    f = load_one(tmp_path, sarif_rule(), sarif_result(uri=uri, snippet="first line\nsecond line"))
    assert f.path == "invoicing/db.py" and f.code == "first line" and f.line == 13 and f.tool == "semgrep"
    assert load_one(tmp_path, sarif_rule(), sarif_result(snippet=None)).code == ""


def bandit_result(**kw):
    r = {"test_id": "B608", "filename": "./invoicing/db.py", "line_number": 13,
         "issue_severity": "MEDIUM", "issue_confidence": "HIGH", "issue_text": "text",
         "issue_cwe": {"id": 89, "link": "x"},
         "code": "12 x = 1\n13     cur.execute(q)\n14 y = 2\n"}
    r.update(kw)
    return r


def load_b(tmp_path, *results):
    return load_bandit(write(tmp_path, "b.json", {"results": list(results)}), P)


@pytest.mark.parametrize("sev, conf, expected", [
    ("HIGH", "HIGH", "high"), ("HIGH", "MEDIUM", "high"), ("HIGH", "LOW", "medium"),
    ("MEDIUM", "HIGH", "medium"), ("MEDIUM", "MEDIUM", "medium"), ("MEDIUM", "LOW", "low"),
    ("LOW", "HIGH", "low"), ("LOW", "MEDIUM", "low"), ("LOW", "LOW", "info"),
    ("UNDEFINED", "HIGH", "info"), ("UNDEFINED", "LOW", "info"),
])
def test_bandit_severity_and_confidence(tmp_path, sev, conf, expected):
    f = load_b(tmp_path, bandit_result(issue_severity=sev, issue_confidence=conf))[0]
    assert f.severity == expected


def test_bandit_missing_cwe_and_fields(tmp_path):
    r = bandit_result()
    del r["issue_cwe"]
    f = load_b(tmp_path, r)[0]
    assert f.cwe is None and f.tool == "bandit" and f.rule_id == "B608" and f.path == "invoicing/db.py"
    assert load_b(tmp_path, bandit_result())[0].cwe == 89


def test_bandit_code_line_is_the_one_that_equals_line_number(tmp_path):
    block = "9 a = 1\n10 b = 2\n100 c = 3\n"
    assert load_b(tmp_path, bandit_result(line_number=9, code=block))[0].code == "a = 1"
    assert load_b(tmp_path, bandit_result(line_number=10, code=block))[0].code == "b = 2"
    assert load_b(tmp_path, bandit_result(line_number=100, code=block))[0].code == "c = 3"


def test_bandit_code_line_edge_cases(tmp_path):
    assert load_b(tmp_path, bandit_result(line_number=10, code="99 x\n100 y\n101 z\n"))[0].code == ""
    assert load_b(tmp_path, bandit_result(line_number=100, code="99 x\n100 y\n101 z\n"))[0].code == "y"
    assert load_b(tmp_path, bandit_result(line_number=5, code="4 a\n5 return x"))[0].code == "return x"
    assert load_b(tmp_path, bandit_result())[0].code.strip() == "cur.execute(q)"
    assert load_b(tmp_path, bandit_result(code=""))[0].code == ""