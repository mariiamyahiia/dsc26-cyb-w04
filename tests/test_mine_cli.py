import json
from pathlib import Path

from triage.__main__ import main
from triage.core import fingerprint, load_semgrep_sarif

FIX = Path(__file__).resolve().parent.parent / "fixtures"
P = "diwan_invoicing"


def make_inputs(tmp_path):
    sarif = {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Semgrep OSS", "rules": [
            {"id": "r1", "properties": {"tags": ["CWE-89: SQL Injection"], "security-severity": "8.8"}}]}},
        "results": [{"ruleId": "r1", "message": {"text": "m"}, "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "invoicing/db.py"},
            "region": {"startLine": 13, "snippet": {"text": "cur.execute(q)\n"}}}}]}],
    }]}
    s, b = tmp_path / "s.sarif", tmp_path / "b.json"
    s.write_text(json.dumps(sarif))
    b.write_text(json.dumps({"results": []}))
    return s, b, fingerprint(load_semgrep_sarif(s, P)[0])


def run(capsys, *args):
    code = main(list(args))
    return code, capsys.readouterr().out


def base_args(s, b):
    return ["--sarif", str(s), "--bandit", str(b), "--project", P]


def test_new_high_finding_fails_the_gate(tmp_path, capsys):
    s, b, _ = make_inputs(tmp_path)
    code, out = run(capsys, *base_args(s, b))
    data = json.loads(out)
    assert code == 1 and data["passed"] is False
    assert set(data) == {"passed", "new", "existing", "suppressed", "fixed", "invalid_suppressions"}
    assert set(data["new"][0]) == {"key", "path", "line", "severity", "tools", "fingerprints"}


def test_fail_on_critical_lets_a_high_finding_pass(tmp_path, capsys):
    s, b, _ = make_inputs(tmp_path)
    code, out = run(capsys, *base_args(s, b), "--fail-on", "critical")
    assert code == 0 and json.loads(out)["passed"] is True


def test_baseline_turns_new_into_existing_and_reports_fixed(tmp_path, capsys):
    s, b, fp = make_inputs(tmp_path)
    base = tmp_path / "base.json"
    base.write_text(json.dumps([fp, "c" * 64]))
    code, out = run(capsys, *base_args(s, b), "--baseline", str(base))
    data = json.loads(out)
    assert code == 0 and data["new"] == [] and len(data["existing"]) == 1 and data["fixed"] == ["c" * 64]


def test_suppression_applies_until_it_expires(tmp_path, capsys):
    s, b, fp = make_inputs(tmp_path)
    sup = tmp_path / "sup.json"
    sup.write_text(json.dumps([
        {"fingerprint": fp, "reason": "a clear and checkable reason", "by": "pod", "expires": "2026-11-20"},
        {"fingerprint": fp, "reason": "short", "by": "pod", "expires": "2026-11-20"},
    ]))
    code, out = run(capsys, *base_args(s, b), "--suppressions", str(sup), "--today", "2026-11-03")
    data = json.loads(out)
    assert code == 0 and len(data["suppressed"]) == 1 and data["invalid_suppressions"] == 1
    code, out = run(capsys, *base_args(s, b), "--suppressions", str(sup), "--today", "2026-12-01")
    assert code == 1 and json.loads(out)["suppressed"] == []


def test_bad_inputs_exit_with_2(tmp_path, capsys):
    s, b, _ = make_inputs(tmp_path)
    assert run(capsys, "--sarif", str(tmp_path / "missing.sarif"), "--bandit", str(b), "--project", P)[0] == 2
    broken = tmp_path / "broken.json"
    broken.write_text("this is not json")
    assert run(capsys, "--sarif", str(s), "--bandit", str(broken), "--project", P)[0] == 2
    assert run(capsys, *base_args(s, b), "--baseline", str(broken))[0] == 2


def test_public_fixture_end_to_end(capsys):
    code, out = run(capsys, "--sarif", str(FIX / "semgrep.sarif"), "--bandit", str(FIX / "bandit.json"),
                    "--project", P, "--equivalences", str(FIX / "equivalences.json"),
                    "--suppressions", str(FIX / "suppressions.json"), "--today", "2026-11-03")
    data = json.loads(out)
    assert code == 1 and data["passed"] is False and data["invalid_suppressions"] == 1
    assert len(data["new"]) + len(data["existing"]) + len(data["suppressed"]) == 11