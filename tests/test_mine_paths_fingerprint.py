import hashlib
import re

import pytest

from triage.core import Finding, fingerprint, normalize_path

P = "diwan_invoicing"


@pytest.mark.parametrize("raw", [
    "invoicing/web.py",
    "./invoicing/web.py",
    ".\\invoicing\\web.py",
    "invoicing//./web.py",
    "diwan_invoicing\\invoicing\\web.py",
    "/home/runner/work/diwan_invoicing/diwan_invoicing/invoicing/web.py",
    "file:///home/runner/work/diwan_invoicing/diwan_invoicing/invoicing/web.py",
    "C:\\Users\\mariam\\diwan_invoicing\\invoicing\\web.py",
])
def test_one_spelling_per_file(raw):
    assert normalize_path(raw, P) == "invoicing/web.py"


def finding(**kw):
    base = dict(tool="bandit", rule_id="B608", path="invoicing/db.py", line=13,
                severity="medium", cwe=89, message="m", code='    cur.execute("..." % x)')
    base.update(kw)
    return Finding(**base)


def test_fingerprint_matches_the_documented_formula():
    expected = hashlib.sha256('bandit|B608|invoicing/db.py|cur.execute("..." % x)'.encode()).hexdigest()
    assert fingerprint(finding()) == expected
    assert re.fullmatch(r"[0-9a-f]{64}", fingerprint(finding()))


def test_fingerprint_survives_line_shifts_and_reindentation():
    base = fingerprint(finding())
    assert fingerprint(finding(line=99)) == base
    assert fingerprint(finding(code='\tcur.execute("..."   %   x)')) == base


def test_fingerprint_changes_with_tool_rule_path_or_code():
    base = fingerprint(finding())
    assert fingerprint(finding(tool="semgrep")) != base
    assert fingerprint(finding(rule_id="B609")) != base
    assert fingerprint(finding(path="invoicing/web.py")) != base
    assert fingerprint(finding(code='cur.execute("..." % y)')) != base