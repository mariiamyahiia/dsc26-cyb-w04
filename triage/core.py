"""triage: read Semgrep SARIF and Bandit JSON, dedupe, suppress, diff a baseline, gate a build.

Fill in every function. Keep the names and signatures exactly as they are: the grader imports them.
The full rules are in README.md ("What to build").
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
import hashlib
import json
import re

SEVERITIES = ["info", "low", "medium", "high", "critical"]   # lowest to highest

_RANK = {s: i for i, s in enumerate(SEVERITIES)}
_SARIF_LEVELS = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
_BANDIT_SEVERITIES = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_CWE_TAG = re.compile(r"CWE-([0-9]+)")

@dataclass(frozen=True)
class Finding:
    tool: str            # "semgrep" or "bandit"
    rule_id: str
    path: str            # normalised, see normalize_path
    line: int
    severity: str        # one of SEVERITIES
    cwe: int | None
    message: str
    code: str            # the source text of the finding's line, as reported by the tool


@dataclass
class Group:
    key: str             # the issue key shared by its findings
    path: str
    line: int
    severity: str        # the highest severity among its findings
    findings: list[Finding] = field(default_factory=list)

    @property
    def tools(self) -> list[str]:
        """Sorted list of the tool names of the members."""
        return sorted({f.tool for f in self.findings})

    @property
    def fingerprints(self) -> list[str]:
        """Sorted list of the members' fingerprints."""
        return sorted(fingerprint(f) for f in self.findings)


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    reason: str
    expires: date
    by: str


def normalize_path(raw: str, project: str) -> str:
    path = raw.replace("\\", "/")
    if path.startswith("file://"):
        path = path[len("file://"):]
    parts = [p for p in path.split("/") if p not in ("", ".")]
    if project in parts:
        # keep only what comes after the LAST occurrence of the project name
        last = len(parts) - 1 - parts[::-1].index(project)
        parts = parts[last + 1:]
    return "/".join(parts)


def fingerprint(f: Finding) -> str:
    code = " ".join(f.code.split())     # indentation and spacing do not change identity
    key = f"{f.tool}|{f.rule_id}|{f.path}|{code}"
    return hashlib.sha256(key.encode()).hexdigest()


def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _as_list(value) -> list:
    return value if isinstance(value, list) else []


def _read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _to_int(value) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _score_to_severity(value) -> str | None:
    """Map a security-severity score to a severity, or None if it is not a usable number."""
    if isinstance(value, bool):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not 0 < score <= 10:        # also rejects nan and inf
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _sarif_severity(result: dict, rule: dict) -> str:
    mapped = _score_to_severity(_as_dict(rule.get("properties")).get("security-severity"))
    if mapped is not None:
        return mapped
    level = result.get("level")
    if level is None:
        level = _as_dict(rule.get("defaultConfiguration")).get("level")
    if level is None:
        level = "warning"
    return _SARIF_LEVELS.get(str(level).lower(), "medium")


def _cwe_from_tags(rule: dict) -> int | None:
    for tag in _as_list(_as_dict(rule.get("properties")).get("tags")):
        if isinstance(tag, str):
            match = _CWE_TAG.match(tag)
            if match:
                return int(match.group(1))
    return None


def load_semgrep_sarif(path, project: str) -> list[Finding]:
    data = _read_json(path)
    if not isinstance(data, dict):
        raise ValueError("SARIF file must contain a JSON object")
    findings: list[Finding] = []
    for run in _as_list(data.get("runs")):
        run = _as_dict(run)
        driver = _as_dict(_as_dict(run.get("tool")).get("driver"))
        rules = {}
        for rule in _as_list(driver.get("rules")):          # join results to rules within THIS run
            if isinstance(rule, dict) and "id" in rule:
                rules.setdefault(rule["id"], rule)
        for result in _as_list(run.get("results")):
            if not isinstance(result, dict):
                continue
            rule_id = result.get("ruleId") or ""
            rule = rules.get(rule_id, {})
            locations = _as_list(result.get("locations"))
            physical = _as_dict(_as_dict(locations[0] if locations else {}).get("physicalLocation"))
            uri = _as_dict(physical.get("artifactLocation")).get("uri") or ""
            region = _as_dict(physical.get("region"))
            line = region.get("startLine")
            text = _as_dict(region.get("snippet")).get("text")
            lines = text.splitlines() if isinstance(text, str) else []
            findings.append(Finding(
                tool="semgrep",
                rule_id=rule_id,
                path=normalize_path(str(uri), project),
                line=line if type(line) is int else 0,
                severity=_sarif_severity(result, rule),
                cwe=_cwe_from_tags(rule),
                message=_as_dict(result.get("message")).get("text") or "",
                code=lines[0] if lines else "",
            ))
    return findings


def _bandit_severity(severity, confidence) -> str:
    base = _BANDIT_SEVERITIES.get(str(severity).upper(), "info")
    if str(confidence).upper() == "LOW":
        base = SEVERITIES[max(_RANK[base] - 1, 0)]       # one step lower; info stays info
    return base


def _bandit_code_line(block, line_number: int) -> str:
    """Bandit's code block: several lines, each 'NUMBER text'. Take the line whose number EQUALS line_number."""
    if not isinstance(block, str):
        return ""
    for row in block.split("\n"):
        match = re.fullmatch(r"([0-9]{1,18})(?: (.*))?", row.rstrip("\r"))
        if match and int(match.group(1)) == line_number:
            return match.group(2) or ""
    return ""


def load_bandit(path, project: str) -> list[Finding]:
    data = _read_json(path)
    if not isinstance(data, dict):
        raise ValueError("Bandit file must contain a JSON object")
    findings: list[Finding] = []
    for entry in _as_list(data.get("results")):
        if not isinstance(entry, dict):
            continue
        line = entry.get("line_number")
        line = line if type(line) is int else 0
        findings.append(Finding(
            tool="bandit",
            rule_id=str(entry.get("test_id") or ""),
            path=normalize_path(str(entry.get("filename") or ""), project),
            line=line,
            severity=_bandit_severity(entry.get("issue_severity"), entry.get("issue_confidence")),
            cwe=_to_int(_as_dict(entry.get("issue_cwe")).get("id")),
            message=entry.get("issue_text") or "",
            code=_bandit_code_line(entry.get("code"), line),
        ))
    return findings

def issue_key(f: Finding, equivalences: dict[str, str]) -> str:
    raise NotImplementedError


def dedupe(findings: list[Finding], equivalences: dict[str, str] | None = None) -> list[Group]:
    raise NotImplementedError


def load_suppressions(entries: list[dict]) -> tuple[list[Suppression], list[dict]]:
    raise NotImplementedError


def apply_suppressions(groups: list[Group], suppressions: list[Suppression],
                       today: date) -> tuple[list[Group], list[Group]]:
    raise NotImplementedError


def diff_baseline(groups: list[Group], baseline: set[str]) -> tuple[list[Group], list[Group], list[str]]:
    raise NotImplementedError


def gate(new_active: list[Group], fail_on: str) -> bool:
    """True means the build passes."""
    raise NotImplementedError
