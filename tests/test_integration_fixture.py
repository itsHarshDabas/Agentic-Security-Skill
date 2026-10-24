"""Real tools against the seeded fixture (skipped when a tool is not installed)."""
import json

import pytest

from conftest import NETWORK, have
from benchmark import score

pytestmark = pytest.mark.skipif(not (have("semgrep") and have("bandit") and have("gitleaks")),
                                reason="semgrep, bandit and gitleaks are required")


def test_stack_identified(bench):
    inv = bench["report"]["inventory"]
    assert {"python", "javascript"} <= set(inv["languages"])
    assert {"flask", "express"} <= set(inv["frameworks"])
    assert {m["path"] for m in inv["manifests"]} >= {"requirements.txt", "web/package.json", "web/package-lock.json"}
    assert inv["docker"] and inv["ci"]
    assert inv["high_risk_files"][0]["file"] == "app.py"


def test_tools_ran_and_raw_output_preserved(bench):
    checks = {c["check_id"]: c for c in bench["report"]["checks"]}
    for t in ("semgrep", "bandit", "gitleaks"):
        assert checks[t]["status"] == "COMPLETED", checks[t]
        assert checks[t]["raw_outputs"]
    manifest = json.loads((bench["store"].path / "evidence" / "manifest.json").read_text())
    assert all(len(m["sha256"]) == 64 for m in manifest)
    assert bench["store"].verify() == []


def test_seeded_vulnerabilities_detected(bench):
    s = score(bench["report"], bench["marks"], bench["target"])
    # Rules were written alongside this fixture, so high recall here is expected and
    # says little about unseen code. The floor guards against regressions.
    assert s["scanner_seed_recall"] >= 0.9, s["scanner_seeds_missed"]
    assert s["config_seed_recall"] >= 0.9, s["config_seeds_missed"]
    assert s["secrets_found"] == s["secrets_injected"]


def test_no_finding_confirmed_without_triage(bench):
    assert {f["validation"] for f in bench["report"]["findings"]} <= {"unverified"}
    assert bench["report"]["summary"]["release_blockers"] == []


def test_read_only_scan_did_not_modify_target(bench):
    assert bench["before"] == bench["after"]


def test_injected_secrets_never_appear_in_outputs(bench):
    token = (bench["target"] / "settings_local.py").read_text().split('"')[1]
    key_line = (bench["target"] / "deploy_key.pem").read_text().splitlines()[1]
    for p in bench["store"].path.rglob("*"):
        if p.is_file():
            data = p.read_text(errors="replace")
            assert token not in data, p
            assert key_line not in data, p


def test_dependency_checks_match_permission(bench):
    checks = {c["check_id"]: c["status"] for c in bench["report"]["checks"]}
    if NETWORK:
        assert checks["pip-audit"] in ("COMPLETED", "PARTIAL")
    else:
        assert checks["pip-audit"] == "SKIPPED_NOT_PERMITTED"
        assert "grant `network`" in (bench["store"].path / "report.md").read_text()


def test_findings_are_prioritized_with_evidence(bench):
    rep = bench["report"]
    code = [f for f in rep["findings"] if f["kind"] == "code"]
    assert all(f["risk_score"] is not None and f["priority"] and f["confidence_factors"] for f in rep["findings"])
    assert all(f["code_context"] for f in code)
    assert "P0" in rep["summary"]["by_priority"] or "P1" in rep["summary"]["by_priority"]
    md = (bench["store"].path / "report.md").read_text()
    assert "## Prioritized remediation queue" in md
