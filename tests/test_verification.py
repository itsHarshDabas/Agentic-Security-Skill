"""Phase 4: verification statuses, before/after, regression detection."""
import json

import pytest

from conftest import have
from remediation_helpers import UNITTEST, SECURITY_TEST, fix_patch, make_repo, scope, sqli_finding, udiff
from secaudit.pipeline import scan
from secaudit.remediation import FixSession
from secaudit.scope import load_scope
from secaudit.verification import _status, compare, verify

needs = pytest.mark.skipif(not (have("semgrep") and have("bandit")), reason="semgrep and bandit required")


@pytest.fixture
def session(tmp_path):
    repo = make_repo(tmp_path)
    store = scan(load_scope(repo, scope(tmp_path, modify_source=True, execute_project_code=True)),
                 tmp_path / "runs", only={"semgrep", "bandit"})
    report = json.loads((store.path / "report.json").read_text())
    fs = FixSession.start(store.path)
    return {"tmp": tmp_path, "repo": repo, "run": store.path, "report": report, "fs": fs,
            "finding": sqli_finding(report)}


def _apply(s, text, **kw):
    p = s["tmp"] / "p.diff"
    p.write_text(text)
    return s["fs"].apply_patch(s["finding"]["id"], p, **kw)


@needs
def test_effective_fix_is_fixed_verified_with_before_after(session):
    s = session
    assert _apply(s, fix_patch(s["fs"].fix))["status"] == "FIX_APPLIED_UNVERIFIED"
    s["fs"].test(s["finding"]["id"], UNITTEST)
    v = verify(s["run"], suite_cmd=UNITTEST)
    r = v["results"][0]
    assert r["status"] == "FIXED_VERIFIED", r
    sm = v["summary"]
    assert sm["remediation_success_rate"] == 1.0 and sm["verification_coverage"] == 1.0
    assert sm["regression_rate"] == 0.0 and sm["suite_passed"] is True and sm["operator_tree_unchanged"]
    assert sm["findings_after"] < sm["findings_before"]
    state = json.loads((s["run"] / "state.json").read_text())
    assert next(f for f in state["findings"] if f["id"] == r["finding"])["remediation_status"] == "FIXED_VERIFIED"
    md = (s["run"] / "report.md").read_text()
    assert "**FIXED_VERIFIED**" in md and "Before:" in md and "After (re-scan" in md


@needs
def test_fix_without_test_is_unverified(session):
    s = session
    _apply(s, fix_patch(s["fs"].fix, with_test=False), no_test_reason="covered by manual review")
    assert verify(s["run"])["results"][0]["status"] == "FIX_APPLIED_UNVERIFIED"


@needs
def test_ineffective_fix_is_unresolved(session):
    s = session
    src = (s["fs"].fix / "store.py").read_text()
    cosmetic = src.replace("def find_user(conn, name):", "def find_user(conn, name):  # escaped upstream")
    _apply(s, udiff("store.py", src, cosmetic) + udiff("tests/test_security.py", None, SECURITY_TEST))
    rt = s["fs"].test(s["finding"]["id"], UNITTEST)
    assert not rt["green_passed"]
    assert verify(s["run"])["results"][0]["status"] == "UNRESOLVED"


@needs
def test_regression_introduced_by_fix_is_detected(session):
    s = session
    patch = fix_patch(s["fs"].fix)
    src = (s["fs"].fix / "store.py").read_text()
    fixed = src[:src.index("def find_user")] + (
        'def find_user(conn, name):\n    return conn.execute("SELECT id, name FROM users WHERE name = ?", (name,)).fetchall()\n'
        "\n\ndef backup(path):\n    import os\n    os.system('cp users.db ' + path)\n")
    patch = udiff("store.py", src, fixed) + udiff("tests/test_security.py", None, SECURITY_TEST)
    _apply(s, patch)
    s["fs"].test(s["finding"]["id"], UNITTEST)
    v = verify(s["run"])
    r = v["results"][0]
    assert r["introduced_findings"], v["introduced"]
    assert r["status"] == "FIX_APPLIED_UNVERIFIED"
    assert v["summary"]["regression_rate"] == 1.0
    assert "New findings introduced by the fixes" in (s["run"] / "report.md").read_text()


@needs
def test_blocked_fix_reported(session):
    s = session
    s["fs"].plan([s["finding"]["id"]])
    src = (s["fs"].fix / "store.py").read_text()
    _apply(s, udiff("store.py", src, src.replace("fetchall()\n", "fetchall()  # nosec\n")))
    assert verify(s["run"])["results"][0]["status"] == "BLOCKED"


def test_status_rules_for_contextual_and_partial():
    orig = {"severity": "high"}
    rg = {"red_green": True, "red_exit": 1, "green_exit": 0}
    assert _status(orig, None, rg, [], {})[0] == "FIXED_VERIFIED"
    assert _status(orig, {"severity": "low"}, None, ["semgrep"], {})[0] == "PARTIALLY_MITIGATED"
    assert _status(orig, {"severity": "high"}, rg, ["semgrep"], {})[0] == "PARTIALLY_MITIGATED"
    assert _status(orig, None, None, ["semgrep"], {})[0] == "FIX_APPLIED_UNVERIFIED"


def test_compare_reports(tmp_path):
    mk = lambda ids: {"findings": [{"id": i, "title": i, "severity": "low", "locations": [{"path": "a"}]} for i in ids]}
    (tmp_path / "a.json").write_text(json.dumps(mk(["A", "B"])))
    (tmp_path / "b.json").write_text(json.dumps(mk(["B", "C"])))
    c = compare(tmp_path / "a.json", tmp_path / "b.json")
    assert [x["id"] for x in c["new"]] == ["C"] and [x["id"] for x in c["no_longer_reported"]] == ["A"]
