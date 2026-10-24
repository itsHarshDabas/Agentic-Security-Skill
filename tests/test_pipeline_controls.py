"""Pipeline behaviour with fake tools: honest statuses, permission gating, evidence integrity."""
import json
import os

import pytest

from conftest import make_fake_tool, write_scope
from secaudit.pipeline import scan
from secaudit.scope import load_scope


@pytest.fixture
def project(tmp_path):
    t = tmp_path / "proj"
    t.mkdir()
    (t / "app.py").write_text("import os\nos.system(input())\n")
    (t / "requirements.txt").write_text("flask==0.12.2\n")
    (t / "web").mkdir()
    (t / "web" / "package.json").write_text('{"name":"x","version":"1.0.0"}')
    (t / "web" / "package-lock.json").write_text('{"lockfileVersion":3,"packages":{"":{}}}')
    return t


@pytest.fixture
def only_fakes(tmp_path, monkeypatch):
    """Run with a tool path containing only fake tools (and no PATH fallback)."""
    bindir = tmp_path / "fakebin"
    bindir.mkdir()
    monkeypatch.setenv("SECAUDIT_TOOL_PATH", str(bindir))
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + "/usr/bin:/bin")
    return bindir


def _checks(store):
    return {c["check_id"]: c for c in json.loads((store.path / "report.json").read_text())["checks"]}


def test_network_tools_skipped_without_permission(project, tmp_path, only_fakes):
    for name in ("pip-audit", "npm", "osv-scanner"):
        make_fake_tool(only_fakes, name, "import sys; open('/tmp/secaudit-should-not-run','w'); sys.exit(0)\n")
    store = scan(load_scope(project, None), tmp_path / "runs")
    c = _checks(store)
    for cid in ("pip-audit", "npm-audit", "osv-scanner"):
        assert c[cid]["status"] == "SKIPPED_NOT_PERMITTED", cid
        assert c[cid]["argv"] is None


def test_missing_tools_reported_unavailable(project, tmp_path, only_fakes):
    c = _checks(scan(load_scope(project, None), tmp_path / "runs"))
    assert c["bandit"]["status"] == "UNAVAILABLE"
    assert c["semgrep"]["status"] == "UNAVAILABLE"
    md = (next((tmp_path / "runs").iterdir()) / "report.md").read_text()
    assert "| bandit | UNAVAILABLE |" in md


def test_malformed_output_is_failed_not_clean(project, tmp_path, only_fakes):
    make_fake_tool(only_fakes, "bandit", "print('this is not json')\n")
    c = _checks(scan(load_scope(project, None), tmp_path / "runs", only={"bandit"}))
    assert c["bandit"]["status"] == "FAILED" and c["bandit"]["findings_count"] == 0
    assert "unparseable" in c["bandit"]["reason"]


def test_unexpected_npm_output_is_failed_not_clean(project, tmp_path, only_fakes):
    # Regression: npm printed a config error and exit 0; it must not count as "no vulnerabilities".
    make_fake_tool(only_fakes, "npm", "import sys\nif '--version' in sys.argv: print('10.0.0')\nelse: print('{}')\n")
    m = write_scope(tmp_path / "s.json", network=True)
    c = _checks(scan(load_scope(project, m), tmp_path / "runs", only={"npm-audit"}))
    assert c["npm-audit"]["status"] == "FAILED"


def test_network_denied_is_blocked(project, tmp_path, only_fakes):
    make_fake_tool(only_fakes, "osv-scanner",
                   "import sys\nif '--version' in sys.argv: print('osv-scanner version: 2.7.0'); sys.exit(0)\n"
                   "sys.stderr.write('Post https://api.osv.dev/v1/querybatch: Forbidden'); sys.exit(127)\n")
    m = write_scope(tmp_path / "s.json", network=True)
    c = _checks(scan(load_scope(project, m), tmp_path / "runs", only={"osv-scanner"}))
    assert c["osv-scanner"]["status"] == "BLOCKED"


def test_timeout_reported(project, tmp_path, only_fakes):
    make_fake_tool(only_fakes, "bandit", "import sys,time\nif '--version' in sys.argv: print('1.0'); sys.exit()\ntime.sleep(30)\n")
    c = _checks(scan(load_scope(project, None), tmp_path / "runs", only={"bandit"}, timeout=1))
    assert c["bandit"]["status"] == "TIMED_OUT"


def test_tool_paths_outside_target_are_dropped(project, tmp_path, only_fakes):
    out = {"results": [{"filename": "/etc/passwd", "line_number": 1, "test_id": "B1", "test_name": "x",
                        "issue_severity": "HIGH", "issue_confidence": "HIGH", "issue_text": "t"},
                       {"filename": "./app.py", "line_number": 2, "test_id": "B605", "test_name": "shell",
                        "issue_severity": "HIGH", "issue_confidence": "HIGH", "issue_text": "t",
                        "issue_cwe": {"id": 78}}], "errors": []}
    make_fake_tool(only_fakes, "bandit", f"import sys,json\nprint(json.dumps({out!r}))\nsys.exit(1)\n")
    store = scan(load_scope(project, None), tmp_path / "runs", only={"bandit"})
    findings = json.loads((store.path / "report.json").read_text())["findings"]
    assert [f["locations"][0]["path"] for f in findings] == ["app.py"]
    assert findings[0]["validation"] == "unverified"


def test_evidence_tamper_is_detected(project, tmp_path, only_fakes):
    make_fake_tool(only_fakes, "bandit", "import json\nprint(json.dumps({'results': [], 'errors': []}))\n")
    store = scan(load_scope(project, None), tmp_path / "runs", only={"bandit"})
    (store.path / "evidence" / "bandit.json").write_text('{"results": [], "forged": true}')
    from secaudit.report import render
    render(store)
    report = json.loads((store.path / "report.json").read_text())
    assert report["evidence_integrity"]["mismatched_files"] == ["evidence/bandit.json"]
    assert "WARNING: evidence files changed" in (store.path / "report.md").read_text()


def test_unimplemented_checks_are_listed(project, tmp_path, only_fakes):
    c = _checks(scan(load_scope(project, None), tmp_path / "runs"))
    assert c["dast"]["status"] == "NOT_IMPLEMENTED"
    assert c["agent-review"]["status"] == "PENDING"
