"""Phase 6: checkov IaC adapter, git-history secret scanning, run history."""
import json
import os
import subprocess

import pytest

from conftest import have, write_scope
from secaudit.cli import main
from secaudit.pipeline import scan
from secaudit.scope import load_scope

AWS_KEY = "AKIAZ5QW3ERTYUIOPLKJ"  # synthetic, matches the aws-access-token pattern
TF = '''resource "aws_security_group" "sg" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''


def _git(repo, *args):
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                   check=True, capture_output=True, env=env)


def _checks(store):
    r = json.loads((store.path / "report.json").read_text())
    return r, {c["check_id"]: c for c in r["checks"]}


@pytest.mark.skipif(not have("checkov"), reason="checkov not installed")
def test_checkov_finds_iac_issues_and_ignores_target_config(tmp_path):
    t = tmp_path / "t"
    (t / "infra").mkdir(parents=True)
    (t / "infra" / "main.tf").write_text(TF)
    (t / "Dockerfile").write_text("FROM python:3.12\nCOPY . /app\nCMD [\"python\", \"app.py\"]\n")
    # A target-supplied config that would skip the check and load external checks from the repo.
    (t / ".checkov.yaml").write_text("skip-check:\n  - CKV_AWS_24\nexternal-checks-dir:\n  - evil\n")
    (t / "evil").mkdir()
    (t / "evil" / "__init__.py").write_text("open(__file__ + '.ran', 'w').write('x')\n")
    store = scan(load_scope(t, None), tmp_path / "runs", only={"checkov"})
    r, c = _checks(store)
    assert c["checkov"]["status"] == "COMPLETED", c["checkov"]
    ck = [f for f in r["findings"] if "checkov" in f["tools"]]
    sg = [f for f in ck if f["evidence"][0]["rule_id"] == "CKV_AWS_24"]
    assert sg and sg[0]["severity"] == "high" and sg[0]["locations"][0]["path"] == "infra/main.tf"
    assert sg[0]["severity_source"] == "secaudit-map"
    assert any(f["locations"][0]["path"] == "Dockerfile" for f in ck)
    assert not (t / "evil" / "__init__.py.ran").exists()
    assert ".checkov.yaml" in r["inventory"]["tool_configs_in_target"]


@pytest.mark.skipif(not have("checkov"), reason="checkov not installed")
def test_checkov_reports_inline_suppressions(tmp_path):
    t = tmp_path / "t"
    t.mkdir()
    (t / "main.tf").write_text(TF.replace("ingress {", "ingress {\n    # checkov:skip=CKV_AWS_24: trust me"))
    store = scan(load_scope(t, None), tmp_path / "runs", only={"checkov"})
    r, c = _checks(store)
    sg = [f for f in r["findings"] if f["evidence"][0]["rule_id"] == "CKV_AWS_24"]
    assert sg and "suppresses this check inline" in sg[0]["description"]
    assert any("suppressions" in n for n in c["checkov"]["notes"])


def _repo_with_deleted_secret(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    _git(t, "init", "-q")
    (t / "config.py").write_text(f'AWS_ACCESS_KEY_ID = "{AWS_KEY}"\n')
    _git(t, "add", ".")
    _git(t, "commit", "-qm", "add config")
    (t / "config.py").write_text('import os\nAWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]\n')
    # A target allowlist that would hide everything if gitleaks loaded it.
    (t / ".gitleaks.toml").write_text('[allowlist]\npaths = [".*"]\n')
    _git(t, "add", ".")
    _git(t, "commit", "-qm", "use env")
    return t


@pytest.mark.skipif(not have("gitleaks"), reason="gitleaks not installed")
def test_history_scan_finds_deleted_secret_redacted(tmp_path):
    t = _repo_with_deleted_secret(tmp_path)
    store = scan(load_scope(t, None), tmp_path / "runs", only={"gitleaks", "gitleaks-history"})
    r, c = _checks(store)
    assert c["gitleaks-history"]["status"] == "COMPLETED", c["gitleaks-history"]
    assert c["gitleaks"]["status"] == "COMPLETED"
    hist = [f for f in r["findings"] if f["tools"] == ["gitleaks-history"]]
    assert len(hist) == 1 and hist[0]["locations"][0]["path"] == "config.py"
    assert "remains in history" not in hist[0]["description"]  # file still exists, secret removed from it
    assert "still exists" in hist[0]["description"]
    for p in store.path.rglob("*"):
        if p.is_file():
            assert AWS_KEY not in p.read_text(errors="replace"), p


@pytest.mark.skipif(not have("gitleaks"), reason="gitleaks not installed")
def test_history_scan_blocked_on_risky_repo_config(tmp_path):
    t = _repo_with_deleted_secret(tmp_path)
    marker = tmp_path / "pwned"
    _git(t, "config", "diff.x.textconv", f"touch {marker}")
    store = scan(load_scope(t, None), tmp_path / "runs", only={"gitleaks-history"})
    _, c = _checks(store)
    assert c["gitleaks-history"]["status"] == "BLOCKED" and "diff.x.textconv" in c["gitleaks-history"]["reason"]
    assert not marker.exists()


def test_history_not_applicable_without_git(tmp_path):
    t = tmp_path / "t"
    t.mkdir()
    (t / "a.py").write_text("x = 1\n")
    _, c = _checks(scan(load_scope(t, None), tmp_path / "runs", only={"gitleaks-history"}))
    assert c["gitleaks-history"]["status"] == "SKIPPED_NOT_APPLICABLE"


def _fake_report(run_dir, target, started, findings, status="COMPLETED"):
    run_dir.mkdir(parents=True)
    (run_dir / "report.json").write_text(json.dumps({
        "meta": {"started": started}, "scope": {"target": str(target)},
        "summary": {"by_severity": {}, "release_blockers": []},
        "checks": [{"check_id": "semgrep", "status": status}],
        "findings": [{"id": i, "title": i, "severity": "high", "validation": "unverified"} for i in findings]}))


def test_history_trend_new_resolved_persistent(tmp_path, capsys):
    t = tmp_path / "t"
    t.mkdir()
    runs = tmp_path / "runs"
    _fake_report(runs / "r1", t, "2026-01-01T00:00:00", ["A", "B"])
    _fake_report(runs / "r2", t, "2026-02-01T00:00:00", ["B", "C"], status="FAILED")
    _fake_report(runs / "r3", t, "2026-03-01T00:00:00", ["B", "C", "D"])
    assert main(["history", str(runs)]) == 0
    h = json.loads(capsys.readouterr().out)
    assert [r["run"] for r in h["runs"]] == ["r1", "r2", "r3"]
    assert h["runs"][1]["new"] == ["C"] and h["runs"][1]["no_longer_reported"] == ["A"]
    assert h["runs"][1]["checks_not_completed"] == ["semgrep"]
    assert [p["id"] for p in h["persistent_findings"]] == ["B", "C"]
    _fake_report(runs / "other", tmp_path / "x", "2026-03-02T00:00:00", [])
    assert main(["history", str(runs)]) == 3
    assert main(["history", str(runs), "--target", str(t)]) == 0
