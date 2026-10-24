import json
import subprocess
from pathlib import Path

WRAPPER = Path(__file__).resolve().parent.parent / "skills" / "security-audit" / "scripts" / "secaudit"


def run(*args, cwd=None):
    return subprocess.run([str(WRAPPER), *args], capture_output=True, text=True, cwd=cwd, timeout=300)


def test_doctor_lists_every_adapter():
    r = run("doctor")
    assert r.returncode == 0
    names = {t["tool"] for t in json.loads(r.stdout)["tools"]}
    assert names == {"semgrep", "bandit", "gitleaks", "osv-scanner", "pip-audit", "npm-audit"}


def test_scope_refusal_exit_code(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    (target / "scope.json").write_text('{"permissions": {"network": true}}')
    r = run("scan", str(target), "--scope", str(target / "scope.json"), "--out", str(tmp_path / "out"))
    assert r.returncode == 2 and "refused" in r.stderr
    assert not (tmp_path / "out").exists()


def test_report_inside_target_refused(tmp_path):
    r = run("scan", str(tmp_path), "--out", str(tmp_path / "reports"))
    assert r.returncode == 2 and "read-only" in r.stderr


def test_target_files_cannot_shadow_engine_modules(tmp_path):
    # A malicious repo with a json.py / secaudit package must not be imported by the engine.
    (tmp_path / "json.py").write_text("raise SystemExit('hijacked')\n")
    (tmp_path / "secaudit").mkdir()
    (tmp_path / "secaudit" / "__init__.py").write_text("raise SystemExit('hijacked')\n")
    r = run("discover", str(tmp_path), cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert "hijacked" not in r.stdout + r.stderr


def test_fix_and_verify_via_cli(tmp_path):
    import pytest
    from conftest import have
    if not (have("semgrep") and have("bandit")):
        pytest.skip("semgrep and bandit required")
    from remediation_helpers import UNITTEST, fix_patch, make_repo, scope
    repo = make_repo(tmp_path)
    m = scope(tmp_path, modify_source=True, execute_project_code=True)
    r = run("scan", str(repo), "--scope", str(m), "--out", str(tmp_path / "runs"), "--only", "semgrep,bandit")
    assert r.returncode == 0, r.stderr
    rd = json.loads(r.stdout)["run_dir"]
    fid = next(f["id"] for f in json.loads(Path(rd, "report.json").read_text())["findings"]
               if f["locations"][0]["path"] == "store.py" and "CWE-89" in f["cwe"])
    start = json.loads(run("fix", "start", rd).stdout)
    patch = tmp_path / "fix.diff"
    patch.write_text(fix_patch(Path(start["fix_worktree"])))
    assert run("fix", "apply", rd, "--finding", fid, "--patch", str(patch)).returncode == 0
    t = run("fix", "test", rd, "--finding", fid, "--", *UNITTEST)
    assert json.loads(t.stdout)["red_green"] is True, t.stdout + t.stderr
    v = run("verify", rd, "--", *UNITTEST)
    assert v.returncode == 0, v.stderr
    assert json.loads(v.stdout)["results"][0]["status"] == "FIXED_VERIFIED"
    bad = tmp_path / "bad.diff"
    bad.write_text("diff --git a/store.py b/store.py\n--- a/store.py\n+++ b/store.py\n@@ -1 +1 @@\n-\"\"\"User store. Intentionally vulnerable; see README.md.\"\"\"\n+\"\"\"User store.\"\"\"  # nosec\n")
    assert run("fix", "apply", rd, "--finding", fid, "--patch", str(bad)).returncode == 4
