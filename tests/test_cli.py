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
