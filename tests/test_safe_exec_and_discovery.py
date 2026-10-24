import os
import sys
from pathlib import Path

import pytest

from secaudit import safe_exec
from secaudit.discovery import discover
from secaudit.errors import SecauditError
from secaudit.scope import load_scope


def test_rejects_shell_strings_and_nul():
    with pytest.raises(SecauditError):
        safe_exec.run("echo hi; rm -rf /", cwd=Path("."), env={})
    with pytest.raises(SecauditError):
        safe_exec.run(["echo", "a\x00b"], cwd=Path("."), env={})


def test_metacharacters_are_not_interpreted(tmp_path):
    marker = tmp_path / "pwned"
    r = safe_exec.run(["echo", f"x; touch {marker}"], cwd=tmp_path, env=safe_exec.build_env(False))
    assert r.returncode == 0 and not marker.exists()


def test_timeout_kills_process(tmp_path):
    r = safe_exec.run([sys.executable, "-c", "import time; time.sleep(30)"], cwd=tmp_path,
                      env=safe_exec.build_env(False), timeout=1)
    assert r.timed_out and r.returncode is None and r.duration_s < 10


def test_output_cap_flags_truncation(tmp_path):
    r = safe_exec.run([sys.executable, "-c", "print('x' * 100000)"], cwd=tmp_path,
                      env=safe_exec.build_env(False), max_output=1000)
    assert r.stdout_truncated and len(r.stdout) == 1000


def test_environment_is_scrubbed(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_should_not_leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "nope")
    r = safe_exec.run([sys.executable, "-c", "import os; print(sorted(os.environ))"], cwd=tmp_path,
                      env=safe_exec.build_env(False))
    out = r.stdout.decode()
    assert "GITHUB_TOKEN" not in out and "AWS_SECRET_ACCESS_KEY" not in out


def test_no_network_env_points_proxies_nowhere():
    env = safe_exec.build_env(network=False)
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:9"


def test_discovery_does_not_follow_symlinks_out_of_target(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir()
    (secret_dir / "leak.py").write_text("import subprocess\n")
    (target / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n")
    (target / "escape").symlink_to(secret_dir)
    (target / "escape_file.py").symlink_to(secret_dir / "leak.py")
    inv = discover(load_scope(target, None))
    assert inv["files_scanned"] == 1
    assert set(inv["symlinks_escaping_target"]) == {"escape", "escape_file.py"}
    assert "flask" in inv["frameworks"]


def test_discovery_respects_excludes_and_reports_tool_configs(tmp_path):
    target = tmp_path / "repo"
    (target / "node_modules" / "x").mkdir(parents=True)
    (target / "node_modules" / "x" / "a.js").write_text("eval(x)")
    (target / "vendor").mkdir()
    (target / "vendor" / "b.py").write_text("x=1")
    (target / ".gitleaks.toml").write_text("")
    m = tmp_path / "s.json"
    m.write_text('{"exclude": ["vendor"]}')
    inv = discover(load_scope(target, m))
    assert inv["files_scanned"] == 1  # only .gitleaks.toml
    assert inv["tool_configs_in_target"] == [".gitleaks.toml"]
