"""Phase 3: isolated remediation, patch gates, red/green regression tests."""
import json
import subprocess

import pytest

from conftest import have
from remediation_helpers import UNITTEST, fix_patch, git, make_repo, scope, sqli_finding, udiff
from secaudit.errors import ScopeError
from secaudit.patchgate import check
from secaudit.pipeline import scan
from secaudit.remediation import FixSession
from secaudit.scope import load_scope

needs = pytest.mark.skipif(not (have("semgrep") and have("bandit")), reason="semgrep and bandit required")


@pytest.fixture
def setup(tmp_path):
    repo = make_repo(tmp_path)
    manifest = scope(tmp_path, modify_source=True, execute_project_code=True)
    store = scan(load_scope(repo, manifest), tmp_path / "runs", only={"semgrep", "bandit"})
    report = json.loads((store.path / "report.json").read_text())
    return {"tmp": tmp_path, "repo": repo, "run": store.path, "report": report, "manifest": manifest}


# ---- patch gate unit tests ---------------------------------------------------

def _p(path, old, new):
    return udiff(path, old, new)


def test_gate_rejects_suppressions_scanner_config_deletions_and_lost_tests():
    assert not check(_p("app.py", "x = 1\n", "x = 1  # nosec\n"), ["."]).ok
    assert not check(_p(".semgrepignore", "", "app.py\n"), ["."]).ok
    deleted = "diff --git a/app.py b/app.py\ndeleted file mode 100644\n--- a/app.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
    assert not check(deleted, ["."]).ok
    lost = _p("tests/test_a.py", "def test_one():\n    pass\n", "x = 1\n")
    assert any("removes tests" in v for v in check(lost, ["."]).violations)
    skipped = _p("tests/test_a.py", "def test_one():\n    pass\n", "@unittest.skip('x')\ndef test_one():\n    pass\n")
    assert any("skips tests" in v for v in check(skipped, ["."]).violations)
    assert not check(_p("../evil.py", "", "x\n"), ["."]).ok
    assert not check(_p("other/app.py", "", "x\n"), ["src"]).ok


def test_gate_flags_approval_for_large_dependency_and_sensitive_changes():
    big = _p("app.py", "", "".join(f"x{i} = {i}\n" for i in range(70)))
    assert any("changed lines" in r for r in check(big, ["."]).approval_reasons)
    assert check(_p("requirements.txt", "flask==0.12\n", "flask==2.3.3\n"), ["."]).approval_reasons
    assert check(_p("app/auth.py", "a\n", "b\n"), ["."]).approval_reasons
    assert check(_p("app.py", "a\n", "b\n"), ["."]).ok and not check(_p("app.py", "a\n", "b\n"), ["."]).approval_reasons


# ---- session tests -------------------------------------------------------------

@needs
def test_full_fix_flow_red_green_and_operator_changes_preserved(setup):
    s = setup
    f = sqli_finding(s["report"])
    fs = FixSession.start(s["run"])
    readme_before = (s["repo"] / "README.md").read_text()
    plan = fs.plan([f["id"]])
    assert plan[0]["regression_test"] and plan[0]["security_verification"]
    patch = s["tmp"] / "fix.diff"
    patch.write_text(fix_patch(fs.fix))
    res = fs.apply_patch(f["id"], patch)
    assert res["status"] == "FIX_APPLIED_UNVERIFIED", res
    rt = fs.test(f["id"], UNITTEST)
    assert rt["red_failed_as_expected"] and rt["green_passed"] and rt["red_green"], rt
    d = fs.diff()
    assert "tests/test_security.py" in d["diff"] and d["operator_tree_unchanged"]
    # The operator's working tree is untouched: vulnerable code and local edits are still there.
    assert "f\"SELECT" in (s["repo"] / "store.py").read_text()
    assert (s["repo"] / "README.md").read_text() == readme_before
    assert (s["repo"] / "scratch.txt").exists()
    assert git(s["repo"], "rev-parse", "HEAD") .strip() == fs.state["head"]
    # Commit is refused without the commit permission.
    with pytest.raises(ScopeError, match="commit"):
        fs.commit("fix sqli")
    fs.cleanup()
    assert not fs.fix.exists()
    assert fs.state["branch"] in git(s["repo"], "branch", "--list", "secaudit/*")


@needs
def test_gate_rejections_roll_back(setup):
    s = setup
    f = sqli_finding(s["report"])
    fs = FixSession.start(s["run"])
    p = s["tmp"] / "p.diff"
    src = (fs.fix / "store.py").read_text()
    p.write_text(udiff("store.py", src, src.replace("fetchall()\n", "fetchall()  # nosec\n")))
    assert fs.apply_patch(f["id"], p)["status"] == "REJECTED"
    p.write_text(fix_patch(fs.fix, with_test=False))
    r = fs.apply_patch(f["id"], p)
    assert r["status"] == "REJECTED" and "regression test" in r["message"]
    assert "f\"SELECT" in (fs.fix / "store.py").read_text(), "rejected change must be rolled back"
    # Direct edits in the worktree go through the same gate.
    (fs.fix / ".gitleaks.toml").write_text("[allowlist]\n")
    assert fs.record(f["id"])["status"] == "REJECTED"
    assert not (fs.fix / ".gitleaks.toml").exists()


@needs
def test_approval_required_for_large_change(setup):
    s = setup
    f = sqli_finding(s["report"])
    fs = FixSession.start(s["run"])
    p = s["tmp"] / "p.diff"
    filler = "".join(f"# line {i}\n" for i in range(80))
    p.write_text(fix_patch(fs.fix) + udiff("notes_extra.py", None, filler))
    assert fs.apply_patch(f["id"], p)["status"] == "APPROVAL_REQUIRED"
    assert fs.apply_patch(f["id"], p, approve=True)["status"] == "FIX_APPLIED_UNVERIFIED"
    assert fs.state["fixes"][f["id"]]["approved"] is True


@needs
def test_session_requires_permissions(tmp_path):
    repo = make_repo(tmp_path)
    store = scan(load_scope(repo, scope(tmp_path)), tmp_path / "runs", only={"bandit"})
    with pytest.raises(ScopeError, match="modify_source"):
        FixSession.start(store.path)


@needs
def test_tests_require_execute_permission(tmp_path):
    repo = make_repo(tmp_path)
    store = scan(load_scope(repo, scope(tmp_path, modify_source=True)), tmp_path / "runs", only={"semgrep", "bandit"})
    f = sqli_finding(json.loads((store.path / "report.json").read_text()))
    fs = FixSession.start(store.path)
    p = tmp_path / "p.diff"
    p.write_text(fix_patch(fs.fix))
    fs.apply_patch(f["id"], p)
    with pytest.raises(ScopeError, match="execute_project_code"):
        fs.test(f["id"], UNITTEST)


@needs
def test_repo_with_code_executing_git_config_is_refused(tmp_path):
    repo = make_repo(tmp_path)
    marker = tmp_path / "pwned"
    git(repo, "config", "core.fsmonitor", f"touch {marker}")
    store = scan(load_scope(repo, scope(tmp_path, modify_source=True)), tmp_path / "runs", only={"bandit"})
    with pytest.raises(ScopeError, match="core.fsmonitor"):
        FixSession.start(store.path)
    assert not marker.exists()


@needs
def test_scope_change_mid_session_is_refused(setup):
    fs = FixSession.start(setup["run"])
    setup["manifest"].write_text(json.dumps({"version": 1, "permissions": {"modify_source": True, "commit": True}}))
    with pytest.raises(ScopeError, match="changed"):
        fs.scope()


@needs
def test_commit_with_permission_stays_local(tmp_path):
    repo = make_repo(tmp_path)
    store = scan(load_scope(repo, scope(tmp_path, modify_source=True, commit=True)), tmp_path / "runs",
                 only={"semgrep", "bandit"})
    f = sqli_finding(json.loads((store.path / "report.json").read_text()))
    fs = FixSession.start(store.path)
    p = tmp_path / "p.diff"
    p.write_text(fix_patch(fs.fix))
    fs.apply_patch(f["id"], p)
    sha = fs.commit("Fix SQL injection in find_user")
    assert git(repo, "rev-parse", fs.state["branch"]).strip() == sha
    assert git(repo, "rev-parse", "main").strip() == fs.state["head"]
    assert git(repo, "remote").strip() == ""
