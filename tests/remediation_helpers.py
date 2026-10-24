"""Shared setup for remediation/verification tests: a git repo copy of fixapp."""
import difflib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXAPP = ROOT / "fixtures" / "fixapp"
UNITTEST = [sys.executable, "-m", "unittest", "discover", "-s", "tests"]
GIT_ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}

FIXED_FIND = '''def find_user(conn, name):
    return conn.execute("SELECT id, name FROM users WHERE name = ?", (name,)).fetchall()
'''
SECURITY_TEST = '''import unittest

import store


class InjectionTest(unittest.TestCase):
    def test_find_user_treats_quotes_as_data(self):
        conn = store.connect()
        store.add_user(conn, "alice", "pw")
        self.assertEqual([], store.find_user(conn, "x' OR '1'='1"))


if __name__ == "__main__":
    unittest.main()
'''


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=GIT_ENV).stdout


def make_repo(tmp: Path) -> Path:
    repo = tmp / "fixapp"
    shutil.copytree(FIXAPP, repo)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "init")
    # Unrelated operator work that must survive remediation untouched.
    (repo / "README.md").write_text((repo / "README.md").read_text() + "\nlocal notes, not committed\n")
    (repo / "scratch.txt").write_text("untracked operator file\n")
    return repo


def scope(tmp: Path, **perms) -> Path:
    p = tmp / "scope.json"
    p.write_text(json.dumps({"version": 1, "permissions": perms}))
    return p


def udiff(path: str, old: str | None, new: str) -> str:
    a = old.splitlines(keepends=True) if old is not None else []
    b = new.splitlines(keepends=True)
    head = [f"diff --git a/{path} b/{path}\n"]
    if old is None:
        head.append("new file mode 100644\n")
    body = difflib.unified_diff(a, b, fromfile="/dev/null" if old is None else f"a/{path}", tofile=f"b/{path}")
    return "".join(head) + "".join(body)


def fix_patch(repo: Path, with_test=True) -> str:
    src = (repo / "store.py").read_text()
    start = src.index("def find_user")
    new = src[:start] + FIXED_FIND
    p = udiff("store.py", src, new)
    if with_test:
        p += udiff("tests/test_security.py", None, SECURITY_TEST)
    return p


def sqli_finding(report: dict) -> dict:
    return next(f for f in report["findings"] if f["locations"][0]["path"] == "store.py" and "CWE-89" in f["cwe"])
