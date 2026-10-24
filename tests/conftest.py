import json
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "skills" / "security-audit" / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import benchmark  # noqa: E402
from secaudit.pipeline import scan  # noqa: E402
from secaudit.scope import load_scope  # noqa: E402

LOCAL_TOOLS = [str(ROOT / ".tools" / "bin"), str(ROOT / ".venv" / "bin")]
NETWORK = os.environ.get("SECAUDIT_TEST_NETWORK") == "1"


def have(tool):
    return shutil.which(tool, path=os.pathsep.join(LOCAL_TOOLS + [os.environ.get("PATH", "")])) is not None


@pytest.fixture(autouse=True)
def tool_path(monkeypatch):
    existing = os.environ.get("SECAUDIT_TOOL_PATH", "")
    monkeypatch.setenv("SECAUDIT_TOOL_PATH", os.pathsep.join([p for p in [existing] if p] + LOCAL_TOOLS))


def write_scope(path: Path, **perms) -> Path:
    path.write_text(json.dumps({"version": 1, "permissions": perms}))
    return path


def make_fake_tool(bindir: Path, name: str, script: str) -> Path:
    bindir.mkdir(parents=True, exist_ok=True)
    p = bindir / name
    p.write_text(f"#!{sys.executable}\n" + script)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p


@pytest.fixture(scope="session")
def bench(tmp_path_factory):
    """One real scan of the materialized fixture, shared by integration tests."""
    os.environ["SECAUDIT_TOOL_PATH"] = os.pathsep.join(LOCAL_TOOLS)
    work = tmp_path_factory.mktemp("bench")
    target = work / "vulnapp"
    marks = benchmark.materialize(target)
    manifest = write_scope(work / "scope.json", network=NETWORK)
    before = {p: p.read_bytes() for p in target.rglob("*") if p.is_file()}
    store = scan(load_scope(target, manifest), work / "runs")
    after = {p: p.read_bytes() for p in target.rglob("*") if p.is_file()}
    report = json.loads((store.path / "report.json").read_text())
    return {"target": target, "marks": marks, "store": store, "report": report, "work": work,
            "before": before, "after": after}
