"""Phase 3: controlled remediation in isolated git worktrees.

Layout of a session (always under the run directory, outside the target):
  <run>/fix-session/session.json   state, audit log
  <run>/fix-session/fix/           worktree on branch secaudit/fix-<run>, where fixes are made
  <run>/fix-session/base/          detached worktree used for red/green regression checks
  <run>/fix-session/patches/       one accepted diff per finding

The operator's working tree is never touched: fixes are made against HEAD in a
separate worktree, and the session checks before/after that the operator's
uncommitted changes are byte-for-byte unchanged. No commits are made unless the
scope grants `commit`; nothing is ever pushed.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shlex
from pathlib import Path

from . import patchgate, safe_exec, safe_git
from .errors import ScopeError, SecauditError
from .evidence import RunStore
from .paths import is_within
from .prioritize import is_test_path
from .scope import Scope, load_scope

SESSION_DIR = "fix-session"
TEST_TIMEOUT = 900


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _dirty_snapshot(repo: Path) -> dict:
    """Porcelain status plus a content hash of every modified/untracked file."""
    status = safe_git.out(repo, ["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    entries = [e for e in status.split("\x00") if e]
    snap = {}
    for e in entries:
        path = e[3:]
        p = repo / path
        h = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() and not p.is_symlink() else None
        snap[path] = [e[:2], h]
    return snap


class FixSession:
    def __init__(self, run_dir: Path):
        self.run = Path(run_dir).resolve(strict=True)
        self.dir = self.run / SESSION_DIR
        self.state_file = self.dir / "session.json"
        if not self.state_file.exists():
            raise SecauditError(f"no fix session in {self.run}; run `fix start` first")
        self.state = json.loads(self.state_file.read_text())
        self.repo = Path(self.state["repo"])
        self.fix = self.dir / "fix"
        self.base = self.dir / "base"

    # -- lifecycle -----------------------------------------------------------
    @classmethod
    def start(cls, run_dir: Path) -> "FixSession":
        run = Path(run_dir).resolve(strict=True)
        rstate = json.loads((run / "state.json").read_text())
        scope = cls._load_scope(rstate["scope"])
        scope.require("modify_source", "starting a fix session")
        repo = safe_git.toplevel(scope.target)
        if is_within(run, repo):
            raise ScopeError("the run directory is inside the repository; use an --out outside the target for remediation")
        safe_git.require_safe(repo)
        d = run / SESSION_DIR
        if d.exists():
            raise SecauditError(f"a fix session already exists at {d}")
        head = safe_git.out(repo, ["rev-parse", "HEAD"]).strip()
        branch = f"secaudit/fix-{run.name}"[:120]
        d.mkdir(mode=0o700)
        (d / "patches").mkdir(mode=0o700)
        snapshot = _dirty_snapshot(repo)
        safe_git.run(repo, ["worktree", "add", "-q", "-b", branch, str(d / "fix"), head])
        safe_git.run(repo, ["worktree", "add", "-q", "--detach", str(d / "base"), head])
        tree = safe_git.out(d / "fix", ["rev-parse", "HEAD^{tree}"]).strip()
        state = {
            "repo": str(repo), "target": rstate["scope"]["target"], "head": head, "branch": branch,
            "scope_source": rstate["scope"]["source"], "scope_sha256": rstate["scope"]["source_sha256"],
            "started": _now(), "operator_dirty_snapshot": snapshot, "checkpoint_tree": tree,
            "target_prefix": Path(rstate["scope"]["target"]).resolve().relative_to(repo).as_posix(),
            "fixes": {}, "log": [f"{_now()} session started at {head[:12]} on {branch}"],
        }
        fs_path = d / "session.json"
        RunStore._write(fs_path, json.dumps(state, indent=2).encode())
        return cls(run)

    @staticmethod
    def _load_scope(scope_dict: dict) -> Scope:
        src = scope_dict.get("source")
        if not scope_dict.get("source_sha256") or not src or not os.path.exists(src):
            raise ScopeError("remediation needs an operator scope manifest granting modify_source")
        target = Path(scope_dict["target"])
        allow_in = is_within(Path(src).resolve(), target)
        scope = load_scope(target, Path(src), allow_in_target=allow_in)
        if scope.source_sha256 != scope_dict["source_sha256"]:
            raise ScopeError("scope manifest changed since the scan; start a new scan")
        return scope

    def scope(self) -> Scope:
        return self._load_scope({"source": self.state["scope_source"], "source_sha256": self.state["scope_sha256"],
                                 "target": self.state["target"]})

    def save(self):
        RunStore._write(self.state_file, json.dumps(self.state, indent=2).encode())

    def log(self, msg: str):
        self.state["log"].append(f"{_now()} {msg}")

    def findings(self) -> dict:
        return {f["id"]: f for f in json.loads((self.run / "state.json").read_text())["findings"]}

    # -- planning ------------------------------------------------------------
    def plan(self, ids: list[str]) -> list[dict]:
        allf = self.findings()
        plan = []
        for fid in ids:
            f = allf.get(fid)
            if not f:
                raise SecauditError(f"unknown finding {fid}")
            loc = f["locations"][0] if f["locations"] else {}
            approval = []
            if f["kind"] == "dependency":
                approval.append("dependency upgrade")
            if f["kind"] in ("contextual",) or f["category"] in ("broken-object-level-authorization",):
                approval.append("authorization/business-logic change")
            if f["validation"] in ("unverified", "informational", "false_positive"):
                approval.append(f"finding is {f['validation']}; triage before fixing")
            plan.append({
                "finding": fid, "title": f["title"], "severity": f["severity"], "validation": f["validation"],
                "flaw": f["description"], "root_cause": f.get("root_cause") or "(fill in during triage)",
                "intended_change": f.get("remediation") or "(describe the minimal change)",
                "affected_components": [l["path"] for l in f["locations"]],
                "regression_test": f"Add a test under the project's test tree that fails on the vulnerable code at {loc.get('path')}:{loc.get('start_line') or ''} and passes after the fix.",
                "security_verification": "Re-run " + ", ".join(t for t in f["tools"] if t != "agent-review") +
                                         " (finding must disappear) and the regression test red/green check."
                if any(t != "agent-review" for t in f["tools"]) else "Regression test red/green check (no scanner detects this finding).",
                "compatibility_risk": "dependency upgrade may break APIs" if f["kind"] == "dependency" else "low if the change is local",
                "approval_required": bool(approval), "approval_reasons": approval,
            })
        self.state["plan"] = plan
        self.log(f"plan created for {ids}")
        self.save()
        return plan

    # -- applying fixes ------------------------------------------------------
    def _allowed_prefixes(self) -> list[str]:
        scope = self.scope()
        return [r.relative_to(self.repo).as_posix() for r in scope.roots]

    def apply_patch(self, fid: str, patch: Path, approve: bool = False, no_test_reason: str | None = None) -> dict:
        text = Path(patch).read_text()
        pre = patchgate.check(text, self._allowed_prefixes())
        if not pre.ok:
            return self._reject(fid, pre, "patch rejected before apply")
        tmp = self.dir / "incoming.patch"
        RunStore._write(tmp, text.encode())
        er = safe_git.run(self.fix, ["apply", "--check", "--whitespace=nowarn", str(tmp)], check=False)
        if er.returncode != 0:
            raise SecauditError(f"patch does not apply: {er.stderr.decode(errors='replace')[-300:]}")
        safe_git.run(self.fix, ["apply", "--whitespace=nowarn", str(tmp)])
        tmp.unlink()
        return self.record(fid, approve=approve, no_test_reason=no_test_reason)

    def record(self, fid: str, approve: bool = False, no_test_reason: str | None = None) -> dict:
        """Gate and record whatever changed in the fix worktree since the last checkpoint."""
        scope = self.scope()
        scope.require("modify_source", "recording a fix")
        if fid not in self.findings():
            raise SecauditError(f"unknown finding {fid}")
        safe_git.run(self.fix, ["add", "-A"])
        tree = safe_git.out(self.fix, ["write-tree"]).strip()
        prev = self.state["checkpoint_tree"]
        diff = safe_git.out(self.fix, ["diff", "--no-color", "--no-ext-diff", "--no-textconv", "-M", prev, tree])
        gate = patchgate.check(diff, self._allowed_prefixes())
        if not gate.ok:
            # roll the worktree back to the last accepted state
            safe_git.run(self.fix, ["read-tree", "--reset", "-u", prev])
            safe_git.run(self.fix, ["clean", "-fdq"])
            return self._reject(fid, gate, "changes rejected and rolled back")
        if gate.approval_reasons and not approve:
            safe_git.run(self.fix, ["read-tree", "--reset", "-u", prev])
            safe_git.run(self.fix, ["clean", "-fdq"])
            self.log(f"{fid}: approval required {gate.approval_reasons}; changes rolled back")
            self.save()
            return {"finding": fid, "status": "APPROVAL_REQUIRED", "gate": gate.to_dict(),
                    "message": "Show the diff to the operator; re-apply with --approve only after they agree."}
        if not gate.test_files and not no_test_reason:
            safe_git.run(self.fix, ["read-tree", "--reset", "-u", prev])
            safe_git.run(self.fix, ["clean", "-fdq"])
            self.log(f"{fid}: no regression test in change; rolled back")
            self.save()
            return {"finding": fid, "status": "REJECTED", "gate": gate.to_dict(),
                    "message": "Include a regression test, or pass --no-test-reason to accept a fix that can be at best FIX_APPLIED_UNVERIFIED."}
        n = len(self.state["fixes"]) + 1
        patch_rel = f"{SESSION_DIR}/patches/{n:02d}-{fid}.diff"
        RunStore._write(self.run / patch_rel, diff.encode())
        self.state["fixes"][fid] = {
            "order": n, "patch": patch_rel, "patch_sha256": hashlib.sha256(diff.encode()).hexdigest(),
            "tree_before": prev, "tree_after": tree, "gate": gate.to_dict(), "approved": approve,
            "approval_reasons": gate.approval_reasons, "no_test_reason": no_test_reason,
            "test_files": gate.test_files, "status": "FIX_APPLIED_UNVERIFIED", "regression_test": None,
            "recorded": _now(),
        }
        self.state["checkpoint_tree"] = tree
        self.log(f"{fid}: fix recorded ({gate.lines_added}+/{gate.lines_removed}-, files {gate.files})")
        self.save()
        return {"finding": fid, "status": "FIX_APPLIED_UNVERIFIED", "patch": str(self.run / patch_rel),
                "gate": gate.to_dict()}

    def _reject(self, fid, gate, msg) -> dict:
        self.log(f"{fid}: {msg}: {gate.violations}")
        self.save()
        return {"finding": fid, "status": "REJECTED", "gate": gate.to_dict(), "message": msg}

    # -- red/green regression test --------------------------------------------
    def test(self, fid: str, cmd: list[str] | str, timeout: int = TEST_TIMEOUT) -> dict:
        scope = self.scope()
        scope.require("execute_project_code", "running the project's tests")
        fx = self.state["fixes"].get(fid)
        if not fx:
            raise SecauditError(f"no recorded fix for {fid}")
        argv = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
        if not argv:
            raise SecauditError("empty test command")
        prefix = self.state["target_prefix"]
        sub = lambda wt: (wt / prefix) if prefix not in ("", ".") else wt
        # Red: tree before this fix + this fix's test files.
        safe_git.run(self.base, ["read-tree", "--reset", "-u", fx["tree_before"]])
        safe_git.run(self.base, ["clean", "-fdq"])
        if fx["test_files"]:
            safe_git.run(self.base, ["checkout", fx["tree_after"], "--", *fx["test_files"]])
        env = safe_exec.build_env(network=False)
        red = safe_exec.run(argv, cwd=sub(self.base), env=env, timeout=timeout)
        # Green: the fix worktree as it stands.
        green = safe_exec.run(argv, cwd=sub(self.fix), env=env, timeout=timeout)
        store = RunStore(self.run)
        rr = store.save_raw(f"regression-{fid}-red.txt", red.stdout + b"\n--- stderr ---\n" + red.stderr,
                            {"tool": "project-tests", "argv": argv, "exit_code": red.returncode, "phase": "red"})
        gr = store.save_raw(f"regression-{fid}-green.txt", green.stdout + b"\n--- stderr ---\n" + green.stderr,
                            {"tool": "project-tests", "argv": argv, "exit_code": green.returncode, "phase": "green"})
        safe_git.run(self.base, ["read-tree", "--reset", "-u", self.state["head"]])
        safe_git.run(self.base, ["clean", "-fdq"])
        result = {
            "argv": argv, "red_exit": red.returncode, "green_exit": green.returncode,
            "red_timed_out": red.timed_out, "green_timed_out": green.timed_out,
            "red_failed_as_expected": red.returncode not in (0, None) and not red.timed_out,
            "green_passed": green.returncode == 0,
            "evidence": [rr, gr], "had_test_files": bool(fx["test_files"]), "ran": _now(),
        }
        result["red_green"] = result["red_failed_as_expected"] and result["green_passed"] and result["had_test_files"]
        fx["regression_test"] = result
        self.log(f"{fid}: regression test red_exit={red.returncode} green_exit={green.returncode} red_green={result['red_green']}")
        self.save()
        return result

    # -- review / commit / cleanup -----------------------------------------
    def diff(self) -> dict:
        d = safe_git.out(self.fix, ["diff", "--no-color", "--no-ext-diff", "--no-textconv", "-M",
                                    self.state["head"], self.state["checkpoint_tree"]])
        stat = safe_git.out(self.fix, ["diff", "--stat", "--no-ext-diff", self.state["head"], self.state["checkpoint_tree"]])
        gate = patchgate.check(d, self._allowed_prefixes()) if d.strip() else None
        return {"diff": d, "stat": stat, "gate": gate.to_dict() if gate else None,
                "operator_tree_unchanged": self.operator_tree_unchanged()}

    def operator_tree_unchanged(self) -> bool:
        return _dirty_snapshot(self.repo) == self.state["operator_dirty_snapshot"]

    def commit(self, message: str) -> str:
        self.scope().require("commit", "committing fixes")
        if not self.state["fixes"]:
            raise SecauditError("nothing to commit")
        safe_git.run(self.fix, ["add", "-A"])
        tree = safe_git.out(self.fix, ["write-tree"]).strip()
        if tree != self.state["checkpoint_tree"]:
            raise SecauditError("fix worktree has unrecorded changes; record or discard them first")
        safe_git.run(self.fix, ["commit", "-q", "--no-verify", "-m", message])
        sha = safe_git.out(self.fix, ["rev-parse", "HEAD"]).strip()
        self.state["commit"] = sha
        self.log(f"committed {sha[:12]} on {self.state['branch']} (not pushed)")
        self.save()
        return sha

    def cleanup(self) -> None:
        for wt in (self.fix, self.base):
            if wt.exists():
                safe_git.run(self.repo, ["worktree", "remove", "--force", str(wt)], check=False)
        safe_git.run(self.repo, ["worktree", "prune"], check=False)
        self.log(f"worktrees removed; branch {self.state['branch']} kept")
        self.save()
