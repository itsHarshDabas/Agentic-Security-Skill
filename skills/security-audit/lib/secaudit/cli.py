"""secaudit command line. Exit codes: 0 ok, 2 usage/scope refusal, 3 engine error."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .adapters import ALL_ADAPTERS
from .adapters.base import Context
from .discovery import discover
from .errors import ScopeError, SecauditError
from .evidence import RunStore
from .pipeline import scan, tool_dirs
from .scope import load_scope
from .triage import TriageError, apply


def _scope(a):
    return load_scope(Path(a.target), Path(a.scope) if a.scope else None, a.allow_scope_in_target)


def cmd_doctor(a):
    ctx = Context(scope=None, inventory={}, store=None, tool_dirs=tool_dirs())
    rows = []
    for cls in ALL_ADAPTERS:
        ad = cls(ctx)
        rows.append({"tool": ad.name, "binary": ad.binary, "path": ad.path,
                     "version": ad.version() if ad.path else None, "requires": list(ad.requires)})
    print(json.dumps({"engine_version": __version__, "tools": rows}, indent=2))
    return 0


def cmd_discover(a):
    print(json.dumps(discover(_scope(a)), indent=2))
    return 0


def cmd_scan(a):
    only = set(a.only.split(",")) if a.only else None
    store = scan(_scope(a), Path(a.out) if a.out else None, only=only, timeout=a.timeout,
                 semgrep_configs=a.semgrep_config or [], baseline=Path(a.baseline) if a.baseline else None)
    summary = json.loads((store.path / "report.json").read_text())["summary"]
    print(json.dumps({"run_dir": str(store.path), "report_md": str(store.path / "report.md"),
                      "report_json": str(store.path / "report.json"), "summary": summary}, indent=2))
    return 0


def cmd_triage(a):
    run = Path(a.run_dir).resolve(strict=True)
    store = RunStore(run)
    state = json.loads((run / "state.json").read_text())
    from .findings import Finding
    from .redact import redact_obj
    from .report import render
    findings = [Finding.from_dict(f) for f in state["findings"]]
    triage = json.loads(Path(a.triage_file).read_text())
    target = Path(state["scope"]["target"])
    findings, log = apply(findings, triage, target)
    from .prioritize import enrich
    findings = enrich(findings, json.loads((run / "inventory.json").read_text()), target)
    state["findings"] = [f.to_dict() for f in findings]
    state["triage_log"] = state.get("triage_log", []) + log
    for c in state["checks"]:
        if c["check_id"] == "agent-review":
            c["status"] = "COMPLETED"
            c["reason"] = f"triage applied by {triage.get('reviewer', 'agent')}"
            c["findings_count"] = sum(1 for f in findings if f.kind == "contextual")
    store.write_json("state.json", redact_obj(state))
    render(store)
    print(json.dumps({"applied": log, "report_md": str(run / "report.md")}, indent=2))
    return 0


def cmd_report(a):
    from .report import render
    render(RunStore(Path(a.run_dir).resolve(strict=True)))
    print(str(Path(a.run_dir) / "report.md"))
    return 0


def cmd_fix(a):
    from .remediation import FixSession
    if a.fix_cmd == "start":
        fs = FixSession.start(Path(a.run_dir))
        out = {"session": str(fs.dir), "fix_worktree": str(fs.fix), "branch": fs.state["branch"],
               "head": fs.state["head"]}
    else:
        fs = FixSession(Path(a.run_dir))
        if a.fix_cmd == "plan":
            out = fs.plan(a.finding)
        elif a.fix_cmd == "apply":
            out = fs.apply_patch(a.finding, Path(a.patch), approve=a.approve, no_test_reason=a.no_test_reason)
        elif a.fix_cmd == "record":
            out = fs.record(a.finding, approve=a.approve, no_test_reason=a.no_test_reason)
        elif a.fix_cmd == "test":
            out = fs.test(a.finding, a.test_cmd, timeout=a.timeout)
        elif a.fix_cmd == "diff":
            out = fs.diff()
        elif a.fix_cmd == "commit":
            out = {"commit": fs.commit(a.message), "branch": fs.state["branch"], "pushed": False}
        elif a.fix_cmd == "cleanup":
            fs.cleanup()
            out = {"removed_worktrees": True, "branch_kept": fs.state["branch"]}
    print(json.dumps(out, indent=2))
    if isinstance(out, dict) and out.get("status") in ("REJECTED", "APPROVAL_REQUIRED"):
        return 4
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="secaudit", description="Evidence-driven, scope-enforced security audit")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def target_args(sp):
        sp.add_argument("target", help="project directory to assess")
        sp.add_argument("--scope", help="scope manifest (JSON) written by the operator; default is read-only, no network")
        sp.add_argument("--allow-scope-in-target", action="store_true",
                        help="accept a scope manifest located inside the target (normally refused)")

    sp = sub.add_parser("doctor", help="show which tools are available")
    sp.set_defaults(fn=cmd_doctor)
    sp = sub.add_parser("discover", help="print the project inventory (read-only)")
    target_args(sp)
    sp.set_defaults(fn=cmd_discover)
    sp = sub.add_parser("scan", help="run discovery, applicable tools and produce reports")
    target_args(sp)
    sp.add_argument("--out", help="base directory for run output (must be outside the target unless permitted)")
    sp.add_argument("--only", help="comma-separated tool names to run")
    sp.add_argument("--timeout", type=int, default=600, help="per-tool timeout in seconds")
    sp.add_argument("--semgrep-config", action="append", help="extra Semgrep rule file/dir (repeatable)")
    sp.add_argument("--baseline", help="previous report.json to compare against")
    sp.set_defaults(fn=cmd_scan)
    sp = sub.add_parser("triage", help="apply validated triage decisions / contextual findings to a run")
    sp.add_argument("run_dir")
    sp.add_argument("triage_file")
    sp.set_defaults(fn=cmd_triage)
    sp = sub.add_parser("report", help="re-render reports for a run")
    sp.add_argument("run_dir")
    sp.set_defaults(fn=cmd_report)

    fp = sub.add_parser("fix", help="Phase 3: controlled remediation in an isolated git worktree")
    fsub = fp.add_subparsers(dest="fix_cmd", required=True)
    x = fsub.add_parser("start", help="create fix/base worktrees (needs modify_source)")
    x.add_argument("run_dir")
    x = fsub.add_parser("plan", help="write a remediation plan for findings")
    x.add_argument("run_dir")
    x.add_argument("--finding", action="append", required=True)
    for name, helptext in (("apply", "apply a unified diff to the fix worktree, then gate and record it"),
                           ("record", "gate and record edits made directly in the fix worktree")):
        x = fsub.add_parser(name, help=helptext)
        x.add_argument("run_dir")
        x.add_argument("--finding", required=True)
        if name == "apply":
            x.add_argument("--patch", required=True)
        x.add_argument("--approve", action="store_true", help="operator approved a change that needs approval")
        x.add_argument("--no-test-reason", help="accept a fix without a regression test (caps status)")
    x = fsub.add_parser("test", help="red/green regression test (needs execute_project_code)")
    x.add_argument("run_dir")
    x.add_argument("--finding", required=True)
    x.add_argument("--timeout", type=int, default=900)
    x.add_argument("test_cmd", nargs=argparse.REMAINDER, help="test command after --, run without a shell")
    x = fsub.add_parser("diff", help="show the full fix diff and gate results")
    x.add_argument("run_dir")
    x = fsub.add_parser("commit", help="commit recorded fixes on the session branch (needs commit); never pushes")
    x.add_argument("run_dir")
    x.add_argument("-m", "--message", required=True)
    x = fsub.add_parser("cleanup", help="remove the session worktrees, keep the branch")
    x.add_argument("run_dir")
    fp.set_defaults(fn=cmd_fix)

    a = p.parse_args(argv)
    if getattr(a, "test_cmd", None) and a.test_cmd[:1] == ["--"]:
        a.test_cmd = a.test_cmd[1:]
    try:
        return a.fn(a)
    except (ScopeError, TriageError) as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    except (SecauditError, OSError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
