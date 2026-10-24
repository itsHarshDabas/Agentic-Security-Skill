"""Phase 4: verify recorded fixes by re-scanning the fixed tree and comparing evidence.

Statuses (see references/remediation.md) are assigned from recorded evidence
only: the original detector's result on the fixed tree, the red/green
regression test, and new findings in the changed files.
"""
from __future__ import annotations

import datetime as dt
import json
from dataclasses import replace
from pathlib import Path

from . import safe_exec
from .errors import SecauditError
from .evidence import RunStore
from .findings import SEV_RANK, families
from .findings import Finding
from .pipeline import scan
from .remediation import FixSession


def _match_still_present(orig: dict, new: list[dict]) -> dict | None:
    """Same ID, or same file + same detector rule (conservative: any remaining hit counts)."""
    for f in new:
        if f["id"] == orig["id"]:
            return f
    if orig["kind"] == "contextual" or not orig["locations"]:
        return None
    path = orig["locations"][0]["path"]
    rules = {(e["tool"], e["rule_id"]) for e in orig["evidence"] if e["tool"] != "agent-review"}
    fam = set(families(Finding.from_dict(orig)))
    for f in new:
        if not f["locations"] or f["locations"][0]["path"] != path:
            continue
        if rules & {(e["tool"], e["rule_id"]) for e in f["evidence"]} and fam & set(families(Finding.from_dict(f))):
            return f
    return None


def _status(orig, still, rt, detectors, fx) -> tuple[str, list[str]]:
    why = []
    red_green = bool(rt and rt.get("red_green"))
    if rt:
        why.append(f"regression test: red exit {rt['red_exit']}, green exit {rt['green_exit']}"
                   + (" (red/green passed)" if red_green else " (red/green NOT satisfied)"))
    else:
        why.append("regression test not run")
    if fx.get("no_test_reason"):
        why.append(f"accepted without regression test: {fx['no_test_reason']}")
    if detectors:
        why.append(f"{', '.join(detectors)} " + ("still report it" if still else "no longer report it"))
    else:
        why.append("no scanner detects this finding; evidence is the regression test only")
    if rt and rt.get("green_exit") not in (0,):
        return "UNRESOLVED", why + ["regression test fails on the fixed tree"]
    if still:
        if SEV_RANK[still["severity"]] > SEV_RANK[orig["severity"]]:
            return "PARTIALLY_MITIGATED", why + [f"severity reduced {orig['severity']} -> {still['severity']}"]
        if red_green:
            return "PARTIALLY_MITIGATED", why + ["test passes but the detector still matches; inspect manually"]
        return "UNRESOLVED", why
    if red_green:
        return "FIXED_VERIFIED", why
    return "FIX_APPLIED_UNVERIFIED", why


def verify(run_dir: Path, suite_cmd: list[str] | None = None, timeout: int = 900) -> dict:
    fs = FixSession(run_dir)
    scope = fs.scope()
    run = fs.run
    state = json.loads((run / "state.json").read_text())
    original = {f["id"]: f for f in state["findings"]}
    ran = {c["check_id"] for c in state["checks"] if c["status"] in ("COMPLETED", "PARTIAL")} - {"agent-review"}
    prefix = fs.state["target_prefix"]
    fix_target = (fs.fix / prefix) if prefix not in ("", ".") else fs.fix
    fix_scope = replace(scope, target=fix_target.resolve(),
                        roots=tuple((fix_target / r.relative_to(scope.target)).resolve() for r in scope.roots),
                        permissions={**scope.permissions, "write_reports_to_target": False})
    vstore = scan(fix_scope, run / "verification", only=ran or None, baseline=run / "report.json")
    vreport = json.loads((vstore.path / "report.json").read_text())
    new_findings = [f for f in vreport["findings"] if f["validation"] != "false_positive"]

    changed: set[str] = set()
    results = []
    files_by_fix: dict[str, set[str]] = {}
    for fid, fx in sorted(fs.state["fixes"].items(), key=lambda kv: kv[1]["order"]):
        orig = original[fid]
        files_by_fix[fid] = {p[len(prefix) + 1:] if prefix not in ("", ".") and p.startswith(prefix + "/") else p
                             for p in fx["gate"]["files"]}
        changed |= files_by_fix[fid]
        detectors = sorted({t for t in orig["tools"] if t != "agent-review" and t in ran})
        still = _match_still_present(orig, new_findings) if detectors else None
        status, why = _status(orig, still, fx.get("regression_test"), detectors, fx)
        results.append({"finding": fid, "title": orig["title"], "severity": orig["severity"], "status": status,
                        "evidence": why, "still_reported_as": still["id"] if still else None,
                        "regression_test_evidence": (fx.get("regression_test") or {}).get("evidence", []),
                        "patch": fx["patch"]})
    for p in fs.state.get("plan", []):
        if p["finding"] not in fs.state["fixes"]:
            blocked = any(p["finding"] in line and ("rejected" in line or "approval required" in line)
                          for line in fs.state["log"])
            results.append({"finding": p["finding"], "title": p["title"], "severity": p["severity"],
                            "status": "BLOCKED" if blocked else "UNRESOLVED",
                            "evidence": ["fix rejected by a gate or awaiting approval" if blocked else "no fix recorded"],
                            "still_reported_as": None, "regression_test_evidence": [], "patch": None})

    introduced = [f for f in vreport["findings"] if f.get("tracking") == "new"]
    introduced_in_changed = [f for f in introduced if f["locations"] and f["locations"][0]["path"] in changed]
    for r in results:
        mine = [f["id"] for f in introduced_in_changed if f["locations"][0]["path"] in files_by_fix.get(r["finding"], set())]
        r["introduced_findings"] = mine
        if mine:
            r["evidence"].append(f"fix introduced new finding(s) in changed files: {', '.join(mine)}")
            if r["status"] == "FIXED_VERIFIED":
                r["status"] = "FIX_APPLIED_UNVERIFIED"

    suite = None
    if suite_cmd:
        scope.require("execute_project_code", "running the test suite")
        er = safe_exec.run(list(suite_cmd), cwd=fix_target, env=safe_exec.build_env(network=False), timeout=timeout)
        ev = RunStore(run).save_raw("verification-suite.txt", er.stdout + b"\n--- stderr ---\n" + er.stderr,
                                    {"tool": "project-tests", "argv": list(suite_cmd), "exit_code": er.returncode})
        suite = {"argv": list(suite_cmd), "exit_code": er.returncode, "passed": er.returncode == 0,
                 "timed_out": er.timed_out, "evidence": ev}

    attempted = [r for r in results]
    fixed = [r for r in results if r["status"] == "FIXED_VERIFIED"]
    covered = [r for r in results if any("red/green passed" in e or "no longer report" in e for e in r["evidence"])]
    before_active = [f for f in original.values() if f["validation"] != "false_positive"]
    summary = {
        "fixes_attempted": len(attempted),
        "by_status": {s: sum(1 for r in results if r["status"] == s) for s in
                      ("FIXED_VERIFIED", "PARTIALLY_MITIGATED", "FIX_APPLIED_UNVERIFIED", "UNRESOLVED", "BLOCKED")},
        "remediation_success_rate": round(len(fixed) / len(attempted), 3) if attempted else None,
        "verification_coverage": round(len(covered) / len(attempted), 3) if attempted else None,
        "introduced_findings": len(introduced),
        "introduced_in_changed_files": len(introduced_in_changed),
        "regression_rate": round(sum(1 for r in results if r.get("introduced_findings")) / len(attempted), 3)
        if attempted else None,
        "findings_before": len(before_active),
        "findings_after": len(new_findings),
        "by_severity_before": {s: sum(1 for f in before_active if f["severity"] == s) for s in SEV_RANK},
        "by_severity_after": {s: sum(1 for f in new_findings if f["severity"] == s) for s in SEV_RANK},
        "suite_passed": suite["passed"] if suite else None,
        "operator_tree_unchanged": fs.operator_tree_unchanged(),
    }
    verification = {
        "verified_at": dt.datetime.now(dt.timezone.utc).isoformat(), "fix_branch": fs.state["branch"],
        "rescan_run": str(vstore.path), "rescan_checks": {c["check_id"]: c["status"] for c in vreport["checks"]},
        "results": results, "introduced": [{"id": f["id"], "title": f["title"], "severity": f["severity"],
                                            "location": f["locations"][0] if f["locations"] else None}
                                           for f in introduced],
        "suite": suite, "summary": summary,
        "limitations": [
            "A detector that no longer matches is not proof the vulnerability is gone; it may have been rephrased.",
            "A passing regression test covers the tested input, not every attack path.",
            "Only the scanners that completed in the original scan were re-run.",
        ],
    }
    store = RunStore(run)
    store.write_json("verification.json", verification)
    by_id = {r["finding"]: r for r in results}
    for f in state["findings"]:
        if f["id"] in by_id:
            f["remediation_status"] = by_id[f["id"]]["status"]
            f["verification"] = "; ".join(by_id[f["id"]]["evidence"])
    state["verification"] = verification
    store.write_json("state.json", state)
    from .report import render
    render(store)
    return verification


def compare(old_report: Path, new_report: Path) -> dict:
    old = {f["id"]: f for f in json.loads(Path(old_report).read_text())["findings"]}
    new = {f["id"]: f for f in json.loads(Path(new_report).read_text())["findings"]}
    pick = lambda f: {"id": f["id"], "title": f["title"], "severity": f["severity"],
                      "location": (f["locations"] or [{}])[0].get("path")}
    return {"new": [pick(new[i]) for i in new if i not in old],
            "no_longer_reported": [pick(old[i]) for i in old if i not in new],
            "recurring": len(set(old) & set(new))}
