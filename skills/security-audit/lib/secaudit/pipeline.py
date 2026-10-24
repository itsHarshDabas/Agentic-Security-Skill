"""Sequential orchestration: scope -> discover -> plan -> run -> normalize -> report."""
from __future__ import annotations

import datetime as dt
import json
import os
import platform
from pathlib import Path

from . import __version__
from .adapters import ALL_ADAPTERS
from .adapters.base import (FAILED, SKIPPED_BY_OPERATOR, SKIPPED_NOT_APPLICABLE, SKIPPED_NOT_PERMITTED,
                            UNAVAILABLE, CheckResult, Context)
from .discovery import discover
from .errors import ScopeError
from .evidence import RunStore
from .findings import Finding, merge
from .prioritize import enrich
from .redact import redact_obj
from .scope import Scope

NOT_IMPLEMENTED = "NOT_IMPLEMENTED"

# Checks the spec calls for that this release does not perform. Listed so the
# report never implies coverage it does not have.
UNIMPLEMENTED_CHECKS = [
    ("container-iac", "Container image and IaC misconfiguration scanning (Trivy)", "config", [],
     "Planned; Dockerfile/Compose/Actions are partially covered by bundled Semgrep rules"),
    ("secrets-history", "Secret scanning across git history", "secrets", [],
     "Planned; running git against an untrusted repository's config needs isolation first"),
    ("fuzzing", "Fuzzing / property-based testing of input handlers", "testing", [], "Planned for Phase 6"),
]


def tool_dirs() -> list[str]:
    env = os.environ.get("SECAUDIT_TOOL_PATH", "")
    return [d for d in env.split(os.pathsep) if d]


def plan_and_run(scope: Scope, store: RunStore, inventory: dict, only: set[str] | None,
                 timeout: int, semgrep_configs: list[str]) -> tuple[list[CheckResult], list[Finding]]:
    ctx = Context(scope=scope, inventory=inventory, store=store, tool_dirs=tool_dirs(), timeout=timeout,
                  semgrep_configs=semgrep_configs)
    checks: list[CheckResult] = []
    findings: list[Finding] = []
    for cls in ALL_ADAPTERS:
        a = cls(ctx)
        res = a.result()
        if only is not None and a.name not in only:
            res.status, res.reason = SKIPPED_BY_OPERATOR, "not selected with --only"
            checks.append(res)
            continue
        ok, why = a.applicable()
        if not ok:
            res.status, res.reason = SKIPPED_NOT_APPLICABLE, why
            checks.append(res)
            continue
        missing = [p for p in a.requires if not scope.allows(p)]
        if missing:
            res.status = SKIPPED_NOT_PERMITTED
            res.reason = f"needs permission(s) {missing}; scope manifest does not grant them"
            checks.append(res)
            continue
        if not a.path:
            res.status, res.reason = UNAVAILABLE, f"'{a.binary}' not found on PATH or SECAUDIT_TOOL_PATH"
            checks.append(res)
            continue
        try:
            res = a.run()
        except ScopeError:
            raise
        except Exception as e:  # adapter bug or tool weirdness: record, keep going
            res.status, res.reason = FAILED, f"adapter error: {type(e).__name__}: {str(e)[:300]}"
        findings.extend(res.findings)
        checks.append(res)
    for cid, objective, cat, perms, reason in UNIMPLEMENTED_CHECKS:
        checks.append(CheckResult(check_id=cid, tool="-", objective=objective, category=cat,
                                  permissions_required=perms, status=NOT_IMPLEMENTED, reason=reason))
    checks.append(CheckResult(
        check_id="dast", tool="secaudit-http", category="dast", permissions_required=["dynamic_testing"],
        objective="Passive dynamic checks against an approved running target", status="PENDING",
        reason="not run by `scan`; run `secaudit dast <run> --url URL` (needs dynamic_testing and targets.urls)"))
    checks.append(CheckResult(
        check_id="agent-review", tool="agent", category="contextual",
        objective="Targeted manual-style review of high-risk code for issues scanners miss (authz, IDOR, logic)",
        permissions_required=[], status="PENDING", reason="recorded via `secaudit triage`; not yet applied"))
    return checks, merge(findings)


def scan(scope: Scope, out_base: Path | None, only: set[str] | None = None, timeout: int = 600,
         semgrep_configs: list[str] | None = None, baseline: Path | None = None) -> RunStore:
    store = RunStore.create(scope, out_base)
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    inventory = discover(scope)
    store.write_json("inventory.json", inventory)
    checks, findings = plan_and_run(scope, store, inventory, only, timeout, semgrep_configs or [])
    findings = enrich(findings, inventory, scope.target)
    resolved = []
    if baseline:
        prev = json.loads(Path(baseline).read_text())
        prev_ids = {f["id"]: f for f in prev.get("findings", [])}
        cur = {f.id for f in findings}
        for f in findings:
            f.tracking = "recurring" if f.id in prev_ids else "new"
        resolved = [{"id": i, "title": f["title"]} for i, f in prev_ids.items()
                    if i not in cur and f.get("kind") != "contextual"]
    meta = {
        "engine": "secaudit", "engine_version": __version__, "started": started,
        "finished": dt.datetime.now(dt.timezone.utc).isoformat(), "host": platform.platform(),
        "python": platform.python_version(), "baseline": str(baseline) if baseline else None,
        "resolved_since_baseline": resolved,
    }
    state = {"meta": meta, "scope": scope.to_dict(), "checks": [c.to_dict() for c in checks],
             "findings": [f.to_dict() for f in findings], "triage_log": []}
    store.write_json("state.json", redact_obj(state))
    from .report import render
    render(store)
    return store
