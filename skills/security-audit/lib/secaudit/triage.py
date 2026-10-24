"""Merge the agent's triage decisions and contextual findings into a run.

The agent's judgement is recorded, not trusted blindly: every change needs a
rationale, 'confirmed' needs evidence or a reproduction, and locations must
exist inside the target.
"""
from __future__ import annotations

import hashlib

from .errors import SecauditError
from .findings import CONFIDENCES, SEVERITIES, VALIDATIONS, Evidence, Finding, Location, code_id, cwe_norm
from .paths import is_within

MIN_RATIONALE = 20
DECISION_KEYS = {"id", "validation", "rationale", "severity", "confidence", "root_cause", "impact",
                 "reproduction", "evidence", "remediation"}
CONTEXT_KEYS = {"title", "description", "severity", "confidence", "category", "cwe", "locations", "rationale",
                "evidence", "remediation", "validation", "root_cause", "impact", "reproduction"}


class TriageError(SecauditError):
    pass


def _check_loc(target, loc: dict) -> Location:
    if not isinstance(loc, dict) or not isinstance(loc.get("path"), str):
        raise TriageError("location needs a path")
    p = (target / loc["path"]).resolve(strict=False)
    if not is_within(p, target) or not p.is_file():
        raise TriageError(f"location is not a file inside the target: {loc['path']}")
    line = loc.get("start_line")
    if line is not None and (not isinstance(line, int) or line < 1):
        raise TriageError("start_line must be a positive integer")
    return Location(p.relative_to(target).as_posix(), line, loc.get("end_line"), None)


def apply(findings: list[Finding], triage: dict, target) -> tuple[list[Finding], list[str]]:
    if not isinstance(triage, dict) or set(triage) - {"decisions", "contextual_findings", "reviewer"}:
        raise TriageError("triage must be an object with 'decisions' and/or 'contextual_findings'")
    log = []
    by_id = {f.id: f for f in findings}
    for d in triage.get("decisions", []):
        if set(d) - DECISION_KEYS:
            raise TriageError(f"unknown decision keys: {sorted(set(d) - DECISION_KEYS)}")
        f = by_id.get(d.get("id"))
        if not f:
            raise TriageError(f"unknown finding id: {d.get('id')}")
        v = d.get("validation")
        if v not in VALIDATIONS:
            raise TriageError(f"{f.id}: validation must be one of {VALIDATIONS}")
        rationale = (d.get("rationale") or "").strip()
        if len(rationale) < MIN_RATIONALE:
            raise TriageError(f"{f.id}: rationale of at least {MIN_RATIONALE} characters is required")
        if v == "confirmed" and not (d.get("reproduction") or d.get("evidence")):
            raise TriageError(f"{f.id}: 'confirmed' requires reproduction steps or evidence")
        if d.get("severity") is not None and d["severity"] not in SEVERITIES:
            raise TriageError(f"{f.id}: bad severity")
        if d.get("confidence") is not None and d["confidence"] not in CONFIDENCES:
            raise TriageError(f"{f.id}: bad confidence")
        log.append(f"{f.id}: {f.validation} -> {v}")
        f.validation, f.validation_rationale = v, rationale
        if d.get("severity") and d["severity"] != f.severity:
            log.append(f"{f.id}: severity {f.severity} -> {d['severity']} (triage)")
            f.severity, f.severity_source = d["severity"], "triage"
        for k in ("confidence", "root_cause", "impact", "reproduction", "remediation"):
            if d.get(k):
                setattr(f, k, d[k])
        if d.get("evidence"):
            f.evidence.append(Evidence("agent-review", "triage", str(d["evidence"])[:2000]))
        if v == "false_positive":
            f.remediation_status = "FALSE_POSITIVE"

    for c in triage.get("contextual_findings", []):
        if set(c) - CONTEXT_KEYS:
            raise TriageError(f"unknown contextual finding keys: {sorted(set(c) - CONTEXT_KEYS)}")
        for k in ("title", "description", "severity", "rationale", "locations"):
            if not c.get(k):
                raise TriageError(f"contextual finding missing '{k}'")
        if c["severity"] not in SEVERITIES:
            raise TriageError("contextual finding: bad severity")
        v = c.get("validation", "probable")
        if v not in VALIDATIONS:
            raise TriageError("contextual finding: bad validation")
        if v == "confirmed" and not (c.get("reproduction") or c.get("evidence")):
            raise TriageError("contextual finding: 'confirmed' requires reproduction or evidence")
        locs = [_check_loc(target, x) for x in c["locations"]]
        cwes = cwe_norm(c.get("cwe", []))
        fam = cwes[0] if cwes else c.get("category", "contextual")
        first = locs[0]
        line_text = ""
        if first.start_line:
            try:
                line_text = (target / first.path).read_text(errors="replace").splitlines()[first.start_line - 1]
            except IndexError:
                raise TriageError(f"{first.path}: line {first.start_line} does not exist")
        first.snippet = line_text.strip()[:300] or None
        fid = code_id("ctx:" + fam, first.path, line_text or hashlib.sha256(c["title"].encode()).hexdigest())
        f = Finding(
            id=fid, kind="contextual", title=c["title"], description=c["description"], severity=c["severity"],
            severity_source="agent review", confidence=c.get("confidence", "medium"),
            category=c.get("category", "logic"), cwe=cwes, locations=locs,
            evidence=[Evidence("agent-review", "contextual", str(c.get("evidence") or c["rationale"])[:2000])],
            tools=["agent-review"], validation=v, validation_rationale=c["rationale"],
            remediation=c.get("remediation"), root_cause=c.get("root_cause"), impact=c.get("impact"),
            reproduction=c.get("reproduction"))
        if fid in by_id:
            log.append(f"{fid}: contextual finding already present, updated")
        findings = [x for x in findings if x.id != fid] + [f]
        by_id[fid] = f
        log.append(f"{fid}: contextual finding added ({v})")
    return findings, log
