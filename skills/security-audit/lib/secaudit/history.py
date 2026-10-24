"""Phase 6: trends across runs of the same target (read-only over existing report.json files)."""
from __future__ import annotations

import json
from pathlib import Path

from .errors import SecauditError


def _load(runs_dir: Path) -> list[dict]:
    reports = []
    for p in sorted(Path(runs_dir).glob("*/report.json")):
        if p.is_symlink() or p.parent.is_symlink():
            continue
        try:
            r = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if "meta" in r and "findings" in r:
            r["_path"] = str(p)
            reports.append(r)
    return reports


def history(runs_dir: Path, target: str | None = None) -> dict:
    reports = _load(runs_dir)
    targets = sorted({r["scope"]["target"] for r in reports})
    if target:
        want = str(Path(target).resolve())
        reports = [r for r in reports if r["scope"]["target"] == want]
    elif len(targets) > 1:
        raise SecauditError(f"runs for several targets found; pass --target (one of {targets})")
    if not reports:
        raise SecauditError(f"no readable report.json files under {runs_dir}")
    reports.sort(key=lambda r: r["meta"]["started"])
    rows, first_seen, prev = [], {}, None
    for r in reports:
        active = {f["id"]: f for f in r["findings"] if f["validation"] != "false_positive"}
        for i in active:
            first_seen.setdefault(i, r["meta"]["started"])
        row = {"run": Path(r["_path"]).parent.name, "started": r["meta"]["started"],
               "findings_active": len(active), "by_severity": r["summary"]["by_severity"],
               "release_blockers": len(r["summary"]["release_blockers"]),
               "checks_not_completed": sorted(c["check_id"] for c in r["checks"]
                                              if c["status"] not in ("COMPLETED", "SKIPPED_NOT_APPLICABLE"))}
        if prev is not None:
            row["new"] = sorted(set(active) - set(prev))
            row["no_longer_reported"] = sorted(set(prev) - set(active))
        rows.append(row)
        prev = active
    last = reports[-1]
    latest = {f["id"]: f for f in last["findings"] if f["validation"] != "false_positive"}
    persistent = sorted(({"id": i, "title": f["title"], "severity": f["severity"], "first_seen": first_seen[i]}
                         for i, f in latest.items() if first_seen[i] != last["meta"]["started"]),
                        key=lambda x: x["first_seen"])
    return {"target": reports[-1]["scope"]["target"], "runs": rows, "persistent_findings": persistent,
            "note": "'no_longer_reported' is not proof of a fix: the check may not have run or its scope changed. "
                    "Compare checks_not_completed between runs."}
