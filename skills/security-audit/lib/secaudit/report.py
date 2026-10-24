"""Render report.json and report.md from a run's state.json."""
from __future__ import annotations

import json
from collections import Counter

from .evidence import RunStore
from .findings import SEVERITIES
from .redact import redact, redact_obj

SCHEMA_VERSION = "1.0"
DONE = {"COMPLETED"}
LIMITATIONS = [
    "Automated tools cannot find every vulnerability. Absence of a finding is not evidence of absence.",
    "Scanner findings start as 'unverified'. Only findings with a triage rationale are marked confirmed, probable or false positive.",
    "The bundled Semgrep rule pack is small and targets common Python/JS/Docker/CI issues; coverage is far below commercial rule sets.",
    "Dependency results reflect advisory databases at scan time and do not assess whether vulnerable code is reachable.",
    "Business-logic and authorization flaws are only covered by the agent's targeted review, which is non-deterministic and not exhaustive.",
]
NO_DAST = "No dynamic testing was performed for this run; runtime configuration, headers, cookies and CORS were not tested."
PASSIVE_DAST = ("Dynamic checks were passive (GET only: headers, cookies, CORS, debug output) on the listed URLs; "
                "no injection, authentication, authorization or TLS configuration testing was performed.")


def summarize(findings: list[dict], checks: list[dict]) -> dict:
    active = [f for f in findings if f["validation"] != "false_positive"]
    return {
        "findings_total": len(findings),
        "findings_active": len(active),
        "by_severity": {s: sum(1 for f in active if f["severity"] == s) for s in SEVERITIES},
        "by_validation": dict(Counter(f["validation"] for f in findings)),
        "by_kind": dict(Counter(f["kind"] for f in active)),
        "by_priority": dict(sorted(Counter(f.get("priority") or "n/a" for f in active).items())),
        "checks_by_status": dict(Counter(c["status"] for c in checks)),
        "release_blockers": [f["id"] for f in active if f["severity"] in ("critical", "high")
                             and f["validation"] in ("confirmed", "probable")],
    }


def render(store: RunStore) -> None:
    state = json.loads((store.path / "state.json").read_text())
    inventory = json.loads((store.path / "inventory.json").read_text())
    findings, checks = state["findings"], state["checks"]
    summary = summarize(findings, checks)
    tampered = store.verify()
    report = redact_obj({
        "schema_version": SCHEMA_VERSION,
        "meta": state["meta"],
        "scope": state["scope"],
        "summary": summary,
        "inventory": inventory,
        "tools": [{"tool": c["tool"], "version": c["tool_version"]} for c in checks if c.get("tool_version")],
        "checks": checks,
        "coverage_limitations": LIMITATIONS + [PASSIVE_DAST if any(
            c["category"] == "dast" and c["status"] in ("COMPLETED", "PARTIAL") for c in checks) else NO_DAST],
        "findings": findings,
        "triage_log": state.get("triage_log", []),
        "remediation": state.get("verification") or {"status": "not performed",
                                                     "note": "No fix session was verified for this run; no source files were modified."},
        "evidence_integrity": {"manifest": "evidence/manifest.json", "mismatched_files": tampered},
    })
    store.write_json("report.json", report)
    store.write_text("report.md", redact(_markdown(report)))


def _esc(s) -> str:
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")


def _markdown(r: dict) -> str:
    s, inv, sc = r["summary"], r["inventory"], r["scope"]
    L = []
    w = L.append
    w(f"# Security assessment: `{inv['target'].rsplit('/', 1)[-1]}`\n")
    w(f"Run {r['meta']['started']} · engine {r['meta']['engine_version']} · schema {r['schema_version']}\n")
    w("## Executive summary\n")
    bs = s["by_severity"]
    w(f"{s['findings_active']} active finding(s): " + ", ".join(f"{bs[k]} {k}" for k in SEVERITIES) + ".")
    vb = s["by_validation"]
    w(f"Validation: " + ", ".join(f"{v} {k}" for k, v in sorted(vb.items())) + ".")
    if s["release_blockers"]:
        w(f"**Release blockers (high/critical, confirmed or probable):** {', '.join(s['release_blockers'])}")
    else:
        w("No high/critical finding has been confirmed or marked probable yet"
          + (" (triage pending)." if not r["triage_log"] else "."))
    not_done = [c for c in r["checks"] if c["status"] not in DONE]
    w(f"\n{sum(1 for c in r['checks'] if c['status'] in DONE)} check(s) completed; {len(not_done)} skipped, "
      "partial, failed, unavailable or not implemented (listed below). This report covers only the checks "
      "that ran; it is not a statement that the project is secure.\n")
    if r["evidence_integrity"]["mismatched_files"]:
        w(f"**WARNING: evidence files changed after capture:** {r['evidence_integrity']['mismatched_files']}\n")

    w("## Scope and authorization\n")
    w(f"- Target: `{sc['target']}`")
    w(f"- Roots: {', '.join('`'+x+'`' for x in sc['roots'])}")
    w(f"- Excludes: {', '.join(sc['exclude']) or 'none'}")
    w(f"- Permissions: " + ", ".join(f"{k}={'yes' if v else 'no'}" for k, v in sc["permissions"].items()))
    w(f"- Scope source: {sc['source']}" + (f" (sha256 {sc['source_sha256'][:16]}…)" if sc.get("source_sha256") else ""))
    w("- Source code was not modified.\n")

    w("## Project inventory\n")
    w(f"- Files scanned: {inv['files_scanned']}" + (" (truncated at cap)" if inv["truncated"] else ""))
    w(f"- Languages: {', '.join(f'{k} ({v})' for k, v in inv['languages'].items()) or 'none detected'}")
    w(f"- Frameworks: {', '.join(inv['frameworks']) or 'none detected'}")
    w(f"- Manifests: {', '.join(m['path'] for m in inv['manifests']) or 'none'}")
    w(f"- Routes found: {inv['route_count']} · entry points: {', '.join(inv['entry_points']) or 'none'}")
    w(f"- Docker/Compose: {', '.join(inv['docker']) or 'none'} · CI: {', '.join(inv['ci']) or 'none'}")
    w(f"- Tests: {inv['test_count']} file(s)")
    if inv["tool_configs_in_target"]:
        w(f"- **Tool configs in target (could suppress results):** {', '.join(inv['tool_configs_in_target'])}")
    if inv["symlinks_escaping_target"]:
        w(f"- **Symlinks pointing outside target (not followed):** {', '.join(inv['symlinks_escaping_target'])}")
    if inv["high_risk_files"]:
        w("\nHighest-risk files (heuristic):\n")
        for h in inv["high_risk_files"][:10]:
            w(f"- `{h['file']}` score {h['score']}: {', '.join(h['signals'])}")
    w("")

    w("## Checks performed\n")
    w("| Check | Tool | Version | Status | Findings | Duration | Notes |")
    w("|---|---|---|---|---|---|---|")
    for c in r["checks"]:
        if c["status"] in DONE or c["status"] == "PARTIAL":
            w(f"| {_esc(c['check_id'])} | {_esc(c['tool'])} | {_esc(c['tool_version'])} | {c['status']} | "
              f"{c['findings_count']} | {c['duration_s'] or ''}s | {_esc('; '.join(c['notes'][:3]) or c['reason'])} |")
    w("\n## Checks skipped, blocked, failed or not implemented\n")
    w("| Check | Status | Reason |")
    w("|---|---|---|")
    for c in r["checks"]:
        if c["status"] not in DONE and c["status"] != "PARTIAL":
            w(f"| {_esc(c['check_id'])} | {c['status']} | {_esc(c['reason'])} |")
    w("\n## Coverage limitations\n")
    for x in r["coverage_limitations"]:
        w(f"- {x}")
    w("")

    queue = sorted((f for f in r["findings"] if f["validation"] != "false_positive"),
                   key=lambda f: -(f.get("risk_score") or 0))[:15]
    if queue:
        w("## Prioritized remediation queue\n")
        w("Risk score = severity weight x exposure x validation x confidence (factors listed per finding).\n")
        w("| # | Priority | Risk | Finding | Severity | Validation | Location |")
        w("|---|---|---|---|---|---|---|")
        for i, f in enumerate(queue, 1):
            loc = f["locations"][0] if f["locations"] else {}
            w(f"| {i} | {f.get('priority')} | {f.get('risk_score')} | `{f['id']}` {_esc(f['title'][:60])} | "
              f"{f['severity']} | {f['validation']} | `{loc.get('path')}:{loc.get('start_line') or ''}` |")
        w("")

    w("## Findings\n")
    if not r["findings"]:
        w("No findings from the checks that ran.\n")
    for sev in SEVERITIES:
        group = sorted((f for f in r["findings"] if f["severity"] == sev and f["validation"] != "false_positive"),
                       key=lambda f: -(f.get("risk_score") or 0))
        if not group:
            continue
        w(f"### {sev.capitalize()} ({len(group)})\n")
        for f in group:
            _finding(w, f)
    fps = [f for f in r["findings"] if f["validation"] == "false_positive"]
    if fps:
        w(f"### Marked false positive ({len(fps)})\n")
        for f in fps:
            loc = f["locations"][0] if f["locations"] else {}
            w(f"- `{f['id']}` {_esc(f['title'])} at `{loc.get('path')}:{loc.get('start_line') or ''}`: "
              f"{_esc(f['validation_rationale'])}")
        w("")
    res = r["meta"].get("resolved_since_baseline") or []
    if r["meta"].get("baseline"):
        w("## Change since baseline\n")
        w(f"- New: {sum(1 for f in r['findings'] if f.get('tracking') == 'new')}, recurring: "
          f"{sum(1 for f in r['findings'] if f.get('tracking') == 'recurring')}, no longer reported: {len(res)}")
        for x in res[:50]:
            w(f"  - `{x['id']}` {_esc(x['title'])}")
        w("A finding that is no longer reported is not proof it was fixed; verification is Phase 4.\n")

    w("## Remediation and verification\n")
    v = r["remediation"]
    if v.get("results") is None:
        w("Not performed for this run. No fixes were applied, so there is no before/after comparison "
          "and no finding has status FIXED_VERIFIED.\n")
    else:
        sm = v["summary"]
        w(f"Fixes on branch `{v['fix_branch']}` (not pushed). Re-scan: {', '.join(f'{k} {s}' for k, s in v['rescan_checks'].items() if s in ('COMPLETED', 'PARTIAL', 'FAILED', 'BLOCKED', 'TIMED_OUT'))}.\n")
        w("| Finding | Severity | Status | Evidence |")
        w("|---|---|---|---|")
        for x in v["results"]:
            w(f"| `{x['finding']}` {_esc(x['title'][:50])} | {x['severity']} | **{x['status']}** | {_esc('; '.join(x['evidence']))} |")
        w("")
        w(f"- Before: {sm['findings_before']} active findings ({', '.join(f'{n} {k}' for k, n in sm['by_severity_before'].items() if n)})")
        w(f"- After (re-scan of the fixed tree): {sm['findings_after']} ({', '.join(f'{n} {k}' for k, n in sm['by_severity_after'].items() if n) or 'none'})")
        w(f"- Remediation success rate {sm['remediation_success_rate']}, verification coverage {sm['verification_coverage']}, "
          f"regression rate {sm['regression_rate']}")
        if sm["suite_passed"] is not None:
            w(f"- Project test suite on the fixed tree: {'passed' if sm['suite_passed'] else '**FAILED**'}")
        w(f"- Operator's uncommitted changes unchanged: {'yes' if sm['operator_tree_unchanged'] else '**NO**'}")
        if v["introduced"]:
            w(f"\n**New findings introduced by the fixes ({len(v['introduced'])}):**\n")
            for x in v["introduced"]:
                loc = x["location"] or {}
                w(f"- `{x['id']}` {_esc(x['title'])} ({x['severity']}) at `{loc.get('path')}:{loc.get('start_line') or ''}`")
        w("")
        for lim in v["limitations"]:
            w(f"- {lim}")
        w("")
    w("## Residual risk and next actions\n")
    w("- Triage every high/critical `unverified` finding: confirm with code inspection or mark false positive with a rationale.")
    w("- Review the highest-risk files above for authorization and business-logic flaws scanners cannot see.")
    if any(c["status"] == "SKIPPED_NOT_PERMITTED" for c in r["checks"]):
        w("- Dependency checks were skipped for lack of network permission; grant `network` in the scope manifest to run them.")
    if any(c["status"] in ("UNAVAILABLE", "FAILED", "TIMED_OUT") for c in r["checks"]):
        w("- Install or fix the unavailable/failed tools listed above and re-run.")
    w("- Re-run with `--baseline <previous report.json>` after changes to track new, recurring and resolved findings.")
    return "\n".join(L) + "\n"


def _finding(w, f: dict) -> None:
    loc = f["locations"][0] if f["locations"] else {}
    where = f"`{loc.get('path')}`" + (f" line {loc['start_line']}" if loc.get("start_line") else "")
    w(f"#### `{f['id']}` {_esc(f['title'])}\n")
    w(f"- **Severity** {f['severity']}" + (f" ({f['severity_source']})" if f["severity_source"] != "tool" else "")
      + f" · **Confidence** {f['confidence']} · **Validation** {f['validation']}"
      + (f" · **Tracking** {f['tracking']}" if f.get("tracking") else ""))
    w(f"- **Location** {where}" + (f" · **CWE** {', '.join(f['cwe'])}" if f["cwe"] else "")
      + f" · **Category** {_esc(f['category'])}")
    if f.get("package"):
        p = f["package"]
        w(f"- **Package** {p['ecosystem']}:{p['name']}@{p['version']} · advisories {', '.join(p['advisory_ids'][:6])}"
          + (f" · fixed in {', '.join(p['fixed_versions'][:4])}" if p["fixed_versions"] else ""))
    w(f"- **Detected by** {', '.join(f['tools'])}" + (" · **In test code**" if f.get("in_test_code") else ""))
    if f.get("risk_score") is not None:
        w(f"- **Priority** {f['priority']} · **Risk** {f['risk_score']} ({_esc('; '.join(f.get('risk_factors', [])))})")
        w(f"- **Confidence score** {f['confidence_score']} ({_esc('; '.join(f.get('confidence_factors', [])))})")
    if f.get("code_context"):
        w("")
        w("  ```")
        for c in f["code_context"]:
            mark = ">" if loc.get("start_line") and loc["start_line"] <= c["line"] <= (loc.get("end_line") or loc["start_line"]) else " "
            w(f"  {mark}{c['line']:>5} | {c['text'].replace('```', '` ` `')}")
        w("  ```")
        w("")
    elif loc.get("snippet"):
        w(f"- **Code** `{_esc(loc['snippet'][:200])}`")
    w(f"- **Description** {_esc(f['description'][:600])}")
    if f.get("validation_rationale"):
        w(f"- **Validation rationale** {_esc(f['validation_rationale'][:600])}")
    for k, label in (("root_cause", "Root cause"), ("impact", "Impact"), ("reproduction", "Reproduction"),
                     ("remediation", "Recommended remediation")):
        if f.get(k):
            w(f"- **{label}** {_esc(f[k][:600])}")
    w(f"- **Verification** {f.get('verification') or 'not yet performed'}")
    w(f"- **Evidence** " + "; ".join(f"{e['tool']}:{e['rule_id']}" + (f" ({e['raw_file']})" if e.get("raw_file") else "")
                                     for e in f["evidence"][:5]))
    w("")
