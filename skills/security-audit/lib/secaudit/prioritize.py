"""Phase 2: evidence context, confidence model and risk prioritization.

All scores are deterministic functions of recorded facts, and every score
carries the list of factors that produced it so a reader can disagree with
the inputs rather than with an opaque number.
"""
from __future__ import annotations

import re
from pathlib import Path

from .findings import Finding
from .redact import redact

CONTEXT_LINES = 2
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|testdata|fixtures?)/|(^|/)(test_[^/]*\.py|[^/]*_test\.(py|go)|"
                       r"[^/]*\.(test|spec)\.[jt]sx?|conftest\.py)$")
TOOL_BASE = {"high": 0.8, "medium": 0.55, "low": 0.3}
SEV_WEIGHT = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 2.0, "info": 0.5}
VALIDATION_FACTOR = {"confirmed": 1.2, "probable": 1.0, "unverified": 0.8, "informational": 0.3, "false_positive": 0.0}


def is_test_path(path: str) -> bool:
    return bool(TEST_PATH.search(path))


def _context(target: Path, path: str, start: int | None, end: int | None) -> list[dict] | None:
    if not start:
        return None
    try:
        p = (target / path).resolve(strict=True)
        p.relative_to(target)
        with open(p, "rb") as f:
            lines = f.read(1024 * 1024).decode(errors="replace").splitlines()
    except (OSError, ValueError):
        return None
    lo = max(1, start - CONTEXT_LINES)
    hi = min(len(lines), (end or start) + CONTEXT_LINES, lo + 12)
    return [{"line": i, "text": redact(lines[i - 1][:240])} for i in range(lo, hi + 1)]


def confidence(f: Finding) -> tuple[float, list[str]]:
    factors = []
    if f.validation == "false_positive":
        return 0.0, ["triage: false positive"]
    if f.validation == "confirmed":
        return 1.0, ["triage: confirmed with reproduction/evidence"]
    reported = f.tool_confidence or f.confidence
    score = TOOL_BASE.get(reported, 0.5)
    factors.append(f"base {score:.2f} from tool-reported confidence '{reported}'")
    independent = {t for t in f.tools if t != "agent-review"}
    if len(independent) > 1:
        bump = min(0.15 * (len(independent) - 1), 0.3)
        score += bump
        factors.append(f"+{bump:.2f}: {len(independent)} independent tools agree")
    if f.kind == "dependency":
        factors.append("advisory match is exact; exploitability (reachability) not assessed")
    if f.in_test_code:
        score -= 0.2
        factors.append("-0.20: located in test code")
    if f.validation == "probable":
        score = max(score, 0.75)
        factors.append("triage: probable (floor 0.75)")
    elif f.validation == "informational":
        score = min(score, 0.5)
        factors.append("triage: informational (cap 0.5)")
    return round(min(max(score, 0.05), 0.99), 2), factors


def risk(f: Finding, route_files: set[str], entry_points: set[str]) -> tuple[float, str, list[str]]:
    factors = [f"severity {f.severity} (weight {SEV_WEIGHT[f.severity]})"]
    w = SEV_WEIGHT[f.severity]
    path = f.locations[0].path if f.locations else ""
    exposure = 1.0
    if f.in_test_code:
        exposure = 0.3
        factors.append("exposure x0.3: test code")
    elif f.kind == "dependency":
        direct = (f.package or {}).get("direct")
        exposure = 1.1 if direct else 0.9 if direct is False else 1.0
        factors.append(f"exposure x{exposure}: {'direct' if direct else 'transitive' if direct is False else 'unknown'} dependency")
    elif f.kind == "dynamic":
        exposure = 1.2
        factors.append("exposure x1.2: observed on a running target")
    elif path in route_files:
        exposure = 1.3
        factors.append("exposure x1.3: file defines HTTP routes (externally reachable)")
    elif path in entry_points:
        exposure = 1.15
        factors.append("exposure x1.15: application entry point")
    elif f.kind == "config" and (path.startswith(".github/") or "Dockerfile" in path or "compose" in path):
        exposure = 1.1
        factors.append("exposure x1.1: build/deploy configuration")
    vf = VALIDATION_FACTOR[f.validation]
    factors.append(f"validation x{vf} ({f.validation})")
    conf = f.confidence_score if f.confidence_score is not None else 0.5
    factors.append(f"confidence x{conf}")
    score = round(min(100.0, w * exposure * vf * conf * 10), 1)
    prio = "P0" if score >= 60 else "P1" if score >= 35 else "P2" if score >= 15 else "P3"
    return score, prio, factors


def enrich(findings: list[Finding], inventory: dict, target: Path) -> list[Finding]:
    route_files = {r["file"] for r in inventory.get("routes", [])}
    entry_points = set(inventory.get("entry_points", []))
    for f in findings:
        loc = f.locations[0] if f.locations else None
        f.in_test_code = bool(loc and is_test_path(loc.path))
        if f.tool_confidence is None:
            f.tool_confidence = f.confidence
        if loc and f.kind in ("code", "config", "contextual") and f.code_context is None:
            f.code_context = _context(target, loc.path, loc.start_line, loc.end_line)
        f.confidence_score, f.confidence_factors = confidence(f)
        f.confidence = "high" if f.confidence_score >= 0.75 else "medium" if f.confidence_score >= 0.45 else "low"
        f.risk_score, f.priority, f.risk_factors = risk(f, route_files, entry_points)
    return findings
