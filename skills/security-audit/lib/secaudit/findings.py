"""Common finding schema, stable identifiers and cross-tool merging."""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low")
VALIDATIONS = ("confirmed", "probable", "unverified", "informational", "false_positive")
REMEDIATION_STATUSES = ("FIXED_VERIFIED", "PARTIALLY_MITIGATED", "FIX_APPLIED_UNVERIFIED",
                        "UNRESOLVED", "BLOCKED", "FALSE_POSITIVE")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Tools label the same weakness with neighbouring CWEs; treat these as one family
# when two findings sit on the same line, so one issue is reported once.
CWE_FAMILY = {
    "CWE-327": "crypto", "CWE-328": "crypto", "CWE-916": "crypto", "CWE-759": "crypto",
    "CWE-798": "cred", "CWE-259": "cred", "CWE-321": "cred",
    "CWE-489": "debug", "CWE-94": "debug", "CWE-215": "debug",
    "CWE-502": "deser", "CWE-20": "deser",
    "CWE-78": "cmd", "CWE-77": "cmd",
}


def families(f: "Finding") -> list[str]:
    return [CWE_FAMILY.get(c, c) for c in f.cwe] or [f.category]


@dataclass
class Location:
    path: str
    start_line: int | None = None
    end_line: int | None = None
    snippet: str | None = None


@dataclass
class Evidence:
    tool: str
    rule_id: str
    message: str
    raw_file: str | None = None


@dataclass
class Finding:
    id: str
    kind: str                      # code | dependency | secret | config | contextual
    title: str
    description: str
    severity: str
    confidence: str
    category: str
    cwe: list[str] = field(default_factory=list)
    locations: list[Location] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    severity_source: str = "tool"
    validation: str = "unverified"
    validation_rationale: str | None = None
    cvss: dict | None = None
    package: dict | None = None
    remediation: str | None = None
    references: list[str] = field(default_factory=list)
    root_cause: str | None = None
    impact: str | None = None
    reproduction: str | None = None
    verification: str | None = None
    remediation_status: str | None = None
    tracking: str | None = None    # new | recurring (vs. baseline)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = dict(d)
        d["locations"] = [Location(**x) for x in d.get("locations", [])]
        d["evidence"] = [Evidence(**x) for x in d.get("evidence", [])]
        return cls(**d)


def _h(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]


def normalize_line(text: str | None) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def code_id(family: str, path: str, line_text: str, occurrence: int = 0) -> str:
    return "SA-" + _h(family, path, normalize_line(line_text), str(occurrence))


def secret_id(rule: str, path: str, line_text: str) -> str:
    return "SEC-" + _h(rule, path, hashlib.sha256(normalize_line(line_text).encode()).hexdigest())


def dep_id(ecosystem: str, name: str, version: str, ids: list[str]) -> str:
    cves = sorted(i for i in ids if i.startswith("CVE-"))
    ghsa = sorted(i for i in ids if i.startswith("GHSA-"))
    primary = (cves or ghsa or sorted(ids) or ["?"])[0]
    return "DEP-" + _h(ecosystem.lower(), name.lower(), version, primary)


def cwe_norm(values) -> list[str]:
    out = []
    for v in values or []:
        m = re.search(r"CWE-?(\d+)", str(v), re.I) or re.fullmatch(r"\s*(\d+)\s*", str(v))
        if m:
            c = f"CWE-{int(m.group(1))}"
            if c not in out:
                out.append(c)
    return out


def _merge_into(a: Finding, b: Finding) -> None:
    for t in b.tools:
        if t not in a.tools:
            a.tools.append(t)
    a.evidence.extend(b.evidence)
    for c in b.cwe:
        if c not in a.cwe:
            a.cwe.append(c)
    for r in b.references:
        if r not in a.references:
            a.references.append(r)
    if SEV_RANK[b.severity] < SEV_RANK[a.severity]:
        a.severity, a.severity_source = b.severity, b.severity_source
    # Independent tools agreeing on the same location raises confidence one step.
    if len(a.tools) > 1 and a.confidence == "low":
        a.confidence = "medium"
    elif len(a.tools) > 1 and a.confidence == "medium":
        a.confidence = "high"
    if b.package and a.package:
        ids = set(a.package.get("advisory_ids", [])) | set(b.package.get("advisory_ids", []))
        a.package["advisory_ids"] = sorted(ids)
        fx = set(a.package.get("fixed_versions", [])) | set(b.package.get("fixed_versions", []))
        a.package["fixed_versions"] = sorted(fx)
    a.remediation = a.remediation or b.remediation


def merge(findings: list[Finding]) -> list[Finding]:
    """Merge equivalent findings across tools, keeping every tool's evidence."""
    out: list[Finding] = []
    code_index: dict[tuple, Finding] = {}
    dep_groups: dict[tuple, list[Finding]] = {}
    by_id: dict[str, Finding] = {}
    for f in findings:
        if f.kind == "dependency" and f.package:
            key = (f.package["ecosystem"].lower(), f.package["name"].lower(), f.package["version"])
            ids = set(f.package.get("advisory_ids", []))
            group = dep_groups.setdefault(key, [])
            for g in group:
                if ids & set(g.package.get("advisory_ids", [])):
                    _merge_into(g, f)
                    break
            else:
                group.append(f)
                out.append(f)
            continue
        if f.id in by_id:
            _merge_into(by_id[f.id], f)
            continue
        loc = f.locations[0] if f.locations else None
        merged = False
        if loc and f.kind in ("code", "config"):
            for c in families(f):
                k = (loc.path, loc.start_line, c)
                if k in code_index:
                    _merge_into(code_index[k], f)
                    merged = True
                    break
        if merged:
            continue
        by_id[f.id] = f
        out.append(f)
        if loc and f.kind in ("code", "config"):
            for c in families(f):
                code_index[(loc.path, loc.start_line, c)] = f
    for f in out:
        if f.kind == "dependency" and f.package:
            f.id = dep_id(f.package["ecosystem"], f.package["name"], f.package["version"],
                          f.package.get("advisory_ids", []))
    out.sort(key=lambda f: (SEV_RANK[f.severity], f.kind, f.locations[0].path if f.locations else "", f.id))
    return out
