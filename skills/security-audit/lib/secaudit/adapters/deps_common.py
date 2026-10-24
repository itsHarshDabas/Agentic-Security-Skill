from __future__ import annotations

from ..findings import Evidence, Finding, Location, dep_id, cwe_norm

NPM_SEV = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low",
           "info": "info"}


def dep_finding(tool: str, ecosystem: str, name: str, version: str, ids: list[str], summary: str,
                manifest: str, raw_file: str, severity: str | None, fixed: list[str], cwes=None,
                cvss=None, refs=None, direct: bool | None = None) -> Finding:
    sev = NPM_SEV.get((severity or "").lower())
    fix_txt = f"Upgrade {name} to {', '.join(fixed)} or later compatible patched release." if fixed else \
        f"No fixed version reported for {name}; evaluate replacing the package or mitigating the affected feature."
    return Finding(
        id=dep_id(ecosystem, name, version, ids),
        kind="dependency",
        title=f"Vulnerable dependency {name}@{version} ({(ids or ['?'])[0]})",
        description=summary or "Known vulnerability reported by the advisory database.",
        severity=sev or "medium",
        severity_source="tool" if sev else f"default (no severity provided by {tool})",
        confidence="high",
        category="vulnerable-dependency",
        cwe=cwe_norm(cwes or []),
        locations=[Location(manifest)],
        evidence=[Evidence(tool, (ids or ["?"])[0], (summary or "")[:300], raw_file)],
        tools=[tool],
        cvss=cvss,
        package={"ecosystem": ecosystem, "name": name, "version": version, "advisory_ids": sorted(set(ids)),
                 "fixed_versions": sorted(set(fixed)), "direct": direct},
        remediation=fix_txt,
        references=refs or [],
        validation="unverified",
        validation_rationale=("Known-vulnerable version present. Exploitability depends on whether the "
                              "vulnerable code path is reachable; not assessed automatically."),
    )
