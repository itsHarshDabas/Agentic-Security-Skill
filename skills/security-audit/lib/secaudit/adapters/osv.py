from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .base import COMPLETED, FAILED, SKIPPED_NOT_APPLICABLE, Adapter
from .deps_common import dep_finding

ECO = {"PyPI": "pypi", "npm": "npm", "Go": "go", "crates.io": "cargo", "RubyGems": "rubygems",
       "Maven": "maven", "Packagist": "packagist"}


def _osv_severity(vuln: dict, groups: list[dict]) -> str | None:
    for g in groups:
        if vuln["id"] in g.get("ids", []) and g.get("max_severity"):
            try:
                s = float(g["max_severity"])
            except ValueError:
                continue
            return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
    ds = (vuln.get("database_specific") or {}).get("severity")
    return ds.lower() if isinstance(ds, str) else None


class OsvScannerAdapter(Adapter):
    name = "osv-scanner"
    binary = "osv-scanner"
    category = "sca"
    objective = "Known-vulnerability lookup for dependency manifests and lockfiles across ecosystems (OSV.dev)"
    requires = ("network",)

    def applicable(self):
        if self.ctx.inventory["manifests"]:
            return True, ""
        return False, "no dependency manifests or lockfiles"

    def run(self):
        res = self.result(tool_version=self.version())
        target = self.ctx.scope.target
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "osv.json"
            argv = [self.path, "scan", "source", "-r", "--format", "json", "--output-file", str(out),
                    "--verbosity", "error"]
            for x in self.ctx.scope.exclude:
                argv += ["--x-exclude", x]
            argv += [str(r) for r in self.ctx.scope.roots]
            er = self.execute(argv, cwd=Path(tmp), network=True)
            raw = out.read_bytes() if out.exists() else b""
            # 0 = clean, 1 = vulnerabilities found, 128 = no packages found
            if not self.finish(res, er, "osv-scanner.json", raw=raw, ok_codes=(0, 1, 128)):
                return res
        if er.returncode == 128:
            res.status, res.reason = SKIPPED_NOT_APPLICABLE, "osv-scanner found no supported packages"
            return res
        try:
            data = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            res.status, res.reason = FAILED, "unparseable JSON output"
            return res
        for src in data.get("results", []):
            manifest = self.rel(src.get("source", {}).get("path", "")) or "?"
            for pkg in src.get("packages", []):
                p = pkg["package"]
                for v in pkg.get("vulnerabilities", []):
                    fixed = sorted({e["fixed"] for a in v.get("affected", []) for r in a.get("ranges", [])
                                    for e in r.get("events", []) if "fixed" in e})
                    res.findings.append(dep_finding(
                        "osv-scanner", ECO.get(p.get("ecosystem"), str(p.get("ecosystem")).lower()), p["name"],
                        p.get("version", "?"), [v["id"]] + v.get("aliases", []), v.get("summary", ""),
                        manifest, self.last_raw, _osv_severity(v, pkg.get("groups", [])), fixed,
                        cwes=(v.get("database_specific") or {}).get("cwe_ids"),
                        refs=[r["url"] for r in v.get("references", [])[:5]]))
        res.findings_count = len(res.findings)
        res.status = COMPLETED
        return res
