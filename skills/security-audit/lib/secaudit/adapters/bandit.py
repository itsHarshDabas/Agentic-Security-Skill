from __future__ import annotations

import json

from ..discovery import SKIP_DIRS
from ..findings import Evidence, Finding, Location, code_id, cwe_norm
from .base import COMPLETED, FAILED, Adapter


class BanditAdapter(Adapter):
    name = "bandit"
    binary = "bandit"
    category = "sast"
    objective = "Python-specific static analysis (injection, deserialization, crypto, subprocess misuse)"

    def applicable(self):
        if "python" in self.ctx.inventory["languages"]:
            return True, ""
        return False, "no Python files"

    def run(self):
        res = self.result(tool_version=self.version())
        target = self.ctx.scope.target
        excludes = ",".join(f"*/{d}/*" for d in sorted(SKIP_DIRS)) + "".join(
            f",*/{x}/*" for x in self.ctx.scope.exclude)
        argv = [self.path, "-r", "-f", "json", "-q", "--ignore-nosec", "-x", excludes]
        argv += [r.relative_to(target).as_posix() or "." for r in self.ctx.scope.roots]
        er = self.execute(argv, cwd=target, network=False)
        ok = self.finish(res, er, "bandit.json", ok_codes=(0, 1))
        try:
            data = json.loads(er.stdout or b"{}")
        except json.JSONDecodeError:
            res.status, res.reason = FAILED, "unparseable JSON output"
            return res
        if not ok:
            return res
        if data.get("errors"):
            res.notes.append(f"{len(data['errors'])} file(s) bandit could not parse")
        seen: dict[str, int] = {}
        for r in data.get("results", []):
            rel = self.rel(r["filename"])
            if rel is None:
                continue
            line = r["line_number"]
            cw = r.get("issue_cwe", {}) or {}
            cwes = cwe_norm([cw.get("id")]) if cw.get("id") else []
            text = self.read_line(rel, line)
            fam = cwes[0] if cwes else r["test_id"]
            key = f"{fam}|{rel}|{text}"
            occ = seen.get(key, 0)
            seen[key] = occ + 1
            res.findings.append(Finding(
                id=code_id(fam, rel, text, occ),
                kind="code",
                title=f"{r['test_name'].replace('_', ' ')} ({r['test_id']})",
                description=r["issue_text"],
                severity=r["issue_severity"].lower(),
                confidence=r["issue_confidence"].lower(),
                category=r["test_name"],
                cwe=cwes,
                locations=[Location(rel, line, (r.get("line_range") or [line])[-1], text.strip())],
                evidence=[Evidence("bandit", r["test_id"], r["issue_text"], self.last_raw)],
                tools=["bandit"],
                references=[r["more_info"]] if r.get("more_info") else [],
            ))
        res.findings_count = len(res.findings)
        res.status = COMPLETED
        return res
