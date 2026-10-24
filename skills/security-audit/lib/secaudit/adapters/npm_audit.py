from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from .base import COMPLETED, FAILED, PARTIAL, Adapter
from .deps_common import dep_finding

REGISTRY = "https://registry.npmjs.org/"


class NpmAuditAdapter(Adapter):
    name = "npm-audit"
    binary = "npm"
    category = "sca"
    objective = "Known-vulnerability lookup for npm lockfiles (GitHub advisory data via the npm registry)"
    requires = ("network",)

    def _projects(self):
        paths = {m["path"] for m in self.ctx.inventory["manifests"]}
        return sorted(p.rsplit("/", 1)[0] if "/" in p else "." for p in paths
                      if p.endswith("package-lock.json"))

    def applicable(self):
        if self._projects():
            return True, ""
        if any(m["ecosystem"] == "npm" for m in self.ctx.inventory["manifests"]):
            return False, "package.json without package-lock.json (npm audit needs a lockfile; osv-scanner may still cover it)"
        return False, "no npm manifests"

    def run(self):
        res = self.result(tool_version=self.version())
        target = self.ctx.scope.target
        problems = []
        for i, d in enumerate(self._projects()):
            src = (target / d).resolve(strict=True)
            src.relative_to(target)
            with tempfile.TemporaryDirectory() as tmp:
                # Copy only the two manifest files: no .npmrc, no scripts, no node_modules.
                for name in ("package.json", "package-lock.json"):
                    if (src / name).is_file() and not (src / name).is_symlink():
                        shutil.copyfile(src / name, Path(tmp) / name)
                user_rc, global_rc = Path(tmp) / ".user-npmrc", Path(tmp) / ".global-npmrc"
                user_rc.write_text("")
                global_rc.write_text("")
                argv = [self.path, "audit", "--json", "--package-lock-only", "--ignore-scripts",
                        f"--registry={REGISTRY}", f"--userconfig={user_rc}", f"--globalconfig={global_rc}"]
                er = self.execute(argv, cwd=Path(tmp), network=True,
                                  extra_env={"npm_config_cache": str(Path(tmp) / "cache"), "npm_config_update_notifier": "false"})
            lock_rel = f"{d}/package-lock.json" if d != "." else "package-lock.json"
            if not self.finish(res, er, f"npm-audit-{i}.json", ok_codes=(0, 1)):
                return res
            try:
                data = json.loads(er.stdout or b"{}")
            except json.JSONDecodeError:
                res.status, res.reason = FAILED, "unparseable JSON output"
                return res
            if "error" in data or "vulnerabilities" not in data or "metadata" not in data:
                # Unexpected shape is a failure, never an empty (clean) result.
                res.status = FAILED
                res.reason = f"{lock_rel}: unexpected npm audit output: {str(data.get('error', data))[:300]}"
                return res
            for name, v in (data.get("vulnerabilities") or {}).items():
                version = self._installed_version(src / "package-lock.json", name)
                for via in v.get("via", []):
                    if not isinstance(via, dict):
                        continue  # transitive pointer; the advisory is reported on the package that has it
                    url = via.get("url", "")
                    adv = url.rsplit("/", 1)[-1] if "advisories/" in url else str(via.get("source"))
                    fixed = []
                    fa = v.get("fixAvailable")
                    if isinstance(fa, dict) and fa.get("name") == name:
                        fixed = [fa.get("version")]
                    res.findings.append(dep_finding(
                        "npm-audit", "npm", name, version, [adv], via.get("title", ""), lock_rel,
                        self.last_raw, via.get("severity"),
                        [f for f in fixed if f], cwes=via.get("cwe"),
                        cvss=via.get("cvss") if (via.get("cvss") or {}).get("score") else None,
                        refs=[url] if url else [], direct=v.get("isDirect")))
        res.findings_count = len(res.findings)
        if problems:
            res.status, res.reason = PARTIAL, "; ".join(problems)[:500]
        else:
            res.status = COMPLETED
        return res

    @staticmethod
    def _installed_version(lock: Path, name: str) -> str:
        try:
            data = json.loads(lock.read_text())
        except (OSError, json.JSONDecodeError):
            return "?"
        pkgs = data.get("packages") or {}
        entry = pkgs.get(f"node_modules/{name}") or (data.get("dependencies") or {}).get(name) or {}
        return entry.get("version", "?")
