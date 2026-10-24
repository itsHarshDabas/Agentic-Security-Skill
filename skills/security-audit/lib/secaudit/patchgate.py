"""Policy checks on a remediation diff, enforced in code before a fix is accepted."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .prioritize import is_test_path

MAX_LINES_NO_APPROVAL = 60
MAX_FILES_NO_APPROVAL = 3
SUPPRESSION = re.compile(r"nosec\b|nosemgrep|gitleaks:allow|eslint-disable|NOSONAR|@SuppressWarnings|"
                         r"noqa:\s*S\d|codeql\[|semgrep:\s*ignore|bandit:\s*skip", re.I)
SCANNER_CONFIG = re.compile(r"(^|/)(\.semgrepignore|\.semgrep\.ya?ml|\.semgrep/|\.gitleaks\.toml|\.gitleaksignore|"
                            r"\.bandit|bandit\.ya?ml|\.trivyignore|osv-scanner\.toml|\.osv-scanner\.toml|\.snyk|"
                            r"\.secaudit)")
DEP_MANIFEST = re.compile(r"(^|/)(requirements[^/]*\.txt|pyproject\.toml|Pipfile(\.lock)?|poetry\.lock|uv\.lock|"
                          r"setup\.(py|cfg)|package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|go\.(mod|sum)|"
                          r"Gemfile(\.lock)?|Cargo\.(toml|lock)|composer\.(json|lock))$")
SENSITIVE = re.compile(r"auth|login|session|permission|acl|rbac|security|crypto|password|token", re.I)
TEST_DEF = re.compile(r"^\s*(?:async\s+)?def\s+(test_\w+)|^\s*class\s+(Test\w+)|"
                      r"^\s*(?:it|test|describe)\s*\(\s*['\"`]([^'\"`]+)")


@dataclass
class FileChange:
    path: str
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    new_file: bool = False
    deleted: bool = False
    binary: bool = False
    renamed_from: str | None = None


@dataclass
class GateResult:
    files: list[str]
    lines_added: int
    lines_removed: int
    test_files: list[str]
    source_files: list[str]
    violations: list[str]
    approval_reasons: list[str]

    @property
    def ok(self) -> bool:
        return not self.violations

    def to_dict(self) -> dict:
        return {**self.__dict__, "ok": self.ok}


def parse(diff: str) -> list[FileChange]:
    files: list[FileChange] = []
    cur: FileChange | None = None
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            m = re.match(r"diff --git a/(.+?) b/(.+)$", line)
            cur = FileChange(path=m.group(2) if m else line[11:])
            files.append(cur)
            continue
        if cur is None:
            continue
        if line.startswith("new file mode"):
            cur.new_file = True
        elif line.startswith("deleted file mode"):
            cur.deleted = True
        elif line.startswith("rename from "):
            cur.renamed_from = line[12:]
        elif line.startswith("Binary files") or line.startswith("GIT binary patch"):
            cur.binary = True
        elif line.startswith("+++ ") or line.startswith("--- "):
            continue
        elif line.startswith("+"):
            cur.added.append(line[1:])
        elif line.startswith("-"):
            cur.removed.append(line[1:])
    return files


def _test_names(lines: list[str]) -> set[str]:
    names = set()
    for l in lines:
        m = TEST_DEF.match(l)
        if m:
            names.add(next(g for g in m.groups() if g))
    return names


def check(diff: str, allowed_prefixes: list[str]) -> GateResult:
    files = parse(diff)
    v: list[str] = []
    a: list[str] = []
    for f in files:
        p = f.path
        if p.startswith("/") or ".." in p.split("/") or p.startswith(".git/") or "\x00" in p:
            v.append(f"{p}: path not allowed")
        elif allowed_prefixes and not any(p == x or p.startswith(x.rstrip("/") + "/") or x in ("", ".")
                                          for x in allowed_prefixes):
            v.append(f"{p}: outside the scope roots")
        if f.binary:
            v.append(f"{p}: binary changes are not accepted")
        if f.deleted:
            v.append(f"{p}: deleting files is not allowed in a remediation patch")
        if f.renamed_from and is_test_path(f.renamed_from) and not is_test_path(p):
            v.append(f"{f.renamed_from}: test file renamed out of the test tree")
        if SCANNER_CONFIG.search(p):
            v.append(f"{p}: modifying scanner configuration is not allowed (it could hide findings)")
        if p.endswith("pyproject.toml") and any("[tool.bandit" in x or "[tool.semgrep" in x for x in f.added + f.removed):
            v.append(f"{p}: modifying scanner configuration is not allowed")
        for line in f.added:
            if SUPPRESSION.search(line):
                v.append(f"{p}: adds a scanner suppression ({line.strip()[:80]})")
                break
        if is_test_path(p):
            lost = _test_names(f.removed) - _test_names(f.added)
            if lost:
                v.append(f"{p}: removes tests {sorted(lost)}")
            if any(re.match(r"^\s*(@pytest\.mark\.skip|@unittest\.skip|\.skip\(|xit\(|it\.skip|test\.skip)", l)
                   for l in f.added):
                v.append(f"{p}: skips tests")
        if DEP_MANIFEST.search(p):
            a.append(f"{p}: dependency change (verify compatibility of the upgraded version)")
        if SENSITIVE.search(p) and not is_test_path(p):
            a.append(f"{p}: security-sensitive component")
    added = sum(len(f.added) for f in files)
    removed = sum(len(f.removed) for f in files)
    source = [f.path for f in files if not is_test_path(f.path)]
    tests = [f.path for f in files if is_test_path(f.path)]
    if added + removed > MAX_LINES_NO_APPROVAL:
        a.append(f"{added + removed} changed lines (> {MAX_LINES_NO_APPROVAL})")
    if len(source) > MAX_FILES_NO_APPROVAL:
        a.append(f"{len(source)} source files changed (> {MAX_FILES_NO_APPROVAL})")
    if not files:
        v.append("empty diff")
    return GateResult([f.path for f in files], added, removed, tests, source, v, a)
