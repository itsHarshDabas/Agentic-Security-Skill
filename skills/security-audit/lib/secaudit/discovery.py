"""Read-only project discovery. Never executes project code.

Heuristic by design: it reads files and matches patterns. Its job is to pick
tools and point the reviewer at risky code, not to be a parser.
"""
from __future__ import annotations

import fnmatch
import os
import re
from collections import Counter
from pathlib import Path

from .paths import is_within
from .scope import Scope

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
             ".tox", ".mypy_cache", ".pytest_cache", ".next", "coverage", ".idea", ".vscode"}
MAX_FILES = 50_000
MAX_READ = 1024 * 1024

EXT_LANG = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".sql": "sql", ".go": "go", ".java": "java",
    ".rb": "ruby", ".php": "php", ".rs": "rust", ".cs": "csharp", ".sh": "shell",
    ".yml": "yaml", ".yaml": "yaml", ".tf": "terraform", ".html": "html",
}
MANIFESTS = {
    "requirements.txt": "pypi", "pyproject.toml": "pypi", "Pipfile": "pypi", "Pipfile.lock": "pypi",
    "poetry.lock": "pypi", "setup.py": "pypi", "setup.cfg": "pypi", "uv.lock": "pypi",
    "package.json": "npm", "package-lock.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
    "go.mod": "go", "go.sum": "go", "Gemfile.lock": "rubygems", "composer.lock": "packagist",
    "Cargo.lock": "cargo", "pom.xml": "maven", "build.gradle": "maven",
}
TOOL_CONFIGS = {".checkov.yaml", ".checkov.yml", ".gitleaks.toml", ".gitleaksignore", ".semgrepignore", ".semgrep.yml", ".semgrep",
                ".bandit", "bandit.yaml", "bandit.yml", ".npmrc", "pip.conf", ".osv-scanner.toml",
                "osv-scanner.toml", ".trivyignore"}

FRAMEWORK_PATTERNS = {
    "flask": re.compile(r"^\s*(from\s+flask\s+import|import\s+flask)", re.M),
    "fastapi": re.compile(r"^\s*(from\s+fastapi\s+import|import\s+fastapi)", re.M),
    "django": re.compile(r"^\s*(from\s+django|import\s+django)", re.M),
    "express": re.compile(r"require\(\s*['\"]express['\"]\s*\)|from\s+['\"]express['\"]"),
    "react": re.compile(r"from\s+['\"]react['\"]|require\(\s*['\"]react['\"]\s*\)"),
    "nextjs": re.compile(r"from\s+['\"]next(/[^'\"]*)?['\"]"),
}
ROUTE_PATTERNS = [
    re.compile(r"@\w+\.(route|get|post|put|patch|delete)\(\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"\b(?:app|router)\.(get|post|put|patch|delete|all|use)\(\s*['\"`]([^'\"`]+)['\"`]"),
]
SIGNALS = {
    "auth": re.compile(r"login_required|jwt|jsonwebtoken|passport|session\[|check_password|bcrypt|"
                       r"Depends\(.*(user|auth)|authenticate|@login|req\.user|current_user", re.I),
    "database": re.compile(r"sqlite3|sqlalchemy|psycopg|pymysql|\.execute\(|mongoose|knex|sequelize|"
                           r"prisma|\bpg\b|mysql2", re.I),
    "command_exec": re.compile(r"subprocess|os\.system|os\.popen|child_process|\bexec(Sync)?\(|spawn\("),
    "file_io": re.compile(r"send_file|send_from_directory|open\(|res\.sendFile|fs\.(read|write)|"
                          r"multer|UploadFile|request\.files"),
    "deserialization": re.compile(r"pickle\.loads?|yaml\.load\(|marshal\.loads|jsonpickle|unserialize"),
    "outbound_http": re.compile(r"requests\.(get|post)|urllib\.request|httpx\.|axios|fetch\(|http\.get\("),
    "templating": re.compile(r"render_template_string|Markup\(|dangerouslySetInnerHTML|innerHTML|\|\s*safe"),
    "crypto": re.compile(r"hashlib\.(md5|sha1)|createHash\(['\"](md5|sha1)|random\.random|Math\.random|DES|ECB"),
}


def _excluded(rel: str, patterns: tuple[str, ...]) -> bool:
    parts = rel.split("/")
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat) or any(fnmatch.fnmatch(p, pat) for p in parts):
            return True
    return False


def iter_files(scope: Scope):
    """Yield (abs_path, rel_path) for regular files in scope. Symlinks are reported, never followed."""
    count = 0
    symlinks = []
    for root in scope.roots:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            d = Path(dirpath)
            keep = []
            for name in dirnames:
                full = d / name
                rel = full.relative_to(scope.target).as_posix()
                if full.is_symlink():
                    symlinks.append(rel)
                    continue
                if name in SKIP_DIRS or _excluded(rel, scope.exclude):
                    continue
                keep.append(name)
            dirnames[:] = sorted(keep)
            for name in sorted(filenames):
                full = d / name
                rel = full.relative_to(scope.target).as_posix()
                if full.is_symlink():
                    symlinks.append(rel)
                    continue
                if _excluded(rel, scope.exclude):
                    continue
                count += 1
                if count > MAX_FILES:
                    yield None, "__truncated__"
                    return
                yield full, rel
    yield None, ("__symlinks__", symlinks)


def _read(path: Path) -> str:
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_READ)
    except OSError:
        return ""
    if b"\x00" in data[:4096]:
        return ""
    return data.decode("utf-8", errors="replace")


def discover(scope: Scope) -> dict:
    langs: Counter = Counter()
    manifests: list[dict] = []
    frameworks: dict[str, list[str]] = {}
    routes: list[dict] = []
    signals: dict[str, list[str]] = {k: [] for k in SIGNALS}
    docker, ci, tests, tool_configs, symlinks, entry_points = [], [], [], [], [], []
    truncated = False
    total = 0

    for full, rel in iter_files(scope):
        if full is None:
            if rel == "__truncated__":
                truncated = True
            elif isinstance(rel, tuple):
                symlinks = rel[1]
            continue
        total += 1
        name = full.name
        ext = full.suffix.lower()
        if ext in EXT_LANG:
            langs[EXT_LANG[ext]] += 1
        if name in MANIFESTS or (name.startswith("requirements") and name.endswith(".txt")):
            manifests.append({"path": rel, "ecosystem": MANIFESTS.get(name, "pypi")})
        if name in TOOL_CONFIGS:
            tool_configs.append(rel)
        if name.startswith("Dockerfile") or name.endswith(".dockerfile") or \
                re.fullmatch(r"(docker-)?compose(\.[\w-]+)?\.ya?ml", name):
            docker.append(rel)
        if rel.startswith(".github/workflows/") or "/.github/workflows/" in rel or name == ".gitlab-ci.yml":
            ci.append(rel)
        if re.match(r"(test_.*\.py|.*_test\.py|.*\.(test|spec)\.[jt]sx?)$", name) or "/tests/" in f"/{rel}":
            tests.append(rel)

        if ext not in (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            continue
        text = _read(full)
        if not text:
            continue
        for fw, pat in FRAMEWORK_PATTERNS.items():
            if pat.search(text):
                frameworks.setdefault(fw, []).append(rel)
        for pat in ROUTE_PATTERNS:
            for m in pat.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                routes.append({"file": rel, "line": line, "method": m.group(1).upper(), "path": m.group(2)})
        for sig, pat in SIGNALS.items():
            if pat.search(text):
                signals[sig].append(rel)
        if re.search(r"\.run\(|uvicorn\.run|\.listen\(|if __name__ == ['\"]__main__['\"]", text):
            entry_points.append(rel)

    risk: Counter = Counter()
    route_files = {r["file"] for r in routes}
    weights = {"command_exec": 3, "deserialization": 3, "database": 2, "file_io": 2, "outbound_http": 2,
               "templating": 2, "crypto": 1, "auth": 1}
    for sig, files in signals.items():
        for f in files:
            risk[f] += weights[sig] * (2 if f in route_files else 1)
    high_risk = [{"file": f, "score": s,
                  "signals": sorted(k for k, v in signals.items() if f in v)}
                 for f, s in risk.most_common(15)]

    outside_links = []
    for rel in symlinks:
        target = (scope.target / rel).resolve(strict=False)
        if not is_within(target, scope.target):
            outside_links.append(rel)

    return {
        "target": str(scope.target),
        "files_scanned": total,
        "truncated": truncated,
        "languages": dict(langs.most_common()),
        "frameworks": {k: sorted(set(v)) for k, v in frameworks.items()},
        "manifests": manifests,
        "routes": routes[:500],
        "route_count": len(routes),
        "entry_points": sorted(set(entry_points)),
        "signals": {k: sorted(set(v)) for k, v in signals.items() if v},
        "docker": docker,
        "ci": ci,
        "tests": tests[:200],
        "test_count": len(tests),
        "tool_configs_in_target": tool_configs,
        "symlinks": symlinks,
        "symlinks_escaping_target": outside_links,
        "high_risk_files": high_risk,
        "method": "static pattern matching over file contents; heuristic, may miss or over-report",
    }
