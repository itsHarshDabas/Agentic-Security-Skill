"""Scope manifest and permission gate.

Permissions only ever come from an operator-supplied manifest. The engine never
auto-loads a manifest from the target, and refuses one located inside the target
unless the caller explicitly opts in, so repository content cannot grant itself
network access or write permission.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ScopeError
from .paths import is_within, resolve_dir

PERMISSIONS = (
    "network",                  # tools may contact vulnerability databases / registries
    "modify_source",            # Phase 3: patch files in the target
    "dynamic_testing",          # Phase 5: send requests to running targets
    "external_services",        # contact services other than vuln DBs
    "commit",                   # create commits
    "write_reports_to_target",  # place the run directory inside the target tree
)
INTENSITIES = ("passive", "standard")
TOP_KEYS = {"version", "roots", "exclude", "permissions", "targets", "intensity", "notes"}
MAX_EXCLUDES = 200


@dataclass(frozen=True)
class Scope:
    target: Path
    roots: tuple[Path, ...]
    exclude: tuple[str, ...] = ()
    permissions: dict = field(default_factory=lambda: {p: False for p in PERMISSIONS})
    urls: tuple[str, ...] = ()
    intensity: str = "passive"
    source: str = "default (read-only)"
    source_sha256: str | None = None

    def allows(self, permission: str) -> bool:
        if permission not in PERMISSIONS:
            raise ScopeError(f"unknown permission: {permission}")
        return bool(self.permissions.get(permission, False))

    def require(self, permission: str, what: str) -> None:
        if not self.allows(permission):
            raise ScopeError(f"{what} requires permission '{permission}', which the scope manifest does not grant")

    def to_dict(self) -> dict:
        return {
            "target": str(self.target),
            "roots": [str(r) for r in self.roots],
            "exclude": list(self.exclude),
            "permissions": dict(self.permissions),
            "urls": list(self.urls),
            "intensity": self.intensity,
            "source": self.source,
            "source_sha256": self.source_sha256,
        }


def default_scope(target: Path) -> Scope:
    return Scope(target=target, roots=(target,))


def load_scope(target: Path, manifest: Path | None, allow_in_target: bool = False) -> Scope:
    target = resolve_dir(target)
    if manifest is None:
        return default_scope(target)

    mpath = Path(manifest).expanduser().resolve(strict=True)
    if is_within(mpath, target) and not allow_in_target:
        raise ScopeError(
            "scope manifest is inside the target repository; repository content cannot grant "
            "permissions. Move it outside the target or pass --allow-scope-in-target deliberately."
        )
    raw = mpath.read_bytes()
    if len(raw) > 256 * 1024:
        raise ScopeError("scope manifest too large")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ScopeError(f"scope manifest is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ScopeError("scope manifest must be a JSON object")
    unknown = set(data) - TOP_KEYS
    if unknown:
        raise ScopeError(f"unknown scope keys: {sorted(unknown)}")
    if data.get("version", 1) != 1:
        raise ScopeError("unsupported scope manifest version")

    roots = []
    for r in data.get("roots", ["."]):
        if not isinstance(r, str):
            raise ScopeError("roots must be strings")
        rp = (target / r).resolve(strict=True)
        if not is_within(rp, target):
            raise ScopeError(f"scope root escapes target: {r}")
        if not rp.is_dir():
            raise ScopeError(f"scope root is not a directory: {r}")
        roots.append(rp)
    if not roots:
        raise ScopeError("scope must list at least one root")

    exclude = data.get("exclude", [])
    if not isinstance(exclude, list) or not all(isinstance(e, str) for e in exclude) or len(exclude) > MAX_EXCLUDES:
        raise ScopeError("exclude must be a list of strings")

    perms_in = data.get("permissions", {})
    if not isinstance(perms_in, dict):
        raise ScopeError("permissions must be an object")
    bad = set(perms_in) - set(PERMISSIONS)
    if bad:
        raise ScopeError(f"unknown permissions: {sorted(bad)}")
    perms = {p: False for p in PERMISSIONS}
    for k, v in perms_in.items():
        if not isinstance(v, bool):
            raise ScopeError(f"permission {k} must be true/false")
        perms[k] = v

    intensity = data.get("intensity", "passive")
    if intensity not in INTENSITIES:
        raise ScopeError(f"intensity must be one of {INTENSITIES}")

    targets = data.get("targets", {}) or {}
    urls = targets.get("urls", []) if isinstance(targets, dict) else None
    if not isinstance(urls, list) or not all(isinstance(u, str) for u in urls):
        raise ScopeError("targets.urls must be a list of strings")

    return Scope(
        target=target,
        roots=tuple(roots),
        exclude=tuple(exclude),
        permissions=perms,
        urls=tuple(urls),
        intensity=intensity,
        source=str(mpath),
        source_sha256=hashlib.sha256(raw).hexdigest(),
    )
