"""Path validation. Every path the engine touches goes through here."""
from __future__ import annotations

import os
from pathlib import Path

from .errors import PathError


def resolve_dir(p: str | os.PathLike) -> Path:
    path = Path(p)
    if "\x00" in str(path):
        raise PathError("path contains NUL byte")
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_dir():
        raise PathError(f"not a directory: {resolved}")
    return resolved


def is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def ensure_within(path: Path, roots: list[Path]) -> Path:
    """Resolve `path` (following symlinks) and require it to stay under one of `roots`."""
    resolved = path.resolve(strict=False)
    for root in roots:
        if is_within(resolved, root):
            return resolved
    raise PathError(f"path escapes scope: {path}")


def safe_relpath(path: Path, root: Path) -> str:
    """Relative POSIX path for reports. Raises if outside root."""
    rel = path.resolve(strict=False).relative_to(root)
    return rel.as_posix()
