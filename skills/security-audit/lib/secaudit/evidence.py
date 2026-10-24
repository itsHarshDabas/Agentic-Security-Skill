"""Run directory and evidence store. Raw tool output is kept byte-for-byte with a sha256."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import secrets
from pathlib import Path

from .errors import ScopeError
from .paths import is_within
from .scope import Scope


def default_out_base() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return Path(base) / "secaudit" / "runs"


class RunStore:
    def __init__(self, path: Path):
        self.path = path
        self.evidence = path / "evidence"
        self._manifest: list[dict] = []
        mf = self.evidence / "manifest.json"
        if mf.exists():
            self._manifest = json.loads(mf.read_text())

    @classmethod
    def create(cls, scope: Scope, out_base: Path | None) -> "RunStore":
        base = (Path(out_base).expanduser() if out_base else default_out_base()).resolve(strict=False)
        if is_within(base, scope.target) and not scope.allows("write_reports_to_target"):
            raise ScopeError(
                f"report directory {base} is inside the target; the scope is read-only. Choose an --out "
                "outside the target or grant write_reports_to_target in the scope manifest.")
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        name = f"{scope.target.name or 'target'}-{stamp}-{secrets.token_hex(2)}"
        path = base / name
        path.mkdir(parents=True, mode=0o700, exist_ok=False)
        (path / "evidence").mkdir(mode=0o700)
        return cls(path)

    def write_json(self, name: str, data) -> Path:
        return self._write(self.path / name, json.dumps(data, indent=2, sort_keys=False, default=str).encode())

    def write_text(self, name: str, text: str) -> Path:
        return self._write(self.path / name, text.encode())

    def save_raw(self, name: str, data: bytes, meta: dict) -> str:
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)[:120]
        p = self._write(self.evidence / safe, data)
        entry = {"file": f"evidence/{safe}", "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), **meta}
        self._manifest = [m for m in self._manifest if m["file"] != entry["file"]] + [entry]
        self._write(self.evidence / "manifest.json", json.dumps(self._manifest, indent=2).encode())
        return entry["file"]

    def verify(self) -> list[str]:
        """Return evidence files whose hash no longer matches (tamper/corruption check)."""
        bad = []
        for m in self._manifest:
            p = self.path / m["file"]
            if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest() != m["sha256"]:
                bad.append(m["file"])
        return bad

    @staticmethod
    def _write(path: Path, data: bytes) -> Path:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return path
