"""Seeded-benchmark harness for the vulnapp fixture.

materialize(): copy the fixture to a temp dir, record marker line numbers,
strip the markers, inject generated (fake) secrets.
score(): compare a run's report.json against expected.json.

Run directly for a full benchmark:  python tests/benchmark.py [--network]
"""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "vulnapp"
MARK = re.compile(r"\s*(#|//)\s*(SEED|DECOY):([\w-]+)\s*$")
sys.path.insert(0, str(ROOT / "skills" / "security-audit" / "lib"))


def materialize(dest: Path) -> dict:
    shutil.copytree(FIXTURE, dest, ignore=shutil.ignore_patterns("expected.json", "README.md"))
    marks = {"SEED": {}, "DECOY": {}}
    for p in list(dest.rglob("*.py")) + list(dest.rglob("*.js")):
        lines = p.read_text().splitlines()
        out = []
        for i, line in enumerate(lines, 1):
            m = MARK.search(line)
            if m:
                marks[m.group(2)][m.group(3)] = {"file": p.relative_to(dest).as_posix(), "line": i}
                line = line[:m.start()]
            out.append(line)
        p.write_text("\n".join(out) + "\n")
    # Fake secrets, generated per run and never committed.
    body = base64.b64encode(secrets.token_bytes(600)).decode()
    key = "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64)) + \
          "\n-----END RSA PRIVATE KEY-----\n"
    (dest / "deploy_key.pem").write_text(key)
    token = secrets.token_hex(20)
    (dest / "settings_local.py").write_text(f'PAYMENTS_API_KEY = "{token}"\n')
    return marks


def score(report: dict, marks: dict, target: Path) -> dict:
    exp = json.loads((FIXTURE / "expected.json").read_text())
    code = [f for f in report["findings"] if f["kind"] in ("code", "config")]
    at = {}
    for f in code:
        for loc in f["locations"]:
            at.setdefault((loc["path"], loc["start_line"]), []).append(f)

    def hit(file, line):
        return [f for d in (-1, 0, 1) for f in at.get((file, line + d), [])]

    scanner_seeds = {k: v for k, v in exp["seeds"].items() if v["detect"] == "scanner"}
    found, missed = [], []
    for sid in scanner_seeds:
        m = marks["SEED"][sid]
        (found if hit(m["file"], m["line"]) else missed).append(sid)
    cfg_found, cfg_missed = [], []
    for c in exp["config_seeds"]:
        text = (target / c["file"]).read_text().splitlines()
        line = next(i for i, t in enumerate(text, 1) if re.search(c["pattern"], t))
        (cfg_found if hit(c["file"], line) else cfg_missed).append(c["id"])
    decoy_flagged = [d for d in exp["decoys"] if hit(marks["DECOY"][d]["file"], marks["DECOY"][d]["line"])
                     and not d.startswith("lodash")]
    seed_lines = {(m["file"], m["line"] + d) for m in marks["SEED"].values() for d in (-1, 0, 1)}
    cfg_lines = set()
    for c in exp["config_seeds"]:
        text = (target / c["file"]).read_text().splitlines()
        cfg_lines |= {(c["file"], i) for i, t in enumerate(text, 1) if re.search(c["pattern"], t)}
    decoy_lines = {(m["file"], m["line"]) for m in marks["DECOY"].values()}
    tp = sum(1 for f in code if (f["locations"][0]["path"], f["locations"][0]["start_line"]) in seed_lines | cfg_lines)
    fp = sum(1 for f in code if (f["locations"][0]["path"], f["locations"][0]["start_line"]) in decoy_lines)
    unlabeled = len(code) - tp - fp

    contextual = {k for k, v in exp["seeds"].items() if v["detect"] == "contextual"}
    ctx_found = [k for k in contextual if any(f["kind"] == "contextual" for f in
                                              hit(marks["SEED"][k]["file"], marks["SEED"][k]["line"]))
                 or any(f["kind"] == "contextual" and any(l["path"] == marks["SEED"][k]["file"] and
                        l["start_line"] and abs(l["start_line"] - marks["SEED"][k]["line"]) <= 1 for l in f["locations"])
                        for f in report["findings"])]

    deps = [f for f in report["findings"] if f["kind"] == "dependency"]
    pk_found = {(f["package"]["ecosystem"], f["package"]["name"].lower()) for f in deps}
    expected_pk = {(e, n) for e, names in exp["vulnerable_packages"].items() for n in names}
    secrets_found = [f for f in report["findings"] if f["kind"] == "secret"]
    seed_risk = [f["risk_score"] for f in code if (f["locations"][0]["path"], f["locations"][0]["start_line"]) in seed_lines | cfg_lines
                 and f.get("risk_score") is not None]
    decoy_risk = [f["risk_score"] for f in code if (f["locations"][0]["path"], f["locations"][0]["start_line"]) in decoy_lines
                  and f.get("risk_score") is not None]
    checks = {c["check_id"]: c["status"] for c in report["checks"]}
    confirmed_without_triage = [f["id"] for f in report["findings"]
                                if f["validation"] == "confirmed" and not f.get("validation_rationale")]
    return {
        "scanner_seed_recall": round(len(found) / len(scanner_seeds), 3),
        "scanner_seeds_found": len(found), "scanner_seeds_total": len(scanner_seeds),
        "scanner_seeds_missed": missed,
        "config_seed_recall": round(len(cfg_found) / len(exp["config_seeds"]), 3),
        "config_seeds_missed": cfg_missed,
        "contextual_seed_recall": round(len(ctx_found) / len(contextual), 3),
        "contextual_seeds_found": sorted(ctx_found),
        "code_findings": len(code), "on_seeded_lines": tp, "on_decoy_lines": fp, "unlabeled": unlabeled,
        "precision_labeled": round(tp / (tp + fp), 3) if tp + fp else None,
        "decoy_false_positive_rate": round(len(decoy_flagged) / (len(exp["decoys"]) - 1), 3),
        "decoys_flagged": decoy_flagged,
        "dependency_package_recall": round(len(pk_found & expected_pk) / len(expected_pk), 3) if deps or
        checks.get("pip-audit") == "COMPLETED" else None,
        "dependency_packages_missed": sorted(f"{e}:{n}" for e, n in expected_pk - pk_found),
        "secrets_found": len(secrets_found), "secrets_injected": len(exp["injected_secrets"]),
        "confirmed_without_triage": confirmed_without_triage,
        "mean_risk_seeded": round(sum(seed_risk) / len(seed_risk), 1) if seed_risk else None,
        "mean_risk_decoys": round(sum(decoy_risk) / len(decoy_risk), 1) if decoy_risk else None,
        "check_status": checks,
    }


def run(network: bool) -> dict:
    from secaudit.pipeline import scan
    from secaudit.scope import load_scope
    work = Path(tempfile.mkdtemp(prefix="secaudit-bench-"))
    target = work / "vulnapp"
    marks = materialize(target)
    manifest = work / "scope.json"
    manifest.write_text(json.dumps({"version": 1, "permissions": {"network": network}}))
    t0 = time.monotonic()
    store = scan(load_scope(target, manifest), work / "runs")
    duration = round(time.monotonic() - t0, 2)
    report = json.loads((store.path / "report.json").read_text())
    result = score(report, marks, target)
    result["scan_duration_s"] = duration
    result["run_dir"] = str(store.path)
    return result


if __name__ == "__main__":
    out = json.dumps(run("--network" in sys.argv), indent=2)
    if "--output" in sys.argv:
        Path(sys.argv[sys.argv.index("--output") + 1]).write_text(out)
    print(out)
