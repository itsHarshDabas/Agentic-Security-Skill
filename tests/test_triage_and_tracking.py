import json
import shutil

import pytest

from conftest import have
from secaudit.findings import Finding
from secaudit.pipeline import scan
from secaudit.report import render
from secaudit.scope import load_scope
from secaudit.triage import TriageError, apply

needs_tools = pytest.mark.skipif(not (have("semgrep") and have("bandit")), reason="semgrep and bandit required")


def _findings(store):
    return [Finding.from_dict(f) for f in json.loads((store.path / "state.json").read_text())["findings"]]


def _at(findings, marks, kind, name):
    m = marks[kind][name]
    return [f for f in findings if f.locations and f.locations[0].path == m["file"]
            and f.locations[0].start_line == m["line"]]


@pytest.mark.parametrize("bad,msg", [
    ({"decisions": [{"id": "nope", "validation": "false_positive", "rationale": "x" * 30}]}, "unknown finding"),
    ({"contextual_findings": [{"title": "t", "description": "d", "severity": "high", "rationale": "r" * 30,
                               "locations": [{"path": "../../../etc/passwd", "start_line": 1}]}]}, "inside the target"),
    ({"contextual_findings": [{"title": "t", "description": "d", "severity": "high", "rationale": "r" * 30,
                               "validation": "confirmed", "locations": [{"path": "app.py", "start_line": 1}]}]},
     "requires reproduction"),
    ({"contextual_findings": [{"title": "t", "description": "d", "severity": "urgent", "rationale": "r" * 30,
                               "locations": [{"path": "app.py"}]}]}, "severity"),
    ({"grant": {"network": True}}, "must be an object"),
])
def test_invalid_triage_rejected(tmp_path, bad, msg):
    (tmp_path / "app.py").write_text("x = 1\n")
    with pytest.raises(TriageError, match=msg):
        apply([], bad, tmp_path)


def test_rationale_required(tmp_path):
    from secaudit.findings import Location
    f = Finding(id="SA-1", kind="code", title="t", description="", severity="high", confidence="low",
                category="c", locations=[Location("a.py", 1)])
    with pytest.raises(TriageError, match="rationale"):
        apply([f], {"decisions": [{"id": "SA-1", "validation": "false_positive", "rationale": "nah"}]}, tmp_path)


@needs_tools
def test_triage_marks_decoys_and_adds_contextual_findings(bench, tmp_path):
    work = tmp_path / "run"
    shutil.copytree(bench["store"].path, work)
    from secaudit.evidence import RunStore
    store = RunStore(work)
    marks = bench["marks"]
    findings = _findings(store)
    decisions = []
    for decoy in ("md5-etag", "random-jitter", "fixed-argv-subprocess"):
        for f in _at(findings, marks, "DECOY", decoy):
            decisions.append({"id": f.id, "validation": "false_positive",
                              "rationale": f"Reviewed: {decoy} is not security relevant in this context."})
    sqli = _at(findings, marks, "SEED", "sqli-login")[0]
    decisions.append({"id": sqli.id, "validation": "confirmed", "rationale": "username is interpolated into SQL text",
                      "reproduction": "POST /login username=' OR 1=1 -- returns the first user"})
    idor = marks["SEED"]["idor-invoice"]
    triage = {"reviewer": "test", "decisions": decisions, "contextual_findings": [{
        "title": "Invoice IDOR", "description": "Any authenticated user can read any invoice.",
        "severity": "high", "cwe": ["CWE-639"], "category": "broken-object-level-authorization",
        "rationale": "get_invoice checks login but never compares owner_id with the session user",
        "locations": [{"path": idor["file"], "start_line": idor["line"]}]}]}
    state = json.loads((work / "state.json").read_text())
    new, log = apply(findings, triage, bench["target"])
    state["findings"] = [f.to_dict() for f in new]
    state["triage_log"] = log
    store.write_json("state.json", state)
    render(store)
    report = json.loads((work / "report.json").read_text())
    by_id = {f["id"]: f for f in report["findings"]}
    assert by_id[sqli.id]["validation"] == "confirmed"
    assert sqli.id in report["summary"]["release_blockers"]
    fps = [f for f in report["findings"] if f["validation"] == "false_positive"]
    assert len(fps) == len(decisions) - 1 and all(f["remediation_status"] == "FALSE_POSITIVE" for f in fps)
    assert report["summary"]["findings_active"] == report["summary"]["findings_total"] - len(fps)
    ctx = [f for f in report["findings"] if f["kind"] == "contextual"]
    assert len(ctx) == 1 and ctx[0]["validation"] == "probable" and ctx[0]["tools"] == ["agent-review"]
    from benchmark import score
    assert score(report, marks, bench["target"])["contextual_seeds_found"] == ["idor-invoice"]


@needs_tools
def test_ids_stable_across_edits_and_new_issue_detected(bench, tmp_path):
    target = tmp_path / "vulnapp"
    shutil.copytree(bench["target"], target)
    app = target / "app.py"
    src = app.read_text().replace('"""Tiny invoice service.', '# unrelated edit\n# another line\n"""Tiny invoice service.', 1)
    src += '\n\n@app.route("/eval")\ndef ev():\n    return str(eval(request.args["x"]))\n'
    src = src.replace("import subprocess\n", "import subprocess\nfrom flask import request\n", 1)
    app.write_text(src)
    baseline = bench["store"].path / "report.json"
    store = scan(load_scope(target, None), tmp_path / "runs", only={"semgrep", "bandit"}, baseline=baseline)
    rep = json.loads((store.path / "report.json").read_text())
    prev_code = {f["id"] for f in json.loads(baseline.read_text())["findings"] if f["kind"] in ("code", "config")}
    cur = {f["id"]: f for f in rep["findings"]}
    assert prev_code <= set(cur), "existing findings changed ID after unrelated edits"
    new = [f for f in rep["findings"] if f["tracking"] == "new"]
    assert new and all(f["locations"][0]["path"] == "app.py" for f in new)
    assert any("eval" in (f["locations"][0]["snippet"] or "") for f in new)
