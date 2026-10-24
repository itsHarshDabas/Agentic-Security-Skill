import json

import pytest

from conftest import write_scope
from secaudit.errors import ScopeError
from secaudit.evidence import RunStore
from secaudit.scope import load_scope


def test_default_scope_is_read_only(tmp_path):
    s = load_scope(tmp_path, None)
    assert not any(s.permissions.values())
    assert s.roots == (tmp_path.resolve(),)


def test_manifest_inside_target_is_refused(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    m = write_scope(target / "scope.json", network=True, modify_source=True)
    with pytest.raises(ScopeError, match="inside the target"):
        load_scope(target, m)
    # Only an explicit operator flag accepts it.
    assert load_scope(target, m, allow_in_target=True).allows("network")


def test_scope_file_in_target_is_never_auto_loaded(tmp_path):
    (tmp_path / "scope.json").write_text(json.dumps({"permissions": {"network": True}}))
    (tmp_path / ".secaudit").mkdir()
    (tmp_path / ".secaudit" / "scope.json").write_text(json.dumps({"permissions": {"network": True}}))
    assert not load_scope(tmp_path, None).allows("network")


@pytest.mark.parametrize("data,msg", [
    ({"permissions": {"network": "yes"}}, "true/false"),
    ({"permissions": {"root_shell": True}}, "unknown permissions"),
    ({"grant_everything": True}, "unknown scope keys"),
    ({"roots": ["../"]}, "escapes target"),
    ({"intensity": "aggressive"}, "intensity"),
    ({"version": 2}, "version"),
    ([], "JSON object"),
])
def test_invalid_manifests_rejected(tmp_path, data, msg):
    target = tmp_path / "repo"
    target.mkdir()
    m = tmp_path / "scope.json"
    m.write_text(json.dumps(data))
    with pytest.raises(ScopeError, match=msg):
        load_scope(target, m)


def test_symlinked_root_escaping_target_rejected(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (target / "link").symlink_to(outside)
    m = tmp_path / "scope.json"
    m.write_text(json.dumps({"roots": ["link"]}))
    with pytest.raises(ScopeError, match="escapes target"):
        load_scope(target, m)


def test_report_dir_inside_target_refused_when_read_only(tmp_path):
    s = load_scope(tmp_path, None)
    with pytest.raises(ScopeError, match="read-only"):
        RunStore.create(s, tmp_path / "reports")


def test_report_dir_inside_target_allowed_with_permission(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    s = load_scope(target, write_scope(tmp_path / "s.json", write_reports_to_target=True))
    store = RunStore.create(s, target / "reports")
    assert store.path.is_dir()


def test_require_raises_for_missing_permission(tmp_path):
    with pytest.raises(ScopeError, match="modify_source"):
        load_scope(tmp_path, None).require("modify_source", "patching")
