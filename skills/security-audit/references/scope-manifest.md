# Scope manifest

JSON, written by the operator, stored **outside** the target. The engine refuses a
manifest inside the target unless `--allow-scope-in-target` is passed, and never
auto-discovers one, so repository content cannot grant itself permissions.

```json
{
  "version": 1,
  "roots": ["."],
  "exclude": ["vendor", "fixtures/*"],
  "intensity": "passive",
  "permissions": {
    "network": false,
    "modify_source": false,
    "execute_project_code": false,
    "dynamic_testing": false,
    "external_services": false,
    "commit": false,
    "write_reports_to_target": false
  },
  "targets": {"urls": []},
  "notes": "free text, e.g. ticket or engagement reference"
}
```

| Key | Meaning |
|---|---|
| `roots` | Directories (relative to the target) to assess. Must stay inside the target after resolving symlinks. |
| `exclude` | Glob patterns matched against relative paths and path segments; passed to every tool. |
| `permissions.network` | Allows dependency scanners to query OSV.dev / deps.dev, PyPI and the npm registry. Package names and versions leave the machine; source code does not. |
| `permissions.write_reports_to_target` | Allows `--out` inside the target tree. |
| `permissions.modify_source` | Allows `fix start`: creates a worktree and a `secaudit/fix-*` branch in the repository and records gated fixes there. The operator's working tree is not modified. |
| `permissions.execute_project_code` | Allows `fix test` / `verify` to run the project's own test commands (argv, no shell, network-off env, timeout). This executes repository code; grant only for code you trust enough to run. |
| `permissions.commit` | Allows `fix commit` on the session branch. Nothing is ever pushed. |
| `permissions.dynamic_testing`, `targets.urls` | Reserved for Phase 5 DAST; nothing uses them yet. |
| `intensity` | `passive` or `standard`; reserved for dynamic testing. |

Unknown keys, unknown permissions and non-boolean values are rejected. The report
records the manifest path and its sha256 so scope changes are auditable.

What this does **not** protect against: an agent with unrestricted shell access
can write its own manifest. The engine stops repository content and accidents
from widening scope; the agent platform's permission system (and the rule in
SKILL.md to only use permissions the operator granted) covers the rest.
