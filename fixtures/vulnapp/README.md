# vulnapp: intentionally vulnerable benchmark fixture

**Do not deploy. Do not run on a network.** This app exists only so the
security-audit skill can be measured repeatably.

- Vulnerable lines carry `SEED:<id>` comments, safe-but-suspicious lines carry
  `DECOY:<id>`. `expected.json` describes each one.
- `tests/benchmark.py` copies the app to a temp dir, records marker line
  numbers, strips the markers (so a reviewer can't read the answers), injects
  generated fake secrets, runs the scan, and scores it.
- No real credentials are committed. Secrets are generated at test time.
