# Test strategy and validation gates

Priorities: semantics and trust boundaries first, then reproducibility, output integrity and measured resource behavior. Tests must not alter system security settings or contact target infrastructure.

| Layer | Coverage |
| --- | --- |
| Unit/negative | Every supported predicate, strict types, source boundaries, unsupported grammar, schema metadata, malformed/duplicate/non-finite JSON, unsafe YAML, sizes/counts/timezones/overflow |
| Property | Unicode/integer normalization round trips; deque/counter correlations compared against independently recomputed window oracle; input-order invariance |
| Integration | Separate truth/feature paths, exact scenario outcomes including false positives/misses, official draft-2020-12 schema/hash checks, deterministic fixture regeneration |
| End-to-end | CLI success/refusal, JSON round trip, SQLite constraints/integrity/bound inserts, HTML escaping/CSP, no overwrite, disk failure/sentinel preservation |
| Platform | Linux 3.12/3.14, Windows 3.14, macOS 3.14 hosted workers; Windows symlink creation test skips without developer/admin capability, Unix lanes run it |
| Static/security | Ruff lint/format, strict mypy, exact AST file-header maps/function contracts, README file inventory, pip-audit, Gitleaks history, Trivy HIGH/CRITICAL dependency/configuration, actionlint, ShellCheck, CodeQL security-extended |
| Performance | Warm-up then ten timed 10,000-event detector runs; nearest-rank p95 <5s; separate tracemalloc pass <64MiB |

Coverage is **branch-inclusive**, measured only for `detection/` (development helpers have focused tests but are not included in that percentage). Gate ≥85%; coverage is not correctness proof. Tests include Hypothesis-generated cases beyond the collected pytest item count. The same inputs drive the independent naive oracle, but that oracle recomputes all windows and does not reuse optimized state or emitted outputs.

Activate the hash-locked development environment, then:

```bash
python -m ruff check .
python -m ruff format --check .
python -m mypy
python scripts/code_map.py --check
python scripts/file_guide.py --check
python scripts/scenarios.py --check
python scripts/validate_rules.py
python -m pytest --cov=detection --cov-report=term-missing --cov-report=json:out/coverage.json --junitxml=out/junit.xml
python scripts/benchmark.py
python -m pip_audit -r requirements-dev.lock --disable-pip --no-deps
```

Commands also work individually in PowerShell after activation. `bash scripts/validate.sh` runs the quality portion fail-fast. Security scanner binaries are pinned in `tools.lock.json`, installed by `scripts/tools.py` only on hosted Linux. Windows local testing uses the already reviewed Gitleaks binary; the Linux-hosted job is authoritative for Trivy/actionlint/ShellCheck. No local Docker Desktop change or Docker dependency.

CI has no Actions artifact/cache uploads. Results remain in job logs and summaries; the development outputs in `out/` remain ignored. Long-term synthetic evidence is deliberately saved under `docs/reports/`, with date, platform, scope and run links. Reports must not claim a pending run passed.

Gaps: no native event-source adapters, representative customer data, SIEM backend compatibility, streaming/lateness watermark processing, hostile shared-folder races, sustained distributed load or independently certified accessibility/security assessment. Do not claim fuzzing every language/protocol or zero-day immunity from this suite.
