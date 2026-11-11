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


## Native workbench validation

New project-adapter tests call actual core functions and SQLite exports with independent known fixture oracles. Storage tests exercise one-owner profiles, unknown/incompatible state, safe paths, quotas, transactions, BLOB hashes, stale-confirmation rejection and non-reused run identities. Presentation-adapter tests replace only OS widgets/dialog acquisition while keeping core/storage/thread work real. An actual Windows frozen executable separately instantiates the same Tk widgets/mainloop and runs the actual controls against an explicitly synthetic profile; no result/API is mocked.

`python scripts/build_native.py` requires an isolated patched CPython3.14.10 build environment and exact native lock. `python scripts/test_native_app.py` tests the resulting EXE with no Python/Node on its child PATH and no provider/account environment, validates independent domain oracles and exact private export, checks normal owned-process disappearance and starts a second process to prove exact retained bundle hashes. Screenshots capture only its owned synthetic window. This is not independent OS accessibility automation, populated real-user upgrade or signing proof. Existing coverage, benchmark, property, cross-platform, security-extended CodeQL and dependency/secret/configuration/workflow gates remain mandatory. No artifact/cache uploads were added.

[Actual native candidate observations](reports/native-application-2026-11-10.md) are distinct from historical reports and pending hosted/release results. Do not infer a future CI pass from a local build.

[Native reader/lifecycle follow-up](reports/native-reader-boundary-2026-11-10.md) adds real opened-NUL rejection, an actual POSIX no-writer FIFO replacement child and packaged minimum-width/long-status lifecycle-control assertions. Windows FIFO skips remain explicit; all original analysis/coverage/security gates are retained.
