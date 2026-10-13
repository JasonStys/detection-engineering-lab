# Validation evidence — 2026-10-13

Author: Jason Stys. Initial local evidence; hosted CI status will be recorded after actual runs complete. No pending run is described as passed.

Local Windows / Python 3.14.6: 116 collected tests, **115 passed and one expected Windows-only symlink-creation skip**. Unix hosted lanes must cover that link test. Branch-inclusive application coverage: **97.50%**, above the 85% gate. Strict mypy, official draft-2020-12 Sigma schema, fixture determinism and pinned development dependency audit passed. No known dependency advisories were found after removing the pySigma/DiskCache chain; no suppressions.

Synthetic replay: 72 rows, 71 unique events, one duplicate ignored, one incomplete correlation candidate, 10 alerts. Five emitted detectors (four single-event rules plus one correlation; failed-logon base is not standalone). Universe 355 event-detector pairs: TP7, FP3, FN2, TN343; precision0.70, recall0.7777778, F1=0.7368421, FPR0.0086705. These are deliberate known limits on a small corpus, not operational accuracy claims. See [scenario ledger](../rules.md).

Local 10,000-event benchmark: ten timed detector iterations, warm-up excluded; p95 **0.0371 seconds**, separate traced peak **879,348 bytes**. This excludes normalization/export, interpreter/native memory and sustained/representative operational workload. The gate is p95<5s and traced peak<64MiB; future hardware may differ.

The first local test run failed JSON round-trip due to tuple vs list evidence; the implementation was fixed rather than weakening the assertion. Dependency audit stopped for PYSEC-2026-2447; parser dependency was removed and official offline schema validation retained. Public reports are synthetic only. Tests check output SQL/HTML safety and data leakage boundaries but do not prove absence of unknown vulnerabilities.

Actions storage meter at start: **0.5GB/0.5GB, 100%**; API inventory ≈570MB retained artifacts, caches separate. This repository deliberately uploads no Actions artifacts/caches. No cleanup, billing change or local Docker repair was performed.

## Hosted checks

Pending publication. Final run links, commit, platform results and security findings will be added only after verification.
