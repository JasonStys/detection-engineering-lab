# Validation evidence — 2026-10-13

Author: Jason Stys. Local and hosted evidence below comes from completed checks. No pending run is described as passed.

Local Windows / Python 3.14.6: 116 collected tests, **115 passed and one expected Windows-only symlink-creation skip**. Unix hosted lanes must cover that link test. Branch-inclusive application coverage: **97.50%**, above the 85% gate. Strict mypy, official draft-2020-12 Sigma schema, fixture determinism and pinned development dependency audit passed. No known dependency advisories were found after removing the pySigma/DiskCache chain; no suppressions.

Synthetic replay: 72 rows, 71 unique events, one duplicate ignored, one incomplete correlation candidate, 10 alerts. Five emitted detectors (four single-event rules plus one correlation; failed-logon base is not standalone). Universe 355 event-detector pairs: TP7, FP3, FN2, TN343; precision0.70, recall0.7777778, F1=0.7368421, FPR0.0086705. These are deliberate known limits on a small corpus, not operational accuracy claims. See [scenario ledger](../rules.md).

Local 10,000-event benchmark: ten timed detector iterations, warm-up excluded; p95 **0.0371 seconds**, separate traced peak **879,348 bytes**. This excludes normalization/export, interpreter/native memory and sustained/representative operational workload. The gate is p95<5s and traced peak<64MiB; future hardware may differ.

The first local test run failed JSON round-trip due to tuple vs list evidence; the implementation was fixed rather than weakening the assertion. Dependency audit stopped for PYSEC-2026-2447; parser dependency was removed and official offline schema validation retained. Public reports are synthetic only. Tests check output SQL/HTML safety and data leakage boundaries but do not prove absence of unknown vulnerabilities.

Actions storage meter at start: **0.5GB/0.5GB, 100%**; API inventory ≈570MB retained artifacts, caches separate. This repository deliberately uploads no Actions artifacts/caches. No cleanup, billing change or local Docker repair was performed.

## Completed hosted checks

Validated source commit: [`7e10dcef1ae392a8dee80021bcaf7a4e3dabeea8`](https://github.com/JasonStys/detection-engineering-lab/commit/7e10dcef1ae392a8dee80021bcaf7a4e3dabeea8).

[Validate run 38444846889](https://github.com/JasonStys/detection-engineering-lab/actions/runs/38444846889) completed **successfully** in every job:

| Hosted lane | Tests | Branch-inclusive coverage | 10,000-event detector p95 | Traced peak |
| --- | --- | --- | --- | --- |
| Ubuntu / Python 3.12 | 116 passed | 97.78% | 0.0444s | 866,592 bytes |
| Ubuntu / Python 3.14 | 116 passed | 97.78% | 0.0411s | 879,348 bytes |
| macOS / Python 3.14 | 116 passed | 97.78% | 0.0428s | 879,348 bytes |
| Windows / Python 3.14 | 115 passed, 1 documented skip | 97.50% | 0.0510s | 879,348 bytes |

Security job passed: development/runtime hash-lock audit (no known advisories), full-history redacted secret scan (no leaks found), Trivy HIGH/CRITICAL dependency/configuration gate, actionlint and ShellCheck. No ignored advisories or relaxed scan thresholds. These tools cannot establish absence of unknown vulnerabilities.

[CodeQL run 38444846811](https://github.com/JasonStys/detection-engineering-lab/actions/runs/38444846811) completed **successfully**. GitHub's stored analysis references the same source commit, security-extended Python query suite, **0 results**; open code-scanning alerts: **0** at inspection. Check current results after future changes.

Browser smoke verified the static HTML rendered its styled summary, 71 events/10 candidates/3 false positives/2 misses, per-rule table, author/contact links and expandable timing/fingerprint details. No event commands executed. A temporary loopback-only report preview was used; it is not a deployed website or permanent background service.

Storage rechecked after CI: repository Actions artifacts **0 bytes**, caches **0 bytes**. Account billing meter remained **0.5GB/0.5GB (100%)**, total billable usage after discounts **$0** at inspection. Retained artifact bytes and the billing meter are different measurements; other repositories' caches use a separate allowance. This project did not add stored artifacts/caches or delete anything.

Publishing checklist: source reviewed for input/label isolation and injection/output boundaries; deterministic fixtures and all platform gates passed; known detection blind spots documented; private vulnerability reporting enabled. This is developer self-review, not an independent external assessment. Future commits are covered by their own workflow runs; the immutable links above intentionally preserve this measured source revision.
