# Offline review workflow validation — 2026-11-09

Created by Jason Stys. Local Windows/Python 3.14 validation; no host telemetry was
collected, no incident response was executed and no GitHub Actions run is claimed here.

The exact-snapshot comparison, copyable triage template, reasoned partial review,
immutable source/report behavior, replay-to-review CLI journey and escaped table
were tested using independent synthetic identities and the real example replay.
Stale report hashes, different event/label snapshots, duplicate/unknown identities,
malformed report shapes, unsupported dispositions, empty reasons, hostile text and
existing destinations were rejected or retained as literal data as appropriate.

- 130 tests passed; one existing symlink test skipped because this Windows account
  does not have symlink-creation privilege. Unix CI retains that test.
- Combined runtime statement/branch coverage: 96.80%, above the unchanged 85% gate.
- Ruff lint/format and strict mypy passed.
- Exact source maps, generated file guide and synthetic fixture checks passed.
- Official Sigma schema plus constrained compiler accepted all five authored rules.
- Existing 10,000-event/10-iteration benchmark passed: p95 0.0339 s, traced detector
  peak 879,348 bytes. This measures the in-memory detector, not the new review or a
  universal SOC latency guarantee.

Analyst names/dispositions remain owner-supplied assertions, not authentication,
incident confirmation or modifications to labeled detection accuracy. Files and
analyst reasons are private local outputs. Final hosted native/security gates are
required separately before publication.
