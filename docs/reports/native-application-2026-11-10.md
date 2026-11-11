# Native workbench validation — 2026-11-10

This describes a local uncommitted candidate, not a published release or a future GitHub Actions success. Existing replay/scan/review CLI semantics and all original gates remain. New GUI controls call the same core functions; no telemetry collector, shell response, server or model API was added.

The original prototype used Python 3.14.6/Tcl8.6.15 and completed an actual frozen Tk journey, but it is not the runtime selected for distribution. An official Python.org 3.14.10 full ZIP was SHA256-verified and all 2,208 extracted members reverified in task-local tooling, with no installer/registry/PATH/global Python change. It supplies Tcl/Tk9.0.4 through DLL zipfs. The builder now refuses old interpreter versions, collects actual runtime licenses, and binds the packaged Python DLL to startup and consumer receipts. The old prototype is historical, not substituted for patched-runtime acceptance.

Independent scenarios cover 71 normalized events / 10 candidates / 7 TP / 3 FP / 2 FN, a real changed Sigma literal, exact-event/label report comparison, cumulative reasoned triage preserving original accuracy, malformed input without fallback, private exact export and process restart preserving exact bundle hashes. Profile/retention tests cover unknown and synthetic-vs-normal profiles, exclusive ownership, byte quotas, corruption/tamper, stale removal manifests, non-reused identities and unchanged original/export files. Presentation-adapter unit tests use the real core/SQLite; a separate actual frozen test instantiates real widgets/mainloop. Screenshots are actual owned-window captures, not mockups.

## Observed patched-runtime checks

All commands below used an isolated Python 3.14.10 environment with the existing development lock and exact native-build lock. The tested tree is an uncommitted 1.1.0 candidate, so the package correctly records `source_dirty=true` rather than claiming an immutable new release.

| Check | Actual local outcome |
| --- | --- |
| Full pytest with warnings treated as errors | 167 passed; one existing Windows symlink-permission skip; no failures |
| Branch-inclusive coverage | 95.70%, above the unchanged 85% floor; 1,248/1,289 statements and 399/432 branches covered |
| Ruff lint/format, strict mypy Windows and Linux targets, code maps, exhaustive file guide, Git whitespace | Passed |
| Generated scenarios and official Sigma schema | Current synthetic fixtures; all five authored rules accepted by the official schema and constrained compiler |
| Original 10,000-event, ten-iteration in-memory benchmark | p95 0.04148 seconds; peak traced detector allocation 879,348 bytes; ingestion/export/native memory excluded |
| `pip check` and complete locked development/native advisory queries | No broken requirements and no known vulnerabilities reported; no ignores |
| Actual patched one-file EXE | Two real Tk launches passed independent analysis/triage/export oracles and reopened all three exact saved bundles; both owned application and bootloader processes exited |
| Actual GUI captures | Investigation and cumulative reasoned-review windows individually inspected; readable fictional evidence, no desktop capture fallback |

The frozen runtime identified Python 3.14.10 and Tcl/Tk 9.0.4; the bundled Python DLL matched SHA256 `d8a06cc6ca3348925ea29e343e1c5c5895fe0bb433ff913e1cee44caf358aa6a`. Consumer acceptance removed Python/Node/provider variables from the child environment and left only Windows system executables on its PATH. No default or real-user profile was opened. The initial sandbox advisory query could not resolve PyPI; a separately authorized network query completed successfully, rather than treating unavailable data as a clear audit.

Hosted Windows native acceptance, all OS gates, CodeQL, secret/configuration scans and publication remain pending until independently completed; no unrun green claim is made. The explicit Windows symlink skip remains covered on Unix CI. Original coverage/performance thresholds and no-artifact/cache policy are unchanged. A normal shutdown and a paused-then-completed worker shutdown were exercised; arbitrary OS hangs, external forced termination and every possible failure-cleanup condition were not.

Limits: synthetic cases only; no real populated-user upgrade, external OS accessibility automation, production SIEM accuracy, analyst authentication, administrator-proof storage, live ingestion, arbitrary Sigma support, signing or universal-platform installer claim. Native history is plaintext local evidence; logical retention deletion is not forensic erasure. Historical Office publications retain their original baselines and were not rebuilt by this change.
