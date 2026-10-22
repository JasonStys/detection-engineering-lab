# Detection Engineering Lab

[![Validate](https://github.com/JasonStys/detection-engineering-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/JasonStys/detection-engineering-lab/actions/workflows/ci.yml)
[![CodeQL](https://github.com/JasonStys/detection-engineering-lab/actions/workflows/codeql.yml/badge.svg)](https://github.com/JasonStys/detection-engineering-lab/actions/workflows/codeql.yml)

A defensive, offline detection-engineering portfolio by **Jason Stys**. Replay synthetic Windows, Linux and cloud telemetry, evaluate authored Sigma rules and time-window correlations, and explain false positives and missed detections with reproducible evidence. Python handles validation and detection; YAML expresses rules; SQL stores indexed evidence; Bash orchestrates CI; inert HTML makes results readable.

This is a measured lab, **not a production SIEM, incident verdict, live scanner, full Sigma interpreter, or compliance certification**. It does not execute event commands, collect credentials, contact target machines, use AI services, or upload logs. All included identities, hosts and documentation-range addresses are fictional.

## Quick start

Python 3.12–3.14, from the repository directory. No Docker, administrator access, cloud account or credentials needed. Internet is needed only for initial dependencies; replay itself is offline.

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-runtime.lock
New-Item -ItemType Directory -Path out -Force
.\.venv\Scripts\python.exe -m detection replay --events examples/events.jsonl --labels examples/labels.json --out out/demo
Start-Process out/demo/report.html
```

Linux/macOS:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements-runtime.lock
mkdir -p out
.venv/bin/python -m detection replay --events examples/events.jsonl --labels examples/labels.json --out out/demo
```

Open `out/demo/report.html` locally. JSON results and `evidence.sqlite3` sit beside it. **Use a new output directory each time**; existing outputs are never overwritten. Windows file associations decide the viewer. There is no web server or installed background agent.

## Major features

- **Normalize:** strict JSONL envelope, explicit timezone to UTC, immutable scalar fields, 16MiB/50,000-record cap; identical IDs deduplicate and conflicting IDs fail.
- **Detect:** five authored experimental Sigma rules, official-schema validation, case-insensitive literal comparisons and explicit source boundaries. Unsupported regex, wildcard or condition syntax fails closed.
- **Correlate:** four distinct failed-logon users from one source IP on one host within an inclusive 60-second window. Emit only on threshold crossings, with bounded supporting event identities.
- **Evaluate:** labels live in a separate file and never enter detection. Per-detector confusion matrices, micro precision/recall/F1/FPR and explicit nulls for undefined metrics.
- **Explain:** escaped, responsive offline HTML; JSON provenance hashes of the exact normalized/compiled snapshots; indexed SQLite evidence using bound parameters and foreign keys.
- **Validate continuously:** Windows, macOS and Linux tests, property-based oracle checks, measured performance regression budget, dependency/secret/configuration scans, workflow checks and CodeQL. No Actions artifact/cache uploads.

The sample intentionally produces **7 true positives, 3 false positives and 2 false negatives** across 355 event-detector decisions. That is **70% precision and 77.8% recall on this deliberately small synthetic suite**, not a claim about real deployment accuracy. See [known limits](docs/rules.md) and [measured evidence](docs/reports/validation.md).

## Use your own authorized normalized input

```bash
python -m detection scan --events path/to/authorized-normalized.jsonl --out out/authorized-review
```

`scan` has no ground-truth score; `replay` requires `--labels`. `--rules` and `--correlations` select reviewed configuration directories/files. Native EVTX, raw CloudTrail, auditd log text, online ingestion and arbitrary input formats are **not supported**; write and test an adapter first. Local reports/database retain normalized fields, which can contain sensitive information. Keep them private, restrict filesystem access and never commit real logs.

## Test and maintain

Install `requirements-dev.lock` with `--require-hashes` instead of the runtime lock. With the virtual environment active, run `bash scripts/validate.sh` on Linux/macOS or Git Bash on Windows. On plain PowerShell, run the corresponding Python commands listed in [the test plan](docs/testing.md). Development helpers are not required by end users.

After Python edits: `python -m ruff format .`, then `python scripts/code_map.py`. Generated headers give exact function/class, parameter and variable line positions; docstrings describe contracts. After adding files, stage them and run `python scripts/file_guide.py`. Checks fail on stale code maps, missing function contracts, fixture drift or incomplete README inventory.

Read [architecture](docs/architecture.md), [input/configuration contracts](docs/contracts.md), [rules and triage](docs/rules.md), [security boundaries](docs/threat-model.md), [research](docs/research.md), [operations](docs/runbook.md), and [validation results](docs/reports/validation.md). Help and security reporting: [SECURITY.md](SECURITY.md). Contributions: [CONTRIBUTING.md](CONTRIBUTING.md).

## Every tracked file

<!-- BEGIN FILE GUIDE -->

| File | Purpose |
| --- | --- |
| [.gitattributes](.gitattributes) | Portable LF text and binary database handling. |
| [.github/workflows/ci.yml](.github/workflows/ci.yml) | Four OS/Python validation lanes and unsuppressed security gates; no artifact/cache uploads. |
| [.github/workflows/codeql.yml](.github/workflows/codeql.yml) | Least-privilege Python security-extended CodeQL analysis. |
| [.gitignore](.gitignore) | Excludes environments, databases, keys, caches and local evidence. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributing. |
| [LICENSE](LICENSE) | MIT license for authored code and rules. |
| [README.md](README.md) | Detection Engineering Lab. |
| [SECURITY.md](SECURITY.md) | Security policy. |
| [config/correlations.yml](config/correlations.yml) | Distinct-user threshold, rolling window and source/host grouping. |
| [config/sigma-schema.json](config/sigma-schema.json) | Pinned public-domain official Sigma detection rule schema. |
| [detection/__init__.py](detection/__init__.py) | Offline defensive detection lab, authored by Jason Stys; no telemetry or network calls. |
| [detection/__main__.py](detection/__main__.py) | Offline CLI for bounded synthetic replay or explicitly authorized normalized telemetry. Jason Stys. |
| [detection/engine.py](detection/engine.py) | Label-independent rule matching and inclusive event-time burst correlation. Jason Stys. |
| [detection/evaluate.py](detection/evaluate.py) | Independent labeled replay evaluation with explicit event-detector denominators. Jason Stys. |
| [detection/events.py](detection/events.py) | Normalize bounded JSONL telemetry and deduplicate stable identities. Jason Stys. |
| [detection/io.py](detection/io.py) | Bounded regular-file, strict JSON and safe YAML readers. Created by Jason Stys. |
| [detection/rules.py](detection/rules.py) | Constrained Sigma rule compiler without eval, regex or silent unsupported syntax. Jason Stys. |
| [detection/schema.sql](detection/schema.sql) | STRICT indexed evidence tables and foreign-key constraints. |
| [detection/store.py](detection/store.py) | New-directory-only evidence export, bound SQL inserts and inert escaped HTML. Jason Stys. |
| [docs/architecture.md](docs/architecture.md) | Architecture and decision record. |
| [docs/contracts.md](docs/contracts.md) | Input and output contracts. |
| [docs/reports/demo.html](docs/reports/demo.html) | Offline synthetic demonstration report with escaped data and hash-authorized CSS. |
| [docs/reports/portfolio-sync-2026-10-22.md](docs/reports/portfolio-sync-2026-10-22.md) | <!-- File: docs/reports/portfolio-sync-2026-10-22.md; Purpose: certificate-bundle security repair and evidence by Jason Stys. -->. |
| [docs/reports/replay.json](docs/reports/replay.json) | Measured synthetic replay counts, disagreements, timings and snapshot hashes. |
| [docs/reports/validation.md](docs/reports/validation.md) | Validation evidence — 2026-10-13. |
| [docs/research.md](docs/research.md) | Primary-source research and provenance. |
| [docs/rules.md](docs/rules.md) | Rules, scenarios and triage. |
| [docs/runbook.md](docs/runbook.md) | Operator and contributor runbook. |
| [docs/testing.md](docs/testing.md) | Test strategy and validation gates. |
| [docs/threat-model.md](docs/threat-model.md) | Threat model and security review. |
| [examples/events.jsonl](examples/events.jsonl) | Fictional mixed-source input with disorder and one exact duplicate; no labels. |
| [examples/labels.json](examples/labels.json) | Independently authored benign/positive truth, separate from features. |
| [pyproject.toml](pyproject.toml) | Runtime metadata and strict lint/type/test/coverage gates. |
| [requirements-dev.in](requirements-dev.in) | Reviewed direct development dependencies. |
| [requirements-dev.lock](requirements-dev.lock) | Complete hash-locked development dependency graph. |
| [requirements-runtime.in](requirements-runtime.in) | Minimal reviewed replay runtime dependency. |
| [requirements-runtime.lock](requirements-runtime.lock) | Hash-locked portable runtime installation. |
| [rules/cloud_logging.yml](rules/cloud_logging.yml) | CloudTrail Logging Removal Candidate; experimental authored Sigma rule. |
| [rules/linux_cron.yml](rules/linux_cron.yml) | System Cron Configuration Write Candidate; experimental authored Sigma rule. |
| [rules/windows_auth_failure.yml](rules/windows_auth_failure.yml) | Windows Failed Logon Correlation Base; experimental authored Sigma rule. |
| [rules/windows_log_clear.yml](rules/windows_log_clear.yml) | Windows Security Audit Log Cleared; experimental authored Sigma rule. |
| [rules/windows_powershell.yml](rules/windows_powershell.yml) | PowerShell Encoded Argument Candidate; experimental authored Sigma rule. |
| [scripts/benchmark.py](scripts/benchmark.py) | Measured synthetic detector benchmark, not a production SIEM capacity claim. Jason Stys. |
| [scripts/code_map.py](scripts/code_map.py) | Generate/check exact Python symbol locations in file headers. Created by Jason Stys. |
| [scripts/file_guide.py](scripts/file_guide.py) | Maintain an exhaustive README summary of tracked files, excluding ignored private outputs. Jason Stys. |
| [scripts/scenarios.py](scripts/scenarios.py) | Reproducible synthetic telemetry and independently authored truth, never detector-derived. Jason Stys. |
| [scripts/summary.py](scripts/summary.py) | Small CI job summaries without uploading Actions artifacts or sensitive telemetry. Jason Stys. |
| [scripts/tools.py](scripts/tools.py) | Install only hash-pinned official Linux scanner binaries. Created by Jason Stys. |
| [scripts/validate.sh](scripts/validate.sh) | Fail-fast cross-platform quality, semantic and benchmark checks. |
| [scripts/validate_rules.py](scripts/validate_rules.py) | Validate authored Sigma against pinned official schema and stricter lab grammar. Jason Stys. |
| [tests/test_detection.py](tests/test_detection.py) | Independent semantic oracle, Sigma matching and labeled replay regressions. Jason Stys. |
| [tests/test_export.py](tests/test_export.py) | End-to-end CLI, inert HTML, SQL binding and non-overwrite output tests. Jason Stys. |
| [tests/test_inputs.py](tests/test_inputs.py) | Schema, resource, ambiguity and untrusted-input safety regressions. Jason Stys. |
| [tests/test_tools.py](tests/test_tools.py) | Development-gate drift, schema verification and code-map idempotence. Jason Stys. |
| [tools.lock.json](tools.lock.json) | Official scanner versions, URLs and verified archive digests. |

<!-- END FILE GUIDE -->

## Author and contact

Created by [Jason Stys](https://github.com/JasonStys). Contact through [LinkedIn](https://www.linkedin.com/in/jason-stys-31b30b351/). MIT license covers authored code and rules; the vendored Sigma schema is public domain with [provenance](docs/research.md). No employer endorsement or operational certification is implied.
