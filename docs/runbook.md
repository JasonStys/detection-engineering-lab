# Operator and contributor runbook

## Replay, inspect, and investigate

Use README setup, then choose a new output folder under a trusted existing parent. Exit 2 means rejected input/usage or I/O; inspect the generic message and input contract. Do not relax validation to ingest unknown formats. A successful run can still contain expected false positives and misses. Read the HTML summary, then JSON details and supporting event records before conclusions.

Python read-only query against **your own generated database**:

```python
import sqlite3
from pathlib import Path

path = Path("out/demo/evidence.sqlite3").resolve()
with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as connection:
    rows = connection.execute(
        "SELECT detector, event_id, timestamp, span_seconds FROM alert WHERE detector = ? ORDER BY timestamp, event_id",
        ("auth-burst",),
    ).fetchall()
    print(rows)
```

Expected burst at `burst-3` with 60-second proof span. Database files from untrusted third parties are outside scope; do not run copied SQL or extensions. Connection context commits/rolls back but does not itself close; for long-lived application code use `contextlib.closing` as the implementation does.

## Common issues

- Output exists: retain it, choose a new directory. Nothing is automatically deleted.
- Missing input or invalid type: check UTF-8, required envelope and integer EventID. Raw EVTX/CloudTrail/auditd are not accepted.
- No correlation: examine distinct users, exact source/host grouping, inclusive time window and missing-field counter. Same user retries are not four users.
- High false-positive count: review legitimate changes and add documented tests/tuning; do not infer intent from a regex or level label.
- Pinned schema drift: compare the recorded upstream commit and checksum; update intentionally after license/spec review, not by bypassing the guard.
- Security feed unavailable: rerun when available. A failed/unavailable audit is not “clean”; keep release blocked until verified.
- Partial output after disk error: inspect the new destination and owned files. Keep any needed evidence and choose another new destination. No destructive rollback command is included.

## Change and release checklist

- [ ] Add independent positive, benign and evasion scenarios and review ground truth.
- [ ] Keep strict parser limits and matching/correlation semantics documented.
- [ ] Format code, regenerate exact maps, stage files, update README inventory.
- [ ] Run tests, official-schema checks, benchmark and unsuppressed dependency audit.
- [ ] Review injection, output-race, source/label separation and token permissions.
- [ ] Confirm every workflow on the exact intended commit completed successfully, inspect CodeQL findings as well as run status.
- [ ] Record measured results, known limits and immutable CI run links in docs.
- [ ] Check account Actions storage before triggering/checking CI; alert the owner, distinguish artifact/cache/meter usage. Never delete runs/artifacts or change billing without fresh approval.

There is no production deployment, migration, paid host or on-call service. To roll back behavior, check out a previously validated commit **in a new checkout** and rerun its checks; preserve newer files/evidence. Do not run destructive reset/cleanup. New schema versions require separate outputs and documented migration tests before backward-compatibility claims.

## Dependency updates

Regenerate hash locks with reviewed `pip-tools==7.6.2`, `pip-compile --generate-hashes --allow-unsafe --strip-extras`, then audit all resolved packages and test every platform. Bootstrap tooling belongs in an isolated development environment and is not a replay runtime dependency. Do not execute unknown scanner binaries; installer checks official release paths, caps size and verifies SHA256 before extracting a single regular binary. The lock's Python version describes generation; all supported CI runtimes must verify installation.

Help: [Jason Stys on LinkedIn](https://www.linkedin.com/in/jason-stys-31b30b351/). For a private security report use repository private vulnerability reporting rather than a public issue with logs/secrets.
