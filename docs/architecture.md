# Architecture and decision record

Author: Jason Stys. Accepted: 2026-10-13. Scope: local defensive replay with synthetic, labeled evidence.

```text
JSONL → strict normalizer → ordered unique events → rules + correlation → candidates
                                                           │                 │
Separate truth JSON ────────────────────────────────────────┴─ evaluator ←───┘
                                                                  │
                                                  JSON / SQLite / static HTML
```

The normalizer refuses labels and unknown envelope fields. The detector API has no label argument. Only evaluation compares predictions against the separately authored labels; changing labels does not change alerts. Output hashes fingerprint the exact normalized events, compiled predicates, correlation parameters and independent labels used. These are **semantic snapshot hashes**, not raw-input file signatures, signing attestations or proofs of trustworthy source telemetry.

## Decisions and trade-offs

| Choice | Reason | Cost / rejected alternative |
| --- | --- | --- |
| Python 3.12–3.14, standard-library deques/counters | Clear, tested correlation semantics with portable execution | Not a distributed stream processor; native high-volume engines could perform better |
| Small Sigma subset with official schema | Interoperable authored rules without silently accepting unsupported behavior | Cannot convert arbitrary Sigma or claim full backend compatibility |
| Pinned public-domain upstream schema + jsonschema | Offline validation without the pySigma→DiskCache dependency with an unfixed advisory | Schema is structural validation; behavior needs the separate compiler and tests |
| SQLite STRICT tables and bound inserts | Simple indexed evidence, transactions and integrity checks; no database server | Local unencrypted data, not multi-user storage or access control |
| Inert HTML with escaped values and hash-authorized CSS | Readable local report without JavaScript, ad/tracking dependencies or remote assets | No interactive dashboard or authentication service |
| New-directory-only exports | Protect pre-existing files and keep interrupted exports inspectable | Three output moves are not an atomic directory transaction |
| Hosted checks with no Actions artifact/cache uploads | Preserve scarce account storage while maintaining reviewable logs | Logs and summaries expire under provider retention; dated measured evidence remains in docs |

## Complexity and budgets

Let n be events, r rules, c correlations and p bounded predicates. Parsing/deduplication is O(n), sorting O(n log n), detection O(n·(r·p+c)), and evaluation O(n·emitted detectors). Each correlation candidate enters/leaves a deque once; counter updates are average O(1). Evidence selection is O(threshold), capped at 32. State and timing samples are O(n·c) worst case; inactive group buckets remain until the batch ends. JSON normalization and snapshots also use O(total input bytes). No claim of constant-memory streaming.

Limits: n ≤50,000 JSONL rows, r ≤32, c ≤8, 16MiB input, 16KiB row, 32 scalar fields, 4,096-character strings, threshold 2–32, window 1–3,600 seconds. UTF-8 bytes and character limits are distinct. Regex validates fixed, bounded schemas only, never user regex execution. The 10,000-event benchmark excludes normalization and export; the replay report separately measures pre-export wall time. Trace memory excludes native/interpreter allocations.

Extending this lab needs explicit adapters, richer PowerShell/cron coverage, independent larger evaluation data, streaming watermark semantics and a production telemetry authenticity/privacy design. Do not expand the compiler silently.


## Native workbench boundary

The native entry adds graphical controls around the original core, not a second implementation of its rules. `desktop_project.py` owns project-specific supported input/operation/view semantics; `desktop.py` owns Tk controls and an owned background worker; `desktop_state.py` owns one marked OS-local profile, SQLite transactions, bounded bundles, provenance hashes and explicit retention. Original CLI paths and new-directory exports are preserved.

Only the Tk thread changes widgets. A worker captures scalar settings once, invokes existing analysis functions and saves a completed bundle atomically; the event queue reports completion/errors. Exit waits for that worker before releasing the profile. There is no local HTTP server, remote service, collector/enforcement route or automatic sample execution. Per-user durable storage is outside temporary one-file extraction and the executable installation. Exact frozen resources/interpreter version are checked before opening it. User acknowledgement is not identity authentication.
